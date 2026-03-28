"""
Safe DNS Query MCP Server

Provides DNS lookups and email security analysis without shell execution.
Uses dnspython library directly for all DNS operations.
All DNS operations are performed using pure Python with no subprocess calls.

Tools provided:
  Utility:
  - ping: Lightweight health check (no external dependencies)
  - server_info: Show resolver config (nameservers, dnspython version, etc.)
  - quine: Return the source code of this MCP server
  - session_stats: Per-tool call counts, errors, and latency for this container session
  - reset_stats: Reset session stats and clock without restarting the container

  DNS:
  - dns_query: Standard DNS lookups for common record types
  - dns_dig_style: Detailed dig-style queries showing full response sections
  - dns_query_dot: DNS over TLS (DoT) query with TLS session and EDNS details
  - reverse_dns: PTR record lookups for IP addresses
  - dns_dnssec_validate: DNSSEC chain-of-trust validation
  - nsec_info: NSEC/NSEC3 denial-of-existence analysis and zone walkability check
  - timestamp_converter: Convert between ISO, epoch, and human-readable timestamps

  Email Security:
  - check_spf: SPF record parsing with recursive include resolution
  - check_dmarc: DMARC policy retrieval with org domain fallback
  - check_dkim_selector: DKIM public key record verification
  - check_bimi: BIMI record and VMC check
  - check_mta_sts: MTA-STS DNS record check
  - check_smtp_tlsrpt: SMTP TLS Reporting record check
  - check_tlsa: Direct TLSA record check for any host:port:protocol
  - check_dane: DANE TLSA record check for mail server authentication
  - rdap_lookup: Domain registration data via RDAP (HTTP, not DNS)
  - detect_hijacking: DNS hijacking and tampering detection for a resolver IP
  - check_rbl: IP reputation check against 8 DNS-based RBLs (Spamhaus, SpamCop, SORBS, etc.)
  - check_dbl: Domain reputation check against DNS-based Domain Block Lists (Spamhaus DBL, URIBL, SURBL)
  - cymru_asn: ASN lookup via Team Cymru DNS service (BGP prefix, org name, high-risk ASN flag)
  - check_fast_flux: Fast-flux detection — repeated A/AAAA queries to detect rotating IPs and short TTLs
  - check_ct_logs: Certificate Transparency log enumeration via crt.sh — subdomain discovery, per-cert details, CAA cross-reference
"""

from fastmcp import FastMCP
from pathlib import Path
import dns.resolver
import dns.version
import dns.query
import dns.message
import dns.flags
import dns.rcode
import dns.opcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.reversename
import dns.dnssec
import dns.name
import dns.rrset
from datetime import datetime, timezone
from typing import Literal
import os
import re
import secrets
import ipaddress
import socket
import ssl
import time
import requests
from pydantic import Field
import tracking
from tracking import track, reset_stats as _reset_stats

# IANA root trust anchors — both active KSKs
# Source: https://www.iana.org/dnssec/files
_ROOT_TRUST_ANCHOR_TEXT = [
    # KSK-2017 (tag 20326, alg 8/RSA-SHA256)
    "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3"
    "+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv"
    "ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0"
    "jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZ"
    "G+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRU"
    "fhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1A"
    "kUTV74bU=",
    # KSK-2024 (tag 38696, alg 8/RSA-SHA256)
    "257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/c"
    "idltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGi"
    "ShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUi"
    "RAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuM"
    "oTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2C"
    "XkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC7"
    "3PYc=",
]


def _build_root_trust_anchor() -> tuple[dns.rrset.RRset, dict]:
    """Build root trust anchor RRset from hardcoded IANA key material."""
    rrset = dns.rrset.RRset(dns.name.root, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    for ktext in _ROOT_TRUST_ANCHOR_TEXT:
        rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, ktext)
        rrset.add(rd)
    return rrset, {dns.name.root: rrset}


# Initialize FastMCP server
mcp = FastMCP("DNS Query Server")

# Prompt files directory
_PROMPT_DIR = Path(__file__).parent / "prompts"

# Domain validation regex (strict)
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)

# Allowed DNS record types (security allowlist)
ALLOWED_TYPES = [
    "A",
    "AAAA",
    "MX",
    "TXT",
    "NS",
    "SOA",
    "CNAME",
    "PTR",
    "SRV",
    "DNSKEY",
    "DS",
    "TLSA",
    "CAA",
    "SSHFP",
    "RRSIG",
    "CDS",
    "CDNSKEY",
    "HTTPS",
    "SVCB",
    "NAPTR",
]

# DNS label pattern for DKIM selector validation
DNS_LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# RDAP bootstrap cache (populated on first use)
_rdap_bootstrap_cache = None

# DANE TLSA field name mappings (RFC 6698)
TLSA_USAGE_NAMES = {0: "PKIX-TA", 1: "PKIX-EE", 2: "DANE-TA", 3: "DANE-EE"}
TLSA_SELECTOR_NAMES = {0: "Full certificate", 1: "SubjectPublicKeyInfo"}
TLSA_MATCHING_NAMES = {0: "Exact match", 1: "SHA-256", 2: "SHA-512"}

# Default resolver for direct UDP queries (Quad9 — DNSSEC-validating, privacy-respecting)
DEFAULT_RESOLVER = "9.9.9.9"
# DoT default uses Cloudflare (1.1.1.1) rather than Quad9. When Docker runs
# with --dns 9.9.9.9, it installs NAT rules that interfere with TCP port 853
# connections back to the same IP, causing "Connection reset by peer".
DEFAULT_DOT_RESOLVER = "1.1.1.1"

# Spamhaus Data Query Service key (optional — enables production-grade DQS zone).
# Without it, zen.spamhaus.org is used (works for low-volume analyst use).
# Set via: docker run -e SPAMHAUS_DQS_KEY=yourkey ...
SPAMHAUS_DQS_KEY = os.getenv("SPAMHAUS_DQS_KEY")

# RBL zone definitions — queried in order for check_rbl().
# Each entry: name, zone (FQDN suffix), codes (return code → description),
# positive_codes (set of codes that indicate good reputation, not a listing).
_RBL_LIST = [
    {
        "name": "Spamhaus ZEN",
        "zone": (
            f"{SPAMHAUS_DQS_KEY}.zen.dq.spamhaus.net"
            if SPAMHAUS_DQS_KEY
            else "zen.spamhaus.org"
        ),
        "codes": {
            "127.0.0.2": "SBL — direct spam source",
            "127.0.0.3": "SBL CSS — spam support services",
            "127.0.0.4": "XBL — exploited/compromised host",
            "127.0.0.5": "XBL — exploited/compromised host",
            "127.0.0.6": "XBL — exploited/compromised host",
            "127.0.0.7": "XBL — exploited/compromised host",
            "127.0.0.9": "DROP — do not route or peer",
            "127.0.0.10": "PBL — ISP policy block (dynamic/end-user IP)",
            "127.0.0.11": "PBL — Spamhaus maintained policy block",
        },
        "positive_codes": set(),
        # Spamhaus returns these administrative codes when queries are rate-limited
        # or blocked — they must not be treated as IP listings.
        "quota_codes": {
            "127.255.255.252": (
                "Resolver not allowlisted by Spamhaus — set SPAMHAUS_DQS_KEY "
                "or use a resolver with a Spamhaus agreement"
            ),
            "127.255.255.254": (
                "Query limit exceeded on zen.spamhaus.org — set SPAMHAUS_DQS_KEY "
                "for unrestricted access via the DQS zone"
            ),
            "127.255.255.255": (
                "Source blocked by Spamhaus — set SPAMHAUS_DQS_KEY "
                "for unrestricted access via the DQS zone"
            ),
        },
    },
    {
        "name": "SpamCop",
        "zone": "bl.spamcop.net",
        "codes": {"127.0.0.2": "Listed — spam source"},
        "positive_codes": set(),
    },
    {
        "name": "UCEProtect L1",
        "zone": "dnsbl-1.uceprotect.net",
        "codes": {"127.0.0.2": "Listed — direct spam source"},
        "positive_codes": set(),
    },
    {
        "name": "UCEProtect L2",
        "zone": "dnsbl-2.uceprotect.net",
        "codes": {"127.0.0.2": "Listed — netblock contains spam sources"},
        "positive_codes": set(),
    },
    {
        "name": "Mailspike",
        "zone": "bl.mailspike.net",
        "codes": {
            "127.0.0.2": "Listed — spam source",
            "127.0.0.3": "Listed — poor reputation",
            "127.0.0.4": "Listed — very poor reputation",
            "127.0.0.5": "Listed — worst reputation",
            "127.0.0.10": "Reputation — excellent sender",
            "127.0.0.11": "Reputation — good sender",
            "127.0.0.12": "Reputation — good sender",
            "127.0.0.13": "Reputation — neutral/ham",
            "127.0.0.14": "Reputation — neutral/ham",
        },
        "positive_codes": {
            "127.0.0.10",
            "127.0.0.11",
            "127.0.0.12",
            "127.0.0.13",
            "127.0.0.14",
        },
    },
    {
        "name": "PSBL",
        "zone": "psbl.surriel.com",
        "codes": {"127.0.0.2": "Listed — passive spam source"},
        "positive_codes": set(),
    },
    {
        "name": "Barracuda",
        "zone": "b.barracudacentral.org",
        "codes": {"127.0.0.2": "Listed — spam source"},
        "positive_codes": set(),
    },
    {
        "name": "SORBS",
        "zone": "dnsbl.sorbs.net",
        "codes": {
            "127.0.0.2": "HTTP open proxy",
            "127.0.0.3": "SOCKS open proxy",
            "127.0.0.4": "Miscellaneous open proxy",
            "127.0.0.5": "SMTP open relay",
            "127.0.0.6": "Spam source",
            "127.0.0.7": "Web form spam",
            "127.0.0.8": "DUL — dynamic/end-user IP",
            "127.0.0.10": "Escalated — listed in multiple SORBS zones",
        },
        "positive_codes": set(),
    },
]

# DBL zone definitions — queried in order for check_dbl().
# URIBL and SURBL use bitmask return codes; Spamhaus DBL uses direct code lookup.
_DBL_LIST = [
    {
        "name": "Spamhaus DBL",
        "zone": (
            f"{SPAMHAUS_DQS_KEY}.dbl.dq.spamhaus.net"
            if SPAMHAUS_DQS_KEY
            else "dbl.spamhaus.org"
        ),
        "bitmask": False,
        "codes": {
            "127.0.1.2": "Spam domain",
            "127.0.1.4": "Phishing domain",
            "127.0.1.5": "Malware domain",
            "127.0.1.6": "Botnet C2 domain",
            "127.0.1.102": "Abused legit domain — spam",
            "127.0.1.103": "Abused legit domain — phishing",
            "127.0.1.104": "Abused legit domain — malware",
            "127.0.1.105": "Abused legit domain — botnet C2",
        },
        "quota_codes": {
            "127.255.255.252": (
                "Resolver not allowlisted by Spamhaus — set SPAMHAUS_DQS_KEY "
                "or use a resolver with a Spamhaus agreement"
            ),
            "127.255.255.254": (
                "Query limit exceeded on dbl.spamhaus.org — set SPAMHAUS_DQS_KEY "
                "for unrestricted access via the DQS zone"
            ),
            "127.255.255.255": (
                "Source blocked by Spamhaus — set SPAMHAUS_DQS_KEY "
                "for unrestricted access via the DQS zone"
            ),
        },
    },
    {
        "name": "URIBL",
        "zone": "multi.uribl.com",
        "bitmask": True,
        "bitmask_labels": {
            0x01: "black — confirmed spam domain",
            0x02: "grey — greylist (new/unverified)",
            0x04: "red — aggregate spam domain",
            0x08: "multi — in multiple URIBL lists",
        },
    },
    {
        "name": "SURBL",
        "zone": "multi.surbl.org",
        "bitmask": True,
        "bitmask_labels": {
            0x02: "SC — SpamCop data",
            0x04: "WS — general spam",
            0x08: "AB — abuse.ch malware",
            0x10: "PH — phishing",
            0x40: "MW — malware",
            0x80: "CRX — compromised domain",
        },
    },
]

# Known high-risk / bulletproof ASNs flagged by cymru_asn (non-exhaustive).
_HIGH_RISK_ASNS: dict[int, str] = {
    9009: "M247 — frequently used by spammers and bulletproof hosting operators",
    53667: "Frantech/BuyVM — bulletproof hosting provider",
    36352: "ColoCrossing — frequently abused commodity hosting",
    20473: "Vultr — commodity cloud, high abuse volume",
    14061: "DigitalOcean — commodity cloud, notable abuse volume",
    63949: "Linode/Akamai — commodity cloud, notable abuse volume",
}

# CA organization → CAA identity mapping for CT log cross-reference.
# Maps the O= field from issuer_name (stable across intermediate rotations)
# to the domain used in CAA issue/issuewild tags.
_ORG_TO_CAA_IDENTITY = {
    "Let's Encrypt": "letsencrypt.org",
    "Internet Security Research Group": "letsencrypt.org",  # ISRG root
    "ZeroSSL": "sectigo.com",
    "Sectigo Limited": "sectigo.com",
    "Google Trust Services LLC": "pki.goog",
    "Google Trust Services": "pki.goog",
    "DigiCert Inc": "digicert.com",
    "GlobalSign nv-sa": "globalsign.com",
    "GlobalSign": "globalsign.com",
    "Actalis S.p.A.": "actalis.it",
    "SSL.com": "ssl.com",
    "Buypass AS": "buypass.com",
    "HARICA": "harica.gr",
}

_CT_MAX_RETRIES = 3
_CT_TIMEOUT_SECONDS = 20
_CT_BACKOFF = [0, 2, 5]  # seconds before each attempt

# Hardcoded RDAP fallbacks for common TLDs
_RDAP_FALLBACKS = {
    "com": "https://rdap.verisign.com/com/v1",
    "net": "https://rdap.verisign.com/net/v1",
    "org": "https://rdap.org/",
    "info": "https://rdap.afilias.net/rdap/info/",
    "io": "https://rdap.nic.io/",
}


def validate_domain(domain: str) -> tuple[bool, str]:
    """Validate domain name format"""
    if len(domain) > 253:
        return False, "Domain too long (max 253 chars)"

    if not DOMAIN_PATTERN.match(domain):
        return False, "Invalid domain format"

    return True, domain


def validate_selector(selector: str) -> tuple[bool, str]:
    """Validate DKIM selector as DNS label (alphanumeric + hyphens)"""
    if not selector or len(selector) > 63:
        return False, "Selector must be 1-63 characters"
    if not DNS_LABEL_PATTERN.match(selector):
        return False, "Selector must be alphanumeric with hyphens (DNS label format)"
    return True, selector


def validate_port(port: int) -> tuple[bool, str]:
    """Validate TCP/UDP port number (1-65535)"""
    if not isinstance(port, int) or isinstance(port, bool):
        return False, "Port must be an integer"
    if port < 1 or port > 65535:
        return False, f"Port {port} out of range (must be 1-65535)"
    return True, str(port)


def _parse_tag_value(record: str) -> dict[str, str]:
    """Parse a semicolon-delimited tag=value DNS record (DMARC, DKIM, BIMI, etc.)"""
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip()] = value.strip()
    return tags


def _query_txt_record(fqdn: str) -> tuple[str | None, list[str]]:
    """Query TXT records for a FQDN. Returns (first_record, errors)."""
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(fqdn, "TXT")
        # TXT records can be split across multiple strings; join them
        records = []
        for rdata in answers:
            records.append(
                "".join(
                    s.decode() if isinstance(s, bytes) else s for s in rdata.strings
                )
            )
        return records[0] if records else None, []
    except dns.resolver.NXDOMAIN:
        return None, [f"NXDOMAIN: {fqdn} does not exist"]
    except dns.resolver.NoAnswer:
        return None, []
    except dns.resolver.NoNameservers:
        return None, [f"No nameservers available for {fqdn}"]
    except dns.exception.Timeout:
        return None, [f"DNS query timeout for {fqdn}"]


def _query_all_txt_records(fqdn: str) -> tuple[list[str], list[str]]:
    """Query all TXT records for a FQDN. Returns (records_list, errors)."""
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(fqdn, "TXT")
        records = []
        for rdata in answers:
            records.append(
                "".join(
                    s.decode() if isinstance(s, bytes) else s for s in rdata.strings
                )
            )
        return records, []
    except dns.resolver.NXDOMAIN:
        return [], [f"NXDOMAIN: {fqdn} does not exist"]
    except dns.resolver.NoAnswer:
        return [], []
    except dns.resolver.NoNameservers:
        return [], [f"No nameservers available for {fqdn}"]
    except dns.exception.Timeout:
        return [], [f"DNS query timeout for {fqdn}"]


def _get_org_domain(domain: str) -> str:
    """Extract organizational domain (simple TLD split).
    e.g., 'sub.example.com' -> 'example.com', 'example.co.uk' -> 'co.uk' (simplified)
    """
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    return ".".join(parts[-2:])


@mcp.tool()
@track("ping")
def ping() -> dict:
    """
    Lightweight health check. Returns server status and timestamp with no
    external dependencies — no DNS queries, no HTTP requests.
    """
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "server": "DNS Query Server",
    }


@mcp.tool()
@track("server_info")
def server_info() -> dict:
    """
    Show server configuration: dnspython version, configured nameservers,
    search domains, and default domain. Useful for understanding which
    resolver the server is using and debugging query behavior.
    """
    resolver = dns.resolver.Resolver()
    return {
        "dnspython_version": dns.version.version,
        "nameservers": resolver.nameservers,
        "search": [str(s) for s in resolver.search],
        "domain": str(resolver.domain),
        "timeout": resolver.lifetime,
        "edns": resolver.edns,
        "edns_payload": resolver.payload,
    }


@mcp.tool()
@track("quine")
def quine() -> dict:
    """
    Return the source code of this MCP server.
    Reads and returns the contents of server.py via __file__.
    A diagnostic/introspection tool — no parameters, no external dependencies.
    """
    try:
        with open(__file__, "r") as f:
            source = f.read()
        return {
            "file": __file__,
            "lines": source.count("\n") + 1,
            "source": source,
        }
    except Exception as e:
        return {"error": f"Failed to read source: {str(e)}"}


@mcp.tool()
@track("session_stats")
def session_stats() -> dict:
    """
    Return per-tool call statistics for this container session.
    Reports uptime, total calls, and per-tool count/errors/latency since container start.
    Stats reset on every container restart — in-process only, no persistence.
    """
    now = datetime.now(timezone.utc)
    uptime = (now - tracking._session_start).total_seconds()
    per_tool = tracking.get_stats()
    total = sum(s["count"] for s in per_tool.values())
    return {
        "session_start": tracking._session_start.isoformat(),
        "current_time": now.isoformat(),
        "uptime_seconds": round(uptime, 1),
        "total_calls": total,
        "tools": per_tool,
    }


@mcp.tool()
@track("reset_stats")
def reset_stats() -> dict:
    """
    Reset all per-tool call statistics and restart the session clock.
    Use this to start a fresh measurement window without restarting the container.
    Returns a confirmation with the new session start time.
    """
    _reset_stats()
    return {
        "reset": True,
        "new_session_start": tracking._session_start.isoformat(),
    }


@mcp.tool()
@track("dns_query")
def dns_query(
    domain: str = Field(description="Domain name to query (e.g., 'example.com')"),
    record_type: Literal[
        "A",
        "AAAA",
        "MX",
        "TXT",
        "NS",
        "SOA",
        "CNAME",
        "PTR",
        "SRV",
        "DNSKEY",
        "DS",
        "TLSA",
        "CAA",
        "SSHFP",
        "RRSIG",
        "CDS",
        "CDNSKEY",
        "HTTPS",
        "SVCB",
        "NAPTR",
    ] = "A",
    nameserver: str | None = Field(
        default=None, description="Optional nameserver IP (e.g., '9.9.9.9')"
    ),
) -> dict:
    """
    Query DNS records safely using dnspython library.

    Performs standard DNS lookups for common record types using the system resolver
    or a specified nameserver. Returns structured results with TTL information.

    Supports: A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, SRV, DNSKEY, DS, TLSA,
    CAA, SSHFP, RRSIG, CDS, CDNSKEY, HTTPS, SVCB, NAPTR record types.
    No shell execution - pure Python DNS resolution via dnspython.
    """
    # Validate domain
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    try:
        # Create resolver
        resolver = dns.resolver.Resolver()

        # Use custom nameserver if provided
        if nameserver:
            # Validate nameserver is IP address
            try:
                import ipaddress

                ipaddress.ip_address(nameserver)
                resolver.nameservers = [nameserver]
            except ValueError:
                return {"error": "Invalid nameserver IP address", "domain": domain}

        # Perform query
        answers = resolver.resolve(domain, record_type)

        # Format results based on record type
        results = []
        for rdata in answers:
            if record_type == "MX":
                results.append(
                    {"preference": rdata.preference, "exchange": str(rdata.exchange)}
                )
            elif record_type == "TXT":
                results.append(str(rdata).strip('"'))
            elif record_type == "SOA":
                results.append(
                    {
                        "mname": str(rdata.mname),
                        "rname": str(rdata.rname),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "minimum": rdata.minimum,
                    }
                )
            elif record_type == "SRV":
                results.append(
                    {
                        "priority": rdata.priority,
                        "weight": rdata.weight,
                        "port": rdata.port,
                        "target": str(rdata.target),
                    }
                )
            else:
                results.append(str(rdata))

        return {
            "domain": domain,
            "record_type": record_type,
            "nameserver": nameserver or resolver.nameservers[0],
            "ttl": answers.rrset.ttl,
            "results": results,
            "query_time": datetime.now(timezone.utc).isoformat(),
        }

    except dns.resolver.NXDOMAIN:
        return {
            "error": "Domain does not exist (NXDOMAIN)",
            "domain": domain,
            "record_type": record_type,
        }
    except dns.resolver.NoAnswer:
        return {
            "error": f"No {record_type} records found",
            "domain": domain,
            "record_type": record_type,
        }
    except dns.resolver.Timeout:
        return {
            "error": "DNS query timeout",
            "domain": domain,
            "record_type": record_type,
        }
    except Exception as e:
        return {
            "error": f"DNS query failed: {str(e)}",
            "domain": domain,
            "record_type": record_type,
        }


@mcp.tool()
@track("dns_dig_style")
def dns_dig_style(
    domain: str = Field(description="Domain name to query"),
    record_type: Literal[
        "A",
        "AAAA",
        "MX",
        "TXT",
        "NS",
        "SOA",
        "CNAME",
        "PTR",
        "SRV",
        "DNSKEY",
        "DS",
        "TLSA",
        "CAA",
        "SSHFP",
        "RRSIG",
        "CDS",
        "CDNSKEY",
        "HTTPS",
        "SVCB",
        "NAPTR",
    ] = "A",
    nameserver: str = Field(
        default=DEFAULT_RESOLVER, description="Nameserver to query"
    ),
) -> dict:
    """
    Perform a dig-style DNS query showing full response details.

    Sends a direct UDP query to the specified nameserver and returns detailed
    response information similar to the `dig` command output.

    Returns:
    - Header flags including DNSSEC-related flags (AD=Authenticated Data, CD=Checking Disabled)
    - Response status (NOERROR, NXDOMAIN, SERVFAIL, etc.)
    - Answer, Authority, and Additional sections with full record details
    """
    # Validate domain
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    # Validate nameserver
    try:
        import ipaddress

        ipaddress.ip_address(nameserver)
    except ValueError:
        return {"error": "Invalid nameserver IP address", "domain": domain}

    try:
        # Build DNS query with DNSSEC OK (DO) flag set
        query = dns.message.make_query(domain, record_type, want_dnssec=True)

        # Send query directly to nameserver
        response = dns.query.udp(query, nameserver, timeout=5.0)

        # Parse response sections
        def format_section(section):
            results = []
            for rrset in section:
                for rdata in rrset:
                    results.append(
                        {
                            "name": str(rrset.name),
                            "ttl": rrset.ttl,
                            "class": dns.rdataclass.to_text(rrset.rdclass),
                            "type": dns.rdatatype.to_text(rrset.rdtype),
                            "data": str(rdata),
                        }
                    )
            return results

        # Parse DNSSEC-related flags from response
        flags_int = response.flags
        dnssec_flags = {
            "AD": bool(flags_int & dns.flags.AD),  # Authenticated Data
            "CD": bool(flags_int & dns.flags.CD),  # Checking Disabled
        }

        # Scan authority section for denial-of-existence records (NSEC/NSEC3)
        doe_type = None
        doe_count = 0
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NSEC:
                doe_type = "NSEC"
                doe_count += len(rrset)
            elif rrset.rdtype == dns.rdatatype.NSEC3:
                doe_type = "NSEC3"
                doe_count += len(rrset)

        result = {
            "query": {"domain": domain, "type": record_type, "nameserver": nameserver},
            "header": {
                "id": response.id,
                "flags": dns.flags.to_text(response.flags),
                "status": dns.rcode.to_text(response.rcode()),
                "opcode": dns.opcode.to_text(response.opcode()),
                "dnssec": dnssec_flags,
            },
            "sections": {
                "answer": format_section(response.answer),
                "authority": format_section(response.authority),
                "additional": format_section(response.additional),
            },
            "question_count": len(response.question),
            "answer_count": len(response.answer),
            "authority_count": len(response.authority),
            "additional_count": len(response.additional),
            "query_time": datetime.now(timezone.utc).isoformat(),
        }

        if doe_count > 0:
            result["denial_of_existence"] = {
                "present": True,
                "type": doe_type,
                "record_count": doe_count,
            }

        return result

    except Exception as e:
        return {
            "error": f"Query failed: {str(e)}",
            "domain": domain,
            "record_type": record_type,
            "nameserver": nameserver,
        }


def _dot_query(
    q: dns.message.Message,
    nameserver: str,
    port: int = 853,
    timeout: float = 10.0,
) -> tuple:
    """Send a DNS query over TLS (DoT, RFC 7858). Returns (response, elapsed_ms, tls_info)."""
    ctx = ssl.create_default_context()
    # IP-based resolver connections cannot use hostname verification (no SNI target).
    # This matches kdig's default behaviour when given a bare IP.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    wire = q.to_wire()
    length_prefix = len(wire).to_bytes(2, "big")

    t0 = time.perf_counter()
    with socket.create_connection((nameserver, port), timeout=timeout) as raw_sock:
        raw_sock.settimeout(timeout)
        with ctx.wrap_socket(raw_sock) as tls_sock:
            cipher_tuple = tls_sock.cipher()  # (name, protocol, bits)
            tls_version = tls_sock.version()
            tls_sock.sendall(length_prefix + wire)

            # Read 2-byte response length prefix (RFC 7858 §3.3)
            buf = b""
            while len(buf) < 2:
                chunk = tls_sock.recv(2 - len(buf))
                if not chunk:
                    raise ConnectionError("Connection closed before response length")
                buf += chunk

            msg_len = int.from_bytes(buf, "big")

            msg_data = b""
            while len(msg_data) < msg_len:
                chunk = tls_sock.recv(msg_len - len(msg_data))
                if not chunk:
                    raise ConnectionError("Connection closed before full response")
                msg_data += chunk

    elapsed_ms = (time.perf_counter() - t0) * 1000
    cipher_name, proto_version, cipher_bits = cipher_tuple or ("unknown", "unknown", 0)
    tls_info = {
        "version": tls_version or proto_version,
        "cipher": cipher_name,
        "bits": cipher_bits,
    }
    return dns.message.from_wire(msg_data), elapsed_ms, tls_info


@mcp.tool()
@track("dns_query_dot")
def dns_query_dot(
    domain: str = Field(description="Domain name to query"),
    record_type: Literal[
        "A",
        "AAAA",
        "MX",
        "TXT",
        "NS",
        "SOA",
        "CNAME",
        "PTR",
        "SRV",
        "DNSKEY",
        "DS",
        "TLSA",
        "CAA",
        "SSHFP",
        "RRSIG",
        "CDS",
        "CDNSKEY",
        "HTTPS",
        "SVCB",
        "NAPTR",
    ] = "A",
    nameserver: str = Field(
        default=DEFAULT_DOT_RESOLVER,
        description=f"Resolver IP supporting DoT on port 853 (default: {DEFAULT_DOT_RESOLVER})",
    ),
    port: int = 853,
) -> dict:
    """
    Perform a DNS over TLS (DoT) query showing full response details.

    Establishes a TLS session directly to the resolver and sends a DNSSEC-enabled
    query, similar to: kdig @resolver +tls +dnssec +multi <type> <domain>

    Returns:
    - TLS session: protocol version (TLS1.3), cipher suite, key bits
    - Header: status (NOERROR/NXDOMAIN/SERVFAIL/REFUSED), flags (qr/rd/ra/ad/aa/tc/cd)
    - EDNS pseudosection: version, DO flag, UDP payload size, padding bytes
    - Answer, Authority, Additional sections with full record details
    - Round-trip time in ms
    """
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    try:
        ipaddress.ip_address(nameserver)
    except ValueError:
        return {"error": "Invalid nameserver IP address", "domain": domain}

    valid_port, port_msg = validate_port(port)
    if not valid_port:
        return {"error": port_msg, "domain": domain}

    try:
        rdtype = dns.rdatatype.from_text(record_type)
    except dns.rdatatype.UnknownRdatatype:
        return {"error": f"Unknown record type: {record_type}", "domain": domain}

    q = dns.message.make_query(domain, rdtype, want_dnssec=True)

    try:
        response, elapsed_ms, tls_info = _dot_query(q, nameserver, port)
    except Exception as e:
        return {
            "error": f"DoT query failed: {e}",
            "domain": domain,
            "nameserver": nameserver,
            "port": port,
            "transport": "DoT",
        }

    # Build flags list in wire order
    flags = []
    for flag_bit, flag_name in (
        (dns.flags.QR, "qr"),
        (dns.flags.AA, "aa"),
        (dns.flags.TC, "tc"),
        (dns.flags.RD, "rd"),
        (dns.flags.RA, "ra"),
        (dns.flags.AD, "ad"),
        (dns.flags.CD, "cd"),
    ):
        if response.flags & flag_bit:
            flags.append(flag_name)

    # EDNS pseudosection
    edns_info = None
    if response.edns >= 0:
        edns_flags = []
        if response.ednsflags & dns.flags.DO:
            edns_flags.append("do")
        edns_info = {
            "version": response.edns,
            "flags": edns_flags,
            "udp_size": response.payload,
        }
        for opt in response.options:
            if opt.otype == 12:  # PADDING (RFC 7830)
                edns_info["padding_bytes"] = len(opt.data)

    def format_section(section):
        out = []
        for rrset in section:
            for rdata in rrset:
                out.append(
                    {
                        "name": str(rrset.name),
                        "ttl": rrset.ttl,
                        "class": dns.rdataclass.to_text(rrset.rdclass),
                        "type": dns.rdatatype.to_text(rrset.rdtype),
                        "data": str(rdata),
                    }
                )
        return out

    return {
        "transport": "DoT",
        "nameserver": nameserver,
        "port": port,
        "tls_session": tls_info,
        "header": {
            "id": response.id,
            "opcode": dns.opcode.to_text(response.opcode()),
            "status": dns.rcode.to_text(response.rcode()),
            "flags": flags,
            "question_count": len(response.question),
            "answer_count": len(response.answer),
            "authority_count": len(response.authority),
            # OPT record counts as additional in wire ARCOUNT
            "additional_count": len(response.additional)
            + (1 if response.edns >= 0 else 0),
        },
        "edns": edns_info,
        "sections": {
            "question": [
                {
                    "name": str(q.name),
                    "type": dns.rdatatype.to_text(q.rdtype),
                    "class": dns.rdataclass.to_text(q.rdclass),
                }
                for q in response.question
            ],
            "answer": format_section(response.answer),
            "authority": format_section(response.authority),
            "additional": format_section(response.additional),
        },
        "elapsed_ms": round(elapsed_ms, 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
@track("timestamp_converter")
def timestamp_converter(
    timestamp: str | int | float, convert_to: Literal["iso", "epoch", "human"] = "iso"
) -> dict:
    """
    Convert between different timestamp formats.

    Useful for interpreting DNS record timestamps, SOA serial numbers,
    and other time-based data encountered during DNS analysis.

    Accepts:
    - ISO 8601 strings (e.g., "2024-01-15T10:30:00Z")
    - Unix epoch timestamps (seconds since 1970-01-01)
    - Human-readable strings (YYYY-MM-DD, MM/DD/YYYY)

    Returns conversions to ISO, epoch, human-readable, date, time, and unix_ms formats.
    """
    try:
        # Parse input
        if isinstance(timestamp, (int, float)):
            # Epoch timestamp
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        elif isinstance(timestamp, str):
            # Try parsing ISO format first
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                # Try common formats
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%m/%d/%Y"]:
                    try:
                        dt = datetime.strptime(timestamp, fmt).replace(
                            tzinfo=timezone.utc
                        )
                        break
                    except ValueError:
                        continue
                else:
                    return {"error": "Unable to parse timestamp format"}
        else:
            return {"error": "Timestamp must be string, int, or float"}

        # Convert to all formats
        result = {
            "input": str(timestamp),
            "conversions": {
                "iso": dt.isoformat(),
                "epoch": int(dt.timestamp()),
                "human": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "date": dt.strftime("%Y-%m-%d"),
                "time": dt.strftime("%H:%M:%S UTC"),
                "unix_ms": int(dt.timestamp() * 1000),
            },
            "timezone": "UTC",
        }

        return result

    except Exception as e:
        return {"error": f"Conversion failed: {str(e)}"}


@mcp.tool()
@track("reverse_dns")
def reverse_dns(
    ip_address: str = Field(description="IPv4 or IPv6 address for reverse DNS lookup"),
    nameserver: str = DEFAULT_RESOLVER,
) -> dict:
    """
    Perform reverse DNS (PTR) lookup for an IP address, with forward-confirmed rDNS
    (FCrDNS) verification.

    Converts the IP to its in-addr.arpa / ip6.arpa name, queries PTR records, then
    resolves each PTR hostname forward (A + AAAA) to confirm it maps back to the
    original IP. FCrDNS pass is required for trustworthy mail server identity.
    """
    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return {"error": "Invalid IP address format", "ip_address": ip_address}

    try:
        ipaddress.ip_address(nameserver)
    except ValueError:
        return {"error": "Invalid nameserver IP address", "ip_address": ip_address}

    reverse_name = dns.reversename.from_address(str(ip))
    errors = []

    # PTR lookup
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    ptr_records = []
    ttl = None
    try:
        answers = resolver.resolve(reverse_name, "PTR")
        ptr_records = [str(rdata) for rdata in answers]
        ttl = answers.rrset.ttl
    except dns.resolver.NXDOMAIN:
        errors.append(f"No PTR record found for {ip_address} (NXDOMAIN)")
    except dns.resolver.NoAnswer:
        errors.append(f"No PTR record in answer for {ip_address}")
    except dns.resolver.NoNameservers:
        errors.append("No nameservers available for PTR query")
    except dns.exception.Timeout:
        errors.append("PTR query timed out")

    # FCrDNS: resolve each PTR hostname forward and verify original IP is in results
    fcrDNS_checks = []
    fcrDNS_pass = False
    for hostname in ptr_records:
        forward_ips = []
        for rtype in ("A", "AAAA"):
            try:
                fwd_answers = resolver.resolve(hostname.rstrip("."), rtype)
                forward_ips.extend(str(rdata) for rdata in fwd_answers)
            except Exception:
                pass
        matches = str(ip) in forward_ips
        if matches:
            fcrDNS_pass = True
        fcrDNS_checks.append(
            {"hostname": hostname, "forward_ips": forward_ips, "matches": matches}
        )

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip_address": ip_address,
        "reverse_name": str(reverse_name),
        "ptr_records": ptr_records,
        "ttl": ttl,
        "fcrDNS": {
            "pass": fcrDNS_pass,
            "checks": fcrDNS_checks,
        },
        "nameserver": nameserver,
        "errors": errors,
    }


@mcp.tool()
@track("dns_dnssec_validate")
def dns_dnssec_validate(
    domain: str = Field(
        description="Domain name to validate (e.g., 'claude.lab.deflationhollow.net')"
    ),
    record_type: Literal[
        "A",
        "AAAA",
        "MX",
        "TXT",
        "NS",
        "SOA",
        "CNAME",
        "PTR",
        "SRV",
        "DNSKEY",
        "DS",
        "TLSA",
        "CAA",
        "SSHFP",
        "RRSIG",
        "CDS",
        "CDNSKEY",
        "HTTPS",
        "SVCB",
        "NAPTR",
    ] = "A",
    nameserver: str = Field(
        default=DEFAULT_RESOLVER, description="DNSSEC-validating resolver to use"
    ),
) -> dict:
    """
    Perform DNSSEC chain-of-trust validation similar to `delv +vtrace`.

    Walks the trust chain from the root zone down to the target domain,
    validating DNSKEY and DS records at each level. Reports whether each
    step in the chain validates successfully.

    This tool reconstructs the chain manually (educational "show your work"
    output) and cross-checks its verdict against the resolver's AD flag on
    the same query. If the two disagree, a "discrepancy" field explains which
    to trust and suggests `delv +vtrace <domain>` for final confirmation.

    Returns:
    - Chain of trust from root to target domain
    - Validation status at each level
    - DNSKEY and DS record details
    - Final validation result (secure/insecure/bogus)
    """
    # Validate domain
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    # Validate nameserver
    try:
        import ipaddress

        ipaddress.ip_address(nameserver)
    except ValueError:
        return {"error": "Invalid nameserver IP address", "domain": domain}

    validation_chain = []
    target_name = dns.name.from_text(domain)

    # Build the list of zones to validate (from target down up to root).
    # Include target_name itself — it may be a zone apex with its own DS/DNSKEY
    # (e.g. validating deflationhollow.net/A requires walking the
    # deflationhollow.net zone, not just its parent net.).
    # For hostnames inside a zone (www.example.com), the intermediate name
    # has no DS/DNSKEY and the loop skips it gracefully.
    zones = []
    current = target_name  # Start from target (include zone apex if applicable)
    while current != dns.name.root:
        zones.append(current)
        current = current.parent()
    zones.append(dns.name.root)
    zones.reverse()  # Start from root

    try:
        # First, fetch and validate the root DNSKEY (trust anchor)
        root_step = {"zone": ".", "level": 0, "validations": []}

        try:
            # Query root DNSKEY — use TCP because the root DNSKEY RRset is large
            # and UDP responses are typically truncated (TC=1).
            root_query = dns.message.make_query(".", "DNSKEY", want_dnssec=True)
            root_response = dns.query.udp(root_query, nameserver, timeout=5.0)
            if root_response.flags & 0x0200:  # TC bit — retry over TCP
                root_response = dns.query.tcp(root_query, nameserver, timeout=5.0)

            root_dnskeys = None
            root_rrsig = None
            for rrset in root_response.answer:
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    root_dnskeys = rrset
                elif rrset.rdtype == dns.rdatatype.RRSIG:
                    root_rrsig = rrset

            if root_dnskeys:
                root_step["dnskey_count"] = len(root_dnskeys)
                root_step["key_ids"] = [dns.dnssec.key_id(k) for k in root_dnskeys]

                # Cryptographically verify root DNSKEY RRSIG against hardcoded
                # IANA trust anchors (KSK-2017 tag=20326, KSK-2024 tag=38696).
                anchor_rrset, anchor_keys = _build_root_trust_anchor()
                anchor_tags = [dns.dnssec.key_id(k) for k in anchor_rrset]
                root_step["trust_anchor_key_ids"] = anchor_tags

                if root_rrsig:
                    try:
                        dns.dnssec.validate(root_dnskeys, root_rrsig, anchor_keys)
                        matched_tag = root_rrsig[0].key_tag
                        root_step["validations"].append(
                            {
                                "action": "verify rdataset",
                                "keyid": matched_tag,
                                "result": "success (cryptographic trust anchor verification)",
                            }
                        )
                        root_step["status"] = "secure"
                    except dns.dnssec.ValidationFailure as e:
                        root_step["validations"].append(
                            {
                                "action": "verify rdataset",
                                "result": f"failed: {e}",
                            }
                        )
                        root_step["status"] = "bogus"
                else:
                    root_step["status"] = "insecure"
            else:
                root_step["status"] = "no_dnskey"
                root_step["error"] = "No DNSKEY records found for root"

        except Exception as e:
            root_step["status"] = "error"
            root_step["error"] = str(e)

        validation_chain.append(root_step)

        # Now walk down the chain from root to target
        parent_dnskeys = (
            root_dnskeys if "root_dnskeys" in dir() and root_dnskeys else None
        )

        for i, zone in enumerate(zones[1:], 1):  # Skip root, already done
            zone_str = str(zone)
            step = {"zone": zone_str, "level": i, "validations": []}

            try:
                # Fetch DS record from parent zone
                ds_query = dns.message.make_query(zone, "DS", want_dnssec=True)
                ds_response = dns.query.udp(ds_query, nameserver, timeout=5.0)

                ds_rrset = None
                ds_rrsig = None
                for rrset in ds_response.answer:
                    if rrset.rdtype == dns.rdatatype.DS:
                        ds_rrset = rrset
                    elif rrset.rdtype == dns.rdatatype.RRSIG:
                        ds_rrsig = rrset

                if ds_rrset:
                    step["ds_records"] = [
                        {
                            "key_tag": ds.key_tag,
                            "algorithm": ds.algorithm,
                            "digest_type": ds.digest_type,
                        }
                        for ds in ds_rrset
                    ]
                    step["validations"].append(
                        {
                            "action": "fetch DS",
                            "result": f"found {len(ds_rrset)} DS record(s)",
                        }
                    )

                    # Validate DS against parent DNSKEY
                    if parent_dnskeys and ds_rrsig:
                        try:
                            dns.dnssec.validate(
                                ds_rrset, ds_rrsig, {zones[i - 1]: parent_dnskeys}
                            )
                            step["validations"].append(
                                {
                                    "action": "verify DS rdataset",
                                    "keyid": ds_rrsig[0].key_tag
                                    if ds_rrsig
                                    else "unknown",
                                    "result": "success",
                                }
                            )
                            step["ds_validated"] = True
                        except dns.dnssec.ValidationFailure as e:
                            step["validations"].append(
                                {
                                    "action": "verify DS rdataset",
                                    "result": f"failed: {e}",
                                }
                            )
                            step["ds_validated"] = False
                else:
                    # No DS means unsigned delegation
                    step["validations"].append(
                        {
                            "action": "fetch DS",
                            "result": "no DS records (unsigned delegation)",
                        }
                    )
                    step["ds_records"] = []

                # Fetch DNSKEY for this zone
                dnskey_query = dns.message.make_query(zone, "DNSKEY", want_dnssec=True)
                dnskey_response = dns.query.udp(dnskey_query, nameserver, timeout=5.0)

                zone_dnskeys = None
                dnskey_rrsig = None
                for rrset in dnskey_response.answer:
                    if rrset.rdtype == dns.rdatatype.DNSKEY:
                        zone_dnskeys = rrset
                    elif rrset.rdtype == dns.rdatatype.RRSIG:
                        dnskey_rrsig = rrset

                if zone_dnskeys:
                    step["dnskey_count"] = len(zone_dnskeys)
                    step["key_ids"] = [dns.dnssec.key_id(k) for k in zone_dnskeys]
                    step["validations"].append(
                        {
                            "action": "fetch DNSKEY",
                            "result": f"found {len(zone_dnskeys)} key(s)",
                        }
                    )

                    # Validate DNSKEY against DS
                    if ds_rrset and dnskey_rrsig:
                        try:
                            dns.dnssec.validate(
                                zone_dnskeys, dnskey_rrsig, {zone: zone_dnskeys}
                            )
                            step["validations"].append(
                                {
                                    "action": "verify DNSKEY rdataset",
                                    "keyid": dnskey_rrsig[0].key_tag
                                    if dnskey_rrsig
                                    else "unknown",
                                    "result": "success",
                                }
                            )
                            step["status"] = "secure"
                        except dns.dnssec.ValidationFailure as e:
                            step["validations"].append(
                                {
                                    "action": "verify DNSKEY rdataset",
                                    "result": f"failed: {e}",
                                }
                            )
                            step["status"] = "bogus"
                    elif not ds_rrset:
                        step["status"] = "insecure"
                    else:
                        step["status"] = "indeterminate"

                    parent_dnskeys = zone_dnskeys
                else:
                    step["status"] = "no_dnskey"
                    step["validations"].append(
                        {"action": "fetch DNSKEY", "result": "no DNSKEY records"}
                    )

            except Exception as e:
                step["status"] = "error"
                step["error"] = str(e)

            validation_chain.append(step)

        # Finally, validate the target record against its zone's DNSKEY
        target_step = {
            "target": domain,
            "record_type": record_type,
            "containing_zone": str(target_name.parent()),
            "validations": [],
        }

        resolver_ad_flag = None  # AD flag from the resolver on the target query
        try:
            target_query = dns.message.make_query(domain, record_type, want_dnssec=True)
            target_response = dns.query.udp(target_query, nameserver, timeout=5.0)
            resolver_ad_flag = bool(target_response.flags & dns.flags.AD)

            target_rrset = None
            target_rrsig = None
            for rrset in target_response.answer:
                if rrset.rdtype == dns.rdatatype.from_text(record_type):
                    target_rrset = rrset
                elif rrset.rdtype == dns.rdatatype.RRSIG:
                    target_rrsig = rrset

            if target_rrset:
                target_step["records"] = [str(r) for r in target_rrset]
                target_step["ttl"] = target_rrset.ttl
                target_step["validations"].append(
                    {
                        "action": f"fetch {record_type}",
                        "result": f"found {len(target_rrset)} record(s)",
                    }
                )

                if target_rrsig and parent_dnskeys:
                    target_step["rrsig"] = {
                        "key_tag": target_rrsig[0].key_tag,
                        "algorithm": target_rrsig[0].algorithm,
                        "signer": str(target_rrsig[0].signer),
                        "expiration": str(target_rrsig[0].expiration),
                        "inception": str(target_rrsig[0].inception),
                    }

                    try:
                        signer_name = target_rrsig[0].signer
                        dns.dnssec.validate(
                            target_rrset, target_rrsig, {signer_name: parent_dnskeys}
                        )
                        target_step["validations"].append(
                            {
                                "action": f"verify {record_type} rdataset",
                                "keyid": target_rrsig[0].key_tag,
                                "result": "success",
                            }
                        )
                        target_step["status"] = "secure"
                        target_step["fully_validated"] = True
                    except dns.dnssec.ValidationFailure as e:
                        target_step["validations"].append(
                            {
                                "action": f"verify {record_type} rdataset",
                                "result": f"failed: {e}",
                            }
                        )
                        target_step["status"] = "bogus"
                        target_step["fully_validated"] = False
                elif not target_rrsig:
                    target_step["status"] = "insecure"
                    target_step["validations"].append(
                        {
                            "action": "check RRSIG",
                            "result": "no RRSIG (unsigned record)",
                        }
                    )
                    target_step["fully_validated"] = False
            else:
                # No answer — attempt NSEC/NSEC3 negative proof validation.
                # A signed NSEC denial is a fully-validated negative response,
                # equivalent to delv reporting "negative response, fully validated".
                if target_response.rcode() == dns.rcode.NXDOMAIN:
                    target_step["status"] = "nxdomain"
                    target_step["error"] = "Domain does not exist"
                    target_step["fully_validated"] = False
                else:
                    # NXRRSET — look for NSEC/NSEC3 in authority section
                    nsec_rrset = None
                    nsec_rrsig = None
                    for rrset in target_response.authority:
                        if rrset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                            nsec_rrset = rrset
                        elif rrset.rdtype == dns.rdatatype.RRSIG:
                            nsec_rrsig = rrset

                    if nsec_rrset and nsec_rrsig and parent_dnskeys:
                        try:
                            signer_name = nsec_rrsig[0].signer
                            dns.dnssec.validate(
                                nsec_rrset, nsec_rrsig, {signer_name: parent_dnskeys}
                            )
                            nsec_type = dns.rdatatype.to_text(nsec_rrset.rdtype)
                            target_step["validations"].append(
                                {
                                    "action": f"verify {nsec_type} denial",
                                    "keyid": nsec_rrsig[0].key_tag,
                                    "result": f"success (no {record_type} proven by {nsec_type})",
                                }
                            )
                            target_step["status"] = "secure"
                            target_step["fully_validated"] = True
                            target_step["negative_response"] = True
                            target_step["denial_type"] = nsec_type
                        except dns.dnssec.ValidationFailure as e:
                            target_step["status"] = "bogus"
                            target_step["error"] = (
                                f"{nsec_type} denial validation failed: {e}"
                            )
                            target_step["fully_validated"] = False
                    else:
                        target_step["status"] = "no_answer"
                        target_step["error"] = f"No {record_type} records found"
                        target_step["fully_validated"] = False

        except Exception as e:
            target_step["status"] = "error"
            target_step["error"] = str(e)
            target_step["fully_validated"] = False

        validation_chain.append(target_step)

        # Determine overall validation result.
        # Exclude no_dnskey zone steps: these are hostname nodes (e.g.
        # claude.lab.example.com) that the chain walk tries as zones but
        # which have no DS and no DNSKEY — not a real zone, not a failure.
        zone_steps_secure = all(
            step.get("status") == "secure"
            for step in validation_chain
            if "zone" in step and step.get("status") != "no_dnskey"
        )
        target_validated = any(
            step.get("fully_validated") is True
            for step in validation_chain
            if "target" in step
        )
        all_secure = zone_steps_secure and target_validated
        any_bogus = any(step.get("status") == "bogus" for step in validation_chain)

        if any_bogus:
            overall_status = "bogus"
        elif all_secure:
            overall_status = "fully validated"
        else:
            overall_status = "insecure"

        # Cross-check: compare our chain-walk verdict against the resolver's AD flag.
        # AD=true means the nameserver (a production DNSSEC validator) accepted the chain.
        # Disagreement between the two is a strong signal one way or the other.
        chain_says_valid = overall_status == "fully validated"

        if resolver_ad_flag is not None and chain_says_valid != resolver_ad_flag:
            if chain_says_valid and not resolver_ad_flag:
                discrepancy = (
                    f"DISCREPANCY: this tool's chain walk says fully validated, "
                    f"but {nameserver} did not set the AD (Authenticated Data) flag — "
                    f"meaning the resolver did not confirm the DNSSEC chain. "
                    f"The resolver's judgment takes precedence — treat as unvalidated. "
                    f"To confirm: `dig +dnssec {record_type} {domain} @{nameserver}` "
                    f"and look for 'ad' in the flags line of the header. "
                    f"For a full trace: `delv +vtrace {domain}`"
                )
            else:  # chain says bogus/insecure, resolver says AD=true
                discrepancy = (
                    f"DISCREPANCY: this tool's chain walk says {overall_status}, "
                    f"but {nameserver} set the AD (Authenticated Data) flag — "
                    f"meaning the resolver validated the DNSSEC chain successfully. "
                    f"This is likely a tool limitation, not a real DNS problem. "
                    f"To confirm: `dig +dnssec {record_type} {domain} @{nameserver}` "
                    f"and look for 'ad' in the flags line of the header. "
                    f"For a full trace: `delv +vtrace {domain}`"
                )
        else:
            discrepancy = None

        result = {
            "domain": domain,
            "record_type": record_type,
            "nameserver": nameserver,
            "overall_status": overall_status,
            "resolver_ad_flag": resolver_ad_flag,
            "chain_of_trust": validation_chain,
            "query_time": datetime.now(timezone.utc).isoformat(),
        }

        if discrepancy:
            result["discrepancy"] = discrepancy

        return result

    except Exception as e:
        return {
            "error": f"DNSSEC validation failed: {str(e)}",
            "domain": domain,
            "record_type": record_type,
            "nameserver": nameserver,
        }


# ===========================================================================
# Email Security Analysis Tools
# ===========================================================================


@mcp.tool()
@track("check_spf")
def check_spf(
    domain: str = Field(
        description="Domain to check SPF record for (e.g., 'example.com')"
    ),
) -> dict:
    """
    Retrieve and recursively parse a domain's SPF policy.

    Enumerates all authorized sending IPs/networks by following include chains.
    Enforces the RFC 7208 10-lookup limit to prevent infinite recursion.

    Returns the raw SPF record, parsed mechanisms, authorized networks,
    the 'all' qualifier, and the total lookup count.
    """
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    errors = []
    mechanisms = []
    authorized_networks = []
    all_qualifier = None
    lookup_count = 0

    def _resolve_spf(target: str, depth: int):
        nonlocal lookup_count, all_qualifier
        if lookup_count >= 10:
            errors.append(f"RFC 7208 10-lookup limit reached at {target}")
            return
        if depth > 10:
            errors.append(f"Max recursion depth reached at {target}")
            return

        records, query_errors = _query_all_txt_records(target)
        errors.extend(query_errors)
        if query_errors:
            return

        # Find SPF record
        spf_record = None
        for rec in records:
            if rec.startswith("v=spf1"):
                spf_record = rec
                break

        if not spf_record:
            if depth == 0:
                errors.append(f"No SPF record found for {target}")
            return

        parts = spf_record.split()
        for part in parts[1:]:  # Skip "v=spf1"
            # Parse qualifier
            qualifier = "+"
            mechanism = part
            if part[0] in "+-~?":
                qualifier = part[0]
                mechanism = part[1:]

            if mechanism.startswith("ip4:"):
                network = mechanism[4:]
                mechanisms.append(
                    {"type": "ip4", "value": network, "qualifier": qualifier}
                )
                # Add /32 if no CIDR specified
                if "/" not in network:
                    network += "/32"
                authorized_networks.append(network)

            elif mechanism.startswith("ip6:"):
                network = mechanism[4:]
                mechanisms.append(
                    {"type": "ip6", "value": network, "qualifier": qualifier}
                )
                if "/" not in network:
                    network += "/128"
                authorized_networks.append(network)

            elif mechanism.startswith("include:"):
                include_domain = mechanism[8:]
                mechanisms.append(
                    {"type": "include", "value": include_domain, "qualifier": qualifier}
                )
                lookup_count += 1
                _resolve_spf(include_domain, depth + 1)

            elif mechanism.startswith("redirect="):
                redirect_domain = mechanism[9:]
                mechanisms.append(
                    {
                        "type": "redirect",
                        "value": redirect_domain,
                        "qualifier": qualifier,
                    }
                )
                lookup_count += 1
                _resolve_spf(redirect_domain, depth + 1)

            elif mechanism.startswith("a:") or mechanism == "a":
                a_domain = mechanism[2:] if mechanism.startswith("a:") else target
                mechanisms.append(
                    {"type": "a", "value": a_domain, "qualifier": qualifier}
                )
                lookup_count += 1
                try:
                    resolver = dns.resolver.Resolver()
                    for rdata in resolver.resolve(a_domain, "A"):
                        authorized_networks.append(f"{rdata}/32")
                except Exception:
                    pass

            elif mechanism.startswith("mx:") or mechanism == "mx":
                mx_domain = mechanism[3:] if mechanism.startswith("mx:") else target
                mechanisms.append(
                    {"type": "mx", "value": mx_domain, "qualifier": qualifier}
                )
                lookup_count += 1
                try:
                    resolver = dns.resolver.Resolver()
                    for rdata in resolver.resolve(mx_domain, "MX"):
                        try:
                            for a_rdata in resolver.resolve(str(rdata.exchange), "A"):
                                authorized_networks.append(f"{a_rdata}/32")
                        except Exception:
                            pass
                except Exception:
                    pass

            elif mechanism.startswith("exists:"):
                mechanisms.append(
                    {"type": "exists", "value": mechanism[7:], "qualifier": qualifier}
                )
                lookup_count += 1

            elif mechanism == "all":
                qualifier_map = {
                    "+": "pass",
                    "-": "fail",
                    "~": "softfail",
                    "?": "neutral",
                }
                all_qualifier = qualifier_map.get(qualifier, qualifier)
                mechanisms.append({"type": "all", "qualifier": qualifier})

    # Get the raw record first
    records, initial_errors = _query_all_txt_records(domain)
    raw_record = None
    for rec in records:
        if rec.startswith("v=spf1"):
            raw_record = rec
            break

    # Recursively parse
    _resolve_spf(domain, 0)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "raw_record": raw_record,
        "mechanisms": mechanisms,
        "authorized_networks": authorized_networks,
        "all_qualifier": all_qualifier,
        "lookup_count": lookup_count,
        "errors": errors,
    }


@mcp.tool()
@track("check_dmarc")
def check_dmarc(
    domain: str = Field(description="Domain to check DMARC for (the From: domain)"),
) -> dict:
    """
    Retrieve and parse a domain's DMARC policy.

    Queries _dmarc.{domain} for the DMARC TXT record and parses all tags.
    If no record exists at the exact domain, falls back to the organizational
    domain (e.g., sub.example.com falls back to _dmarc.example.com).

    Returns the parsed policy, alignment modes, reporting URIs, and other tags.
    """
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    errors = []
    record_found_at = None
    raw_record = None

    # Try exact domain first
    fqdn = f"_dmarc.{domain}"
    record, query_errors = _query_txt_record(fqdn)

    if record and record.startswith("v=DMARC1"):
        raw_record = record
        record_found_at = fqdn
    else:
        # Fall back to org domain
        org_domain = _get_org_domain(domain)
        if org_domain != domain:
            fqdn_org = f"_dmarc.{org_domain}"
            record_org, org_errors = _query_txt_record(fqdn_org)
            if record_org and record_org.startswith("v=DMARC1"):
                raw_record = record_org
                record_found_at = fqdn_org
            else:
                errors.extend(org_errors)
        errors.extend(query_errors)

    if not raw_record:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": domain,
            "record_found_at": None,
            "raw_record": None,
            "policy": None,
            "subdomain_policy": None,
            "dkim_alignment": None,
            "spf_alignment": None,
            "percentage": None,
            "rua": [],
            "ruf": [],
            "errors": errors if errors else ["No DMARC record found"],
        }

    tags = _parse_tag_value(raw_record)

    # Parse alignment values
    alignment_map = {"r": "relaxed", "s": "strict"}

    # Parse rua/ruf as lists
    rua = [uri.strip() for uri in tags.get("rua", "").split(",") if uri.strip()]
    ruf = [uri.strip() for uri in tags.get("ruf", "").split(",") if uri.strip()]

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "record_found_at": record_found_at,
        "raw_record": raw_record,
        "policy": tags.get("p"),
        "subdomain_policy": tags.get("sp"),
        "dkim_alignment": alignment_map.get(
            tags.get("adkim", "r"), tags.get("adkim", "r")
        ),
        "spf_alignment": alignment_map.get(
            tags.get("aspf", "r"), tags.get("aspf", "r")
        ),
        "percentage": int(tags["pct"]) if "pct" in tags else 100,
        "rua": rua,
        "ruf": ruf,
        "errors": errors,
    }


@mcp.tool()
@track("check_dkim_selector")
def check_dkim_selector(
    domain: str = Field(
        description="DKIM domain (d= value from DKIM-Signature header)"
    ),
    selector: str = Field(
        description="DKIM selector (s= value from DKIM-Signature header)"
    ),
) -> dict:
    """
    Verify a DKIM public key record exists for a given selector and domain.

    Queries {selector}._domainkey.{domain} for the DKIM TXT record and parses
    key parameters. Reports whether the key exists, its type, and whether it
    has been revoked (empty p= value).
    """
    # Validate selector
    sel_valid, sel_result = validate_selector(selector)
    if not sel_valid:
        return {"error": sel_result, "selector": selector, "domain": domain}

    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "selector": selector, "domain": domain}

    fqdn = f"{selector}._domainkey.{domain}"
    errors = []

    record, query_errors = _query_txt_record(fqdn)
    errors.extend(query_errors)

    if not record:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "selector": selector,
            "domain": domain,
            "fqdn": fqdn,
            "record_exists": False,
            "raw_record": None,
            "key_type": None,
            "key_present": False,
            "key_revoked": False,
            "flags": [],
            "errors": errors if errors else [f"No DKIM record at {fqdn}"],
        }

    tags = _parse_tag_value(record)
    public_key = tags.get("p", "")
    key_revoked = public_key == ""
    key_present = bool(public_key) and not key_revoked

    # Parse flags (t= tag, semicolon separated)
    flags = [f.strip() for f in tags.get("t", "").split(":") if f.strip()]

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "selector": selector,
        "domain": domain,
        "fqdn": fqdn,
        "record_exists": True,
        "raw_record": record,
        "key_type": tags.get("k", "rsa"),  # Default is rsa per RFC 6376
        "key_present": key_present,
        "key_revoked": key_revoked,
        "flags": flags,
        "errors": errors,
    }


@mcp.tool()
@track("check_bimi")
def check_bimi(
    domain: str = Field(description="Domain to check BIMI record for"),
    selector: str = "default",
) -> dict:
    """
    Check for BIMI (Brand Indicators for Message Identification) record.

    Queries {selector}._bimi.{domain} for the BIMI TXT record.
    Reports whether BIMI is configured, the logo SVG URL, and whether
    a VMC (Verified Mark Certificate) is present.
    """
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    sel_valid, sel_result = validate_selector(selector)
    if not sel_valid:
        return {"error": sel_result, "domain": domain, "selector": selector}

    fqdn = f"{selector}._bimi.{domain}"
    errors = []

    record, query_errors = _query_txt_record(fqdn)
    errors.extend(query_errors)

    if not record or not record.startswith("v=BIMI1"):
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": domain,
            "selector": selector,
            "fqdn": fqdn,
            "record_exists": False,
            "raw_record": record,
            "logo_url": None,
            "vmc_url": None,
            "has_vmc": False,
            "errors": errors if errors else [f"No BIMI record at {fqdn}"],
        }

    tags = _parse_tag_value(record)
    logo_url = tags.get("l", "").strip() or None
    vmc_url = tags.get("a", "").strip() or None

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "selector": selector,
        "fqdn": fqdn,
        "record_exists": True,
        "raw_record": record,
        "logo_url": logo_url,
        "vmc_url": vmc_url,
        "has_vmc": vmc_url is not None,
        "errors": errors,
    }


@mcp.tool()
@track("check_mta_sts")
def check_mta_sts(
    domain: str = Field(description="Domain to check MTA-STS record for"),
    fetch_policy: bool = Field(
        default=True,
        description="Also fetch the HTTPS policy file from /.well-known/mta-sts.txt",
    ),
) -> dict:
    """
    Check for MTA-STS (Mail Transfer Agent Strict Transport Security).

    Queries _mta-sts.{domain} for the DNS TXT record and parses version and
    policy ID. When fetch_policy is True (the default), also fetches the HTTPS
    policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt and parses
    the mode, MX patterns, and max_age.
    """
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    fqdn = f"_mta-sts.{domain}"
    errors = []

    record, query_errors = _query_txt_record(fqdn)
    errors.extend(query_errors)

    if not record or "v=STSv1" not in record:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": domain,
            "fqdn": fqdn,
            "record_exists": False,
            "raw_record": record,
            "version": None,
            "policy_id": None,
            "policy": None,
            "errors": errors if errors else [f"No MTA-STS record at {fqdn}"],
        }

    tags = _parse_tag_value(record)

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "fqdn": fqdn,
        "record_exists": True,
        "raw_record": record,
        "version": tags.get("v"),
        "policy_id": tags.get("id"),
        "policy": None,
        "errors": errors,
    }

    if fetch_policy:
        result["policy"] = _fetch_mta_sts_policy(domain, errors)

    return result


def _fetch_mta_sts_policy(domain: str, errors: list) -> dict | None:
    """Fetch and parse the MTA-STS policy file over HTTPS."""
    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        resp = requests.get(policy_url, timeout=10, allow_redirects=False)
        if resp.status_code != 200:
            errors.append(f"MTA-STS policy fetch returned HTTP {resp.status_code}")
            return None

        # Parse key: value lines
        policy = {"url": policy_url, "mx": []}
        for line in resp.text.strip().splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "mx":
                policy["mx"].append(value)
            elif key == "mode":
                policy["mode"] = value
            elif key == "version":
                policy["version"] = value
            elif key == "max_age":
                try:
                    policy["max_age"] = int(value)
                except ValueError:
                    policy["max_age"] = value

        return policy

    except requests.exceptions.SSLError as e:
        errors.append(f"MTA-STS policy SSL error: {e}")
        return None
    except requests.exceptions.Timeout:
        errors.append("MTA-STS policy fetch timed out (10s)")
        return None
    except requests.exceptions.RequestException as e:
        errors.append(f"MTA-STS policy fetch failed: {e}")
        return None


def _fetch_ct_logs(domain: str, errors: list, fetch_metadata: dict) -> list:
    """Fetch certificate data from crt.sh with retry/backoff.
    Populates fetch_metadata dict in-place. Returns list of cert dicts (may be empty).
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(_CT_MAX_RETRIES):
        fetch_metadata["attempts"] = attempt + 1
        if _CT_BACKOFF[attempt] > 0:
            time.sleep(_CT_BACKOFF[attempt])
        try:
            resp = requests.get(url, timeout=_CT_TIMEOUT_SECONDS)
        except requests.exceptions.Timeout:
            errors.append(f"crt.sh timeout on attempt {attempt + 1}")
            continue
        except requests.exceptions.RequestException as e:
            errors.append(f"crt.sh request failed: {e}")
            continue

        # Detect HTML error page
        text = resp.text.strip()
        if text and text[0] == "<":
            errors.append(f"crt.sh returned HTML (attempt {attempt + 1})")
            continue
        # Detect empty body
        if not text:
            errors.append(f"crt.sh returned empty body (attempt {attempt + 1})")
            continue
        # Detect HTTP errors
        if resp.status_code == 429:
            errors.append(f"crt.sh rate limited (attempt {attempt + 1})")
            time.sleep(10)
            continue
        if resp.status_code >= 500:
            errors.append(f"crt.sh HTTP {resp.status_code} (attempt {attempt + 1})")
            continue
        if resp.status_code != 200:
            errors.append(f"crt.sh HTTP {resp.status_code}")
            break  # Non-retryable client error
        # Parse JSON
        try:
            data = resp.json()
        except ValueError:
            errors.append(
                f"crt.sh returned truncated/invalid JSON (attempt {attempt + 1})"
            )
            fetch_metadata["response_truncated"] = True
            continue

        fetch_metadata["success_on_attempt"] = attempt + 1
        return data if isinstance(data, list) else []

    fetch_metadata["error"] = errors[-1] if errors else "all retries exhausted"
    return []


def _parse_issuer_org(issuer_name: str) -> str | None:
    """Extract the O= field from an RFC 4514 DN string."""
    for part in issuer_name.split(","):
        part = part.strip()
        if part.startswith("O="):
            return part[2:].strip()
    return None


@mcp.tool()
@track("check_smtp_tlsrpt")
def check_smtp_tlsrpt(
    domain: str = Field(description="Domain to check SMTP TLS Reporting record for"),
) -> dict:
    """
    Check for SMTP TLS Reporting (TLSRPT) DNS record.

    Queries _smtp._tls.{domain} for the TXT record and parses version
    and reporting URIs. Often paired with MTA-STS.
    """
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    fqdn = f"_smtp._tls.{domain}"
    errors = []

    record, query_errors = _query_txt_record(fqdn)
    errors.extend(query_errors)

    if not record or "v=TLSRPTv1" not in record:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": domain,
            "fqdn": fqdn,
            "record_exists": False,
            "raw_record": record,
            "version": None,
            "reporting_uris": [],
            "errors": errors if errors else [f"No TLSRPT record at {fqdn}"],
        }

    tags = _parse_tag_value(record)
    rua = [uri.strip() for uri in tags.get("rua", "").split(",") if uri.strip()]

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "fqdn": fqdn,
        "record_exists": True,
        "raw_record": record,
        "version": tags.get("v"),
        "reporting_uris": rua,
        "errors": errors,
    }


def _query_tlsa(fqdn: str, nameserver: str) -> dict:
    """
    Query TLSA records for an FQDN with DNSSEC (DO flag) via direct UDP query.
    Returns dict with: tlsa_records (list), ad_flag (bool), error (str|None), timeout (bool).
    """
    try:
        query = dns.message.make_query(fqdn, dns.rdatatype.TLSA, want_dnssec=True)
        response = dns.query.udp(query, nameserver, timeout=5.0)
        ad_flag = bool(response.flags & dns.flags.AD)
        tlsa_records = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.TLSA:
                for rdata in rrset:
                    tlsa_records.append(
                        {
                            "usage": rdata.usage,
                            "usage_name": TLSA_USAGE_NAMES.get(
                                rdata.usage, f"Unknown({rdata.usage})"
                            ),
                            "selector": rdata.selector,
                            "selector_name": TLSA_SELECTOR_NAMES.get(
                                rdata.selector, f"Unknown({rdata.selector})"
                            ),
                            "matching_type": rdata.mtype,
                            "matching_type_name": TLSA_MATCHING_NAMES.get(
                                rdata.mtype, f"Unknown({rdata.mtype})"
                            ),
                            "certificate_data": rdata.cert.hex(),
                        }
                    )
        return {
            "tlsa_records": tlsa_records,
            "ad_flag": ad_flag,
            "error": None,
            "timeout": False,
        }
    except dns.exception.Timeout:
        return {
            "tlsa_records": [],
            "ad_flag": False,
            "error": "Query timed out",
            "timeout": True,
        }
    except Exception as e:
        return {
            "tlsa_records": [],
            "ad_flag": False,
            "error": str(e),
            "timeout": False,
        }


@mcp.tool()
@track("check_dane")
def check_dane(
    domain: str = Field(
        description="Domain to check DANE for (the From: domain, not the MX hostname)"
    ),
) -> dict:
    """
    Check for DANE TLSA records on a domain's mail servers.

    DANE binds TLS certificates to DNS via TLSA records, providing cryptographic
    assurance that a mail server's TLS certificate is the one the domain owner
    intended. DANE requires DNSSEC — without it, TLSA records are ignored by
    compliant MTAs.

    Queries MX records for the domain, then checks _25._tcp.{mx_host} for TLSA
    records and verifies DNSSEC (AD flag) for each. Classifies each MX host as
    dane_valid, dane_present_no_dnssec, or no_dane.
    """
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    errors = []
    mx_hosts = []
    timestamp = datetime.now(timezone.utc).isoformat()

    # Step 1: Query MX records
    try:
        resolver = dns.resolver.Resolver()
        mx_answers = resolver.resolve(domain, "MX")
        mx_list = sorted(
            [
                (rdata.preference, str(rdata.exchange).rstrip("."))
                for rdata in mx_answers
            ],
            key=lambda x: x[0],
        )
    except dns.resolver.NXDOMAIN:
        return {
            "timestamp": timestamp,
            "domain": domain,
            "mx_hosts": [],
            "dane_viable": False,
            "summary": f"Domain {domain} does not exist (NXDOMAIN)",
            "errors": [f"NXDOMAIN: {domain} does not exist"],
        }
    except dns.resolver.NoAnswer:
        return {
            "timestamp": timestamp,
            "domain": domain,
            "mx_hosts": [],
            "dane_viable": False,
            "summary": f"No MX records found for {domain} — DANE requires MX hosts",
            "errors": [f"No MX records for {domain}"],
        }
    except dns.resolver.NoNameservers:
        return {
            "timestamp": timestamp,
            "domain": domain,
            "mx_hosts": [],
            "dane_viable": False,
            "summary": f"No nameservers available for {domain}",
            "errors": [f"No nameservers available for {domain}"],
        }
    except dns.exception.Timeout:
        return {
            "timestamp": timestamp,
            "domain": domain,
            "mx_hosts": [],
            "dane_viable": False,
            "summary": f"DNS query timeout for {domain}",
            "errors": [f"DNS query timeout for {domain}"],
        }

    # Filter null MX (RFC 7505: exchange of ".")
    mx_list = [(pref, host) for pref, host in mx_list if host and host != "."]

    truncated = len(mx_list) > 5
    if truncated:
        mx_list = mx_list[:5]

    # Step 2: Check each MX host for TLSA records + DNSSEC
    for priority, hostname in mx_list:
        tlsa_fqdn = f"_25._tcp.{hostname}"
        host_entry = {
            "hostname": hostname,
            "priority": priority,
            "tlsa_fqdn": tlsa_fqdn,
            "has_tlsa": False,
            "dnssec_valid": False,
            "dane_status": "no_dane",
            "tlsa_records": [],
        }

        tlsa_result = _query_tlsa(tlsa_fqdn, DEFAULT_RESOLVER)
        if tlsa_result["error"]:
            if tlsa_result["timeout"]:
                errors.append(f"TLSA query timeout for {tlsa_fqdn}")
            else:
                errors.append(
                    f"TLSA query failed for {tlsa_fqdn}: {tlsa_result['error']}"
                )
        elif tlsa_result["tlsa_records"]:
            host_entry["has_tlsa"] = True
            host_entry["dnssec_valid"] = tlsa_result["ad_flag"]
            host_entry["tlsa_records"] = tlsa_result["tlsa_records"]
            if tlsa_result["ad_flag"]:
                host_entry["dane_status"] = "dane_valid"
            else:
                host_entry["dane_status"] = "dane_present_no_dnssec"
        # else: no TLSA records → stays "no_dane"

        mx_hosts.append(host_entry)

    # Step 3: Build summary
    dane_valid_count = sum(1 for h in mx_hosts if h["dane_status"] == "dane_valid")
    dane_no_dnssec_count = sum(
        1 for h in mx_hosts if h["dane_status"] == "dane_present_no_dnssec"
    )
    no_dane_count = sum(1 for h in mx_hosts if h["dane_status"] == "no_dane")
    dane_viable = dane_valid_count > 0

    total_mx = len(mx_hosts)
    summary_parts = []
    if dane_valid_count > 0:
        summary_parts.append(
            f"{dane_valid_count} of {total_mx} MX hosts have valid DANE (TLSA + DNSSEC)"
        )
    if dane_no_dnssec_count > 0:
        summary_parts.append(
            f"{dane_no_dnssec_count} MX host(s) have TLSA records but lack DNSSEC — "
            "DANE is not effective without DNSSEC validation"
        )
    if no_dane_count > 0:
        summary_parts.append(
            f"{no_dane_count} MX host(s) have no TLSA records published"
        )
    if not mx_hosts:
        summary_parts.append(f"No MX hosts found for {domain}")
    if truncated:
        summary_parts.append("(only first 5 MX hosts checked)")

    summary = "; ".join(summary_parts) if summary_parts else "No MX hosts to check"

    return {
        "timestamp": timestamp,
        "domain": domain,
        "mx_hosts": mx_hosts,
        "dane_viable": dane_viable,
        "summary": summary,
        "errors": errors,
    }


@mcp.tool()
@track("check_tlsa")
def check_tlsa(
    hostname: str = Field(
        description="Hostname to check TLSA record for (e.g., 'mx1.example.com')"
    ),
    port: int = Field(description="Port number (e.g., 25 for SMTP, 443 for HTTPS)"),
    protocol: Literal["tcp", "udp"] = "tcp",
    nameserver: str | None = Field(
        default=None,
        description=f"Nameserver IP to query (default: {DEFAULT_RESOLVER})",
    ),
) -> dict:
    """
    Check for TLSA records at an arbitrary host:port:protocol combination.

    Builds the TLSA FQDN as _{port}._{protocol}.{hostname} and queries for
    TLSA records with DNSSEC (DO flag set). Reports whether records exist,
    their parameters (usage, selector, matching type, certificate data),
    and whether DNSSEC validation confirms authenticity (AD flag).

    Useful for non-mail DANE (HTTPS on 443, XMPP, etc.) or when you already
    know the MX hostname and want to check it directly without the MX lookup.
    For a domain-level mail DANE check across all MX hosts, use check_dane.
    """
    valid, result = validate_domain(hostname)
    if not valid:
        return {"error": result, "hostname": hostname}

    port_valid, port_result = validate_port(port)
    if not port_valid:
        return {"error": port_result, "hostname": hostname, "port": port}

    if protocol not in ("tcp", "udp"):
        return {
            "error": f"Protocol must be 'tcp' or 'udp', got {protocol!r}",
            "hostname": hostname,
        }

    ns = nameserver if nameserver is not None else DEFAULT_RESOLVER
    if nameserver is not None:
        try:
            import ipaddress

            ipaddress.ip_address(nameserver)
        except ValueError:
            return {"error": "Invalid nameserver IP address", "hostname": hostname}

    tlsa_fqdn = f"_{port}._{protocol}.{hostname}"
    tlsa_result = _query_tlsa(tlsa_fqdn, ns)
    has_tlsa = bool(tlsa_result["tlsa_records"])

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": hostname,
        "port": port,
        "protocol": protocol,
        "nameserver": ns,
        "tlsa_fqdn": tlsa_fqdn,
        "has_tlsa": has_tlsa,
        "dnssec_valid": tlsa_result["ad_flag"] if has_tlsa else False,
        "tlsa_records": tlsa_result["tlsa_records"],
        "errors": [tlsa_result["error"]] if tlsa_result["error"] else [],
    }


@mcp.tool()
@track("nsec_info")
def nsec_info(
    domain: str = Field(description="Domain to check (e.g., 'example.com')"),
) -> dict:
    """
    Probe a zone's DNSSEC denial-of-existence mechanism (NSEC vs NSEC3).

    Resolves the zone's authoritative nameserver, sends a DNSSEC-enabled query
    for a synthetic nonexistent name, and parses the NSEC or NSEC3 records
    returned in the authority section. Reports whether the zone is walkable
    (i.e., all names can be enumerated).

    Also queries the NSEC3PARAM record at the zone apex and cross-checks it
    against actual NSEC3 records to detect re-signing misconfigurations.

    Example: nsec_info("example.com") might return:

      denial_type: "nsec"
      zone_walkable: true
      walkability_note: "Zone uses plain NSEC. Every name in the zone is
        exposed — each NSEC record points to the next name in alphabetical
        order, allowing full zone enumeration by following the chain.
        This is common on smaller or older zones but considered a privacy
        risk for zones with sensitive hostnames."

    vs.

      denial_type: "nsec3"
      nsec3_params: {algorithm: 1, iterations: 10, salt: "aabbccdd", opt_out: false}
      zone_walkable: false
      walkability_note: "Zone uses NSEC3 with 10 iterations and a 4-byte salt.
        Names are SHA-1 hashed before publication, preventing direct zone
        enumeration. An attacker would need offline dictionary/rainbow table
        attacks against the hashed names to recover hostnames."
    """
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    errors = []
    timestamp = datetime.now(timezone.utc).isoformat()

    base_result = {
        "timestamp": timestamp,
        "domain": domain,
        "zone": None,
        "authoritative_ns": None,
        "authoritative_ip": None,
        "probe_name": None,
        "response_code": None,
        "denial_type": None,
        "nsec3_params": None,
        "nsec_records": [],
        "zone_walkable": False,
        "walkability_risk": "none",
        "walkability_note": None,
        "nsec3param": None,
        "nsec3_consistency": None,
        "errors": errors,
    }

    # Step 1: Resolve authoritative NS for the domain
    resolver = dns.resolver.Resolver()
    ns_hostname = None
    ns_ip = None

    try:
        ns_answers = resolver.resolve(domain, "NS")
        ns_hostname = str(ns_answers[0].target).rstrip(".")
    except dns.resolver.NXDOMAIN:
        errors.append(f"NXDOMAIN: {domain} does not exist")
        return base_result
    except dns.resolver.NoAnswer:
        # Try parent zone for NS
        org = _get_org_domain(domain)
        if org != domain:
            try:
                ns_answers = resolver.resolve(org, "NS")
                ns_hostname = str(ns_answers[0].target).rstrip(".")
            except Exception as e:
                errors.append(f"No NS records for {domain} or {org}: {e}")
                return base_result
        else:
            errors.append(f"No NS records for {domain}")
            return base_result
    except dns.resolver.NoNameservers:
        errors.append(f"No nameservers available for {domain}")
        return base_result
    except dns.exception.Timeout:
        errors.append(f"DNS query timeout resolving NS for {domain}")
        return base_result

    # Resolve NS hostname to IP
    try:
        a_answers = resolver.resolve(ns_hostname, "A")
        ns_ip = str(a_answers[0])
    except Exception as e:
        errors.append(f"Failed to resolve NS {ns_hostname} to IP: {e}")
        return base_result

    base_result["authoritative_ns"] = ns_hostname
    base_result["authoritative_ip"] = ns_ip
    base_result["zone"] = domain.rstrip(".") + "."

    # Step 2: Craft probe query for a synthetic nonexistent name
    probe_name = f"_nsec-probe.{domain}"
    base_result["probe_name"] = probe_name

    try:
        query = dns.message.make_query(probe_name, "A", want_dnssec=True)
        query.flags |= dns.flags.CD  # Checking Disabled — get raw NSEC/NSEC3
        response = dns.query.udp(query, ns_ip, timeout=5.0)
    except dns.exception.Timeout:
        errors.append(f"Authoritative query to {ns_ip} timed out (5s)")
        return base_result
    except Exception as e:
        errors.append(f"Authoritative query failed: {e}")
        return base_result

    base_result["response_code"] = dns.rcode.to_text(response.rcode())

    # Step 3: Parse authority section for NSEC/NSEC3
    nsec_records = []
    nsec3_records = []

    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NSEC:
            for rdata in rrset:
                nsec_records.append(str(rdata))
                base_result["nsec_records"].append(
                    f"{rrset.name} {rrset.ttl} IN NSEC {rdata}"
                )
        elif rrset.rdtype == dns.rdatatype.NSEC3:
            for rdata in rrset:
                nsec3_records.append(rdata)
                base_result["nsec_records"].append(
                    f"{rrset.name} {rrset.ttl} IN NSEC3 {rdata}"
                )

    # Step 4: Assess denial type and walkability
    if nsec_records:
        base_result["denial_type"] = "nsec"
        base_result["zone_walkable"] = True
        base_result["walkability_risk"] = "high"
        base_result["walkability_note"] = (
            "Zone uses plain NSEC. Every name in the zone is exposed — each NSEC record "
            "points to the next name in alphabetical order, allowing full zone enumeration "
            "by following the chain. This is common on smaller or older zones but considered "
            "a privacy risk for zones with sensitive hostnames."
        )
    elif nsec3_records:
        base_result["denial_type"] = "nsec3"

        # Extract NSEC3 parameters from the first record
        rdata = nsec3_records[0]
        algorithm = rdata.algorithm
        flags = rdata.flags
        iterations = rdata.iterations
        salt = rdata.salt.hex() if rdata.salt else ""
        opt_out = bool(flags & 0x01)

        base_result["nsec3_params"] = {
            "algorithm": algorithm,
            "iterations": iterations,
            "salt": salt,
            "salt_length": len(rdata.salt) if rdata.salt else 0,
            "opt_out": opt_out,
        }

        if opt_out:
            base_result["zone_walkable"] = False
            base_result["walkability_risk"] = "low"
            base_result["walkability_note"] = (
                f"Zone uses NSEC3 with opt-out flag set. Unsigned delegations are omitted "
                f"from the denial chain, which is typical of large TLD zones. Signed names "
                f"are still hashed (algorithm {algorithm}, {iterations} iterations"
                + (f", {len(rdata.salt)}-byte salt" if rdata.salt else ", no salt")
                + "). Not directly walkable."
            )
        elif iterations == 0 and not salt:
            base_result["zone_walkable"] = False
            base_result["walkability_risk"] = "moderate"
            base_result["walkability_note"] = (
                "Zone uses NSEC3 with iterations=0 and no salt (RFC 9276 recommended config). "
                "Names are SHA-1 hashed but the single-pass no-salt configuration means "
                "precomputed rainbow tables or offline dictionary attacks are feasible against "
                "the hashed names. Not directly walkable, but weaker than salted/iterated NSEC3."
            )
        elif iterations <= 10 or not salt:
            base_result["zone_walkable"] = False
            base_result["walkability_risk"] = "moderate"
            reason_parts = []
            if iterations <= 10:
                reason_parts.append(f"{iterations} iterations")
            if not salt:
                reason_parts.append("no salt")
            base_result["walkability_note"] = (
                f"Zone uses NSEC3 with {' and '.join(reason_parts)}. "
                f"Names are SHA-1 hashed before publication, preventing direct zone enumeration. "
                f"However, the low iteration count"
                + (" and absent salt make" if not salt else " makes")
                + " offline dictionary attacks more practical. RFC 9276 recommends iterations=0 "
                "with no salt for performance, accepting this trade-off."
            )
        else:
            base_result["zone_walkable"] = False
            base_result["walkability_risk"] = "low"
            base_result["walkability_note"] = (
                f"Zone uses NSEC3 with {iterations} iterations and a "
                f"{len(rdata.salt)}-byte salt. Names are SHA-1 hashed before publication, "
                f"preventing direct zone enumeration. An attacker would need offline "
                f"dictionary/rainbow table attacks against the hashed names to recover hostnames."
            )
    else:
        base_result["denial_type"] = "none"
        base_result["walkability_risk"] = "none"
        base_result["walkability_note"] = (
            "No NSEC or NSEC3 records in the authority section. The zone may not be "
            "DNSSEC-signed, or the authoritative server did not include denial-of-existence "
            "records in the response."
        )

    # Step 5: Query NSEC3PARAM at zone apex and cross-check against NSEC3 records
    try:
        nsec3param_query = dns.message.make_query(
            domain, dns.rdatatype.NSEC3PARAM, want_dnssec=True
        )
        nsec3param_query.flags |= dns.flags.CD
        nsec3param_response = dns.query.udp(nsec3param_query, ns_ip, timeout=5.0)

        for rrset in nsec3param_response.answer:
            if rrset.rdtype == dns.rdatatype.NSEC3PARAM:
                rdata = list(rrset)[0]
                base_result["nsec3param"] = {
                    "algorithm": rdata.algorithm,
                    "flags": rdata.flags,
                    "iterations": rdata.iterations,
                    "salt": rdata.salt.hex() if rdata.salt else "",
                    "salt_length": len(rdata.salt) if rdata.salt else 0,
                }
                break
    except dns.exception.Timeout:
        errors.append(f"NSEC3PARAM query to {ns_ip} timed out (5s)")
    except Exception as e:
        errors.append(f"NSEC3PARAM query failed: {e}")

    # Consistency check: only when both NSEC3 denial records and NSEC3PARAM exist
    nsec3param = base_result["nsec3param"]
    nsec3_params = base_result["nsec3_params"]

    if (
        base_result["denial_type"] == "nsec3"
        and nsec3param is not None
        and nsec3_params is not None
    ):
        mismatches = []
        if nsec3param["algorithm"] != nsec3_params["algorithm"]:
            mismatches.append(
                f"Algorithm mismatch: NSEC3PARAM={nsec3param['algorithm']}, "
                f"NSEC3={nsec3_params['algorithm']}"
            )
        if nsec3param["iterations"] != nsec3_params["iterations"]:
            mismatches.append(
                f"Iterations mismatch: NSEC3PARAM={nsec3param['iterations']}, "
                f"NSEC3={nsec3_params['iterations']}"
            )
        if nsec3param["salt"] != nsec3_params["salt"]:
            mismatches.append(
                f"Salt mismatch: NSEC3PARAM='{nsec3param['salt']}', "
                f"NSEC3='{nsec3_params['salt']}'"
            )
        base_result["nsec3_consistency"] = {
            "consistent": len(mismatches) == 0,
            "mismatches": mismatches,
        }
    elif (
        base_result["denial_type"] == "nsec3"
        and nsec3param is None
        and nsec3_params is not None
    ):
        base_result["nsec3_consistency"] = {
            "consistent": False,
            "mismatches": [
                "No NSEC3PARAM record at zone apex despite NSEC3 denial records"
            ],
        }

    return base_result


@mcp.tool()
@track("rdap_lookup")
def rdap_lookup(
    domain: str = Field(
        description="Domain to look up via RDAP (registrable domain, not subdomain)"
    ),
) -> dict:
    """
    Retrieve domain registration data via RDAP (modern WHOIS replacement).

    Looks up the IANA RDAP bootstrap to find the correct server for the TLD,
    then queries for registration data. Calculates domain age for risk assessment
    (< 30 days = HIGH RISK, < 90 days = ELEVATED).

    This is the one tool that makes HTTP calls (not DNS). The domain input is
    validated before any HTTP request is made.
    """
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    errors = []

    # Extract registrable domain (simple TLD split)
    parts = domain.split(".")
    if len(parts) > 2:
        registrable = ".".join(parts[-2:])
    else:
        registrable = domain
    tld = parts[-1].lower()

    # Find RDAP server for this TLD
    rdap_base = _get_rdap_server(tld, errors)
    if not rdap_base:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": registrable,
            "rdap_server": None,
            "errors": errors if errors else [f"No RDAP server found for .{tld}"],
        }

    # Query RDAP
    rdap_url = f"{rdap_base.rstrip('/')}/domain/{registrable}"
    try:
        resp = requests.get(
            rdap_url,
            timeout=10,
            allow_redirects=True,
            headers={"Accept": "application/rdap+json, application/json"},
        )
        # Enforce max 3 redirects (requests follows by default, but cap history)
        if resp.history and len(resp.history) > 3:
            errors.append("Exceeded 3 RDAP redirects")
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "domain": registrable,
                "rdap_server": rdap_base,
                "errors": errors,
            }

        if resp.status_code != 200:
            errors.append(f"RDAP returned HTTP {resp.status_code}")
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "domain": registrable,
                "rdap_server": rdap_base,
                "errors": errors,
            }

        data = resp.json()
    except requests.exceptions.Timeout:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": registrable,
            "rdap_server": rdap_base,
            "errors": ["RDAP request timed out (10s)"],
        }
    except requests.exceptions.RequestException as e:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": registrable,
            "rdap_server": rdap_base,
            "errors": [f"RDAP request failed: {str(e)}"],
        }

    # Parse response
    registrar = None
    creation_date = None
    expiration_date = None
    last_updated = None
    status = data.get("status", [])
    registrant_org = None
    registrant_country = None

    # Registrar from entities
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [None, []])
            if len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        registrar = field[3]
                        break
            # Also check publicIds for registrar name
            if not registrar:
                for pid in entity.get("publicIds", []):
                    if pid.get("type") == "IANA Registrar ID":
                        registrar = entity.get("handle", pid.get("identifier"))
        if "registrant" in roles:
            vcard = entity.get("vcardArray", [None, []])
            if len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "org":
                        registrant_org = field[3]
                    elif field[0] == "adr":
                        # Country is typically the last element of the address array
                        if isinstance(field[3], list) and len(field[3]) >= 7:
                            registrant_country = field[3][6]

    # Parse event dates
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date_val = event.get("eventDate", "")
        if action == "registration":
            creation_date = date_val
        elif action == "expiration":
            expiration_date = date_val
        elif action == "last changed":
            last_updated = date_val

    # Calculate domain age
    domain_age_days = None
    if creation_date:
        try:
            created_dt = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))
            domain_age_days = (datetime.now(timezone.utc) - created_dt).days
        except (ValueError, TypeError):
            pass

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": registrable,
        "rdap_server": rdap_base,
        "registrar": registrar,
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "last_updated": last_updated,
        "status": status,
        "registrant_org": registrant_org or "REDACTED FOR PRIVACY",
        "registrant_country": registrant_country,
        "domain_age_days": domain_age_days,
        "errors": errors,
    }


@mcp.tool()
@track("detect_hijacking")
def detect_hijacking(
    resolver: str = Field(
        description="IP address of the resolver to test (e.g. 192.168.1.1)"
    ),
) -> dict:
    """
    Test a DNS resolver for signs of DNS hijacking or tampering.

    WiFi routers and ISPs sometimes intercept DNS queries and return spoofed
    responses — captive portals, ad-injection landing pages, or NXDOMAIN
    redirects. This tool sends five probes directly to the specified resolver
    and reports a clean/suspicious/hijacked verdict with per-check detail.

    Checks performed:
    1. NXDOMAIN probe — queries a random domain; hijacked resolvers return IPs
    2. Known stable record — a.root-servers.net A must return 198.41.0.4
    3. DNSSEC AD flag — cloudflare.com A; AD set means resolver validates DNSSEC
    4. Resolver identity — whoami.akamai.net TXT reveals the resolver's source IP
    5. Transparent proxy — queries root server directly with RD=0; RA=1 means
       a transparent DNS proxy is intercepting port 53 traffic

    Verdict logic:
    - hijacked: NXDOMAIN probe returned NOERROR+IPs, OR known record IP wrong
    - suspicious: partial failures or timeouts without a clear hijack signal
    - clean: all checks passed
    """
    # Validate resolver IP
    try:
        ipaddress.ip_address(resolver)
    except ValueError:
        return {
            "error": f"Invalid IP address: {resolver!r}",
            "resolver_tested": resolver,
        }

    timestamp = datetime.now(timezone.utc).isoformat()
    errors = []
    findings = []

    # -------------------------------------------------------------------------
    # Check 1: NXDOMAIN probe
    # -------------------------------------------------------------------------
    probe_label = f"nxprobe-{secrets.token_hex(8)}"
    probe_domain = f"{probe_label}.com"
    nxdomain_check: dict = {
        "domain": probe_domain,
        "expected": "NXDOMAIN",
        "got": None,
        "answer_ips": [],
        "passed": False,
    }
    try:
        query = dns.message.make_query(probe_domain, dns.rdatatype.A)
        response = dns.query.udp(query, resolver, timeout=5.0)
        rcode_name = dns.rcode.to_text(response.rcode())
        nxdomain_check["got"] = rcode_name
        answer_ips = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.A:
                answer_ips.extend(str(rr) for rr in rrset)
        nxdomain_check["answer_ips"] = answer_ips
        if rcode_name == "NXDOMAIN" and not answer_ips:
            nxdomain_check["passed"] = True
        else:
            if answer_ips:
                findings.append(
                    f"NXDOMAIN probe returned {rcode_name} with IPs {answer_ips} — "
                    "resolver is hijacking NXDOMAIN responses"
                )
            else:
                findings.append(
                    f"NXDOMAIN probe returned {rcode_name} instead of NXDOMAIN"
                )
    except dns.exception.Timeout:
        nxdomain_check["got"] = "TIMEOUT"
        errors.append(f"NXDOMAIN probe timed out querying {resolver}")
    except Exception as e:
        nxdomain_check["got"] = "ERROR"
        errors.append(f"NXDOMAIN probe error: {e}")

    # -------------------------------------------------------------------------
    # Check 2: Known stable record — a.root-servers.net A = 198.41.0.4
    # -------------------------------------------------------------------------
    KNOWN_DOMAIN = "a.root-servers.net"
    KNOWN_IP = "198.41.0.4"
    known_check: dict = {
        "domain": KNOWN_DOMAIN,
        "expected_ip": KNOWN_IP,
        "got_ips": [],
        "passed": False,
    }
    try:
        query = dns.message.make_query(KNOWN_DOMAIN, dns.rdatatype.A)
        response = dns.query.udp(query, resolver, timeout=5.0)
        got_ips = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.A:
                got_ips.extend(str(rr) for rr in rrset)
        known_check["got_ips"] = got_ips
        if KNOWN_IP in got_ips:
            known_check["passed"] = True
        else:
            if got_ips:
                findings.append(
                    f"{KNOWN_DOMAIN} returned {got_ips} instead of {KNOWN_IP} — "
                    "resolver is tampering with DNS responses"
                )
            else:
                findings.append(
                    f"{KNOWN_DOMAIN} returned no A records (expected {KNOWN_IP})"
                )
    except dns.exception.Timeout:
        errors.append(f"Known-record check timed out querying {resolver}")
    except Exception as e:
        errors.append(f"Known-record check error: {e}")

    # -------------------------------------------------------------------------
    # Check 3: DNSSEC AD flag — informational, not a hijack indicator
    # -------------------------------------------------------------------------
    dnssec_check: dict = {
        "domain": "cloudflare.com",
        "ad_flag": False,
        "note": "",
    }
    try:
        query = dns.message.make_query(
            "cloudflare.com", dns.rdatatype.A, want_dnssec=True
        )
        response = dns.query.udp(query, resolver, timeout=5.0)
        ad_set = bool(response.flags & dns.flags.AD)
        dnssec_check["ad_flag"] = ad_set
        dnssec_check["note"] = (
            "Resolver performs DNSSEC validation"
            if ad_set
            else "Resolver does not set AD flag (may not validate DNSSEC)"
        )
    except dns.exception.Timeout:
        dnssec_check["note"] = "Timed out"
        errors.append(f"DNSSEC AD flag check timed out querying {resolver}")
    except Exception as e:
        dnssec_check["note"] = f"Error: {e}"
        errors.append(f"DNSSEC AD flag check error: {e}")

    # -------------------------------------------------------------------------
    # Check 4: Resolver identity — informational
    # -------------------------------------------------------------------------
    identity_check: dict = {
        "query": "whoami.akamai.net TXT",
        "result": None,
    }
    try:
        query = dns.message.make_query("whoami.akamai.net", dns.rdatatype.TXT)
        response = dns.query.udp(query, resolver, timeout=5.0)
        txt_values = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.TXT:
                for rr in rrset:
                    txt_values.extend(s.decode() for s in rr.strings)
        identity_check["result"] = txt_values[0] if txt_values else None
    except dns.exception.Timeout:
        errors.append(f"Resolver identity check timed out querying {resolver}")
    except Exception as e:
        errors.append(f"Resolver identity check error: {e}")

    # -------------------------------------------------------------------------
    # Check 5: Transparent proxy detection
    # -------------------------------------------------------------------------
    proxy_check: dict = {
        "target": "a.root-servers.net (198.41.0.4)",
        "query": ". NS (RD=0)",
        "expected_flags": "QR AA RA=0",
        "got_flags": None,
        "ra_flag": False,
        "aa_flag": False,
        "passed": False,
        "note": "",
    }
    try:
        query = dns.message.make_query(".", dns.rdatatype.NS)
        query.flags &= ~dns.flags.RD
        response = dns.query.udp(query, "198.41.0.4", timeout=5.0)
        ra_set = bool(response.flags & dns.flags.RA)
        aa_set = bool(response.flags & dns.flags.AA)
        proxy_check["got_flags"] = dns.flags.to_text(response.flags)
        proxy_check["ra_flag"] = ra_set
        proxy_check["aa_flag"] = aa_set
        if ra_set:
            proxy_check["passed"] = False
            proxy_check["note"] = (
                "RA=1 from authoritative root server — a transparent DNS proxy "
                "is intercepting port 53 traffic"
            )
            findings.append(proxy_check["note"])
        else:
            proxy_check["passed"] = True
            proxy_check["note"] = (
                "RA=0 as expected — root server responded directly, no proxy"
            )
    except dns.exception.Timeout:
        proxy_check["got_flags"] = "TIMEOUT"
        proxy_check["note"] = (
            "Timed out querying root server directly — network may block "
            "direct port 53 to external servers"
        )
        errors.append("Transparent proxy check timed out querying 198.41.0.4")
    except Exception as e:
        proxy_check["got_flags"] = "ERROR"
        proxy_check["note"] = f"Error: {e}"
        errors.append(f"Transparent proxy check error: {e}")

    # -------------------------------------------------------------------------
    # Verdict
    # -------------------------------------------------------------------------
    nxdomain_hijacked = nxdomain_check["got"] not in (
        None,
        "NXDOMAIN",
        "TIMEOUT",
        "ERROR",
    ) or bool(nxdomain_check["answer_ips"])
    known_wrong = not known_check["passed"] and bool(known_check.get("got_ips"))

    if nxdomain_hijacked or known_wrong:
        verdict = "hijacked"
    elif findings or (
        errors and not nxdomain_check["passed"] and not known_check["passed"]
    ):
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "timestamp": timestamp,
        "resolver_tested": resolver,
        "resolver_identity": identity_check["result"],
        "checks": {
            "nxdomain_probe": nxdomain_check,
            "known_record": known_check,
            "dnssec_validation": dnssec_check,
            "resolver_identity": identity_check,
            "transparent_proxy": proxy_check,
        },
        "verdict": verdict,
        "findings": findings,
        "errors": errors,
    }


def _get_rdap_server(tld: str, errors: list) -> str | None:
    """Look up the RDAP server for a TLD from IANA bootstrap or fallback map."""
    global _rdap_bootstrap_cache

    if _rdap_bootstrap_cache is None:
        try:
            resp = requests.get(
                "https://data.iana.org/rdap/dns.json",
                timeout=10,
            )
            if resp.status_code == 200:
                _rdap_bootstrap_cache = resp.json()
        except Exception as e:
            errors.append(f"Failed to fetch RDAP bootstrap: {e}")

    # Search bootstrap data
    if _rdap_bootstrap_cache:
        for entry in _rdap_bootstrap_cache.get("services", []):
            tlds = entry[0]
            servers = entry[1]
            if tld in tlds and servers:
                return servers[0]

    # Fallback to hardcoded map
    return _RDAP_FALLBACKS.get(tld)


def _print_startup_banner(transport: str):
    """Print a decorative startup banner to stderr (never touches stdout/protocol)."""
    import random
    import sys

    spotlights = [
        ("dns_dnssec_validate", "Chain-of-trust validation, root to leaf"),
        ("nsec_info", "NSEC/NSEC3 denial-of-existence & walkability"),
        ("check_spf", "SPF include-chain resolution (RFC 7208)"),
        ("check_dmarc", "DMARC policy with org-domain fallback"),
        ("check_dkim_selector", "DKIM public key retrieval & validation"),
        ("check_bimi", "Brand indicator & VMC verification"),
        ("check_mta_sts", "MTA-STS transport security policy analysis"),
        ("rdap_lookup", "Live domain registration data via RDAP"),
        ("check_tlsa", "Direct TLSA record check for any host:port:protocol"),
        ("check_dane", "DANE TLSA + DNSSEC mail server authentication"),
        ("dns_dig_style", "Dig-style output with DNSSEC flags + DoE"),
        ("detect_hijacking", "DNS hijacking & tampering detection"),
        ("check_rbl", "IP reputation across 8 DNS-based RBLs"),
        ("check_dbl", "Domain reputation via Spamhaus DBL, URIBL, SURBL"),
        ("cymru_asn", "BGP ASN + org lookup via Team Cymru DNS"),
        ("quine", "The server reads its own source code"),
    ]

    tool, desc = random.choice(spotlights)

    W = 54

    def line(text, emojis=0):
        return "║" + text + " " * (W - len(text) - emojis) + "║"

    empty = "║" + " " * W + "║"
    banner = "\n".join(
        [
            "",
            "╔" + "═" * W + "╗",
            empty,
            line("   🔍  d n s - m c p", 1),
            empty,
            line("   DNS & Domain Security Analysis Server"),
            line(f"   26 tools · 3 resources · DNSSEC · MCP · {transport}"),
            empty,
            line(f"   ✨ Spotlight: {tool}", 1),
            line(f"      {desc}"),
            empty,
            "╚" + "═" * W + "╝",
            "",
        ]
    )

    print(banner, file=sys.stderr)


# ---------------------------------------------------------------------------
# check_rbl
# ---------------------------------------------------------------------------


@mcp.tool()
@track("check_rbl")
def check_rbl(
    ip_address: str = Field(
        description="IPv4 or IPv6 address to check against DNS-based RBLs"
    ),
    nameserver: str = DEFAULT_RESOLVER,
) -> dict:
    """
    Check an IP address against 8 DNS-based Real-time Blackhole Lists (RBLs).

    Uses the standard DNS lookup method: reverses the IP octets (IPv4) or nibbles
    (IPv6), appends the RBL zone, and queries for A + TXT records. An A record
    answer means the IP is listed; the return code identifies the listing type.

    RBLs queried (in order):
      Spamhaus ZEN, SpamCop, UCEProtect L1, UCEProtect L2, Mailspike,
      PSBL, Barracuda, SORBS

    Spamhaus ZEN uses zen.spamhaus.org by default (low-volume analyst use).
    Set the SPAMHAUS_DQS_KEY env var to enable production DQS queries.

    SORBS may timeout occasionally — handled gracefully with per-RBL error
    capture so a slow zone never blocks the rest of the results.

    Mailspike returns positive reputation codes (127.0.0.10–14) for known-good
    senders — these are reported with listed=false and a reputation description.
    """
    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return {"error": "Invalid IP address format", "ip_address": ip_address}

    try:
        ipaddress.ip_address(nameserver)
    except ValueError:
        return {"error": "Invalid nameserver IP address", "ip_address": ip_address}

    errors = []

    is_private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    if is_private:
        errors.append(
            f"{ip_address} is a private/reserved address — RBL results will be meaningless"
        )

    # Build reversed IP string for RBL zone suffix
    if ip.version == 4:
        reversed_ip = ".".join(reversed(str(ip).split(".")))
    else:
        expanded = ip.exploded.replace(":", "")  # 32 hex nibbles, no colons
        reversed_ip = ".".join(reversed(expanded))

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.lifetime = 5.0

    results = []
    listed_count = 0
    clean_count = 0
    error_count = 0

    for rbl in _RBL_LIST:
        zone = rbl["zone"]
        fqdn = f"{reversed_ip}.{zone}"
        codes_map = rbl["codes"]
        positive_codes = rbl["positive_codes"]

        entry: dict = {
            "rbl": rbl["name"],
            "zone_queried": fqdn,
            "listed": False,
            "return_codes": [],
            "listing_types": [],
            "explanation": None,
            "error": None,
        }

        try:
            a_answers = resolver.resolve(fqdn, "A")
            return_codes = [str(rdata) for rdata in a_answers]
            entry["return_codes"] = return_codes

            # Check for administrative quota/block codes before treating as a listing.
            # Spamhaus returns 127.255.255.x when queries are rate-limited or blocked;
            # these must not be counted as IP listings (would be a false positive).
            quota_codes = rbl.get("quota_codes", {})
            quota_hits = [c for c in return_codes if c in quota_codes]
            if quota_hits:
                entry["error"] = quota_codes[quota_hits[0]]
                entry["listed"] = False
                error_count += 1
                results.append(entry)
                continue

            listing_types = []
            is_positive_only = True
            for code in return_codes:
                listing_types.append(codes_map.get(code, f"Unknown return code {code}"))
                if code not in positive_codes:
                    is_positive_only = False

            entry["listing_types"] = listing_types
            entry["listed"] = not is_positive_only

            if entry["listed"]:
                listed_count += 1
            else:
                clean_count += 1

            # TXT is informational — failure is non-fatal
            try:
                txt_answers = resolver.resolve(fqdn, "TXT")
                txts = []
                for rdata in txt_answers:
                    txts.append(
                        " ".join(
                            s.decode() if isinstance(s, bytes) else s
                            for s in rdata.strings
                        )
                    )
                entry["explanation"] = "; ".join(txts)
            except Exception:
                pass

        except dns.resolver.NXDOMAIN:
            clean_count += 1
        except dns.resolver.NoAnswer:
            clean_count += 1
        except dns.exception.Timeout:
            error_count += 1
            entry["error"] = "timeout"
            errors.append(f"{rbl['name']} ({zone}): query timed out")
        except dns.resolver.NoNameservers:
            error_count += 1
            entry["error"] = "no nameservers"
            errors.append(f"{rbl['name']} ({zone}): no nameservers available")
        except Exception as exc:
            error_count += 1
            entry["error"] = str(exc)
            errors.append(f"{rbl['name']} ({zone}): {exc}")

        results.append(entry)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip_address": ip_address,
        "ip_version": ip.version,
        "is_private": is_private,
        "reversed_ip": reversed_ip,
        "spamhaus_dqs": bool(SPAMHAUS_DQS_KEY),
        "listed_count": listed_count,
        "clean_count": clean_count,
        "error_count": error_count,
        "results": results,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# check_dbl
# ---------------------------------------------------------------------------


@mcp.tool()
@track("check_dbl")
def check_dbl(
    domain: str = Field(
        description="Domain to check against DNS-based Domain Block Lists"
    ),
    nameserver: str = DEFAULT_RESOLVER,
) -> dict:
    """
    Check a domain against DNS-based Domain Block Lists (DBLs).

    DBLs classify domains rather than IPs. Query pattern: {domain}.{dbl-zone}.
    The registered (org) domain is used for the lookup, stripping subdomains.

    Lists queried (in order):
      Spamhaus DBL — classifies: spam / phishing / malware / botnet C2 /
                     abused-legit variants. Direct return-code lookup.
      URIBL (multi.uribl.com) — bitmask: black / grey / red / multi.
      SURBL (multi.surbl.org) — bitmask: SC / WS / AB / PH / MW / CRX.

    Spamhaus DBL uses dbl.spamhaus.org by default (low-volume analyst use).
    Set SPAMHAUS_DQS_KEY env var to enable production DQS queries.
    """
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    try:
        ipaddress.ip_address(nameserver)
    except ValueError:
        return {"error": "Invalid nameserver IP address", "domain": domain}

    org = _get_org_domain(domain)

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.lifetime = 5.0

    errors = []
    results = []
    listed_count = 0
    clean_count = 0
    error_count = 0

    for dbl in _DBL_LIST:
        fqdn = f"{org}.{dbl['zone']}"
        entry: dict = {
            "dbl": dbl["name"],
            "zone_queried": fqdn,
            "listed": False,
            "listing_types": [],
            "explanation": None,
            "error": None,
        }

        try:
            a_answers = resolver.resolve(fqdn, "A")
            return_codes = [str(rdata) for rdata in a_answers]

            if dbl["bitmask"]:
                # Decode bitmask from last octet of each return code
                listing_types = []
                listed = False
                for code in return_codes:
                    try:
                        last_octet = int(code.split(".")[-1])
                        for bit, label in dbl["bitmask_labels"].items():
                            if last_octet & bit:
                                listing_types.append(label)
                                listed = True
                    except (ValueError, IndexError):
                        listing_types.append(f"Unknown return code {code}")
                        listed = True
                entry["listing_types"] = listing_types
                entry["listed"] = listed
            else:
                # Spamhaus DBL: direct code lookup with quota-code guard
                quota_codes = dbl.get("quota_codes", {})
                quota_hits = [c for c in return_codes if c in quota_codes]
                if quota_hits:
                    entry["error"] = quota_codes[quota_hits[0]]
                    error_count += 1
                    results.append(entry)
                    continue

                listing_types = [
                    dbl["codes"].get(code, f"Unknown return code {code}")
                    for code in return_codes
                ]
                entry["listing_types"] = listing_types
                entry["listed"] = bool(listing_types)

            if entry["listed"]:
                listed_count += 1
            else:
                clean_count += 1

            # TXT is informational — failure is non-fatal
            try:
                txt_answers = resolver.resolve(fqdn, "TXT")
                txts = []
                for rdata in txt_answers:
                    txts.append(
                        " ".join(
                            s.decode() if isinstance(s, bytes) else s
                            for s in rdata.strings
                        )
                    )
                entry["explanation"] = "; ".join(txts)
            except Exception:
                pass

        except dns.resolver.NXDOMAIN:
            clean_count += 1
        except dns.resolver.NoAnswer:
            clean_count += 1
        except dns.exception.Timeout:
            error_count += 1
            entry["error"] = "timeout"
            errors.append(f"{dbl['name']}: query timed out")
        except dns.resolver.NoNameservers:
            error_count += 1
            entry["error"] = "no nameservers"
            errors.append(f"{dbl['name']}: no nameservers available")
        except Exception as exc:
            error_count += 1
            entry["error"] = str(exc)
            errors.append(f"{dbl['name']}: {exc}")

        results.append(entry)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "org_domain": org,
        "spamhaus_dqs": bool(SPAMHAUS_DQS_KEY),
        "listed_count": listed_count,
        "clean_count": clean_count,
        "error_count": error_count,
        "results": results,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# cymru_asn
# ---------------------------------------------------------------------------


@mcp.tool()
@track("cymru_asn")
def cymru_asn(
    ip_address: str = Field(description="IPv4 or IPv6 address for ASN lookup"),
    nameserver: str = DEFAULT_RESOLVER,
) -> dict:
    """
    Look up the Autonomous System Number (ASN) for an IP via Team Cymru's DNS service.

    Step 1 — Origin lookup:
      IPv4: {reversed_octets}.origin.asn.cymru.com TXT
      IPv6: {reversed_nibbles}.origin6.asn.cymru.com TXT
      Response format: "ASN | prefix | CC | registry | allocated"

    Step 2 — Org name lookup:
      AS{asn}.asn.cymru.com TXT
      Response format: "ASN | | CC | registry | allocated | org name"

    100% DNS — no HTTP. Authoritative BGP routing data.
    Flags known bulletproof / high-abuse ASNs from a built-in reference list.
    """
    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return {"error": "Invalid IP address format", "ip_address": ip_address}

    try:
        ipaddress.ip_address(nameserver)
    except ValueError:
        return {"error": "Invalid nameserver IP address", "ip_address": ip_address}

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.lifetime = 5.0

    errors = []

    # Build reversed lookup FQDN
    if ip.version == 4:
        reversed_ip = ".".join(reversed(str(ip).split(".")))
        origin_fqdn = f"{reversed_ip}.origin.asn.cymru.com"
    else:
        expanded = ip.exploded.replace(":", "")
        reversed_ip = ".".join(reversed(expanded))
        origin_fqdn = f"{reversed_ip}.origin6.asn.cymru.com"

    asn: int | None = None
    prefix: str | None = None
    country: str | None = None
    registry: str | None = None
    allocated: str | None = None
    org_name: str | None = None

    # Step 1: origin lookup
    try:
        txt_answers = resolver.resolve(origin_fqdn, "TXT")
        for rdata in txt_answers:
            raw = " ".join(
                s.decode() if isinstance(s, bytes) else s for s in rdata.strings
            ).strip()
            # Format: "ASN | prefix | CC | registry | allocated"
            # Multihomed IPs may have multiple space-separated ASNs in field 0
            parts = [p.strip() for p in raw.split("|")]
            if len(parts) >= 1:
                asn_str = parts[0].split()[0]  # take first ASN if multihomed
                try:
                    asn = int(asn_str)
                except ValueError:
                    errors.append(f"Could not parse ASN from: {raw}")
            if len(parts) >= 2:
                prefix = parts[1].strip() or None
            if len(parts) >= 3:
                country = parts[2].strip() or None
            if len(parts) >= 4:
                registry = parts[3].strip() or None
            if len(parts) >= 5:
                allocated = parts[4].strip() or None
            break  # use first TXT record
    except dns.resolver.NXDOMAIN:
        errors.append(f"No ASN record found for {ip_address}")
    except dns.exception.Timeout:
        errors.append(f"Timeout on origin lookup ({origin_fqdn})")
    except Exception as exc:
        errors.append(f"Origin lookup error: {exc}")

    # Step 2: org name lookup
    if asn is not None:
        asn_fqdn = f"AS{asn}.asn.cymru.com"
        try:
            txt_answers = resolver.resolve(asn_fqdn, "TXT")
            for rdata in txt_answers:
                raw = " ".join(
                    s.decode() if isinstance(s, bytes) else s for s in rdata.strings
                ).strip()
                # Format: "ASN | | CC | registry | allocated | org name"
                parts = [p.strip() for p in raw.split("|")]
                if len(parts) >= 6:
                    org_name = parts[5].strip() or None
                elif len(parts) >= 2:
                    org_name = parts[-1].strip() or None
                break
        except Exception as exc:
            errors.append(f"ASN org name lookup error: {exc}")

    high_risk_note = _HIGH_RISK_ASNS.get(asn) if asn is not None else None

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip_address": ip_address,
        "ip_version": ip.version,
        "asn": asn,
        "prefix": prefix,
        "country": country,
        "registry": registry,
        "allocated": allocated,
        "org_name": org_name,
        "high_risk_asn": high_risk_note is not None,
        "high_risk_note": high_risk_note,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# check_fast_flux
# ---------------------------------------------------------------------------


@mcp.tool()
@track("check_fast_flux")
def check_fast_flux(
    domain: str = Field(description="Domain to probe for fast-flux behaviour"),
    nameserver: str | None = Field(
        default=None,
        description=f"Nameserver IP (default: {DEFAULT_RESOLVER})",
    ),
    query_count: int = Field(
        default=5,
        description="Number of A/AAAA query rounds to send (3–10)",
    ),
    delay_seconds: float = Field(
        default=1.0,
        description="Delay between query rounds in seconds (0.0–5.0)",
    ),
) -> dict:
    """
    Detect fast-flux DNS by querying a domain's A/AAAA records multiple times
    and comparing the returned IP sets between rounds.

    Fast-flux is a technique used by botnets and phishing infrastructure to evade
    takedowns: the domain's records rotate rapidly through a large pool of
    compromised hosts, with very short TTLs (often < 60 s).

    Detection heuristic:
      - Sends query_count rounds of A + AAAA queries with delay_seconds between them.
      - flux_detected = True  when  min_ttl < 300 s  AND  ip_set_changes > 0

    Returns:
      - min_ttl: lowest TTL observed across all answers (seconds)
      - unique_ips_seen: count of distinct IPs seen across all rounds
      - ip_set_changes: how many times the answer set changed between consecutive rounds
      - all_ips: sorted list of every distinct IP observed
      - flux_detected: bool — True when TTL is suspiciously low AND IPs rotated
      - queries: per-round detail [{index, ips, ttl}]
    """
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    ns = nameserver if nameserver is not None else DEFAULT_RESOLVER
    try:
        ipaddress.ip_address(ns)
    except ValueError:
        return {"error": "Invalid nameserver IP address", "domain": domain}

    if not (3 <= query_count <= 10):
        return {"error": "query_count must be between 3 and 10", "domain": domain}
    if not (0.0 <= delay_seconds <= 5.0):
        return {"error": "delay_seconds must be between 0.0 and 5.0", "domain": domain}

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ns]
    resolver.lifetime = 5.0

    errors: list[str] = []
    queries: list[dict] = []
    all_ips: set[str] = set()
    min_ttl: int | None = None

    for i in range(query_count):
        if i > 0 and delay_seconds > 0:
            time.sleep(delay_seconds)

        ips: list[str] = []
        round_ttl: int | None = None
        nxdomain = False

        for rtype in ("A", "AAAA"):
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    ips.append(str(rdata))
                if round_ttl is None or answers.rrset.ttl < round_ttl:
                    round_ttl = answers.rrset.ttl
            except dns.resolver.NXDOMAIN:
                errors.append(f"NXDOMAIN for {domain}")
                nxdomain = True
                break
            except dns.resolver.NoAnswer:
                pass  # no record of this type — normal
            except dns.exception.Timeout:
                errors.append(f"Round {i + 1} timed out")
            except Exception as exc:
                errors.append(f"Round {i + 1} error: {exc}")

        queries.append({"index": i + 1, "ips": sorted(ips), "ttl": round_ttl})
        all_ips.update(ips)

        if round_ttl is not None:
            if min_ttl is None or round_ttl < min_ttl:
                min_ttl = round_ttl

        if nxdomain:
            break

    # Count how many times the IP set changed between consecutive rounds
    ip_set_changes = sum(
        1
        for j in range(1, len(queries))
        if set(queries[j]["ips"]) != set(queries[j - 1]["ips"])
    )

    flux_detected = min_ttl is not None and min_ttl < 300 and ip_set_changes > 0

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "nameserver": ns,
        "query_count": len(queries),
        "delay_seconds": delay_seconds,
        "min_ttl": min_ttl,
        "unique_ips_seen": len(all_ips),
        "ip_set_changes": ip_set_changes,
        "all_ips": sorted(all_ips),
        "flux_detected": flux_detected,
        "queries": queries,
        "errors": errors,
    }


@mcp.tool()
@track("check_ct_logs")
def check_ct_logs(
    domain: str = Field(
        description="Apex domain to query CT logs for (e.g. deflationhollow.net)"
    ),
    include_expired: bool = Field(
        default=False,
        description="Include expired certificates in the results list (always counted in summary)",
    ),
) -> dict:
    """
    Query Certificate Transparency logs via crt.sh for a domain.

    Returns all certificates logged for the domain and its subdomains,
    including: unique names/SANs discovered (useful for subdomain enumeration),
    per-cert details (issuer, validity, wildcard status), active vs expired
    counts, and a CAA cross-reference that correctly maps intermediate CA
    names to their parent CA identity (e.g. E7/E8 -> letsencrypt.org) rather
    than doing a naive string comparison that produces false positives.

    Retries automatically -- crt.sh is unreliable and frequently returns
    empty responses or times out on the first attempt.
    """
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}

    errors: list[str] = []
    caa_warnings: list[dict] = []
    caa_infos: list[dict] = []
    caa_historical: list[dict] = []
    fetch_metadata: dict = {
        "attempts": 0,
        "success_on_attempt": None,
        "response_truncated": False,
        "error": None,
    }

    raw_certs = _fetch_ct_logs(domain, errors, fetch_metadata)

    # Deduplicate on crt.sh id (same cert logged to multiple logs)
    seen_ids: set[int] = set()
    unique_raw: list[dict] = []
    for cert in raw_certs:
        cid = cert.get("id")
        if cid is not None and cid not in seen_ids:
            seen_ids.add(cid)
            unique_raw.append(cert)

    # CAA lookup
    caa_issue: list[str] = []
    caa_issuewild: list[str] = []
    caa_configured = False
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [DEFAULT_RESOLVER]
        resolver.lifetime = 5.0
        answers = resolver.resolve(domain, "CAA")
        for rdata in answers:
            tag = rdata.tag.decode() if isinstance(rdata.tag, bytes) else rdata.tag
            value = (
                rdata.value.decode() if isinstance(rdata.value, bytes) else rdata.value
            )
            if tag == "issue":
                caa_issue.append(value.strip())
                caa_configured = True
            elif tag == "issuewild":
                caa_issuewild.append(value.strip())
                caa_configured = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except dns.exception.Timeout:
        errors.append("CAA lookup timed out")

    # Process certs
    now = datetime.now(timezone.utc)
    all_names: set[str] = set()
    certificates: list[dict] = []
    active_count = expired_count = wildcard_count = 0
    issuer_orgs_seen: set[str] = set()

    for raw in unique_raw:
        # Parse names
        sans = [
            n.strip() for n in (raw.get("name_value") or "").split("\n") if n.strip()
        ]
        if not sans:
            sans = [raw.get("common_name", "")]
        all_names.update(sans)

        is_wildcard = any(n.startswith("*.") for n in sans)
        if is_wildcard:
            wildcard_count += 1

        # Parse validity
        not_after_str = raw.get("not_after", "")
        try:
            not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
            active = not_after > now
        except (ValueError, AttributeError):
            active = True
            not_after = now  # fallback for days_since_expiry calculation

        if active:
            active_count += 1
        else:
            expired_count += 1

        # Issuer parsing
        issuer_name = raw.get("issuer_name", "")
        issuer_org = _parse_issuer_org(issuer_name)
        issuer_cn = None
        for part in issuer_name.split(","):
            part = part.strip()
            if part.startswith("CN="):
                issuer_cn = part[3:].strip()
                break
        if issuer_org:
            issuer_orgs_seen.add(issuer_org)

        caa_identity = _ORG_TO_CAA_IDENTITY.get(issuer_org) if issuer_org else None
        caa_identity_unknown = issuer_org is not None and caa_identity is None

        # CAA cross-reference (only if CAA is configured)
        if caa_configured:
            applicable_tags = caa_issuewild if is_wildcard else caa_issue
            if not applicable_tags:
                applicable_tags = caa_issue

            cert_id = raw.get("id")
            days_since_expiry = (now - not_after).days if not active else None

            if caa_identity_unknown:
                caa_historical.append(
                    {
                        "cert_id": cert_id,
                        "permalink": f"https://crt.sh/?id={cert_id}",
                        "severity": "NOTE",
                        "unknown_issuer_org": issuer_org,
                        "raw_issuer_name": issuer_name,
                        "raw_issuer_cn": issuer_cn,
                        "is_wildcard": is_wildcard,
                        "suggestion": (
                            "If this is a known CA, add it to _ORG_TO_CAA_IDENTITY in the source."
                        ),
                    }
                )
            elif caa_identity not in applicable_tags:
                entry = {
                    "cert_id": cert_id,
                    "permalink": f"https://crt.sh/?id={cert_id}",
                    "issuer_org": issuer_org,
                    "caa_identity": caa_identity,
                    "applicable_caa_tags": applicable_tags,
                    "is_wildcard": is_wildcard,
                    "note": (
                        "DNS CAA records reflect current policy only -- this tool cannot "
                        "determine whether the cert was issued before or after CAA was "
                        "configured. This is not necessarily a violation."
                    ),
                }
                if active:
                    entry["severity"] = "WARN"
                    caa_warnings.append(entry)
                elif days_since_expiry is not None and days_since_expiry <= 30:
                    entry["severity"] = "INFO"
                    caa_infos.append(entry)
                else:
                    entry["severity"] = "NOTE"
                    caa_historical.append(entry)

        cert_entry = {
            "id": raw.get("id"),
            "permalink": f"https://crt.sh/?id={raw.get('id')}",
            "common_name": raw.get("common_name"),
            "sans": sans,
            "is_wildcard": is_wildcard,
            "issuer_cn": issuer_cn,
            "issuer_org": issuer_org,
            "caa_identity": caa_identity,
            "caa_identity_unknown": caa_identity_unknown,
            "not_before": raw.get("not_before"),
            "not_after": not_after_str,
            "active": active,
            "logged_at": raw.get("logged_at"),
        }

        if include_expired or active:
            certificates.append(cert_entry)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "query": f"%.{domain}",
        "crtsh_url": f"https://crt.sh/?q=%25.{domain}",
        "summary": {
            "total_certs": len(unique_raw),
            "active_certs": active_count,
            "expired_certs": expired_count,
            "wildcard_certs": wildcard_count,
            "unique_names": len(all_names),
            "unique_issuers": len(issuer_orgs_seen),
            "caa_configured": caa_configured,
            "caa_warnings": len(caa_warnings),
            "caa_infos": len(caa_infos),
        },
        "unique_names": sorted(all_names),
        "caa_check": {
            "issue_tags": caa_issue,
            "issuewild_tags": caa_issuewild,
            "warnings": caa_warnings,
            "infos": caa_infos,
            "historical_mismatches": caa_historical if include_expired else [],
        },
        "certificates": certificates,
        "fetch_metadata": fetch_metadata,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Analyst prompts
# ---------------------------------------------------------------------------


@mcp.prompt()
def email_security_audit() -> str:
    """Audit the email security posture of a domain (SPF, DKIM, DMARC, MTA-STS, BIMI). Grades A–F."""
    return (_PROMPT_DIR / "email_security_audit.txt").read_text()


@mcp.prompt()
def dnssec_chain_audit() -> str:
    """Full DNSSEC chain-of-trust audit from the IANA root trust anchor down to a target domain."""
    return (_PROMPT_DIR / "dnssec_chain_audit.txt").read_text()


@mcp.prompt()
def soc_email_forensics() -> str:
    """Forensic phishing analysis of a raw email (.eml or pasted headers). Returns TRUSTABLE / SUSPICIOUS / PHISHING / FURTHER ANALYSIS REQUIRED."""
    return (_PROMPT_DIR / "soc_email_forensics.txt").read_text()


# ---------------------------------------------------------------------------
# Resources — reference data for interpreting tool outputs
# ---------------------------------------------------------------------------


@mcp.resource(
    "dns-mcp://output-guide",
    name="output-guide",
    description="Field-by-field reference for interpreting dns-mcp tool outputs",
    mime_type="text/markdown",
)
def output_guide() -> str:
    """Reference guide for interpreting dns-mcp tool output fields and status values."""
    return """\
# dns-mcp Output Interpretation Guide

## DNSSEC — ds_dnssec_validate

### DS vs DNSKEY: the parent/child relationship
- **DS** (Delegation Signer) lives in the **parent zone** — one level up in
  the DNS hierarchy. For a TLD-registered domain (example.com) this means
  your registrar submits it to the TLD. For a delegated subdomain you control
  (sub.example.com), you manage it yourself in the parent zone (example.com).
  Either way: DS always lives in the parent, not your zone.
- **DNSKEY** lives in **your own zone**. Two key types:
  - KSK (Key Signing Key, flags=257) — signs the DNSKEY RRset; its hash is
    what the parent DS must match.
  - ZSK (Zone Signing Key, flags=256) — signs your A, MX, TXT records etc.
- **Chain of trust:** resolver fetches DS from parent → computes hash of
  child KSK → must match → then trusts child DNSKEY set → validates records.
  A mismatch anywhere = bogus.

### overall_status values
- `fully validated` — chain walked cleanly AND resolver AD flag confirmed it.
- `bogus` — chain walk found a break (wrong key, expired RRSIG, hash mismatch).
  Always cross-check with `resolver_ad_flag` before acting — see discrepancy.
- `insecure` — no DNSSEC on this zone (no DS in parent); not an error.

### resolver_ad_flag
The AD (Authenticated Data) flag in the DNS response header. Set by a
validating resolver (e.g. Quad9) when it has independently verified the chain.
`true` = resolver accepts the chain as secure.

### discrepancy field
Present only when `overall_status` and `resolver_ad_flag` disagree.
- Tool says bogus, AD=true → likely a tool limitation; resolver wins.
  Run `dig +dnssec A <domain> @9.9.9.9` and look for `ad` in the flags line.
- Tool says validated, AD=false → resolver does not confirm; treat as unvalidated.

### chain_of_trust steps
Each step has a `status`: `secure`, `bogus`, `insecure`, `no_dnskey`,
`indeterminate`, or `error`. The first non-secure step is where the break is.

---

## reverse_dns

### fcrDNS (Forward-Confirmed Reverse DNS)
- `fcrDNS.pass: true` — PTR resolves to a hostname, and that hostname resolves
  back to the original IP. This is the gold standard for mail server identity.
- `fcrDNS.pass: false` — PTR exists but the forward lookup doesn't confirm the
  IP, or no PTR exists at all. Many spam filters reject mail from such hosts.
- `fcrDNS.forward_match: false` — hostname resolved, but IPs returned did not
  include the original IP (misconfigured forward DNS).
- `fcrDNS.hostname: null` — no PTR record exists (NXDOMAIN on reverse lookup).

---

## check_dane

- `dane_valid` — TLSA records found AND DNSSEC-validated by the resolver.
- `dane_present_no_dnssec` — TLSA records found but the resolver did not set
  AD=true. DANE without DNSSEC is untrustworthy (records can be spoofed).
- `dane_missing` — no TLSA records found for the MX host(s).

---

## check_rbl

Each RBL entry has three possible states:
- `listed: true` — IP matched a listing; `listing_types` describes the reason.
- `listed: false, error: null` — IP is clean (NXDOMAIN response = not listed).
- `listed: false, error: "<message>"` — query errored or hit a quota/block code.
  For Spamhaus this means the query limit was exceeded or the resolver is not
  allowlisted — set `SPAMHAUS_DQS_KEY` env var. This is NOT a listing.

`listed_count + clean_count + error_count` always equals 8 (one per RBL).

---

## detect_hijacking

### passed field semantics
`passed: true` = the check found **no hijacking** on that probe.
`passed: false` = the check found evidence of tampering (or could not complete).

### transparent_proxy check
`passed: false` here means a transparent DNS proxy intercepting port 53 was
**detected** — not that the check failed to run. The `note` field explains.
This is the strongest hijack signal: direct query to a root server returned
RA=1 (Recursion Available), which root servers never set legitimately.

### DNSSEC AD flag (check 3)
Informational only — does not contribute to the `hijacked` verdict. A resolver
that does not set AD is not hijacked, just not validating DNSSEC.

---

## dns_dig_style / dns_query_dot

### AD flag (header.dnssec.ad)
`true` means the queried resolver validated the DNSSEC chain for this response.
Absent or `false` means the resolver either doesn't validate DNSSEC or the
chain is broken. Use `dns_dnssec_validate` to investigate further.
"""


@mcp.resource(
    "dns-mcp://rbl-reference",
    name="rbl-reference",
    description="Return code reference for all 8 RBLs queried by check_rbl",
    mime_type="text/markdown",
)
def rbl_reference() -> str:
    """Return code meanings for all RBLs queried by check_rbl."""
    return """\
# RBL Return Code Reference

All RBLs use the pattern: `{reversed-ip}.{rbl-zone}` A query.
NXDOMAIN = not listed. Any A record = listed (see codes below).

## Spamhaus ZEN (zen.spamhaus.org / DQS)
Composite zone covering SBL, XBL, and PBL.

| Return code | Meaning |
|-------------|---------|
| 127.0.0.2 | SBL — direct spam source |
| 127.0.0.3 | SBL CSS — spam support services (hosting, bulletproof) |
| 127.0.0.4–7 | XBL — exploited/compromised host (CBL data) |
| 127.0.0.9 | DROP — do not route or peer (hijacked netblock) |
| 127.0.0.10 | PBL — ISP policy block (dynamic/end-user IP range) |
| 127.0.0.11 | PBL — Spamhaus maintained policy block |

**Quota/administrative codes (NOT listings — treated as errors):**

| Return code | Meaning |
|-------------|---------|
| 127.255.255.252 | Resolver not allowlisted by Spamhaus — use SPAMHAUS_DQS_KEY |
| 127.255.255.254 | Query limit exceeded — use SPAMHAUS_DQS_KEY for unrestricted access |
| 127.255.255.255 | Source IP blocked — use SPAMHAUS_DQS_KEY |

## SpamCop (bl.spamcop.net)
| 127.0.0.2 | Listed — reported spam source |

## UCEProtect L1 (dnsbl-1.uceprotect.net)
| 127.0.0.2 | Listed — direct spam source (single IP) |

## UCEProtect L2 (dnsbl-2.uceprotect.net)
| 127.0.0.2 | Listed — netblock contains spam sources (wider net than L1) |

## Mailspike (bl.mailspike.net)
Unique: also returns **positive reputation** codes for known-good senders.

| Return code | Meaning | listed |
|-------------|---------|--------|
| 127.0.0.2 | Spam source | true |
| 127.0.0.3 | Poor reputation | true |
| 127.0.0.4 | Very poor reputation | true |
| 127.0.0.5 | Worst reputation | true |
| 127.0.0.10 | Excellent sender reputation | false (positive) |
| 127.0.0.11–14 | Good/neutral sender reputation | false (positive) |

## PSBL (psbl.surriel.com)
| 127.0.0.2 | Listed — passive spam source |

## Barracuda (b.barracudacentral.org)
| 127.0.0.2 | Listed — spam source |

## SORBS (dnsbl.sorbs.net)
| Return code | Meaning |
|-------------|---------|
| 127.0.0.2 | HTTP proxy |
| 127.0.0.3 | SOCKS proxy |
| 127.0.0.4 | Misc open proxy |
| 127.0.0.5 | SMTP open relay |
| 127.0.0.6 | Spam source (direct) |
| 127.0.0.7 | Web form abuse |
| 127.0.0.8 | DUL — dynamic/end-user IP |
| 127.0.0.10 | Escalated — listed in multiple SORBS zones |

---
SORBS may timeout occasionally — handled gracefully; counted as error_count.
"""


@mcp.resource(
    "dns-mcp://test-zones",
    name="test-zones",
    description="Live DNSSEC/NSEC test zones maintained on deflationhollow.net",
    mime_type="text/markdown",
)
def test_zones() -> str:
    """Reference for the live NSEC/NSEC3 test zones used with nsec_info."""
    return """\
# dns-mcp Live Test Zones (deflationhollow.net)

These zones exist specifically for testing DNSSEC denial-of-existence tooling.
All are DNSSEC-signed with DS records in the parent zone.

| Zone | NSEC type | Parameters | Risk level |
|------|-----------|------------|------------|
| nsec-test.deflationhollow.net | NSEC | — | High — zone is walkable (all names enumerable) |
| nsec3-weak.deflationhollow.net | NSEC3 | iter=0, no salt | Moderate — RFC 9276 default, offline hash attack feasible |
| nsec3-salted.deflationhollow.net | NSEC3 | iter=0, 8-byte salt | Moderate — salt raises offline attack cost |
| nsec3-optout.deflationhollow.net | NSEC3 | opt-out flag set | Low — opt-out means unsigned delegations may not appear |

## Notes
- All four zones are on ns1/ns2/ns3.deflationhollow.net
- Use these as `nsec_info` targets when you need known-good assertions
- Avoid Cloudflare zones for NSEC testing — wildcard responses return NOERROR
  instead of NXDOMAIN, breaking denial-of-existence probes
- Modern BIND (9.18+) enforces iterations=0 — high-iteration zones are not
  creatable but still exist in the wild (~88% of NSEC3 zones per research)
"""


if __name__ == "__main__":
    _print_startup_banner("stdio")
    mcp.run(transport="stdio")
