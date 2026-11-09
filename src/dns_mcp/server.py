"""dns-mcp — DNS security MCP server for SOC investigations.

Streamable HTTP on standalone fastmcp 4, authenticated by Pocket ID via CIMD.
Tool implementations are thin wrappers around `dns_tool`; this module owns tool
and prompt registration. `dns_tool` owns all DNS logic.

Source layout (matches tiny-mcp):
  src/dns_mcp/
  ├── __main__.py     entrypoint — create_server(settings).run(transport="http")
  ├── config.py       pydantic-settings Settings (required URLs, ALLOWED_SUBS)
  ├── auth.py         fastmcp JWTVerifier + fail-closed sub allowlist
  └── server.py       (this file) tools + prompts + /health
"""

import asyncio
import ipaddress
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal

import dns.reversename
import dns_tool
from dns_tool.cert import (
    check_bimi as _check_bimi,
)
from dns_tool.cert import (
    check_caa as _check_caa,
)
from dns_tool.core import DOH_ENDPOINT, doh_query, parse_response
from dns_tool.email import (
    check_dane as _check_dane,
)
from dns_tool.email import (
    check_dkim as _check_dkim,
)
from dns_tool.email import (
    check_dmarc as _check_dmarc,
)
from dns_tool.email import (
    check_mta_sts as _check_mta_sts,
)
from dns_tool.email import (
    check_smtp_tlsrpt as _check_smtp_tlsrpt,
)
from dns_tool.email import (
    check_spf as _check_spf,
)
from dns_tool.email import (
    check_tlsa as _check_tlsa,
)
from dns_tool.email import (
    enumerate_dkim_selectors as _enumerate_dkim_selectors,
)
from dns_tool.intel import (
    check_ct_logs as _check_ct_logs,
)
from dns_tool.intel import (
    check_dbl as _check_dbl,
)
from dns_tool.intel import (
    check_fast_flux as _check_fast_flux,
)
from dns_tool.intel import (
    check_rbl as _check_rbl,
)
from dns_tool.intel import (
    check_zone_transfer as _check_zone_transfer,
)
from dns_tool.intel import (
    cymru_asn as _cymru_asn,
)
from dns_tool.intel import (
    detect_hijacking as _detect_hijacking,
)
from dns_tool.intel import (
    nsec_info as _nsec_info,
)
from dns_tool.rdap import rdap_lookup as _rdap_lookup
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_access_token
from mcp.types import ToolAnnotations
from pydantic import AfterValidator, Field
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import tracking
from .auth import build_auth
from .config import Settings, settings
from .tracking import get_stats, track

# ── Tool parameter types ─────────────────────────────────────────────────
# Defined once and reused across @app.tool() signatures below. Pydantic Field
# metadata (descriptions, regex patterns, length/range constraints) flows into
# the JSON Schema FastMCP advertises via tools/list. The LLM sees the
# constraints, FastMCP rejects malformed input at the boundary before our code
# runs, and humans reading the source see the same definitions in one place.

# DNS record types — Literal so the LLM gets the exact valid set, not "string".
# Matches the docstring enumeration on dns_query: 20 types covering A/AAAA,
# email auth (MX/TXT/TLSA), DNSSEC (DNSKEY/DS/RRSIG/NSEC/NSEC3), service
# discovery (SRV/NAPTR/HTTPS/SVCB), and policy (CAA).
DnsQType = Literal[
    "A",
    "AAAA",
    "MX",
    "TXT",
    "NS",
    "SOA",
    "CNAME",
    "PTR",
    "SRV",
    "CAA",
    "DNSKEY",
    "DS",
    "RRSIG",
    "NSEC",
    "NSEC3",
    "TLSA",
    "SSHFP",
    "HTTPS",
    "SVCB",
    "NAPTR",
]

# FQDN — RFC 1035 syntax. max_length=253 is the wire-format limit. The pattern
# accepts labels of 1-63 chars (alphanumeric + hyphen, hyphen not first/last)
# joined by dots. Underscores not permitted at this layer; tools that need
# them (DKIM selectors, _service._proto labels) construct the full name
# internally from validated components.
Domain = Annotated[
    str,
    Field(
        description=(
            "Fully-qualified domain name (e.g. 'example.com'). No scheme, no path — just the FQDN."
        ),
        pattern=(
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$"
        ),
        max_length=253,
    ),
]

# IPv4 dotted-quad. Pattern is a simple structural check (4 octets, 1-3 digits
# each); tighter range checks happen in dns_tool when needed. Strings, not
# IPv4Address objects, because dns_tool functions take strings.
IPv4 = Annotated[
    str,
    Field(
        description="IPv4 address in dotted-quad notation (e.g. '8.8.8.8').",
        pattern=r"^(\d{1,3}\.){3}\d{1,3}$",
        max_length=15,
    ),
]


def _require_public_ip(value: str) -> str:
    """Reject non-global addresses: from a cloud container, a private, loopback,
    link-local or reserved resolver can only be our own internal network."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"not an IP address: {value!r}") from None
    if not addr.is_global:
        raise ValueError(f"{value} is not a public address")
    return value


PublicIPv4 = Annotated[IPv4, AfterValidator(_require_public_ip)]

# IPv4 or IPv6 — used by tools (cymru_asn) that accept both. Loose pattern
# accepting either form; dns_tool does the real parsing.
IPAddress = Annotated[
    str,
    Field(
        description="IP address — IPv4 (e.g. '8.8.8.8') or IPv6 (e.g. '2001:db8::1').",
        pattern=r"^([0-9a-fA-F:.]+)$",
        min_length=2,
        max_length=45,
    ),
]

# EDNS Client Subnet hint (RFC 7871): an address, optionally /prefix. Loose
# structural pattern; dns_tool.core.parse_subnet does the real parsing and
# zeroes host bits. 49 = full IPv6 address + "/128".
Subnet = Annotated[
    str | None,
    Field(
        description=(
            "Optional EDNS Client Subnet hint (RFC 7871), like dig +subnet=: resolve "
            "as if the client were in this subnet, e.g. '8.8.8.0/24' or "
            "'2001:db8::/48'. Use it to see what a geo/CDN-steered name returns to a "
            "given network. Omit for a normal query."
        ),
        pattern=r"^[0-9a-fA-F:.]+(/[0-9]{1,3})?$",
        max_length=49,
    ),
]

# DKIM selector — the label that prefixes `_domainkey.<domain>`. RFC 6376
# permits the same character set as DNS labels (alphanumeric + hyphen +
# underscore in practice). max_length=63 is the DNS label limit.
DkimSelector = Annotated[
    str,
    Field(
        description=(
            "DKIM selector — the label prefixing '_domainkey.<domain>'. "
            "Examples: 's1', 'google', 'selector1', 'k1'. Just the label, "
            "not the full FQDN."
        ),
        pattern=r"^[a-zA-Z0-9_-]+$",
        max_length=63,
    ),
]

# Raw message header block (or a bare DKIM-Signature value). dns_tool caps
# the same 64 KiB; enforcing it here rejects oversize input at the boundary.
MailHeaders = Annotated[
    str,
    Field(
        description=(
            "Raw email headers from a real message (or just a DKIM-Signature "
            "value). The selector is taken from the DKIM-Signature whose d= "
            "equals the domain: evidence instead of guessing."
        ),
        max_length=65536,
    ),
]

# TCP/UDP port number. ge=1 / le=65535 enforces the valid range; 0 is reserved.
Port = Annotated[
    int,
    Field(
        description="TCP/UDP port number (1-65535).",
        ge=1,
        le=65535,
    ),
]

# Transport protocol for TLSA records. _<port>._<proto>.<host> form requires
# either 'tcp' or 'udp' per RFC 6698. Literal so the LLM never picks 'TCP'
# or 'sctp' or anything else.
Proto = Literal["tcp", "udp"]


def _reverse_name(ip: str) -> str:
    """Build the in-addr.arpa / ip6.arpa owner name for an IP address.

    Raises ValueError for anything `ipaddress` does not parse as an IPv4 or
    IPv6 address (the IPAddress pattern is deliberately loose). The result
    has no trailing dot, matching how names are passed to dns_query.
    """
    addr = ipaddress.ip_address(ip.strip())
    return dns.reversename.from_address(str(addr)).to_text(omit_final_dot=True)


async def _dns_query(
    name: str, qtype: str, dnssec: bool, subnet: str | None = None
) -> dict[str, Any]:
    msg = await asyncio.to_thread(
        doh_query, name, qtype.upper(), DOH_ENDPOINT, dnssec, subnet=subnet
    )
    return parse_response(msg, name, qtype.upper(), subnet=subnet)


_START_TIME = time.time()

# Claude.ai rejects tool results over ~150,000 chars (connector docs). Measured
# 2026-11-09: check_ct_logs("google.com") returned 285k chars, 270k of it the
# `certificates` list (304 certs with full SAN lists). Keep headroom for the
# rest of the result.
_CT_CERT_BUDGET = 100_000


def _fit_ct_result(result: dict[str, Any], domain: str) -> dict[str, Any]:
    """Cap `certificates` to the budget, newest-first order preserved as given,
    and say so: counts plus a link to the full search on crt.sh. Everything else
    (summary, subdomains, findings, verdict) is left untouched — the summary and
    subdomain list are computed from ALL certificates before this cut."""
    certs = result.get("certificates")
    if not isinstance(certs, list):
        return result
    kept: list = []
    used = 0
    for cert in certs:
        size = len(json.dumps(cert, default=str))
        if kept and used + size > _CT_CERT_BUDGET:
            break
        kept.append(cert)
        used += size
    if len(kept) == len(certs):
        return result
    return {
        **result,
        "certificates": kept,
        "certificates_total": len(certs),
        "certificates_returned": len(kept),
        "certificates_truncated": True,
        "full_results_url": f"https://crt.sh/?q={domain}",
    }


INSTRUCTIONS = (
    "DNS and email-security investigation tools for SOC work, backed by the dns_tool "
    "library over DNSSEC-validating DoH. Use dns_query / reverse_dns / dnssec_validate "
    "for lookups; check_spf, check_dmarc, check_dkim, check_mta_sts, check_dane, "
    "check_smtp_tlsrpt and check_bimi for email authentication posture; check_rbl, "
    "check_dbl, check_fast_flux, check_ct_logs, rdap_lookup and cymru_asn for threat "
    "intel; check_zone_transfer for AXFR exposure. Results carry a verdict and "
    "findings with ids — quote the finding ids. Every tool is read-only."
)


def _tool(title: str, *, open_world: bool = True) -> dict:
    """Title + annotations. Claude's connector docs require readOnlyHint and
    destructiveHint on every tool. Most tools reach external DNS/HTTP services
    (openWorldHint); every tool is read-only."""
    return {
        "title": title,
        "annotations": ToolAnnotations(
            title=title,
            read_only_hint=True,
            destructive_hint=False,
            open_world_hint=open_world,
        ),
    }


# Prompt templates live at the repo root, copied to /app/prompts/ in the
# container. From src/dns_mcp/server.py: ../../prompts/.
_PROMPTS_DIR = Path(__file__).resolve().parent.parent.parent / "prompts"


def create_server(cfg: Settings | None = None) -> FastMCP:
    app = FastMCP(name="dns-mcp", instructions=INSTRUCTIONS, auth=build_auth(cfg or settings))

    @app.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> Response:
        return JSONResponse(
            {
                "status": "ok",
                "uptime_seconds": round(time.time() - _START_TIME, 2),
                "dns_tool_version": dns_tool.__version__,
                "dns_tool_commit": dns_tool.__commit__,
            }
        )

    # ── Meta tools ────────────────────────────────────────────────────────

    @app.tool(**_tool("Ping / version", open_world=False))
    @track("ping")
    async def ping() -> dict[str, Any]:
        """Return current timestamp, server uptime, and dns_tool version."""
        return {
            "timestamp": time.time(),
            "uptime_seconds": round(time.time() - _START_TIME, 2),
            "dns_tool_version": dns_tool.__version__,
            "dns_tool_commit": dns_tool.__commit__,
        }

    @app.tool(**_tool("Who am I", open_world=False))
    @track("whoami")
    async def whoami() -> dict[str, Any]:
        """Return the authenticated user's identity from JWT claims."""
        token = get_access_token()
        if token is None:
            return {"error": "no identity available"}
        c = token.claims
        return {
            "sub": c.get("sub"),
            "email": c.get("email"),
            "name": c.get("name"),
            "preferred_username": c.get("preferred_username"),
        }

    # ── DNS basic ─────────────────────────────────────────────────────────

    @app.tool(**_tool("DNS query"))
    @track("dns_query")
    async def dns_query(
        name: Domain,
        qtype: DnsQType = "A",
        dnssec: Annotated[
            bool,
            Field(
                description=(
                    "Set the DO bit (DNSSEC OK) on the query. When true, the resolver "
                    "returns RRSIG records alongside the answer for cryptographic "
                    "verification. Default true."
                ),
            ),
        ] = True,
        subnet: Subnet = None,
    ) -> dict[str, Any]:
        """Query the configured DoH resolver for an arbitrary DNS record type.

        Supports any RR type — A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, SRV, CAA,
        DNSKEY, DS, RRSIG, NSEC, NSEC3, TLSA, SSHFP, HTTPS, SVCB, NAPTR.
        When dnssec=True (default), sets the DO bit so RRSIG records are
        returned alongside the answer. Returns answer/authority sections,
        AD/CD flags, rcode, and timing.

        With subnet (an EDNS Client Subnet hint), the result adds an `ecs`
        block. Read it before claiming an answer is what that subnet sees:
        only `tailored: true` means that (valid for /`scope`). `scope: 0`
        means the authority gave its default answer (it ignores ECS or
        answers everyone alike); `returned: null` means the resolver dropped
        the hint. Neither of those is evidence about the subnet.
        """
        return await _dns_query(name, qtype, dnssec, subnet)

    @app.tool(**_tool("Reverse DNS"))
    @track("reverse_dns")
    async def reverse_dns(
        ip: IPAddress,
        dnssec: Annotated[
            bool,
            Field(description="Set the DO bit (DNSSEC OK), as for dns_query. Default true."),
        ] = True,
    ) -> dict[str, Any]:
        """Reverse DNS (PTR) lookup for an IPv4 or IPv6 address.

        Builds the reverse name (`4.3.2.1.in-addr.arpa` for IPv4, the
        nibble-reversed `...ip6.arpa` name for IPv6) and runs a PTR query
        through the same path as dns_query, returning the same shape
        (`query.name` shows the reverse name that was asked).

        Use this instead of dns_query with a bare IP: dns_query would look up
        the literal name (e.g. "8.8.8.8.") and get NXDOMAIN from the root,
        which looks like "no PTR" but is not. An NXDOMAIN or empty answer
        here does mean the address has no PTR record.
        """
        return await _dns_query(_reverse_name(ip), "PTR", dnssec)

    # ── DNSSEC ────────────────────────────────────────────────────────────

    @app.tool(**_tool("DNSSEC validation"))
    @track("dnssec_validate")
    async def dnssec_validate(domain: Domain, qtype: DnsQType = "A") -> dict[str, Any]:
        """Walk the full DNSSEC trust chain from the IANA root trust anchor down
        to <domain>, performing real cryptographic validation at every zone cut.

        At each delegation: validates DS RRSIG against parent ZSK, verifies
        DS<->DNSKEY linkage by recomputing the digest, validates DNSKEY RRSIG
        against the zone's own KSK, tracks RRSIG inception/expiration windows.

        Returns a structured result with `verdict` (validated /
        validated_with_warnings / failed), per-zone findings (`zones[]`),
        full event transcript (`events[]`), and the final answer RRset
        (`target_step`).

        Use for diagnosing DNSSEC failures (broken DS<->DNSKEY linkage, expired
        RRSIGs, NXDOMAIN with NSEC denial). Read `verdict` for automation;
        consult `events[]` / `zones[]` for forensic detail.
        """
        return await asyncio.to_thread(dns_tool.validate, domain, qtype.upper())

    # ── Email security ────────────────────────────────────────────────────

    @app.tool(**_tool("SPF check"))
    @track("check_spf")
    async def check_spf(domain: Domain) -> dict[str, Any]:
        """Retrieve and recursively parse a domain's SPF policy.

        Enumerates all authorized sending IPs/networks by following include
        chains. Enforces the RFC 7208 10-lookup limit. Returns the raw SPF
        record, parsed mechanisms, authorized networks, the 'all' qualifier,
        and lookup count.
        """
        return await asyncio.to_thread(_check_spf, domain, DOH_ENDPOINT)

    @app.tool(**_tool("DMARC check"))
    @track("check_dmarc")
    async def check_dmarc(domain: Domain) -> dict[str, Any]:
        """Retrieve and parse a domain's DMARC policy.

        Falls back to the organizational domain if no policy is found at the
        queried name. Returns policy verdict (none/quarantine/reject), pct,
        subdomain policy, rua/ruf reporting addresses, and DNSSEC AD flag.
        """
        return await asyncio.to_thread(_check_dmarc, domain, DOH_ENDPOINT)

    @app.tool(**_tool("DKIM check"))
    @track("check_dkim")
    async def check_dkim(
        domain: Domain,
        selector: DkimSelector | None = None,
        headers: MailHeaders | None = None,
    ) -> dict[str, Any]:
        """Retrieve and strictly validate a DKIM public key for <domain>.

        Give either `selector`, or `headers` from a real message. With
        headers, the selector comes from the DKIM-Signature whose d= matches
        the domain (`selector_source: "header"`). Prefer headers whenever
        you have them: many providers (e.g. ForwardEmail `fe-<hex>`) use
        selectors that cannot be guessed.

        Returns key type (RSA / Ed25519), exact key bits, flags, the joined
        record, and `record_strings`. Fails closed: an undecodable key is
        DKIM_KEY_UNPARSEABLE, bad tag syntax is DKIM_RECORD_MALFORMED, and an
        empty p= is DKIM_KEY_REVOKED.
        """
        return await asyncio.to_thread(_check_dkim, domain, selector, DOH_ENDPOINT, headers=headers)

    @app.tool(**_tool("DKIM selector probe"))
    @track("enumerate_dkim_selectors")
    async def enumerate_dkim_selectors(
        domain: Domain, headers: MailHeaders | None = None
    ) -> dict[str, Any]:
        """Find a domain's DKIM keys: header evidence first, guessing last.

        Selectors from `headers` (DKIM-Signature with d=<domain>) are checked
        first, then well-known names (`dns_tool.email.COMMON_SELECTORS`).

        A miss is NOT evidence of "no DKIM". DNS cannot list selectors, so
        when nothing is found the verdict is `undetermined`
        (DKIM_SELECTOR_NOT_FOUND_IN_PROBE_LIST, info). Never report "this
        domain has no DKIM" from this tool alone. Ask for a message header
        instead. A header selector with no published key IS proof of
        breakage (DKIM_SIGNING_SELECTOR_UNPUBLISHED, high).
        """
        return await asyncio.to_thread(
            _enumerate_dkim_selectors, domain, DOH_ENDPOINT, headers=headers
        )

    @app.tool(**_tool("SMTP TLS-RPT check"))
    @track("check_smtp_tlsrpt")
    async def check_smtp_tlsrpt(domain: Domain) -> dict[str, Any]:
        """SMTP TLS Reporting (RFC 8460) check for <domain>.

        Queries `_smtp._tls.<domain>` TXT for the TLSRPT record and validates
        `v=TLSRPTv1` plus `rua=` reporting destinations (each URI must be
        `mailto:` or `https:`). A record without a `rua=` is useless — there
        is no destination for aggregate TLS failure reports — and verdicts
        as `fail`.

        Pairs with `check_mta_sts`: TLSRPT alone reports the failures
        MTA-STS would have prevented. Returns a contract-conforming envelope
        with `verdict`/`findings` (RESPONSE_CONTRACT.md).
        """
        return await asyncio.to_thread(_check_smtp_tlsrpt, domain, DOH_ENDPOINT)

    @app.tool(**_tool("MTA-STS check"))
    @track("check_mta_sts")
    async def check_mta_sts(domain: Domain, fetch_policy: bool = True) -> dict[str, Any]:
        """MTA-STS (RFC 8461) DNS + policy file check for <domain>.

        Two-part check: (1) DNS TXT at `_mta-sts.<domain>` for the
        `v=STSv1; id=...` announcement; (2) HTTPS fetch of the policy file
        at `https://mta-sts.<domain>/.well-known/mta-sts.txt` (parses
        `version`, `mode`, `mx`, `max_age`). The two steps are reported
        separately under `dns_query` and `policy_fetch` so a missing DNS
        record is distinguishable from a fetchable announcement whose
        policy file is broken.

        Set `fetch_policy=False` to skip the HTTPS step (DNS-only). SSL
        verification on the policy fetch is always on — an invalid cert on
        the policy host is itself a misconfiguration signal.
        """
        return await asyncio.to_thread(_check_mta_sts, domain, DOH_ENDPOINT, fetch_policy)

    @app.tool(**_tool("DANE (mail) check"))
    @track("check_dane")
    async def check_dane(domain: Domain) -> dict[str, Any]:
        """Check DANE/SMTP publication for all MX hosts of <domain>.

        Performs MX lookup, then queries TLSA records at port 25 for each MX
        host. Reports certificate usage, selector, matching type, and digest.

        DANE protects the domain only if BOTH the TLSA records AND the
        domain's own MX RRset are DNSSEC-validated (RFC 7672 §2.2.1). An
        unsigned MX RRset yields DANE_MX_NOT_DNSSEC_VALIDATED. PKIX usages
        (0/1) are unusable for SMTP.

        This tool does NOT connect to the mail server, so it does not verify
        that the TLSA records match the certificate the server actually
        presents. `dane_valid` means "published and DNSSEC-signed", not
        "delivery will succeed". A stale TLSA after a cert rotation passes
        here but bounces mail from DANE-validating senders.
        """
        return await asyncio.to_thread(_check_dane, domain, DOH_ENDPOINT)

    @app.tool(**_tool("TLSA check"))
    @track("check_tlsa")
    async def check_tlsa(
        host: Domain,
        port: Port = 25,
        proto: Proto = "tcp",
    ) -> dict[str, Any]:
        """Retrieve a TLSA record at the standard `_<port>._<proto>.<host>`
        location. Defaults to TCP port 25 (SMTP/STARTTLS).

        Returns certificate usage (PKIX-TA / PKIX-EE / DANE-TA / DANE-EE),
        selector (cert / spki), matching type (full / SHA-256 / SHA-512),
        and digest hex.

        DNS only: this tool does NOT connect to <host>, so it does not check
        that the records match the certificate the server presents.
        """
        return await asyncio.to_thread(_check_tlsa, host, port, proto, DOH_ENDPOINT)

    @app.tool(**_tool("CAA check"))
    @track("check_caa")
    async def check_caa(domain: Domain) -> dict[str, Any]:
        """CAA record analysis with CNAME chain + wildcard delegation detection.

        Beyond a plain CAA lookup, this tool surfaces policy gaps a CA would
        actually act on at issuance time:

        - Tree-climbing (RFC 8659 §3): finds the effective policy when no CAA
          exists at the queried name.
        - CNAME chain tracing: follows aliases and flags hops that cross a
          registrable-domain boundary (third-party CAA control).
        - Wildcard CNAME detection: a `*.<domain>` CNAME silently delegates
          CAA authority for unmatched subdomains. Confirmed via a random
          subdomain probe. Common with ngrok/Cloudflare-Pages style platforms.
        - Policy summary: issue/issuewild, hard blocks (issue ";"), iodef,
          RFC 8657 accounturi/validationmethods.
        - Risk flags at HIGH/MEDIUM/LOW/INFO with an overall_risk rollup.
        """
        return await asyncio.to_thread(_check_caa, domain, DOH_ENDPOINT)

    @app.tool(**_tool("BIMI check"))
    @track("check_bimi")
    async def check_bimi(
        domain: Domain,
        selector: str = "default",
        fetch_vmc: bool = True,
        check_dmarc_dependency: bool = True,
    ) -> dict[str, Any]:
        """BIMI (RFC 9091) record check with DMARC and VMC validation.

        Queries `<selector>._bimi.<domain>` TXT for the BIMI record and
        parses the `l=` logo URL and `a=` Verified Mark Certificate URL.
        Default selector is `"default"` per RFC 9091 §3.

        Two cross-cuts beyond a pure record fetch:
        - **DMARC precondition**: BIMI without DMARC at `p=quarantine` or
          `p=reject` is decorative — Gmail / Apple Mail gate logo display
          on DMARC enforcement. Disable with `check_dmarc_dependency=False`.
        - **VMC reachability**: confirms the VMC URL responds 200 with a
          plausible cert content type. Does not validate the PKIX chain.
          Disable with `fetch_vmc=False`.

        Lives in `dns_tool.cert` (alongside CAA) rather than `dns_tool.email`
        because BIMI authorizes a logo via a certificate; the policy target
        is the CA/PKI tree.
        """
        return await asyncio.to_thread(
            _check_bimi, domain, DOH_ENDPOINT, selector, fetch_vmc, check_dmarc_dependency
        )

    # ── Threat intelligence ───────────────────────────────────────────────

    @app.tool(**_tool("IP blocklist (RBL) check"))
    @track("check_rbl")
    async def check_rbl(ip: IPv4) -> dict[str, Any]:
        """Check an IPv4 address against 8 well-known RBLs (Spamhaus ZEN,
        Barracuda BRBL, SORBS, etc.).

        Returns per-RBL listing status, return-code interpretation (e.g.
        Spamhaus return-code-to-listing-class mapping), and any TXT
        evidence records.
        """
        return await asyncio.to_thread(_check_rbl, ip, DOH_ENDPOINT)

    @app.tool(**_tool("Domain blocklist (DBL) check"))
    @track("check_dbl")
    async def check_dbl(domain: Domain) -> dict[str, Any]:
        """Check a domain against domain block lists (Spamhaus DBL, SURBL,
        URIBL).

        Returns per-DBL listing status. Useful for triaging unknown domains
        in phishing emails or suspicious URLs.
        """
        return await asyncio.to_thread(_check_dbl, domain, DOH_ENDPOINT)

    @app.tool(**_tool("IP to ASN (Team Cymru)"))
    @track("cymru_asn")
    async def cymru_asn(ip: IPAddress) -> dict[str, Any]:
        """Look up the autonomous system (ASN) and originating prefix for an
        IP address via Team Cymru's DNS-based service.

        Returns ASN, AS name, prefix, country code, registry, and allocation
        date. No API key required.
        """
        return await asyncio.to_thread(_cymru_asn, ip, DOH_ENDPOINT)

    @app.tool(**_tool("Fast-flux check"))
    @track("check_fast_flux")
    async def check_fast_flux(domain: Domain) -> dict[str, Any]:
        """Detect fast-flux behavior by repeatedly querying <domain> A records
        and observing IP rotation across queries.

        Returns the unique IP set, ASN diversity (more ASNs = more
        suspicious), TTL behavior, and a heuristic verdict. Used in malware
        C2 and phishing infrastructure investigations.
        """
        return await asyncio.to_thread(_check_fast_flux, domain, DOH_ENDPOINT)

    @app.tool(**_tool("NSEC/NSEC3 info"))
    @track("nsec_info")
    async def nsec_info(zone: Domain) -> dict[str, Any]:
        """Probe a zone's NSEC / NSEC3 denial-of-existence mechanism.

        Returns whether NSEC or NSEC3 is in use, NSEC3 hash parameters
        (algorithm, iterations, salt), and zone enumeration risk. NSEC
        leaks the next name in zone order (enumeration trivial); NSEC3
        with high iterations resists enumeration.
        """
        return await asyncio.to_thread(_nsec_info, zone, DOH_ENDPOINT)

    @app.tool(**_tool("Resolver hijack check"))
    @track("detect_hijacking")
    async def detect_hijacking(resolver_ip: PublicIPv4) -> dict[str, Any]:
        """Test a recursive resolver for tampering / NXDOMAIN hijacking by
        querying known-good and known-bad names against it.

        Returns whether the resolver wildcards NXDOMAIN responses (a common
        ISP misbehavior), serves stale or modified answers, or respects
        DNSSEC.
        """
        return await asyncio.to_thread(_detect_hijacking, resolver_ip, DOH_ENDPOINT)

    @app.tool(**_tool("Certificate Transparency search"))
    @track("check_ct_logs")
    async def check_ct_logs(
        domain: Domain,
        include_expired: bool = False,
    ) -> dict[str, Any]:
        """Enumerate Certificate Transparency log entries for a domain.

        Queries Cert Spotter (primary) and crt.sh (secondary) in parallel for
        certificates logged under <domain> or its subdomains, merges them, and
        summarizes: unique subdomains, per-cert issuer/validity/wildcard flags,
        active vs expired counts. Primary forensic use: **subdomain
        enumeration** from SAN lists.

        Reading the result (dns_tool 0.15.0):
        - `sources[]` records each source's outcome (ok/empty/timeout/
          rate_limited/http_error...). crt.sh is unreliable; **no negative
          ever rests on it alone**.
        - NO_CT_RECORDS (info) means Cert Spotter answered with zero *current*
          certs — "none found in CT logs", never "no certificate was ever
          issued" (pre-2018 certs may not be logged at all).
        - Cert Spotter's free API returns no expired certs; expired history
          comes only from crt.sh, so an empty expired history is
          `undetermined` (CT_EXPIRED_HISTORY_UNDETERMINED), not a negative.
        - CT_NEGATIVE_UNVERIFIED → `undetermined`: Cert Spotter was
          unavailable, so absence could not be confirmed.

        Set include_expired=True to emit expired certs in the certificates
        list (they're always counted in the summary regardless).

        Large domains: the certificates list is capped to fit the result size
        limit — `certificates_truncated`, `certificates_total` and
        `certificates_returned` say so, `full_results_url` opens the complete
        crt.sh search. `summary` and `subdomains` always cover every cert.
        """
        result = await asyncio.to_thread(_check_ct_logs, domain, include_expired)
        return _fit_ct_result(result, domain)

    @app.tool(**_tool("Zone transfer (AXFR) exposure"))
    @track("check_zone_transfer")
    async def check_zone_transfer(domain: Domain) -> dict[str, Any]:
        """Attempt AXFR zone transfer against every authoritative NS for <domain>.

        Open zone transfers are a NIST SP 800-81r3 §3.1 violation: any
        host can enumerate the full zone, exposing hostnames, mail
        servers, internal structure, and DNSSEC key material to
        reconnaissance. Transfers should be restricted to authorised
        secondaries.

        Per-NS state is recorded as `open` / `refused` / `error`. When at
        least one NS allows the transfer, the first successful transfer's
        zone summary (SOA serial, name list capped at 200, record type
        summary, total record count) is preserved in `zone_data` — showing
        exactly what an attacker would obtain.

        Note: AXFR runs over raw TCP/UDP (no DoH transport exists for zone
        transfer), so this tool is one of two architectural exceptions to
        dns_tool's DoH-only stance. NS resolution still uses DoH.
        """
        return await asyncio.to_thread(_check_zone_transfer, domain, DOH_ENDPOINT)

    # ── Registration / RDAP ───────────────────────────────────────────────

    @app.tool(**_tool("RDAP registration lookup"))
    @track("rdap_lookup")
    async def rdap_lookup(domain: Domain) -> dict[str, Any]:
        """Query RDAP for domain registration data.

        Returns registration date, expiration date, registrar, status,
        nameservers, and contact information when published. Useful for
        triaging recently-registered domains in phishing investigations
        (look for domains registered within the last 30 days).
        """
        return await asyncio.to_thread(_rdap_lookup, domain)

    # ── Observability ─────────────────────────────────────────────────────

    @app.tool(**_tool("Session stats", open_world=False))
    @track("session_stats")
    async def session_stats() -> dict[str, Any]:
        """Return per-tool call statistics for the current server session.

        Session = process lifetime; counters reset on container restart.
        Returns uptime, total call count, and a per-tool breakdown of
        count / error_count / mean_ms / max_ms / first_called / last_called.

        Use as the final call in a multi-tool investigation to record
        which tools were consulted and how expensive the run was.
        """
        now = datetime.now(UTC)
        uptime = (now - tracking._session_start).total_seconds()
        per_tool = get_stats()
        total = sum(s["count"] for s in per_tool.values())
        return {
            "session_start": tracking._session_start.isoformat(),
            "current_time": now.isoformat(),
            "uptime_seconds": round(uptime, 1),
            "total_calls": total,
            "tools": per_tool,
        }

    # ── Prompts ───────────────────────────────────────────────────────────
    # Read prompt templates from prompts/ at the repo root; register each
    # filename stem as an MCP prompt resource. e.g. dnssec_chain_audit.txt
    # becomes a prompt named 'dnssec_chain_audit' that returns the file body.
    #
    # NOTE: this dynamic-registration pattern relies on FastMCP accepting
    # `app.prompt(name=...)(handler)`. If the SDK API differs, convert to
    # explicit @app.prompt() decorators per file (4 prompts total).

    if _PROMPTS_DIR.exists():
        for path in sorted(_PROMPTS_DIR.glob("*.txt")):
            prompt_name = path.stem
            text = path.read_text()

            def _make_handler(content: str):
                async def _handler() -> str:
                    return content

                return _handler

            handler = _make_handler(text)
            handler.__doc__ = f"Prompt template: {prompt_name}"
            app.prompt(name=prompt_name)(handler)

    return app
