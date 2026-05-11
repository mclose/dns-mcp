"""dns-mcp — DNS security MCP server for SOC investigations.

Streamable HTTP / OAuth-protected via Pocket ID. Tool implementations are thin
wrappers around `dns_tool`; this module owns auth bootstrap and tool/prompt
registration. `dns_tool` owns all DNS logic.

OAuth bootstrap routes (`/.well-known/oauth-authorization-server`,
`/oauth/authorize`, `/oauth/register`) are lifted verbatim from tiny-mcp —
they are generic Pocket-ID DCR shim plumbing, not dns-mcp-specific.

Source layout matches tiny-mcp:
  src/dns_mcp/
  ├── __main__.py     entrypoint — create_server().run(transport="streamable-http")
  ├── config.py       pydantic-settings Settings class
  ├── auth.py         JWKSTokenVerifier + JWTAccessToken
  └── server.py       (this file) FastMCP app — OAuth routes + tools + prompts
"""

import asyncio
import json
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlencode

import dns_tool
import httpx
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
    check_spf as _check_spf,
)
from dns_tool.email import (
    check_tlsa as _check_tlsa,
)
from dns_tool.email import (
    enumerate_dkim_selectors as _enumerate_dkim_selectors,
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
    cymru_asn as _cymru_asn,
)
from dns_tool.intel import (
    detect_hijacking as _detect_hijacking,
)
from dns_tool.intel import (
    nsec_info as _nsec_info,
)
from dns_tool.rdap import rdap_lookup as _rdap_lookup
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl, Field
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from . import tracking
from .auth import JWKSTokenVerifier, JWTAccessToken
from .config import settings
from .tracking import get_stats, track
from .tracking import reset_stats as _reset_stats_impl

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


_START_TIME = time.time()
# Prompt templates live at the repo root, copied to /app/prompts/ in the
# container. From src/dns_mcp/server.py: ../../prompts/.
_PROMPTS_DIR = Path(__file__).resolve().parent.parent.parent / "prompts"


def create_server() -> FastMCP:
    server_url = str(settings.server_url).rstrip("/")
    pocket_id_url = str(settings.pocket_id_base_url).rstrip("/")

    app = FastMCP(
        name="dns-mcp",
        host="0.0.0.0",
        port=8000,
        token_verifier=JWKSTokenVerifier(),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(server_url),
            required_scopes=[],
            resource_server_url=AnyHttpUrl(server_url),
        ),
    )

    # ── OAuth bootstrap routes (no auth required) ─────────────────────────
    # Generic Pocket-ID DCR shim — lifted verbatim from tiny-mcp/server.py.
    # If a third server inherits this pattern, factor these four routes into
    # a shared `mcp_pocket_id_shim` package.

    @app.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
    async def oauth_metadata(request: Request) -> Response:
        return JSONResponse(
            {
                "issuer": pocket_id_url,
                "authorization_endpoint": f"{server_url}/oauth/authorize",
                "token_endpoint": f"{pocket_id_url}/api/oidc/token",
                "jwks_uri": f"{pocket_id_url}/.well-known/jwks.json",
                "registration_endpoint": f"{server_url}/oauth/register",
                "scopes_supported": ["openid", "profile", "email"],
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256", "plain"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post",
                    "none",
                ],
            }
        )

    @app.custom_route("/oauth/authorize", methods=["GET"])
    async def proxy_authorize(request: Request) -> Response:
        # Claude.ai omits scope from the authorization URL — inject it here
        # before forwarding to Pocket ID, which rejects requests with no scope.
        params = dict(request.query_params)
        if not params.get("scope"):
            params["scope"] = "openid profile email"
        return RedirectResponse(
            url=f"{pocket_id_url}/authorize?{urlencode(params)}",
            status_code=302,
        )

    @app.custom_route("/oauth/register", methods=["POST"])
    async def register_client(request: Request) -> Response:
        try:
            body: dict[str, Any] = await request.json()
        except Exception:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid JSON body"},
                status_code=400,
            )

        redirect_uris: list[str] = body.get("redirect_uris", [])
        if not isinstance(redirect_uris, list):
            return JSONResponse(
                {"error": "invalid_request", "error_description": "redirect_uris must be an array"},
                status_code=400,
            )

        raw_name: str = body.get("client_name") or f"dcr-{uuid.uuid4().hex[:8]}"
        client_name = raw_name[:50]  # Pocket ID enforces max=50

        # Public PKCE client — Claude.ai performs the token exchange with
        # only client_id + code + code_verifier (no client_secret).
        payload = {
            "name": client_name,
            "callbackURLs": redirect_uris,
            "logoutCallbackURLs": [],
            "isPublic": True,
            "pkceEnabled": True,
        }
        headers = {
            "X-API-Key": settings.pocket_id_api_key,
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=15) as client:
            create_resp = await client.post(
                f"{pocket_id_url}/api/oidc/clients",
                content=json.dumps(payload),
                headers=headers,
            )
            if create_resp.status_code not in (200, 201):
                return JSONResponse(
                    {"error": "server_error", "error_description": "Client creation failed"},
                    status_code=500,
                )
            created = create_resp.json()
            client_id: str = created["id"]

        registered_scope = body.get("scope", "openid profile email")
        return JSONResponse(
            {
                "client_id": client_id,
                "client_id_issued_at": int(time.time()),
                "redirect_uris": redirect_uris,
                "client_name": client_name,
                "grant_types": body.get("grant_types", ["authorization_code"]),
                "response_types": body.get("response_types", ["code"]),
                "token_endpoint_auth_method": "none",
                "scope": registered_scope,
            },
            status_code=201,
        )

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

    @app.tool()
    @track("ping")
    async def ping() -> dict[str, Any]:
        """Return current timestamp, server uptime, and dns_tool version."""
        return {
            "timestamp": time.time(),
            "uptime_seconds": round(time.time() - _START_TIME, 2),
            "dns_tool_version": dns_tool.__version__,
            "dns_tool_commit": dns_tool.__commit__,
        }

    @app.tool()
    @track("whoami")
    async def whoami() -> dict[str, Any]:
        """Return the authenticated user's identity from JWT claims."""
        token = get_access_token()
        if not isinstance(token, JWTAccessToken):
            return {"error": "no identity available"}
        c = token.claims
        return {
            "sub": c.get("sub"),
            "email": c.get("email"),
            "name": c.get("name"),
            "preferred_username": c.get("preferred_username"),
        }

    # ── DNS basic ─────────────────────────────────────────────────────────

    @app.tool()
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
    ) -> dict[str, Any]:
        """Query the configured DoH resolver for an arbitrary DNS record type.

        Supports any RR type — A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, SRV, CAA,
        DNSKEY, DS, RRSIG, NSEC, NSEC3, TLSA, SSHFP, HTTPS, SVCB, NAPTR.
        When dnssec=True (default), sets the DO bit so RRSIG records are
        returned alongside the answer. Returns answer/authority sections,
        AD/CD flags, rcode, and timing.
        """
        msg = await asyncio.to_thread(doh_query, name, qtype.upper(), DOH_ENDPOINT, dnssec)
        return parse_response(msg, name, qtype.upper())

    # ── DNSSEC ────────────────────────────────────────────────────────────

    @app.tool()
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

    @app.tool()
    @track("check_spf")
    async def check_spf(domain: Domain) -> dict[str, Any]:
        """Retrieve and recursively parse a domain's SPF policy.

        Enumerates all authorized sending IPs/networks by following include
        chains. Enforces the RFC 7208 10-lookup limit. Returns the raw SPF
        record, parsed mechanisms, authorized networks, the 'all' qualifier,
        and lookup count.
        """
        return await asyncio.to_thread(_check_spf, domain, DOH_ENDPOINT)

    @app.tool()
    @track("check_dmarc")
    async def check_dmarc(domain: Domain) -> dict[str, Any]:
        """Retrieve and parse a domain's DMARC policy.

        Falls back to the organizational domain if no policy is found at the
        queried name. Returns policy verdict (none/quarantine/reject), pct,
        subdomain policy, rua/ruf reporting addresses, and DNSSEC AD flag.
        """
        return await asyncio.to_thread(_check_dmarc, domain, DOH_ENDPOINT)

    @app.tool()
    @track("check_dkim")
    async def check_dkim(domain: Domain, selector: DkimSelector) -> dict[str, Any]:
        """Retrieve a DKIM public key for <domain> at <selector>.

        Returns key type (RSA / Ed25519), key length in bits for RSA keys
        (2048+ recommended; 1024 flagged as weak), flags, and the raw record.
        """
        return await asyncio.to_thread(_check_dkim, domain, selector, DOH_ENDPOINT)

    @app.tool()
    @track("enumerate_dkim_selectors")
    async def enumerate_dkim_selectors(domain: Domain) -> dict[str, Any]:
        """Probe a domain for DKIM keys at a list of common selector names.

        Tries well-known selectors (e.g. 's1', 'google', 'selector1',
        'k1', 'default', 'mail') against `<sel>._domainkey.<domain>` and
        returns the ones that resolve to a valid public key, plus the
        total number of selectors probed.

        Use when you don't know which selector a domain uses, or to
        profile a sender's DKIM key inventory for forensics. The list of
        selectors probed lives in `dns_tool.email.COMMON_SELECTORS`.
        """
        return await asyncio.to_thread(_enumerate_dkim_selectors, domain, DOH_ENDPOINT)

    @app.tool()
    @track("check_dane")
    async def check_dane(domain: Domain) -> dict[str, Any]:
        """Check DANE/SMTP for all MX hosts of <domain>.

        Performs MX lookup, then queries TLSA records at port 25 for each MX
        host. Reports certificate usage, selector, matching type, and digest.
        DNSSEC AD flag is required for DANE to be trusted.
        """
        return await asyncio.to_thread(_check_dane, domain, DOH_ENDPOINT)

    @app.tool()
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
        """
        return await asyncio.to_thread(_check_tlsa, host, port, proto, DOH_ENDPOINT)

    # ── Threat intelligence ───────────────────────────────────────────────

    @app.tool()
    @track("check_rbl")
    async def check_rbl(ip: IPv4) -> dict[str, Any]:
        """Check an IPv4 address against 8 well-known RBLs (Spamhaus ZEN,
        Barracuda BRBL, SORBS, etc.).

        Returns per-RBL listing status, return-code interpretation (e.g.
        Spamhaus return-code-to-listing-class mapping), and any TXT
        evidence records.
        """
        return await asyncio.to_thread(_check_rbl, ip, DOH_ENDPOINT)

    @app.tool()
    @track("check_dbl")
    async def check_dbl(domain: Domain) -> dict[str, Any]:
        """Check a domain against domain block lists (Spamhaus DBL, SURBL,
        URIBL).

        Returns per-DBL listing status. Useful for triaging unknown domains
        in phishing emails or suspicious URLs.
        """
        return await asyncio.to_thread(_check_dbl, domain, DOH_ENDPOINT)

    @app.tool()
    @track("cymru_asn")
    async def cymru_asn(ip: IPAddress) -> dict[str, Any]:
        """Look up the autonomous system (ASN) and originating prefix for an
        IP address via Team Cymru's DNS-based service.

        Returns ASN, AS name, prefix, country code, registry, and allocation
        date. No API key required.
        """
        return await asyncio.to_thread(_cymru_asn, ip, DOH_ENDPOINT)

    @app.tool()
    @track("check_fast_flux")
    async def check_fast_flux(domain: Domain) -> dict[str, Any]:
        """Detect fast-flux behavior by repeatedly querying <domain> A records
        and observing IP rotation across queries.

        Returns the unique IP set, ASN diversity (more ASNs = more
        suspicious), TTL behavior, and a heuristic verdict. Used in malware
        C2 and phishing infrastructure investigations.
        """
        return await asyncio.to_thread(_check_fast_flux, domain, DOH_ENDPOINT)

    @app.tool()
    @track("nsec_info")
    async def nsec_info(zone: Domain) -> dict[str, Any]:
        """Probe a zone's NSEC / NSEC3 denial-of-existence mechanism.

        Returns whether NSEC or NSEC3 is in use, NSEC3 hash parameters
        (algorithm, iterations, salt), and zone enumeration risk. NSEC
        leaks the next name in zone order (enumeration trivial); NSEC3
        with high iterations resists enumeration.
        """
        return await asyncio.to_thread(_nsec_info, zone, DOH_ENDPOINT)

    @app.tool()
    @track("detect_hijacking")
    async def detect_hijacking(resolver_ip: IPv4) -> dict[str, Any]:
        """Test a recursive resolver for tampering / NXDOMAIN hijacking by
        querying known-good and known-bad names against it.

        Returns whether the resolver wildcards NXDOMAIN responses (a common
        ISP misbehavior), serves stale or modified answers, or respects
        DNSSEC.
        """
        return await asyncio.to_thread(_detect_hijacking, resolver_ip, DOH_ENDPOINT)

    # ── Registration / RDAP ───────────────────────────────────────────────

    @app.tool()
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

    @app.tool()
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

    @app.tool()
    @track("reset_stats")
    async def reset_stats() -> dict[str, Any]:
        """Clear all tool-call statistics and restart the session clock.

        Use sparingly — once stats are cleared they cannot be recovered.
        Returns the new session_start timestamp.
        """
        _reset_stats_impl()
        return {
            "status": "reset",
            "session_start": tracking._session_start.isoformat(),
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
