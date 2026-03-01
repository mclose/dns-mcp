# DNS MCP Server — Migration & Email Security Tools Spec

**Project:** dns-mcp (extend existing)
**Date:** 2026-02-08
**Status:** Approved

---

## Architecture

```
Client (Claude Desktop / CLI / test-mcp.sh)
  |
  v
HTTPS reverse proxy (optional, runs on HOST — not in Docker)
  |
  v
Flask auth proxy (container, port 8082 exposed to host)
  |  - Bearer token validation
  |  - XFF logging to mounted volume for fail2ban
  |  - gunicorn with --timeout 0 for SSE
  v
FastMCP server (container, port 8083 internal only)
  |  - All DNS tools (existing + new)
  |  - dnspython for all DNS queries
  |  - requests for RDAP only
```

### Key Architectural Decisions

- **One Docker image, two compose services.** The proxy service overrides the
  entrypoint to launch gunicorn. The MCP service uses the default entrypoint.
- **HTTPS reverse proxy runs on the host**, not in Docker. Docker has no reverse proxy dependency.
- **Bearer token auth** is the front door. Token is injected via environment
  variable or mounted file — never baked into the image.
- **fail2ban stays on the host.** Proxy logs are written to a mounted volume
  (`/var/log/mcp-proxy/`) so fail2ban can read them from the host filesystem.
- **CORS is deferred.** Current clients are CLI and Claude Desktop, not browsers.
  Will be added when a browser-based client is built.
- **RDAP is the one non-DNS tool.** It makes outbound HTTP requests via the
  `requests` library. This is an accepted, documented exception to the pure-DNS
  pattern.
- **Ports 8082 (proxy) and 8083 (FastMCP)** are the defaults, configurable via
  `.env` file that docker-compose reads.

---

## Phase 0: Docker-Based Development Workflow

### Goal

Move from "run Python directly on the host" to "build and test inside Docker"
so that iteration is containerized and reproducible.

### 0.1 Dockerfile

Single Dockerfile used by both compose services.

Requirements:
- Alpine 3.19+ base
- Install system packages: python3, py3-pip, bind-tools, drill, bind-dnssec-tools,
  jq, bash, curl
- Install Python dependencies from requirements.txt using `--break-system-packages`
  (no venv in container)
- Create non-root user `claude` (uid 1000)
- Run as non-root user
- Default entrypoint: FastMCP server (`python server.py`)

### 0.2 docker-compose.yml

Two services from the same image:

**Service: `mcp`**
- Builds from Dockerfile
- Exposes port 8083 on the internal bridge network only (not to host)
- Sets `PYTHONUNBUFFERED=1`
- Healthcheck against FastMCP endpoint
- Default entrypoint (FastMCP server)

**Service: `proxy`**
- Same image as `mcp`
- Overrides entrypoint to run gunicorn with `server-proxy:app`
  (`gunicorn --bind 0.0.0.0:8082 --timeout 0 server-proxy:app`)
- Exposes port 8082 to host
- Sets `PYTHONUNBUFFERED=1`
- Depends on `mcp` service
- Reads bearer token from environment variable (`MCP_BEARER_TOKEN`)
- Mounts `/var/log/mcp-proxy/` to host for fail2ban access
- Healthcheck against proxy endpoint

**Network:**
- Single bridge network for internal communication
- Only port 8082 is exposed to the host

**Configuration:**
- `.env` file for configurable values: ports, bearer token, log path
- `.env` is gitignored
- Provide `.env.example` with documented defaults

### 0.3 startup.sh

Host convenience wrapper. Replaces the current startup.sh that launches
processes directly.

Behavior:
- Runs `docker compose up -d`
- Optionally tails logs (`startup.sh --logs` or `startup.sh -f`)
- Prints status summary (ports, health)

### 0.4 Makefile

Targets:

| Target    | Command                                         |
|-----------|------------------------------------------------|
| `build`   | `docker compose build`                          |
| `up`      | `docker compose up -d`                          |
| `down`    | `docker compose down`                           |
| `test`    | `docker compose exec mcp pytest tests/ -v`      |
| `logs`    | `docker compose logs -f`                         |
| `shell`   | `docker compose exec mcp /bin/bash`              |
| `rebuild` | `docker compose down && docker compose up -d --build` |

### 0.5 test_tools.py (bootstrap)

Location: `tests/test_tools.py`

In Phase 0, test only the 5 existing tools:
- `dns_query` — known-good domain, bad domain, invalid record type
- `dns_dig_style` — known-good domain, NXDOMAIN
- `timestamp_converter` — valid inputs, invalid inputs
- `reverse_dns` — valid IP, invalid IP
- `dns_dnssec_validate` — signed domain, unsigned domain

Uses pytest. Runs inside the container via `make test`.

Tests call the tool functions directly (import from server.py), not via MCP
protocol. This tests logic, not transport.

### 0.6 Preserve Existing Architecture

- Flask proxy + bearer auth + gunicorn: unchanged in behavior, now runs in
  a container instead of on the host.
- fail2ban configs: unchanged. Only the log path in the jail config may need
  updating to point at the mounted volume path.
- HTTPS reverse proxy: unchanged. Runs on host, points at localhost:8082.
- test-mcp.sh: unchanged. Still tests the full stack via HTTP.

### What NOT to do in Phase 0

- Do not run an HTTPS reverse proxy inside Docker
- Do not use Docker Hub or any registry — local builds only
- Do not introduce subprocess calls for DNS queries
- Do not change tool behavior or output formats
- Do not change the MCP protocol or transport

---

## Phase 1: Email Security Analysis Tools

### Goal

Add tools that let an AI analyst validate email authentication claims against
live DNS records. All tools follow existing patterns in server.py.

### Shared patterns (all new tools)

- Use dnspython directly (no subprocess)
- Input validation via existing `validate_domain()` function
- Return structured JSON with `timestamp`, `errors` array, and tool-specific fields
- Catch `dns.resolver.NXDOMAIN`, `dns.resolver.NoAnswer`,
  `dns.resolver.NoNameservers`, `dns.exception.Timeout` gracefully
- Added to the existing FastMCP server (`server.py`), not a separate server

### 1.1 `check_spf`

**Purpose:** Retrieve and recursively parse a domain's SPF policy to enumerate
all authorized sending IPs/networks.

**Parameters:**
```
domain: str  — Domain to check (e.g., "example.com")
```

**Behavior:**
- Query TXT records for the domain
- Find the record starting with `v=spf1`
- Parse all mechanisms: `ip4`, `ip6`, `a`, `mx`, `include`, `redirect`, `exists`, `all`
- Recursively resolve `include:` mechanisms (max depth 10 per RFC 7208 lookup limit)
- Return the complete list of authorized IP ranges/CIDRs

**Output:**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "raw_record": "v=spf1 include:_spf.google.com ~all",
  "mechanisms": [],
  "authorized_networks": ["35.190.247.0/24", "64.233.160.0/19"],
  "all_qualifier": "softfail",
  "lookup_count": 4,
  "errors": []
}
```

### 1.2 `check_dmarc`

**Purpose:** Retrieve and parse a domain's DMARC policy.

**Parameters:**
```
domain: str  — Domain to check (the From: domain)
```

**Behavior:**
- Query TXT record for `_dmarc.{domain}`
- Parse all DMARC tags: `v`, `p`, `sp`, `rua`, `ruf`, `adkim`, `aspf`, `pct`, `ri`, `fo`
- If no record at exact domain, check organizational domain
  (e.g., sub.example.com falls back to _dmarc.example.com)

**Output:**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "record_found_at": "_dmarc.example.com",
  "raw_record": "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:...",
  "policy": "reject",
  "subdomain_policy": null,
  "dkim_alignment": "strict",
  "spf_alignment": "strict",
  "percentage": 100,
  "rua": ["mailto:dmarc@example.com"],
  "ruf": [],
  "errors": []
}
```

### 1.3 `check_dkim_selector`

**Purpose:** Verify a DKIM public key record exists for a given selector and domain.

**Parameters:**
```
selector: str  — DKIM selector (s= value from DKIM-Signature header)
domain: str    — DKIM domain (d= value from DKIM-Signature header)
```

**Input validation:** Selector must match DNS label pattern (alphanumeric plus
hyphens only). Validate before querying.

**Behavior:**
- Query TXT record for `{selector}._domainkey.{domain}`
- Parse key parameters: `v`, `k` (key type), `p` (public key), `t` (flags),
  `h` (hash algorithms)
- Report whether the key exists and is valid (`p=` is not empty)
- An empty `p=` value means the key has been revoked

**Output:**
```json
{
  "timestamp": "2026-02-07T...",
  "selector": "s1",
  "domain": "example.com",
  "fqdn": "s1._domainkey.example.com",
  "record_exists": true,
  "raw_record": "v=DKIM1; k=rsa; p=MIIBIjAN...",
  "key_type": "rsa",
  "key_present": true,
  "key_revoked": false,
  "flags": [],
  "errors": []
}
```

### 1.4 `check_bimi`

**Purpose:** Check for BIMI (Brand Indicators for Message Identification) record.

**Parameters:**
```
domain: str              — Domain to check
selector: str = "default" — BIMI selector (almost always "default")
```

**Behavior:**
- Query TXT record for `{selector}._bimi.{domain}`
- Parse: `v` (version), `l` (logo SVG URL), `a` (VMC certificate URL)
- Report whether BIMI is configured and whether a VMC is present

**Output:**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "selector": "default",
  "fqdn": "default._bimi.example.com",
  "record_exists": true,
  "raw_record": "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
  "logo_url": "https://example.com/logo.svg",
  "vmc_url": "https://example.com/vmc.pem",
  "has_vmc": true,
  "errors": []
}
```

### 1.5 `check_mta_sts`

**Purpose:** Check for MTA-STS DNS record.

**Parameters:**
```
domain: str  — Domain to check
```

**Behavior:**
- Query TXT record for `_mta-sts.{domain}`
- Parse: `v` (version), `id` (policy identifier)
- Do NOT fetch the HTTPS policy file (/.well-known/mta-sts.txt) — DNS scope only

**Output:**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "fqdn": "_mta-sts.example.com",
  "record_exists": true,
  "raw_record": "v=STSv1; id=20260207T000000",
  "version": "STSv1",
  "policy_id": "20260207T000000",
  "errors": []
}
```

### 1.6 `check_smtp_tlsrpt`

**Purpose:** Check for SMTP TLS Reporting record.

**Parameters:**
```
domain: str  — Domain to check
```

**Behavior:**
- Query TXT record for `_smtp._tls.{domain}`
- Parse: `v` (version), `rua` (reporting URIs)

**Output:**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "fqdn": "_smtp._tls.example.com",
  "record_exists": true,
  "raw_record": "v=TLSRPTv1; rua=mailto:tls-reports@example.com",
  "version": "TLSRPTv1",
  "reporting_uris": ["mailto:tls-reports@example.com"],
  "errors": []
}
```

### 1.7 `rdap_lookup`

**Purpose:** Retrieve domain registration data via RDAP (modern WHOIS replacement).

**Parameters:**
```
domain: str  — Domain to look up (registrable domain, not subdomain)
```

**Behavior:**
- Extract the registrable domain (e.g., "example.com" from "mail.sub.example.com")
  using simple TLD split — don't over-engineer
- Fetch IANA RDAP bootstrap file (`https://data.iana.org/rdap/dns.json`) to find
  the correct RDAP server for the TLD. Cache in memory. Fall back to hardcoded
  map of common TLDs (.com, .net, .org) if fetch fails.
- Query RDAP server: `GET {rdap_base}/domain/{domain}`
- Parse: registrar, creation/expiration/updated dates, status codes,
  registrant org/country (often redacted post-GDPR)
- Calculate `domain_age_days` from creation_date to now
- Timeout: 10 seconds
- Max 3 redirects. No auth or cookies sent.

**Dependencies:** `requests` library (add to requirements.txt)

**Output:**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "rdap_server": "https://rdap.verisign.com/com/v1",
  "registrar": "Example Registrar, Inc.",
  "creation_date": "1995-08-14T00:00:00Z",
  "expiration_date": "2026-08-13T00:00:00Z",
  "last_updated": "2025-06-15T12:00:00Z",
  "status": ["clientTransferProhibited", "serverDeleteProhibited"],
  "registrant_org": "REDACTED FOR PRIVACY",
  "registrant_country": "US",
  "domain_age_days": 11134,
  "errors": []
}
```

**Note:** This is the only tool that makes HTTP calls (not DNS). This is an
accepted exception, documented here and in code comments. Domain age supports
SOC email analysis risk assessment (< 30 days = HIGH RISK, < 90 days = ELEVATED).

---

## Phase 2: Full Test Coverage

### Location

`tests/test_tools.py` (bootstrapped in Phase 0, extended here)

### Test matrix — existing tools

| Tool | Happy path | No record | NXDOMAIN | Bad input |
|------|-----------|-----------|----------|-----------|
| `dns_query` | google.com A | — | nxdomain.invalid | empty string |
| `dns_dig_style` | google.com A | — | nxdomain.invalid | special chars |
| `timestamp_converter` | valid epoch | — | — | non-numeric |
| `reverse_dns` | 8.8.8.8 | — | — | invalid IP |
| `dns_dnssec_validate` | cloudflare.com | unsigned domain | nxdomain.invalid | empty string |

### Test matrix — new email tools

| Tool | Happy path | No record | NXDOMAIN | Bad input | Edge case |
|------|-----------|-----------|----------|-----------|-----------|
| `check_spf` | google.com | domain w/o SPF | nxdomain.invalid | empty string | Deep include chain (lookup limit) |
| `check_dmarc` | google.com | domain w/o DMARC | nxdomain.invalid | empty string | Subdomain fallback to org domain |
| `check_dkim_selector` | known selector+domain | bad selector | nxdomain.invalid | invalid selector chars | Revoked key (empty p=) |
| `check_bimi` | domain w/ BIMI | domain w/o BIMI | nxdomain.invalid | empty string | — |
| `check_mta_sts` | domain w/ MTA-STS | domain w/o MTA-STS | nxdomain.invalid | empty string | — |
| `check_smtp_tlsrpt` | domain w/ TLSRPT | domain w/o TLSRPT | nxdomain.invalid | empty string | — |
| `rdap_lookup` | google.com | — | nxdomain.invalid | empty string | Redacted WHOIS, timeout handling |

### Running tests

```bash
make test
# equivalent to:
docker compose exec mcp pytest tests/ -v
```

Tests call tool functions directly (import from server.py). This tests logic,
not MCP transport. The existing `test-mcp.sh` covers end-to-end protocol testing.

---

## Deliverables Checklist

| # | File | Phase | Description |
|---|------|-------|-------------|
| 1 | `Dockerfile` | 0 | Alpine-based, single image for both services |
| 2 | `docker-compose.yml` | 0 | Two services (mcp + proxy), bridge network, log volume |
| 3 | `.env.example` | 0 | Documented defaults for ports, token, log path |
| 4 | `Makefile` | 0 | build/up/down/test/logs/shell/rebuild targets |
| 5 | `startup.sh` | 0 | Updated to docker compose wrapper |
| 6 | `tests/test_tools.py` | 0+2 | Bootstrapped in Phase 0, extended in Phase 2 |
| 7 | `server.py` | 1 | 7 new tools added alongside existing 5 |
| 8 | `requirements.txt` | 1 | Add `requests` for RDAP |
| 9 | `README.md` | 2 | Updated with new tool docs and Docker workflow |

### Not changed

- Bearer auth logic in `server-proxy.py` (behavior preserved)
- fail2ban filter/jail configs (only host-side log path may change)
- HTTPS reverse proxy setup (runs on host, unchanged)
- MCP protocol/transport (FastMCP streamable-http, unchanged)

---

## Security Properties (preserved)

- All external input validated before use
- No subprocess/shell execution for DNS queries
- Non-root container user (`claude`, uid 1000)
- Bearer token never baked into image
- Domain validation regex on all inputs
- Query type allowlists
- RDAP: input validated before HTTP request, max 3 redirects, 10s timeout, no auth sent
- SPF recursion: enforced 10-lookup limit per RFC 7208

---

## Open Items (future, not in scope)

- **CORS headers** — Add when a browser-based client is built
- **Auth beyond bearer** — Noted as future need; out of scope for this work
- **MTA-STS policy file fetch** — Intentionally excluded (HTTP, not DNS)
- **DKIM signature verification** — Would require the email body; out of scope
