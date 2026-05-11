# DNS MCP Server

Real-time DNS security analysis for AI assistants via MCP. Gives your
assistant the ability to investigate domains the way a practitioner would —
DNSSEC chain validation, email authentication posture, and registration
intelligence — without leaving your chat session.

Built by a cybersecurity professional for SOC investigation workflows.
Not a toy — the same queries you would run at the command line, accessible
through any MCP-compatible assistant in real time.

## Architecture (2.0.0)

dns-mcp is a Streamable HTTP MCP server with OAuth via [Pocket
ID](https://pocket-id.org/). Tool implementations are thin wrappers around the
[`dns_tool`](https://github.com/mclose/claude-packages) Python library, which
owns all DNS logic. The server itself is ~430 lines of code: auth bootstrap,
tool registration, and prompt loading.

```
Claude.ai / Claude Code / any MCP client
              │
              │ Streamable HTTP + OAuth bearer (JWT)
              ▼
       Caddy reverse proxy           (TLS, DNS-01 / Let's Encrypt)
              │
              ▼
     dns-mcp container               (FastMCP, OAuth verifier)
              │
              ▼
        dns_tool library             (DoH client, validators, parsers)
              │
              ▼
   doh.lab.deflationhollow.net      (Unbound DoH resolver, optional)
```

Three benefits over the previous stdio-only architecture:

1. **Network-accessible** — hosted MCP servers can serve any client, not just
   ones that can spawn a local subprocess.
2. **OAuth-protected** — bearer JWTs verified against Pocket ID JWKS; per-user
   identity available to tools via `whoami`.
3. **Library-first** — `dns_tool` is published independently and reusable. The
   same code powers a CLI, this MCP server, and (eventually) a REST API.

The old stdio architecture lives at `server.py.legacy` for porting reference.
The `remote` branch (mcp-shim Go bridge) is deprecated.

## Tools

dns-mcp 2.0.0 currently exposes **19 tools**. Ten additional tools from the
1.x stdio architecture are pending port into `dns_tool` — see
[Open work](#open-work).

### Meta

| Tool | Description |
|------|-------------|
| `ping` | Server uptime, current timestamp, dns_tool version + commit hash |
| `whoami` | Authenticated user identity from JWT claims |

### DNS

| Tool | Description |
|------|-------------|
| `dns_query` | Standard DNS lookup over DoH — 20 record types (A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, SRV, CAA, DNSKEY, DS, RRSIG, NSEC, NSEC3, TLSA, SSHFP, HTTPS, SVCB, NAPTR) |
| `dnssec_validate` | Full DNSSEC chain walk from IANA root trust anchor down to target. Real cryptographic validation at every zone cut. Returns structured `verdict` + per-zone findings + event transcript |
| `nsec_info` | NSEC / NSEC3 denial-of-existence analysis — zone walkability assessment, NSEC3 hash parameters, opt-out detection |

### Email security

| Tool | Description |
|------|-------------|
| `check_spf` | SPF record parsing with recursive include resolution (RFC 7208 10-lookup limit) |
| `check_dmarc` | DMARC policy retrieval with organizational domain fallback |
| `check_dkim` | DKIM public key record verification for a selector + domain pair |
| `enumerate_dkim_selectors` | Probe a domain for DKIM keys at well-known selector names; returns the selectors that resolve |
| `check_dane` | DANE TLSA records for all MX hosts of a domain |
| `check_tlsa` | Standalone TLSA record lookup at `_<port>._<proto>.<host>` |

### Threat intelligence

| Tool | Description |
|------|-------------|
| `check_rbl` | IP reputation against 8 DNS-based RBLs (Spamhaus ZEN, SpamCop, UCEProtect L1/L2, Mailspike, PSBL, Barracuda, SORBS) |
| `check_dbl` | Domain reputation against DNS-based Domain Block Lists (Spamhaus DBL, URIBL, SURBL) |
| `cymru_asn` | ASN lookup via Team Cymru DNS service — BGP prefix, org, country |
| `check_fast_flux` | Fast-flux detection — repeated A/AAAA queries to identify rotating IPs and short TTLs |
| `detect_hijacking` | Test a recursive resolver for tampering — NXDOMAIN wildcards, DNSSEC handling, identity |

### Registration

| Tool | Description |
|------|-------------|
| `rdap_lookup` | Domain registration data via RDAP (modern WHOIS replacement) |

### Observability

| Tool | Description |
|------|-------------|
| `session_stats` | Per-tool call statistics for the current process — count, error_count, mean_ms, max_ms, first/last_called timestamps; plus session uptime and total call count. Module-level state (resets on container restart). Backed by `dns_mcp/tracking.py`. |
| `reset_stats` | Clear all tool-call statistics and restart the session clock. |

Downstream consumers (e.g. `~/projects/yahoo` batch forensics) call
`session_stats` as the final tool in each investigation to record which
DNS tools were consulted; an empty stats dict indicates a "cold read"
where the analyst LLM produced a verdict without DNS verification.

## Tool descriptors

All 19 tools use Pydantic `Field` for parameter descriptors. The LLM sees:

- **Per-parameter descriptions** explaining what the parameter means
- **`Literal[...]` enums** for record types and protocols (no string-guessing)
- **Regex patterns** validating FQDN syntax, IPv4 dotted-quad, DKIM selector format
- **Length and range constraints** (port 1–65535, FQDN max 253 chars, etc.)

Constraints are advertised in the tool descriptor JSON Schema and enforced at
the MCP boundary by FastMCP — invalid input is rejected before `dns_tool` is
called. See `src/dns_mcp/server.py` for the type alias definitions.

## Analyst Prompts

Four analyst prompt templates ship with the server. Any MCP-compatible client
that supports prompts can list and invoke them.

| Prompt | What it does |
|--------|-------------|
| `email_security_audit` | SPF, DKIM, DMARC, MTA-STS, BIMI — graded A through F with prioritized recommendations |
| `dnssec_chain_audit` | Full DNSSEC chain-of-trust audit from IANA root down to target |
| `soc_email_forensics` | Forensic phishing analysis of a raw email — TRUSTABLE / SUSPICIOUS / PHISHING / FURTHER ANALYSIS REQUIRED |
| `nist_800_81r3_audit` | Domain security posture audit aligned with NIST SP 800-81r3 |

Prompt invocation requires client-side UI support. Claude Code surfaces them
as `/mcp__dns-mcp__<prompt_name>`. Claude.ai web exposes prompts via the
slash-command picker. Use tools ad-hoc in clients that do not support prompts.

## Example

Ask your assistant: *"Check the email security posture of example.com"*

The assistant calls `check_spf`, `check_dmarc`, `check_dane` in sequence and
returns a complete analysis:

```
✅ SPF:     Hard fail (-all), 3 lookups (under RFC limit)
✅ DMARC:   p=reject, pct=100 — full enforcement, aggregate reporting configured
✅ DANE:    TLSA records present and DNSSEC-validated
```

No copy-pasting dig commands. No tab-switching. One question.

## Quick Start

### Prerequisites

- Docker
- A Pocket ID instance (or any OIDC provider supporting Dynamic Client Registration)
- A reverse proxy with TLS termination (Caddy, nginx, etc.)
- A domain name pointing at your reverse proxy

### 1. Pocket ID

Mint an admin API key in Pocket ID's UI: **Settings → API Keys → Create new
key**. Name it `dns-mcp` so you can revoke just this service if needed. Copy
the key value (it is shown once).

### 2. .env

```bash
POCKET_ID_BASE_URL=https://pocketid.example.com
POCKET_ID_API_KEY=<the key from step 1>
SERVER_URL=https://dns-mcp.example.com
```

### 3. Deploy

```bash
git clone https://github.com/mclose/dns-mcp.git
cd dns-mcp
docker compose up -d
```

The image installs `dns_tool` as a versioned dependency (URL-pinned in
`pyproject.toml`); `make build` is also available for direct development.

### 4. Reverse proxy

The container listens on port 8000 (HTTP). Front it with TLS termination:

```caddy
dns-mcp.example.com {
    reverse_proxy dns-mcp:8000 {
        flush_interval -1   # required for Streamable HTTP / SSE
    }
}
```

If you use [`mclose/gateway`](https://github.com/mclose/gateway) (the Caddy +
DNS-01 setup that serves dns-mcp.lab.deflationhollow.net), drop a
`conf.d/dns-mcp.conf` matching the existing pattern.

### 5. Connect

Add `https://dns-mcp.example.com/mcp` as a connector in your MCP client. The
OAuth flow runs once on first connect — Claude.ai redirects to Pocket ID, you
authenticate, the server creates a DCR client on your Pocket ID instance, and
returns a JWT. Subsequent tool calls send that JWT as a bearer token; the
server verifies against Pocket ID JWKS.

## Open work

Eleven tools from the 1.x stdio architecture are not yet ported into
`dns_tool` and are therefore not registered in 2.0.0:

- `check_caa` (with CNAME chain tracing and wildcard delegation detection)
- `check_zone_transfer` (AXFR enumeration)
- `check_bimi`, `check_mta_sts`, `check_smtp_tlsrpt`
- `check_ct_logs` (Certificate Transparency log enumeration via crt.sh)
- `timestamp_converter`, `reverse_dns`
- `enumerate_dkim_selectors`, `dns_dig_style`, `dns_query_dot`

Reference implementations live in `server.py.legacy`. Each port involves
moving the function into the appropriate `dns_tool` module
(`dns_tool.email`, `dns_tool.intel`, etc.), adding tests on the library
side, and registering a one-line wrapper in `src/dns_mcp/server.py`.

## File structure

```
dns-mcp/
├── src/dns_mcp/
│   ├── __init__.py
│   ├── __main__.py            # entrypoint — create_server().run(transport="streamable-http")
│   ├── config.py              # pydantic-settings Settings class
│   ├── auth.py                # JWKSTokenVerifier + JWTAccessToken
│   └── server.py              # FastMCP app: OAuth routes + 16 tools + 4 prompts (~430 lines)
├── prompts/                   # MCP analyst prompt text files
├── tests/                     # pytest unit tests (legacy — pending rewrite)
├── tools/                     # operator scripts (smoke tests, deploy helpers)
├── server.py.legacy           # 1.x stdio server (5,095 lines), reference for 11 deferred tool ports
├── compose.yaml
├── Dockerfile
├── pyproject.toml             # dns_tool URL-pinned to dist tarball
└── Makefile                   # build/lint/import-check
```

## Day-to-day

| Command | What it does |
|---------|-------------|
| `make build` | Rebuild the Docker image |
| `make rebuild` | Full clean build, no cache |
| `make lint` | `pre-commit run --all-files` (ruff check + format) |
| `make import-check` | Build image, run `create_server()` inside, assert tools register |
| `make shell` | Interactive shell inside the container |
| `make deploy` | Push to GitHub + VPS post-receive hook |
| `make logs` | Tail container logs |
| `make status` | Container status |

## Security

- No shell execution — all DNS via `dns_tool` (dnspython internally), RDAP via
  `requests`
- OAuth bearer JWT verification against Pocket ID JWKS on every tool call
- Pydantic `Field` constraints enforced at MCP boundary — invalid input
  rejected before reaching `dns_tool`
- Non-root container user (`claude`, uid 1000)
- SPF recursion limit enforced (RFC 7208)
- RDAP: 10s timeout, max 3 redirects

## License

MIT
