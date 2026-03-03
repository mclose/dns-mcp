# DNS MCP Server

Real-time DNS security analysis for AI assistants via MCP. Gives your
assistant the ability to investigate domains the way a practitioner would —
DNSSEC chain validation, email authentication posture, and registration
intelligence — without leaving your chat session.

Built by a cybersecurity professional for SOC investigation workflows.
Not a toy — the same queries you'd run at the command line, accessible
through any MCP-compatible assistant in real time.

## Tools

### DNS Tools
| Tool | Description |
|------|-------------|
| `dns_query` | Standard DNS lookups (A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, SRV) |
| `dns_dig_style` | Detailed dig-style output with DNSSEC flags (DO flag set) |
| `dns_dnssec_validate` | Chain-of-trust validation like `delv +vtrace` |
| `nsec_info` | NSEC/NSEC3 denial-of-existence analysis and zone walkability assessment |
| `reverse_dns` | PTR record lookups for IP addresses |
| `timestamp_converter` | Convert between ISO, epoch, and human-readable timestamps |
| `detect_hijacking` | Test a resolver for DNS hijacking/tampering (NXDOMAIN probe, known record, DNSSEC, identity) |

### Email Security Tools
| Tool | Description |
|------|-------------|
| `check_spf` | SPF record parsing with recursive include resolution (RFC 7208 10-lookup limit) |
| `check_dmarc` | DMARC policy retrieval with organizational domain fallback |
| `check_dkim_selector` | DKIM public key record verification for a selector+domain pair |
| `check_bimi` | BIMI record and VMC (Verified Mark Certificate) check |
| `check_mta_sts` | MTA-STS DNS record + HTTPS policy file fetch (mode, MX patterns, max_age) |
| `check_smtp_tlsrpt` | SMTP TLS Reporting record check |
| `check_dane` | DANE TLSA record check with DNSSEC validation |
| `rdap_lookup` | Domain registration data via RDAP (modern WHOIS replacement) |

### Utility
| Tool | Description |
|------|-------------|
| `ping` | Health check — returns pong with timestamp |
| `quine` | Returns the source code of this server |

## Analyst Prompts

The server ships with three analyst prompt templates. Any MCP-compatible client
can list and invoke them — no Claude-specific configuration required.

| Prompt | What it does |
|--------|-------------|
| `email_security_audit` | Domain email security audit: SPF, DKIM, DMARC, MTA-STS, BIMI — graded A through F with prioritized recommendations |
| `dnssec_chain_audit` | Full DNSSEC chain-of-trust audit from the IANA root trust anchor down to the target domain |
| `soc_email_forensics` | Forensic phishing analysis of a raw email (.eml or pasted headers) — returns TRUSTABLE / SUSPICIOUS / PHISHING / FURTHER ANALYSIS REQUIRED |

Prompts set the analyst context and tool-use strategy for the session. The LLM
runs the appropriate tools in sequence and synthesizes a structured report.

**Client support note:** MCP prompt invocation requires client-side UI support.
Claude Code CLI supports prompts via slash commands (see Quick Start §4).
Claude Desktop currently exposes MCP tools only — prompts are registered but
not reachable from the UI. Use tools ad-hoc in Desktop, or describe the
analysis you want and the model will apply the same workflow.

## Example

Ask your assistant: *"Check the email security posture of deflationhollow.net"*

The assistant calls `check_spf`, `check_dmarc`, `check_dane`, `check_mta_sts`,
and `check_bimi` in sequence and returns a complete analysis:
```
✅ SPF: Hard fail (-all), delegated to ForwardEmail, 5 lookups (under RFC limit)
✅ DMARC: p=reject, pct=100 — full enforcement, aggregate reporting configured
⚠️  DANE: TLSA records present but unverifiable — DNSSEC not enabled on zone
⚠️  MTA-STS: Not configured — no TLS enforcement policy published  
⚠️  BIMI: Not configured
```

**Overall: B+ — Strong fundamentals, three actionable gaps identified.**

No copy-pasting dig commands. No tab-switching. One question.

## Quick Start

### Prerequisites
- Docker

### 1. Build

```bash
git clone https://github.com/mclose/dns-mcp.git
cd dns-mcp
make build
```

### 2. Connect

Any MCP client that supports stdio transport works. Claude Desktop is the
primary tested client — add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dns-mcp": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--dns", "9.9.9.9",
        "dns-mcp",
        "python", "server.py"
      ]
    }
  }
}
```

Config file location:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Other MCP clients (Cursor, VS Code with MCP extension, etc.) use the same
`command` / `args` pattern — consult your client's documentation for the
config file location and format.

The `--dns 9.9.9.9` flag ensures DNSSEC-correct resolution regardless of the
host's DNS configuration.

### 3. Verify

```bash
make test                  # unit tests inside container
./test-mcp-stdio.sh        # end-to-end stdio test
```

### 4. Start an analysis

**Claude Code CLI** — invoke analyst prompts directly with slash commands:

```
/mcp__dns-mcp__email_security_audit   → "Check deflationhollow.net"
/mcp__dns-mcp__dnssec_chain_audit     → "Audit dnssec.works"
/mcp__dns-mcp__soc_email_forensics    → (paste raw .eml headers)
```

Type `/mcp__dns-mcp__` and tab-complete to see all three.

**Claude Desktop** — prompts are not exposed in the Desktop UI (Desktop
surfaces MCP tools only, not prompts). Just ask ad-hoc — the tools are all
available and the model will run the same workflow:

> *"Check the email security posture of deflationhollow.net"*
> *"Audit the DNSSEC chain for dnssec.works"*

## Architecture

```
MCP Client (e.g. Claude Desktop)
  |
  | (spawns per-session)
  v
docker run --rm -i dns-mcp python server.py
  |
  | stdin/stdout (MCP stdio transport)
  v
FastMCP server (server.py)
  |  - All 17 tools
  |  - dnspython for DNS queries
  |  - requests for RDAP only
```

No network ports. No auth tokens. No proxy. The MCP client manages the
container lifecycle — one container per session, cleaned up on exit.

## Day-to-Day

| Command | What it does |
|---------|-------------|
| `make build` | Build the Docker image (uses layer cache) |
| `make rebuild` | Full clean build, no cache — use when something feels off |
| `make test` | Run unit tests inside the container |
| `make shell` | Interactive shell inside the container |
| `./test-mcp-stdio.sh` | End-to-end stdio protocol test |

## Testing

**Unit tests** — tool logic, input validation, error handling:
```bash
make test    # runs pytest inside container
```

**End-to-end stdio** — full MCP protocol over stdin/stdout:
```bash
./test-mcp-stdio.sh
```

## Security

- No shell execution — all DNS via dnspython, RDAP via requests
- Strict domain validation (regex allowlist)
- IP address validation (ipaddress module)
- Query type allowlist
- Non-root container user (`claude`, uid 1000)
- SPF recursion limit enforced (RFC 7208)
- RDAP: input validated before HTTP request, 10s timeout, max 3 redirects

## File Structure

```
dns-mcp/
├── server.py              # FastMCP server (17 tools, stdio transport)
├── Dockerfile             # Single-stage Alpine image
├── docker-compose.yml     # Build target
├── Makefile               # build/test/shell
├── requirements.txt       # Python dependencies
├── test-mcp-stdio.sh      # End-to-end stdio test
└── tests/
    └── test_tools.py      # pytest unit tests
```

## Contributing

```bash
pip install pre-commit
pre-commit install
```

That's it. On every commit, ruff will lint and auto-fix staged Python files.
The full test suite (pytest + stdio e2e) runs in CI on every push and pull request.

## Remote / HTTP Transport

The `remote` branch contains the HTTP Streamable transport version of this
server, including a Flask auth proxy sidecar, bearer token authentication,
fail2ban integration, and instructions for exposing the server via an HTTPS
reverse proxy. See that branch if you need network-accessible deployment.

## License

MIT
