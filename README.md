# DNS MCP Server

A Model Context Protocol (MCP) server providing DNS lookup and email security
analysis tools with DNSSEC chain-of-trust validation. Runs as a Docker
container in stdio mode — Claude Desktop spawns it directly, no network or
auth configuration required.

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

## Quick Start

### Prerequisites
- Docker

### 1. Build

```bash
git clone <repo-url> dns-mcp
cd dns-mcp
make build
```

### 2. Connect (Claude Desktop)

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dns-mcp": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--dns", "8.8.8.8",
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

The `--dns 8.8.8.8` flag ensures DNSSEC-correct resolution regardless of the
host's DNS configuration.

### 3. Verify

```bash
make test                  # unit tests inside container
./test-mcp-stdio.sh        # end-to-end stdio test
```

## Architecture

```
Claude Desktop
  |
  | (spawns per-session)
  v
docker run --rm -i dns-mcp python server.py
  |
  | stdin/stdout (MCP stdio transport)
  v
FastMCP server (server.py)
  |  - All 16 tools
  |  - dnspython for DNS queries
  |  - requests for RDAP only
```

No network ports. No auth tokens. No proxy. Claude Desktop manages the
container lifecycle — one container per session, cleaned up on exit.

## Day-to-Day

| Command | What it does |
|---------|-------------|
| `make build` | Build the Docker image |
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
├── server.py              # FastMCP server (16 tools, stdio transport)
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
