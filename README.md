# DNS MCP Server

A secure Model Context Protocol (MCP) server providing DNS lookup and email
security analysis tools with DNSSEC chain-of-trust validation. Runs in Docker
with a Flask auth proxy sidecar. Usable on localhost or exposed via an HTTPS
reverse proxy for remote access.

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
| `rdap_lookup` | Domain registration data via RDAP (modern WHOIS replacement) |

## Architecture

```
MCP Client (Claude Desktop / Claude Code / curl / test-mcp.sh)
  |
  v
HTTPS reverse proxy (optional, runs on host)   # skip for local-only use or Docker stdio deployments (ie Desktop)
  |
  v
Flask auth proxy container (port 8082)
  |  - Bearer token validation
  |  - XFF logging to mounted volume for fail2ban
  |  - gunicorn with --timeout 0 for SSE
  v
FastMCP server container (port 8083, internal only)
  |  - All 14 tools
  |  - dnspython for DNS queries
  |  - requests for RDAP only
```

One Docker image, two compose services. Works on localhost for local-only use,
via Docker stdio for Claude Desktop, or behind any HTTPS reverse proxy for
remote access.

## Quick Start

### Prerequisites
- Docker and Docker Compose

### 1. Clone and Configure

```bash
git clone <repo-url> dns-mcp
cd dns-mcp
cp .env.example .env
# Edit .env — at minimum, set a real MCP_BEARER_TOKEN
```

### 2. Build and Start

```bash
make build    # Build the Docker image
make up       # Start both containers
```

### 3. Verify

```bash
./test-mcp.sh                                              # local
./test-mcp.sh https://your-server.example.com/mcp TOKEN    # remote
make test                                                   # unit tests
```

## Connecting MCP Clients

Use your HTTPS endpoint for remote access, or `http://localhost:8082/mcp` for
local-only use.

### Claude Code (CLI)

```bash
# Remote
claude mcp add --transport http dns-mcp https://your-server.example.com/mcp \
  --header "Authorization: Bearer YOUR_TOKEN"

# Local-only
claude mcp add --transport http dns-mcp http://localhost:8082/mcp \
  --header "Authorization: Bearer YOUR_TOKEN"
```

### Claude Desktop

**Option A: Local Docker (stdio, no network/auth needed)**

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dns-mcp": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "dns-mcp-mcp",
        "python", "server.py", "--stdio"
      ]
    }
  }
}
```

Requires the image built locally (`make build`). No proxy, no token, no network
— Claude Desktop spawns the container and talks over stdin/stdout.

Config file location:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

**Option B: Remote via `mcp-remote` bridge (requires Node.js)**

```json
{
  "mcpServers": {
    "dns-mcp": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-server.example.com/mcp",
        "--header",
        "Authorization: Bearer ${MCP_TOKEN}"
      ],
      "env": {
        "MCP_TOKEN": "YOUR_TOKEN"
      }
    }
  }
}
```

### curl (manual poking)

MCP is just HTTP. You can call any tool directly:

```bash
# Initialize a session (use your HTTPS endpoint or localhost:8082)
curl -s -i -X POST http://localhost:8082/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},
    "clientInfo":{"name":"curl","version":"1.0"}}}'

# Grab the mcp-session-id header from the response, then call a tool:
curl -s -X POST http://localhost:8082/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: SESSION_ID_HERE" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
    "name":"check_spf","arguments":{"domain":"google.com"}}}'
```

Or just use `test-mcp.sh` which handles session management for you.

## Day-to-Day Operations

| Command | What it does |
|---------|-------------|
| `make up` | Start the stack |
| `make down` | Stop the stack |
| `make rebuild` | Rebuild image and restart (after code changes) |
| `make test` | Run unit tests inside the container |
| `make logs` | Tail container logs |
| `make shell` | Shell into the MCP container |
| `./test-mcp.sh` | Run 18 end-to-end tests (localhost, reads token from .env) |

## Environment Variables

See `.env.example` for all options:

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_BEARER_TOKEN` | *(required)* | Auth token for the proxy |
| `MCP_PORT` | `8083` | FastMCP server port (internal) |
| `PROXY_PORT` | `8082` | Proxy port (exposed to host) |
| `LOG_PATH` | `/var/log/mcp-proxy` | Host path for proxy logs (see note below) |

> **LOG_PATH on macOS:** Use a local path like `./logs` instead of `/var/log/mcp-proxy`.
> On Linux, the directory must be owned by uid 1000 (`sudo chown -R 1000:1000 /var/log/mcp-proxy`).

## Testing

Three layers:

**Unit tests** — tool logic, input validation, error handling:
```bash
make test    # 106 tests, runs inside the container
```

**Bash end-to-end** — every tool over HTTP with curl and JSON-RPC:
```bash
./test-mcp.sh                                                # localhost
./test-mcp.sh https://dnsmcp.lab.deflationhollow.net/mcp token  # remote
```

**MCP SDK client** — real `fastmcp.Client` with bearer auth, same path
any MCP client takes:
```bash
python test-mcp-client.py                                     # localhost
python test-mcp-client.py http://localhost:8082/mcp changeme   # explicit
```

### MCP Inspector

```bash
npx @modelcontextprotocol/inspector
# Transport Type: HTTP Streamable
# URL: http://localhost:8082/mcp
# Authentication: Bearer <your-token>
```

## Fail2ban Integration

The proxy logs requests with X-Forwarded-For headers to a mounted volume.

```bash
sudo chown -R 1000:1000 /var/log/mcp-proxy   # Match container user UID
sudo cp fail2ban/filter.d/dns-mcp.conf /etc/fail2ban/filter.d/
sudo cp fail2ban/jail.d/dns-mcp.conf /etc/fail2ban/jail.d/
sudo systemctl reload fail2ban
```

Bans IPs that trigger 10+ 4xx errors within 5 minutes.

## File Structure

```
dns-mcp/
├── server.py              # FastMCP server (14 tools)
├── server-proxy.py         # Flask auth proxy
├── Dockerfile              # Single image for both services
├── docker-compose.yml      # Two services: mcp + proxy
├── Makefile                # build/up/down/test/logs/shell/rebuild
├── startup.sh              # Host convenience wrapper
├── requirements.txt        # Python dependencies
├── .env.example            # Documented config defaults
├── tests/
│   └── test_tools.py       # 106 pytest tests
├── fail2ban/
│   ├── filter.d/dns-mcp.conf
│   └── jail.d/dns-mcp.conf
├── test-mcp.sh             # Bash end-to-end test (curl/JSON-RPC)
├── test-mcp-client.py      # MCP SDK client integration test
└── SPEC.md                 # Implementation spec (Phase 0/1/2)
```

## Security

- No shell execution — all DNS via dnspython, RDAP via requests
- Strict domain validation (regex allowlist)
- IP address validation (ipaddress module)
- Query type allowlist
- Bearer token authentication
- Non-root container user (`claude`, uid 1000)
- Token never baked into image (injected via environment)
- SPF recursion limit enforced (RFC 7208)
- RDAP: input validated before HTTP request, 10s timeout, max 3 redirects

## License

MIT
