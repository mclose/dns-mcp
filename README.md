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
| `dns_query` | Standard DNS lookups (A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, SRV, DNSKEY, DS, TLSA, CAA, SSHFP, RRSIG, CDS, CDNSKEY, HTTPS, SVCB, NAPTR) |
| `dns_dig_style` | Detailed dig-style output with DNSSEC flags (DO flag set) — same 20 record types |
| `dns_query_dot` | DNS over TLS (DoT) query — TLS session info, EDNS pseudosection, DNSSEC flags — same 20 record types |
| `dns_dnssec_validate` | Chain-of-trust validation like `delv +vtrace`; cross-checks verdict against resolver AD flag and flags discrepancies |
| `nsec_info` | NSEC/NSEC3 denial-of-existence analysis and zone walkability assessment |
| `reverse_dns` | PTR lookup + forward-confirmed rDNS (FCrDNS) verification — essential for mail server identity |
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
| `check_dane` | DANE TLSA record check with DNSSEC validation for a domain's MX hosts |
| `check_tlsa` | Standalone TLSA record lookup for any hostname, port, and protocol |
| `rdap_lookup` | Domain registration data via RDAP (modern WHOIS replacement) |
| `check_rbl` | IP reputation check against 8 DNS-based RBLs (Spamhaus ZEN, SpamCop, UCEProtect L1/L2, Mailspike, PSBL, Barracuda, SORBS); optional Spamhaus DQS key via `SPAMHAUS_DQS_KEY` env var |

### Threat Intelligence
| Tool | Description |
|------|-------------|
| `check_dbl` | Domain reputation check against DNS-based Domain Block Lists (Spamhaus DBL, URIBL, SURBL) |
| `cymru_asn` | ASN lookup via Team Cymru DNS service — BGP prefix, org name, country, and high-risk ASN flag |
| `check_fast_flux` | Fast-flux detection — repeated A/AAAA queries to identify rotating IPs and suspiciously short TTLs; signals botnet/phishing infrastructure |
| `check_ct_logs` | Certificate Transparency log enumeration via crt.sh — unique subdomain names, per-cert issuer/validity details, wildcard detection, and CAA cross-reference with correct O= field mapping |
| `check_caa` | CAA record analysis with CNAME chain tracing and wildcard delegation detection — tree-climbs for effective policy, follows CNAME chains, detects wildcard CNAMEs that delegate CAA authority to third parties (RFC 8659 §3), surfaces RFC 8657 binding gaps |
| `check_zone_transfer` | AXFR zone transfer attempt against every authoritative NS — open transfer is a NIST SP 800-81r3 §3.1 violation; returns full zone contents (names, record type summary) when transfer succeeds |

### Utility
| Tool | Description |
|------|-------------|
| `ping` | Health check — returns pong with timestamp |
| `server_info` | Show resolver config: dnspython version, nameservers, EDNS settings |
| `quine` | Returns the source code of this server |
| `session_stats` | Per-tool call counts, error rates, and latency for this container session |
| `reset_stats` | Reset session stats and clock without restarting the container |

## Resources

Three reference resources are available to MCP clients that support resource
reading. They cover tool-specific output vocabulary that a client AI cannot
infer from tool schemas alone — field meanings, status codes, and RBL return
codes specific to this server's output format.

| Resource URI | Contents |
|-------------|----------|
| `dns-mcp://output-guide` | Field-by-field reference: DNSSEC chain status values, DS vs DNSKEY parent/child relationship, FCrDNS fields, DANE status, RBL listed/clean/error semantics, detect_hijacking `passed` convention |
| `dns-mcp://rbl-reference` | Return code tables for all 8 RBLs including Spamhaus quota codes |
| `dns-mcp://test-zones` | Live NSEC/NSEC3 test zones on deflationhollow.net with parameters and risk levels |

Resources are pull-based — clients load them on demand, not on every message.

## Analyst Prompts

The server ships with four analyst prompt templates. Any MCP-compatible client
can list and invoke them — no Claude-specific configuration required.

| Prompt | What it does |
|--------|-------------|
| `email_security_audit` | Domain email security audit: SPF, DKIM, DMARC, MTA-STS, BIMI — graded A through F with prioritized recommendations |
| `dnssec_chain_audit` | Full DNSSEC chain-of-trust audit from the IANA root trust anchor down to the target domain |
| `soc_email_forensics` | Forensic phishing analysis of a raw email (.eml or pasted headers) — returns TRUSTABLE / SUSPICIOUS / PHISHING / FURTHER ANALYSIS REQUIRED |
| `nist_800_81r3_audit` | Domain security posture audit aligned with NIST SP 800-81r3 — covers delegation integrity, DNSSEC, CAA, email authentication, reputation, and resolver integrity |

Prompts set the analyst context and tool-use strategy for the session. The LLM
runs the appropriate tools in sequence and synthesizes a structured report.

**Client support note:** MCP prompt invocation requires client-side UI support.
Claude Code CLI supports prompts via slash commands (see Quick Start §4).
Claude Desktop currently exposes MCP tools only — prompts are registered but
not reachable from the UI. Use tools ad-hoc in Desktop, or describe the
analysis you want and the model will apply the same workflow.

## Example

Ask your assistant: *"Check the email security posture of example.com"*

The assistant calls `check_spf`, `check_dmarc`, `check_dane`, `check_mta_sts`,
and `check_bimi` in sequence and returns a complete analysis:
```
✅ SPF: Hard fail (-all), 3 lookups (under RFC limit)
✅ DMARC: p=reject, pct=100 — full enforcement, aggregate reporting configured
✅ DANE: TLSA records present and DNSSEC-validated
⚠️  MTA-STS: Not configured — no TLS enforcement policy published
⚠️  BIMI: Not configured
```

**Overall: B+ — Strong fundamentals, two actionable gaps identified.**

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

Any MCP client that supports stdio transport works. The server config block
is the same across all clients — see [Client Support](#client-support) for
client-specific setup instructions and config file locations.

The `--dns 9.9.9.9` flag ensures DNSSEC-correct resolution regardless of the
host's DNS configuration.

### 3. Verify

```bash
make test                  # unit tests inside container
./test-mcp-stdio.sh        # end-to-end stdio test
```

### 4. Start an analysis

Once connected, just ask:

> *"Check the email security posture of deflationhollow.net"*
> *"Audit the DNSSEC chain for dnssec.works"*
> *"Is this email headers trustworthy?"* (paste raw headers)
> *"Run a NIST SP 800-81r3 security audit on example.com"*

Clients that support MCP prompts can also invoke the structured analyst
workflows directly — see [Client Support](#client-support) for details.

## Client Support

All clients use the same server block. The `command` and `args` are identical
everywhere — only the config file location and prompt invocation differ.

```json
{
  "mcpServers": {
    "dns-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "--dns", "9.9.9.9", "dns-mcp", "python", "server.py"]
    }
  }
}
```

### Optional: Spamhaus DQS key

`check_rbl` queries `zen.spamhaus.org` by default. This works for occasional
analyst use, but Spamhaus rate-limits or blocks queries from resolvers without
a service agreement. When this happens, Spamhaus returns administrative codes
(`127.255.255.252–255`) that the tool detects and surfaces as an error on that
RBL entry — not a false listing — with a message explaining the cause.

For reliable, unrestricted access, set your free
[Spamhaus Data Query Service](https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account/)
key via the `SPAMHAUS_DQS_KEY` environment variable — the tool will
automatically switch to the DQS zone:

```json
{
  "mcpServers": {
    "dns-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "--dns", "9.9.9.9", "-e", "SPAMHAUS_DQS_KEY", "dns-mcp", "python", "server.py"],
      "env": { "SPAMHAUS_DQS_KEY": "your-key-here" }
    }
  }
}
```

### Claude Desktop

**Prompts:** Not supported — Desktop exposes MCP tools only. Use ad-hoc questions.

Config file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### Claude Code CLI

**Prompts:** Full support via `/` slash commands.

Add the server with one command (adds to local project config):

```bash
claude mcp add dns-mcp -- docker run --rm -i --dns 9.9.9.9 dns-mcp python server.py
```

Or add `--scope user` to make it available across all projects. Invoke prompts
by typing `/` in the chat — the four analyst prompts appear as:

```
/mcp__dns-mcp__email_security_audit
/mcp__dns-mcp__dnssec_chain_audit
/mcp__dns-mcp__soc_email_forensics
/mcp__dns-mcp__nist_800_81r3_audit
```

Type `/mcp__dns-mcp__` and tab-complete to see all four.

### Gemini CLI

**Prompts:** Supported (Gemini CLI implements the full MCP spec).

Add the server with one command:

```bash
gemini mcp add dns-mcp -- docker run --rm -i --dns 9.9.9.9 dns-mcp python server.py
```

Or add manually to `~/.gemini/settings.json` (user scope) or
`.gemini/settings.json` (project scope) using the same JSON block above.

### Cursor

**Prompts:** Verify with your installed version — Cursor MCP support is active
and evolving. Config location: consult [Cursor MCP docs](https://docs.cursor.com/context/model-context-protocol).

Add the JSON block above to your Cursor MCP config file.

### VS Code (GitHub Copilot / Continue / Cline)

**Prompts:** Depends on the extension — check extension documentation.

Config location varies by extension. The JSON block above is the standard
stdio format; consult your extension's MCP setup guide for the exact file path.

### Zed

**Prompts:** Check current Zed release notes — MCP support is active.
Config location: consult [Zed MCP docs](https://zed.dev/docs/assistant/model-context-protocol).

### Windsurf

**Prompts:** Check current Windsurf release notes.
Config location: consult Windsurf MCP documentation.

---

> **Note on prompt support:** MCP prompts require explicit client-side UI
> (a slash command picker or equivalent). Not all clients have implemented
> this yet. When prompts aren't available, ask ad-hoc — the tools work the
> same way and the model applies the same workflow.

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
  |  - All 29 tools
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
├── server.py              # FastMCP server (29 tools, 4 prompts, stdio transport)
├── Dockerfile             # Single-stage Alpine image
├── docker-compose.yml     # Build target
├── Makefile               # build/test/shell
├── requirements.txt       # Python dependencies
├── test-mcp-stdio.sh      # End-to-end stdio test
├── prompts/               # Analyst prompt text files (MCP prompts)
├── tools/
│   ├── check_shim.sh          # Verify mcp-shim + dns-mcp stack end-to-end
│   └── soc_email_forensics.sh # AI forensics on raw .eml files (stdio or http)
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

## HTTP Transport via mcp-shim

For clients that need MCP Streamable HTTP transport instead of stdio (headless
batch workflows, remote access via reverse proxy), use
[mcp-shim](../mcp-shim) — a lightweight Go bridge that exposes the stdio
server over HTTP without modifying `server.py`.

### Start the shim

```bash
nohup ~/projects/mcp-shim/mcp-shim \
  --addr 127.0.0.1:58676 \
  --idle 30m \
  -- docker run --rm -i --dns 9.9.9.9 dns-mcp python server.py \
  > /tmp/shim.log 2>&1 &

curl -sf http://127.0.0.1:58676/health && echo "shim ready"
```

- Listens on loopback only (port 58676)
- Spins up one dns-mcp docker container per MCP session
- Containers are reaped after 30 minutes of inactivity
- `tail -f /tmp/shim.log` shows live tool call traffic

### MCP config for HTTP clients

```json
{
  "mcpServers": {
    "dns-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:58676/mcp"
    }
  }
}
```

### Verify the stack end-to-end

```bash
export ANTHROPIC_API_KEY=sk-ant-...
./tools/check_shim.sh                    # looks up deflationhollow.net
./tools/check_shim.sh example.com        # or any domain
```

Runs a single `dns_query` tool call via claude (~10s, ~$0.001). Confirms API
key, shim reachability, docker startup, and MCP tool call routing in one shot.
Any failure is reported before tokens are spent.

### Session lifecycle

Each `initialize` from an MCP client spawns a fresh dns-mcp container. For
long-running clients (interactive claude sessions, claude.ai), the container
stays warm for the session duration and is reaped after 30 minutes idle.
Batch scripts that invoke `claude -p` per email get one container per email —
acceptable overhead, and reliable because docker startup is managed by the shim
rather than racing against the client's subprocess timeout.

### Remote access

For network-accessible deployment, put Caddy (or nginx) in front of the shim
with TLS termination and auth. The shim itself has no authentication — keep it
on loopback and let the reverse proxy handle access control.

## License

MIT
