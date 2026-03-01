# DNS MCP Server - Quick Reference

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt
sudo apt install moreutils  # for 'ts' command

# 2. Start server
./startup.sh

# 3. Test
./mcp-test/mcp-test.sh -u http://localhost:8082/mcp \
  -t YOUR_BEARER_TOKEN_HERE
```

## Available Tools

| Tool | Description | Example Args |
|------|-------------|--------------|
| `dns_query` | Standard DNS lookup | `domain="example.com", record_type="A"` |
| `dns_dig_style` | Detailed dig-style query with DNSSEC flags | `domain="google.com", record_type="MX", nameserver="8.8.8.8"` |
| `reverse_dns` | PTR record lookup | `ip_address="8.8.8.8"` |
| `timestamp_converter` | Time format conversion | `timestamp=1705334400, convert_to="iso"` |

## Common Commands

```bash
# Start server (MCP on 8083, proxy on 8082)
./startup.sh

# Run FastMCP directly without proxy (dev mode)
python server.py

# Test with bearer token
curl -X POST http://localhost:8082/mcp \
  -H "Authorization: Bearer YOUR_BEARER_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{"method": "initialize", "params": {}}'

# View logs
tail -f /var/log/dns-mcp-access.log
```

## Lovable Integration

1. Add to Lovable:
   - **Settings** -> **Connectors** -> **Personal connectors**
   - **Add custom MCP server**
   - **Name**: DNS Query Server
   - **URL**: `https://YOUR_MCP_ENDPOINT/mcp`
   - **Auth**: Bearer token
   - **Token**: `YOUR_BEARER_TOKEN_HERE`

3. Test in Lovable:
   ```
   "Look up the A records for example.com"
   "What's the reverse DNS for 1.1.1.1?"
   "Do a dig-style query for cloudflare.com"
   ```

## Test Queries

```bash
# DNS query
./mcp-test/mcp-test.sh -u http://localhost:8082/mcp \
  -t YOUR_BEARER_TOKEN_HERE \
  -m tools/call -p '{"name":"dns_query","arguments":{"domain":"example.com"}}'

# Dig-style with DNSSEC info
./mcp-test/mcp-test.sh -u http://localhost:8082/mcp \
  -t YOUR_BEARER_TOKEN_HERE \
  -m tools/call -p '{"name":"dns_dig_style","arguments":{"domain":"cloudflare.com","nameserver":"8.8.8.8"}}'

# Reverse DNS
./mcp-test/mcp-test.sh -u http://localhost:8082/mcp \
  -t YOUR_BEARER_TOKEN_HERE \
  -m tools/call -p '{"name":"reverse_dns","arguments":{"ip_address":"8.8.8.8"}}'
```

## Environment Variables

```bash
# Custom bearer token (optional)
export MCP_BEARER_TOKEN="your-custom-token"
```

## Fail2ban Setup

```bash
sudo cp fail2ban/filter.d/dns-mcp.conf /etc/fail2ban/filter.d/
sudo cp fail2ban/jail.d/dns-mcp.conf /etc/fail2ban/jail.d/
sudo systemctl reload fail2ban
```

## Troubleshooting

### Server not starting
```bash
# Check if ports are in use
lsof -i :8082
lsof -i :8083

# Check Python dependencies
pip install -r requirements.txt
```

### Auth errors (401)
- Verify bearer token matches
- Check Authorization header format: `Bearer <token>`

### Connection refused
- Ensure both proxy (8082) and MCP server (8083) are running
- Check startup.sh output for errors

## File Structure

```
dns-mcp/
├── server.py              # FastMCP DNS server (port 8083)
├── server-proxy.py        # Flask auth proxy (port 8082)
├── startup.sh             # Start both services
├── requirements.txt       # Python dependencies
├── fail2ban/              # Fail2ban configs
├── README.md              # Full documentation
└── QUICKSTART.md          # This file
```

## Links

- FastMCP: https://gofastmcp.com/
- dnspython: https://dnspython.readthedocs.io/
- MCP Spec: https://modelcontextprotocol.io/
