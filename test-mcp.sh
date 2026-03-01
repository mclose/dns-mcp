#!/usr/bin/env bash

# DNS MCP Server - End-to-End Test Script
#
# Exercises every tool over the MCP protocol via the auth proxy.
# This is the "poke the server from the command line" tool.
# MCP isn't magic — it's just HTTP endpoints tailored for AI consumption.
#
# Usage:
#   ./test-mcp.sh [url] [token]
#   ./test-mcp.sh                                           # localhost + token from .env
#   ./test-mcp.sh http://localhost:8082/mcp changeme         # explicit
#   ./test-mcp.sh https://your-server.example.com/mcp mytoken  # remote

set -e

URL="${1:-http://localhost:8082/mcp}"

# Default token: read from .env if it exists, else fall back to "changeme"
if [ -z "$2" ]; then
    if [ -f .env ]; then
        TOKEN=$(grep '^MCP_BEARER_TOKEN=' .env | cut -d= -f2-)
    fi
    TOKEN="${TOKEN:-changeme}"
else
    TOKEN="$2"
fi

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

PASS=0
FAIL=0

# ── Helpers ──────────────────────────────────────────────────

parse_sse() {
    grep '^data: ' | sed 's/^data: //' | jq .
}

# call_tool <test_num> <label> <json_body>
#   Sends a JSON-RPC request with auth + session, parses SSE response.
call_tool() {
    local num="$1" label="$2" body="$3"
    echo -e "${YELLOW}[${num}] ${label}${NC}"
    echo -e "${GREEN}>>> POST ${URL}${NC}"
    echo "$body" | jq .

    local output
    output=$(curl -sf -X POST "$URL" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "mcp-session-id: $SESSION_ID" \
        -d "$body" 2>&1) || true

    if [ -n "$output" ]; then
        echo "$output" | grep '^data: ' | sed 's/^data: //' | jq .
        PASS=$((PASS + 1))
    else
        echo -e "${RED}  FAILED - no response${NC}"
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

# ── Banner ───────────────────────────────────────────────────

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DNS MCP Server - End-to-End Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "URL:   ${URL}"
echo -e "Token: ${TOKEN:0:20}..."
echo ""

# ── Test 1: Initialize (get session ID) ─────────────────────

echo -e "${YELLOW}[1] Initialize - Getting session ID${NC}"
echo -e "${GREEN}>>> POST ${URL}${NC}"
INIT_BODY='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-mcp.sh","version":"2.0.0"}}}'
echo "$INIT_BODY" | jq .

INIT_RESPONSE=$(curl -s -i -X POST "$URL" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d "$INIT_BODY")

SESSION_ID=$(echo "$INIT_RESPONSE" | grep -i '^mcp-session-id:' | tr -d '\r' | cut -d' ' -f2)
echo -e "${GREEN}<<< Session ID: ${SESSION_ID}${NC}"
echo "$INIT_RESPONSE" | grep '^data: ' | sed 's/^data: //' | jq .
echo ""

if [ -z "$SESSION_ID" ]; then
    echo -e "${RED}ERROR: Failed to get session ID. Is the server running?${NC}"
    exit 1
fi
PASS=$((PASS + 1))

# ── Test 2: List tools ──────────────────────────────────────

echo -e "${YELLOW}[2] List Tools (expect 16)${NC}"
echo -e "${GREEN}>>> POST ${URL}${NC}"
LIST_BODY='{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
echo "$LIST_BODY" | jq .

LIST_RESPONSE=$(curl -s -X POST "$URL" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "mcp-session-id: $SESSION_ID" \
    -d "$LIST_BODY")

TOOL_NAMES=$(echo "$LIST_RESPONSE" | grep '^data: ' | sed 's/^data: //' | jq -r '.result.tools[].name' 2>/dev/null)
TOOL_COUNT=$(echo "$TOOL_NAMES" | wc -l | tr -d ' ')
echo -e "  Tools found: ${TOOL_COUNT}"
echo "$TOOL_NAMES" | while read -r name; do echo "    - $name"; done
echo ""

if [ "$TOOL_COUNT" -ge 16 ]; then
    PASS=$((PASS + 1))
else
    echo -e "${RED}  EXPECTED 16 tools, got ${TOOL_COUNT}${NC}"
    FAIL=$((FAIL + 1))
fi

# ── DNS Tools ────────────────────────────────────────────────

call_tool 3 "dns_query - google.com A record" \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"dns_query","arguments":{"domain":"google.com"}}}'

call_tool 4 "dns_dig_style - google.com (DNSSEC flags)" \
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"dns_dig_style","arguments":{"domain":"google.com","nameserver":"8.8.8.8"}}}'

call_tool 5 "dns_query - lab.deflationhollow.net A record" \
    '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"dns_query","arguments":{"domain":"lab.deflationhollow.net"}}}'

call_tool 6 "dns_dig_style - lab.deflationhollow.net (DNSSEC)" \
    '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"dns_dig_style","arguments":{"domain":"lab.deflationhollow.net","nameserver":"8.8.8.8"}}}'

call_tool 7 "reverse_dns - 8.8.8.8" \
    '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"reverse_dns","arguments":{"ip_address":"8.8.8.8"}}}'

call_tool 8 "dns_dnssec_validate - claude.lab.deflationhollow.net (chain of trust)" \
    '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"dns_dnssec_validate","arguments":{"domain":"claude.lab.deflationhollow.net","record_type":"A","nameserver":"8.8.8.8"}}}'

call_tool 9 "nsec_info - cloudflare.com (NSEC/NSEC3 analysis)" \
    '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"nsec_info","arguments":{"domain":"cloudflare.com"}}}'

call_tool 10 "timestamp_converter - epoch to ISO" \
    '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"timestamp_converter","arguments":{"timestamp":1705314600,"convert_to":"iso"}}}'

# ── Email Security Tools ─────────────────────────────────────

call_tool 11 "check_spf - google.com" \
    '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"check_spf","arguments":{"domain":"google.com"}}}'

call_tool 12 "check_dmarc - google.com" \
    '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"check_dmarc","arguments":{"domain":"google.com"}}}'

call_tool 13 "check_dkim_selector - google (20230601._domainkey.gmail.com)" \
    '{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"check_dkim_selector","arguments":{"selector":"20230601","domain":"gmail.com"}}}'

call_tool 14 "check_bimi - cnn.com (known BIMI adopter)" \
    '{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"check_bimi","arguments":{"domain":"cnn.com"}}}'

call_tool 15 "check_mta_sts - google.com" \
    '{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"check_mta_sts","arguments":{"domain":"google.com"}}}'

call_tool 16 "check_smtp_tlsrpt - google.com" \
    '{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"check_smtp_tlsrpt","arguments":{"domain":"google.com"}}}'

call_tool 17 "rdap_lookup - google.com (domain registration)" \
    '{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"rdap_lookup","arguments":{"domain":"google.com"}}}'

# ── Utility Tools ───────────────────────────────────────────

call_tool 18 "quine - server source introspection" \
    '{"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"quine","arguments":{}}}'

call_tool 19 "check_dane - bund.de (known DANE deployer)" \
    '{"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"check_dane","arguments":{"domain":"bund.de"}}}'

# ── Auth Rejection ───────────────────────────────────────────

echo -e "${YELLOW}[20] Auth rejection test (expect 401)${NC}"
echo -e "${GREEN}>>> POST ${URL} (with bad token)${NC}"

REJECT_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$URL" \
    -H "Authorization: Bearer bad-token" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":20,"method":"initialize","params":{}}')

HTTP_CODE=$(echo "$REJECT_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$REJECT_RESPONSE" | grep -v "HTTP_CODE:")

echo -e "  HTTP Status: ${HTTP_CODE}"
echo "$BODY" | jq . 2>/dev/null || echo "$BODY"

if [ "$HTTP_CODE" = "401" ]; then
    PASS=$((PASS + 1))
else
    echo -e "${RED}  EXPECTED 401, got ${HTTP_CODE}${NC}"
    FAIL=$((FAIL + 1))
fi
echo ""

# ── Summary ──────────────────────────────────────────────────

TOTAL=$((PASS + FAIL))
echo -e "${BLUE}========================================${NC}"
if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}All ${TOTAL} tests passed${NC}"
else
    echo -e "${RED}${FAIL}/${TOTAL} tests FAILED${NC}"
fi
echo -e "${BLUE}========================================${NC}"

exit "$FAIL"
