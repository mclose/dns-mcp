#!/usr/bin/env bash

# DNS MCP Server - stdio Transport End-to-End Tests
#
# Exercises every tool over the MCP protocol via stdin/stdout.
#
# The stdio transport is used by Claude Desktop and other local clients that
# spawn the server as a subprocess. No auth, no sessions, no SSE — just
# JSON-RPC lines on stdin/stdout.
#
# Usage:
#   ./test-mcp-stdio.sh                    # ephemeral container (dns-mcp image)
#   ./test-mcp-stdio.sh <image>            # ephemeral container, custom image
#   ./test-mcp-stdio.sh --exec <container> # exec into an already-running container
#
# The --exec mode spawns a new server process inside the running container
# (e.g., the one Claude Desktop created). Same image, same deps — just a
# fresh stdio session that doesn't disturb the existing connection.
#
# Prerequisites:
#   make build                              # image must exist (ephemeral mode)
#   docker ps                               # container must be running (--exec mode)

set -e

MODE="run"
IMAGE="dns-mcp"
CONTAINER=""

if [ "$1" = "--exec" ]; then
    if [ -z "$2" ]; then
        echo "Usage: $0 --exec <container_name_or_id>"
        exit 1
    fi
    MODE="exec"
    CONTAINER="$2"
elif [ -n "$1" ]; then
    IMAGE="$1"
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

# call_tool <test_num> <label> <json_body>
#   Sends a JSON-RPC request via FD 3 (server stdin), reads response from FD 4 (server stdout).
call_tool() {
    local num="$1" label="$2" body="$3"
    echo -e "${YELLOW}[${num}] ${label}${NC}"
    echo "$body" | jq .
    echo "$body" >&3
    local response
    if read -t 30 -r response <&4; then
        echo "$response" | jq .
        PASS=$((PASS + 1))
    else
        echo -e "${RED}  FAILED - no response (30s timeout)${NC}"
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

# ── Banner ───────────────────────────────────────────────────

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DNS MCP Server - stdio Transport Tests${NC}"
echo -e "${BLUE}========================================${NC}"
if [ "$MODE" = "exec" ]; then
    echo -e "Mode:      exec into running container"
    echo -e "Container: ${CONTAINER}"
else
    echo -e "Mode:  ephemeral container"
    echo -e "Image: ${IMAGE}"
fi
echo ""

# ── Start server (named pipes — works on bash 3.2+/macOS) ────

FIFO_DIR=$(mktemp -d)
mkfifo "$FIFO_DIR/in" "$FIFO_DIR/out"

if [ "$MODE" = "exec" ]; then
    echo -e "${BLUE}Exec'ing into container ${CONTAINER}...${NC}"
    docker exec -i "$CONTAINER" python server.py --stdio < "$FIFO_DIR/in" > "$FIFO_DIR/out" 2>/dev/null &
else
    echo -e "${BLUE}Starting ephemeral container...${NC}"
    docker run --rm -i "$IMAGE" python server.py --stdio < "$FIFO_DIR/in" > "$FIFO_DIR/out" 2>/dev/null &
fi
MCP_PID=$!

# Open FDs — write end unblocks docker's stdin read, then docker's stdout unblocks our read
exec 3>"$FIFO_DIR/in" 4<"$FIFO_DIR/out"

cleanup() {
    exec 3>&- 2>/dev/null || true
    exec 4<&- 2>/dev/null || true
    wait $MCP_PID 2>/dev/null || true
    rm -rf "$FIFO_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Give the server a moment to start
sleep 1

# ── Test 1: Initialize ───────────────────────────────────────

echo -e "${YELLOW}[1] Initialize${NC}"
INIT_BODY='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-mcp-stdio.sh","version":"1.0.0"}}}'
echo "$INIT_BODY" | jq .
echo "$INIT_BODY" >&3

INIT_RESPONSE=""
if read -t 10 -r INIT_RESPONSE <&4; then
    echo "$INIT_RESPONSE" | jq .
    SERVER_NAME=$(echo "$INIT_RESPONSE" | jq -r '.result.serverInfo.name // empty')
    if [ -n "$SERVER_NAME" ]; then
        echo -e "${GREEN}  Server: ${SERVER_NAME}${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}  FAILED - no serverInfo in response${NC}"
        FAIL=$((FAIL + 1))
    fi
else
    echo -e "${RED}  FAILED - no response (10s timeout). Is the image built?${NC}"
    exit 1
fi
echo ""

# Send required initialized notification (no response expected)
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}' >&3
sleep 0.5

# ── Test 2: List tools ───────────────────────────────────────

echo -e "${YELLOW}[2] List Tools (expect 21)${NC}"
LIST_BODY='{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
echo "$LIST_BODY" | jq .
echo "$LIST_BODY" >&3

LIST_RESPONSE=""
if read -t 10 -r LIST_RESPONSE <&4; then
    TOOL_NAMES=$(echo "$LIST_RESPONSE" | jq -r '.result.tools[].name' 2>/dev/null)
    TOOL_COUNT=$(echo "$TOOL_NAMES" | wc -l | tr -d ' ')
    echo -e "  Tools found: ${TOOL_COUNT}"
    echo "$TOOL_NAMES" | while read -r name; do echo "    - $name"; done

    if [ "$TOOL_COUNT" -ge 21 ]; then
        PASS=$((PASS + 1))
    else
        echo -e "${RED}  EXPECTED 21 tools, got ${TOOL_COUNT}${NC}"
        FAIL=$((FAIL + 1))
    fi
else
    echo -e "${RED}  FAILED - no response (10s timeout)${NC}"
    FAIL=$((FAIL + 1))
fi
echo ""

# ── Test 3: ping ─────────────────────────────────────────────

call_tool 3 "ping (health check)" \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}'

call_tool 4 "server_info (resolver config)" \
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"server_info","arguments":{}}}'

# ── DNS Tools ────────────────────────────────────────────────

call_tool 5 "dns_query - google.com A record" \
    '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"dns_query","arguments":{"domain":"google.com"}}}'

call_tool 6 "dns_dig_style - google.com (DNSSEC flags)" \
    '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"dns_dig_style","arguments":{"domain":"google.com","nameserver":"9.9.9.9"}}}'

call_tool 7 "dns_query - lab.deflationhollow.net A record" \
    '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"dns_query","arguments":{"domain":"lab.deflationhollow.net"}}}'

call_tool 8 "dns_dig_style - lab.deflationhollow.net (DNSSEC)" \
    '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"dns_dig_style","arguments":{"domain":"lab.deflationhollow.net","nameserver":"9.9.9.9"}}}'

call_tool 9 "reverse_dns - 9.9.9.9" \
    '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"reverse_dns","arguments":{"ip_address":"9.9.9.9"}}}'

call_tool 10 "dns_dnssec_validate - claude.lab.deflationhollow.net (chain of trust)" \
    '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"dns_dnssec_validate","arguments":{"domain":"claude.lab.deflationhollow.net","record_type":"A","nameserver":"9.9.9.9"}}}'

call_tool 11 "nsec_info - cloudflare.com (NSEC/NSEC3 analysis)" \
    '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"nsec_info","arguments":{"domain":"cloudflare.com"}}}'

call_tool 12 "timestamp_converter - epoch to ISO" \
    '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"timestamp_converter","arguments":{"timestamp":1705314600,"convert_to":"iso"}}}'

# ── Email Security Tools ─────────────────────────────────────

call_tool 13 "check_spf - google.com" \
    '{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"check_spf","arguments":{"domain":"google.com"}}}'

call_tool 14 "check_dmarc - google.com" \
    '{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"check_dmarc","arguments":{"domain":"google.com"}}}'

call_tool 15 "check_dkim_selector - google (20230601._domainkey.gmail.com)" \
    '{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"check_dkim_selector","arguments":{"selector":"20230601","domain":"gmail.com"}}}'

call_tool 16 "check_bimi - cnn.com (known BIMI adopter)" \
    '{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"check_bimi","arguments":{"domain":"cnn.com"}}}'

call_tool 17 "check_mta_sts - google.com" \
    '{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"check_mta_sts","arguments":{"domain":"google.com"}}}'

call_tool 18 "check_smtp_tlsrpt - google.com" \
    '{"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"check_smtp_tlsrpt","arguments":{"domain":"google.com"}}}'

call_tool 19 "rdap_lookup - google.com (domain registration)" \
    '{"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"rdap_lookup","arguments":{"domain":"google.com"}}}'

# ── Utility Tools ────────────────────────────────────────────

call_tool 20 "quine - server source introspection" \
    '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"quine","arguments":{}}}'

call_tool 21 "check_dane - bund.de (known DANE deployer)" \
    '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"check_dane","arguments":{"domain":"bund.de"}}}'

call_tool 22 "check_tlsa - _25._tcp.mx1.bund.de (SMTP TLSA)" \
    '{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"check_tlsa","arguments":{"hostname":"mx1.bund.de","port":25,"protocol":"tcp","nameserver":"9.9.9.9"}}}'

call_tool 23 "detect_hijacking - 9.9.9.9 (Quad9)" \
    '{"jsonrpc":"2.0","id":23,"method":"tools/call","params":{"name":"detect_hijacking","arguments":{"resolver":"9.9.9.9"}}}'

call_tool 24 "session_stats - container lifetime stats" \
    '{"jsonrpc":"2.0","id":24,"method":"tools/call","params":{"name":"session_stats","arguments":{}}}'

call_tool 25 "reset_stats - reset session clock and counters" \
    '{"jsonrpc":"2.0","id":25,"method":"tools/call","params":{"name":"reset_stats","arguments":{}}}'

# ── Analyst Prompts ───────────────────────────────────────────

echo -e "${YELLOW}[26] List Prompts (expect 3)${NC}"
PROMPTS_LIST_BODY='{"jsonrpc":"2.0","id":26,"method":"prompts/list"}'
echo "$PROMPTS_LIST_BODY" | jq .
echo "$PROMPTS_LIST_BODY" >&3
if read -t 10 -r PROMPTS_LIST_RESPONSE <&4; then
    PROMPT_NAMES=$(echo "$PROMPTS_LIST_RESPONSE" | jq -r '.result.prompts[].name' 2>/dev/null)
    PROMPT_COUNT=$(echo "$PROMPT_NAMES" | grep -c . || true)
    echo -e "  Prompts found: ${PROMPT_COUNT}"
    echo "$PROMPT_NAMES" | while read -r name; do echo "    - $name"; done
    if [ "$PROMPT_COUNT" -ge 3 ]; then
        PASS=$((PASS + 1))
    else
        echo -e "${RED}  EXPECTED 3 prompts, got ${PROMPT_COUNT}${NC}"
        FAIL=$((FAIL + 1))
    fi
else
    echo -e "${RED}  FAILED - no response (10s timeout)${NC}"
    FAIL=$((FAIL + 1))
fi
echo ""

echo -e "${YELLOW}[27] Get Prompt - email_security_audit${NC}"
PROMPT_GET_BODY='{"jsonrpc":"2.0","id":27,"method":"prompts/get","params":{"name":"email_security_audit"}}'
echo "$PROMPT_GET_BODY" | jq .
echo "$PROMPT_GET_BODY" >&3
if read -t 10 -r PROMPT_GET_RESPONSE <&4; then
    PROMPT_TEXT=$(echo "$PROMPT_GET_RESPONSE" | jq -r '.result.messages[0].content.text // empty' 2>/dev/null)
    if echo "$PROMPT_TEXT" | grep -q "email security auditor"; then
        echo -e "  Content verified (contains 'email security auditor')"
        echo "$PROMPT_GET_RESPONSE" | jq '{id: .id, messages_count: (.result.messages | length)}'
        PASS=$((PASS + 1))
    else
        echo -e "${RED}  FAILED - prompt content missing expected text${NC}"
        echo "$PROMPT_GET_RESPONSE" | jq .
        FAIL=$((FAIL + 1))
    fi
else
    echo -e "${RED}  FAILED - no response (10s timeout)${NC}"
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
