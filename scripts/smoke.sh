#!/usr/bin/env bash
#
# smoke.sh — end-to-end curl-based smoke test for dns-mcp.
#
# Every step prints the curl command verbatim so this script doubles as
# a usage cookbook. Exit non-zero on any failure with a labeled message.
#
# Usage:
#   scripts/smoke.sh                       # against https://dns-mcp.lab.deflationhollow.net
#   scripts/smoke.sh URL                   # custom base URL
#   scripts/smoke.sh URL TOKEN             # also run authenticated MCP steps
#
# Env:
#   DNS_MCP_URL    — overrides the base URL (same as $1)
#   DNS_MCP_TOKEN  — bearer JWT for authenticated MCP steps (same as $2)
#
# Returns 0 if every step passes, 1 on the first failure.
set -u
set -o pipefail

BASE="${1:-${DNS_MCP_URL:-https://dns-mcp.lab.deflationhollow.net}}"
TOKEN="${2:-${DNS_MCP_TOKEN:-}}"

# ── output helpers ──────────────────────────────────────────────────────
if [ -t 1 ]; then
  C_HDR=$'\033[1;34m'; C_OK=$'\033[1;32m'; C_FAIL=$'\033[1;31m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
else
  C_HDR=""; C_OK=""; C_FAIL=""; C_DIM=""; C_RST=""
fi

PASS=0
FAIL=0

step() { printf '\n%s== %s ==%s\n' "$C_HDR" "$1" "$C_RST"; }
show() { printf '%s$ %s%s\n' "$C_DIM" "$1" "$C_RST"; }
ok()   { printf '%sok%s — %s\n' "$C_OK" "$C_RST" "$1"; PASS=$((PASS+1)); }
fail() { printf '%sFAIL%s — %s\n' "$C_FAIL" "$C_RST" "$1"; FAIL=$((FAIL+1)); }

# Run a curl command, write body to $BODY and HTTP status to $STATUS.
# Side-effect interface (not stdout) so $STATUS isn't lost to subshells.
BODY=
STATUS=
http() {
  local body_f status_f
  body_f=$(mktemp); status_f=$(mktemp)
  curl -sS -o "$body_f" -w '%{http_code}' "$@" > "$status_f" || true
  STATUS=$(cat "$status_f")
  BODY=$(cat "$body_f")
  rm -f "$body_f" "$status_f"
}

# Assert response status matches expected, otherwise print body excerpt.
expect_status() {
  local got="$1" want="$2" label="$3" body="$4"
  if [ "$got" = "$want" ]; then
    ok "$label (HTTP $got)"
  else
    fail "$label — expected HTTP $want, got $got"
    printf '%s%s%s\n' "$C_DIM" "$(printf '%s' "$body" | head -c 400)" "$C_RST"
  fi
}

echo "Target: $BASE"
[ -n "$TOKEN" ] && echo "Token : ${TOKEN:0:20}…" || echo "Token : (none — auth steps will be skipped)"

# ── 1. /health ──────────────────────────────────────────────────────────
step "health probe"
show "curl $BASE/health"
http "$BASE/health"
expect_status "$STATUS" 200 "/health returns 200" "$BODY"
if echo "$BODY" | grep -q '"status": *"ok"'; then
  ok "/health body has status=ok"
else
  fail "/health body missing status=ok"
fi

# ── 2. OAuth discovery doc ──────────────────────────────────────────────
step "OAuth discovery (RFC 8414)"
show "curl $BASE/.well-known/oauth-authorization-server"
http "$BASE/.well-known/oauth-authorization-server"
expect_status "$STATUS" 200 "discovery doc returns 200" "$BODY"
for key in issuer authorization_endpoint token_endpoint jwks_uri registration_endpoint; do
  if echo "$BODY" | grep -q "\"$key\""; then
    ok "discovery doc contains $key"
  else
    fail "discovery doc missing $key"
  fi
done

# ── 3. /oauth/authorize — must 302 to Pocket ID ─────────────────────────
step "authorize redirect"
show "curl -I '$BASE/oauth/authorize?client_id=smoke&response_type=code'"
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' -D /tmp/smoke-hdrs \
  "$BASE/oauth/authorize?client_id=smoke&response_type=code" || true)
expect_status "$STATUS" 302 "authorize returns 302" ""
LOC=$(grep -i '^location:' /tmp/smoke-hdrs | head -1 | tr -d '\r\n' || true)
rm -f /tmp/smoke-hdrs
if echo "$LOC" | grep -qi 'scope=openid'; then
  ok "authorize injects 'scope=openid…' when missing"
else
  fail "authorize did not inject scope; Location: $LOC"
fi

# ── 4. Authenticated MCP flow (requires $TOKEN) ─────────────────────────
if [ -z "$TOKEN" ]; then
  step "MCP protocol (skipped — no token)"
  echo "  set \$2 or DNS_MCP_TOKEN to a Bearer JWT to run these steps."
else
  step "MCP initialize"
  INIT_PAYLOAD='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}'
  show "curl -X POST $BASE/mcp -H 'Authorization: Bearer …' -H 'Accept: application/json, text/event-stream' -d <initialize>"
  RAW=$(curl -sS -D /tmp/smoke-hdrs -o /tmp/smoke-body -w '%{http_code}' \
    -X POST "$BASE/mcp" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/json, text/event-stream" \
    -H "Content-Type: application/json" \
    -d "$INIT_PAYLOAD" || true)
  BODY=$(cat /tmp/smoke-body)
  expect_status "$RAW" 200 "initialize returns 200" "$BODY"
  SESSION=$(grep -i '^mcp-session-id:' /tmp/smoke-hdrs | awk '{print $2}' | tr -d '\r\n' || true)
  rm -f /tmp/smoke-hdrs /tmp/smoke-body
  if [ -n "$SESSION" ]; then
    ok "captured mcp-session-id: ${SESSION:0:16}…"
  else
    fail "no mcp-session-id header on initialize"
  fi

  if [ -n "$SESSION" ]; then
    step "MCP tools/list"
    show "curl -X POST $BASE/mcp -H 'mcp-session-id: $SESSION' -d <tools/list>"
    BODY=$(curl -sS \
      -X POST "$BASE/mcp" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Accept: application/json, text/event-stream" \
      -H "Content-Type: application/json" \
      -H "mcp-session-id: $SESSION" \
      -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' || true)
    if echo "$BODY" | grep -q '"name":"ping"'; then
      ok "tools/list includes ping"
    else
      fail "tools/list missing ping; body excerpt: $(printf '%s' "$BODY" | head -c 200)"
    fi
    if echo "$BODY" | grep -q '"name":"dns_query"'; then
      ok "tools/list includes dns_query"
    else
      fail "tools/list missing dns_query"
    fi

    step "MCP tools/call ping"
    show "curl -X POST $BASE/mcp ... -d <tools/call name=ping>"
    BODY=$(curl -sS \
      -X POST "$BASE/mcp" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Accept: application/json, text/event-stream" \
      -H "Content-Type: application/json" \
      -H "mcp-session-id: $SESSION" \
      -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}' \
      || true)
    if echo "$BODY" | grep -q 'dns_tool_version'; then
      ok "ping response contains dns_tool_version"
    else
      fail "ping response missing dns_tool_version"
    fi

    step "MCP tools/call session_stats"
    show "curl -X POST $BASE/mcp ... -d <tools/call name=session_stats>"
    BODY=$(curl -sS \
      -X POST "$BASE/mcp" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Accept: application/json, text/event-stream" \
      -H "Content-Type: application/json" \
      -H "mcp-session-id: $SESSION" \
      -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"session_stats","arguments":{}}}' \
      || true)
    if echo "$BODY" | grep -q 'session_start'; then
      ok "session_stats response contains session_start"
    else
      fail "session_stats response missing session_start"
    fi
  fi
fi

# ── summary ─────────────────────────────────────────────────────────────
printf '\n%s\n' "────────────────────────────────"
printf '%s%d passed%s, %s%d failed%s\n' \
  "$C_OK" "$PASS" "$C_RST" "$C_FAIL" "$FAIL" "$C_RST"
[ "$FAIL" -eq 0 ]
