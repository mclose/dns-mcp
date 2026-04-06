#!/usr/bin/env bash
# check_shim.sh — Verify the mcp-shim + dns-mcp stack is healthy.
#
# Runs a single DNS lookup via claude using the shim, confirming:
#   1. ANTHROPIC_API_KEY is set and valid
#   2. mcp-shim is reachable on port 58676
#   3. dns-mcp docker container spins up and responds
#   4. MCP tool calls are flowing end-to-end
#
# Usage:
#   ./tools/check_shim.sh [domain]
#
# Examples:
#   ./tools/check_shim.sh
#   ./tools/check_shim.sh deflationhollow.net
#   ./tools/check_shim.sh example.com

set -euo pipefail

SHIM_URL="http://127.0.0.1:58676/mcp"
DOMAIN="${1:-deflationhollow.net}"
MODEL="claude-haiku-4-5-20251001"

# ── Sanity checks ─────────────────────────────────────────────────────────────
if ! command -v claude >/dev/null 2>&1; then
  echo "ERROR: claude CLI not found in PATH" >&2
  exit 1
fi
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "ERROR: ANTHROPIC_API_KEY not set. Run: export \$(grep ANTHROPIC_API_KEY .env)" >&2
  exit 1
fi
if ! curl -sf "${SHIM_URL%/mcp}/health" >/dev/null 2>&1; then
  echo "ERROR: mcp-shim not reachable at $SHIM_URL" >&2
  echo ""
  echo "Start it with:"
  echo "  nohup ~/projects/mcp-shim/mcp-shim \\"
  echo "    --addr 127.0.0.1:58676 --idle 30m \\"
  echo "    -- docker run --rm -i --dns 9.9.9.9 dns-mcp python server.py \\"
  echo "    > /tmp/shim.log 2>&1 &"
  exit 1
fi

# ── Temp MCP config ───────────────────────────────────────────────────────────
MCP_CFG=$(mktemp /tmp/shim-check-XXXXX.json)
trap 'rm -f "$MCP_CFG"' EXIT

cat > "$MCP_CFG" <<EOF
{
  "mcpServers": {
    "dns-mcp": {
      "type": "http",
      "url": "$SHIM_URL"
    }
  }
}
EOF

# ── Run ───────────────────────────────────────────────────────────────────────
echo "── Shim:   $SHIM_URL  ✓"
echo "── Domain: $DOMAIN"
echo "── Model:  $MODEL"
echo ""

claude \
  -p "Use dns_query to look up the A record for ${DOMAIN} and report the result." \
  --model "$MODEL" \
  --mcp-config "$MCP_CFG" \
  --strict-mcp-config \
  --allowedTools "mcp__dns-mcp__*" \
  --max-turns 3

echo ""
echo "── Done. If you saw a DNS result above, the stack is healthy."
