#!/usr/bin/env bash
# email_security_posture_claude.sh
# Spins up a fresh dns-mcp container per run, audits a domain, emits JSON.
# All working files go to a temp dir and are cleaned up on exit.
# Output JSON is written to the directory you called this script from.
set -euo pipefail

# ── Parse flags ───────────────────────────────────────────────────────────────
AUTO_APPROVE=false
DKIM_SELECTORS=()
POSITIONAL=()
SKIP_NEXT=false
for i in $(seq 1 $#); do
  if [ "$SKIP_NEXT" = true ]; then
    SKIP_NEXT=false
    continue
  fi
  arg="${!i}"
  case "$arg" in
    -y|--yes) AUTO_APPROVE=true ;;
    -k|--dkim-selector)
      next_i=$((i + 1))
      next_val="${!next_i:-}"
      if [ -z "$next_val" ]; then
        echo "ERROR: --dkim-selector requires a value" >&2
        exit 1
      fi
      # Split on commas to support -k sel1,sel2
      IFS=',' read -ra sels <<< "$next_val"
      DKIM_SELECTORS+=("${sels[@]}")
      SKIP_NEXT=true
      ;;
    -h|--help)
      echo "Usage: $(basename "$0") [options] [domain]"
      echo ""
      echo "Runs Claude Code with a system prompt that audits the email security"
      echo "posture of a domain via DNS lookups (SPF, DKIM, DMARC, MTA-STS, BIMI)."
      echo "Output is a structured JSON report written to the current directory."
      echo ""
      echo "Options:"
      echo "  -y, --yes                  Auto-approve dns-mcp tool permissions (skip prompt)"
      echo "  -k, --dkim-selector SEL    Add a known DKIM selector from your provider's"
      echo "                             dashboard. Use multiple times or comma-separate."
      echo "  -h, --help                 Show this help"
      echo ""
      echo "Examples:"
      echo "  $(basename "$0") example.com"
      echo "  $(basename "$0") -y example.com"
      echo "  $(basename "$0") -k fe-abc123 -k fe-def456 example.com"
      echo "  $(basename "$0") -k fe-abc123,fe-def456 example.com"
      exit 0
      ;;
    *)        POSITIONAL+=("$arg") ;;
  esac
done
DOMAIN="${POSITIONAL[0]:-deflationhollow.net}"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
ORIG_DIR="$(pwd)"
OUTPUT_FILE="${ORIG_DIR}/posture-${DOMAIN}-${TIMESTAMP}.json"

# ── Temp workspace — cleaned up on exit (normal, error, or interrupt) ─────────
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

# ── 1. Sanity check ────────────────────────────────────────────────────────────
if ! docker image inspect dns-mcp >/dev/null 2>&1; then
  echo "ERROR: dns-mcp image not found. Run: make build" >&2
  exit 1
fi

# ── 2. MCP config — spawns a fresh container per invocation ───────────────────
cat > "$WORK_DIR/mcp.json" <<'EOF'
{
  "mcpServers": {
    "dns-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "--dns", "9.9.9.9", "dns-mcp", "python", "server.py"]
    }
  }
}
EOF

# ── 3. System prompt ───────────────────────────────────────────────────────────
cat > "$WORK_DIR/system-prompt.txt" <<'EOF'
You are an email security auditor. Use the available DNS MCP tools to check the
email security posture of the requested domain.

Step 1 — Check MX records first. Identify the mail provider from the MX
hostnames to determine whether DKIM selectors are discoverable or opaque:

  Provider fingerprints (MX pattern → selector style):
    *.google.com / aspmx.l.google.com → discoverable: google
    *.protection.outlook.com          → discoverable: selector1, selector2
    *.mailgun.org                     → discoverable: mx, mailo
    *.sendgrid.net                    → discoverable: s1, s2, smtpapi
    *.forwardemail.net                → opaque: hash-based, not guessable
    *.amazonses.com                   → opaque: UUID-based, not guessable
    *.mailchimp.com / *.mandrill.com  → discoverable: k1
    unknown / self-hosted             → unknown: attempt probe only

Step 2 — Probe DKIM selectors in this order: google, default, mail, k1, s1,
s2, smtpapi, dkim, selector1, selector2.

Step 3 — If the provider uses opaque selectors and no selector was found, set
dkim.status to "unverified" rather than "absent".

Step 4 — After completing all lookups respond ONLY with a single valid JSON
object. No prose, no markdown, no code fences. Schema:

{
  "domain": "<string>",
  "timestamp": "<ISO-8601 UTC>",
  "mx": {
    "records": ["<string>"],
    "provider": "<identified provider name or unknown>",
    "dkim_selector_style": "<discoverable|opaque|unknown>",
    "issues": ["<string>"]
  },
  "spf": {
    "present": <bool>,
    "record": "<raw TXT or null>",
    "pass_policy": "<pass|softfail|fail|neutral|none>",
    "issues": ["<string>"]
  },
  "dkim": {
    "selectors_checked": ["<string>"],
    "found": [{ "selector": "<string>", "record": "<raw TXT>" }],
    "status": "<verified|unverified|absent>",
    "issues": ["<string>"]
  },
  "dmarc": {
    "present": <bool>,
    "record": "<raw TXT or null>",
    "policy": "<none|quarantine|reject>",
    "pct": <int 0-100>,
    "rua": "<URI or null>",
    "ruf": "<URI or null>",
    "issues": ["<string>"]
  },
  "bimi": {
    "present": <bool>,
    "record": "<raw TXT or null>"
  },
  "mta_sts": {
    "present": <bool>,
    "policy_mode": "<enforce|testing|none>"
  },
  "summary": {
    "overall_grade": "<A|A-|B|C|D|F>",
    "critical_issues": ["<string>"],
    "recommendations": ["<string>"]
  }
}

Grading rubric:
  A  = SPF strict (-all), DMARC reject at 100%, DKIM verified, MTA-STS enforce
  A- = SPF strict (-all), DMARC reject at 100%, DKIM verified, MTA-STS missing
  B  = Any of: DMARC quarantine or reject <100%, DKIM unverified (opaque
       provider), or SPF present but not strict
  C  = SPF present, DMARC none or missing, DKIM found
  D  = SPF softfail or missing, no DMARC, DKIM unknown
  F  = No SPF, no DMARC, no DKIM
EOF

# Append provider-specific selectors if supplied via --dkim-selector
if [ ${#DKIM_SELECTORS[@]} -gt 0 ]; then
  {
    echo ""
    echo "IMPORTANT — The operator has provided known DKIM selectors from their"
    echo "provider dashboard. Probe these FIRST, before the standard list above."
    echo "If any of these resolve, mark dkim.status as \"verified\"."
    echo ""
    echo "Provider-supplied selectors:"
    for sel in "${DKIM_SELECTORS[@]}"; do
      echo "  - $sel"
    done
  } >> "$WORK_DIR/system-prompt.txt"
fi

# ── 4. Permissions prompt ─────────────────────────────────────────────────────

# list_mcp_tools — spins up a throwaway container, queries tools/list via MCP
list_mcp_tools() {
  local fifo_dir
  fifo_dir=$(mktemp -d)
  mkfifo "$fifo_dir/in" "$fifo_dir/out"

  docker run --rm -i dns-mcp python server.py --stdio \
    < "$fifo_dir/in" > "$fifo_dir/out" 2>/dev/null &
  local pid=$!

  exec 5>"$fifo_dir/in" 6<"$fifo_dir/out"
  sleep 1

  # Initialize handshake
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"tool-lister","version":"1.0.0"}}}' >&5
  read -t 5 -r _ <&6 || true
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}' >&5
  sleep 0.3

  # Request tool list
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' >&5
  local response
  if read -t 5 -r response <&6; then
    echo "$response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
tools = data.get('result', {}).get('tools', [])
for t in tools:
    desc = t.get('description', '').split('.')[0]
    print(f\"    {t['name']:30s} {desc}\")
" 2>/dev/null
  else
    echo "    (could not retrieve tool list)"
  fi

  # Cleanup
  exec 5>&- 2>/dev/null || true
  exec 6<&- 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -rf "$fifo_dir" 2>/dev/null || true
}

ALLOWED_TOOLS_FLAG=()
if [ "$AUTO_APPROVE" = true ]; then
  echo "── Auto-approving dns-mcp tool permissions (--yes)"
  ALLOWED_TOOLS_FLAG=(--allowedTools "mcp__dns-mcp__*")
else
  while true; do
    echo ""
    echo "This script uses MCP tools from the dns-mcp server."
    echo "These are read-only DNS lookups (dig, whois, etc.) with no side effects."
    echo ""
    read -r -p "Allow all dns-mcp tools for this run? [y/N/l to list] " response
    case "$response" in
      [lL])
        echo ""
        echo "  Tools provided by dns-mcp:"
        list_mcp_tools
        ;;
      [yY]|[yY][eE][sS])
        ALLOWED_TOOLS_FLAG=(--allowedTools "mcp__dns-mcp__*")
        break
        ;;
      *)
        echo "Proceeding without pre-approved permissions."
        echo "Claude will prompt for each tool individually."
        break
        ;;
    esac
  done
fi

# ── 5. Run ─────────────────────────────────────────────────────────────────────
echo ""
echo "── Domain:  $DOMAIN"
if [ ${#DKIM_SELECTORS[@]} -gt 0 ]; then
  echo "── DKIM:    ${DKIM_SELECTORS[*]}"
fi
echo "── Output:  $OUTPUT_FILE"
echo ""

claude \
  -p "Check the email security posture of ${DOMAIN}" \
  --model claude-sonnet-4-6 \
  --mcp-config "$WORK_DIR/mcp.json" \
  --system-prompt-file "$WORK_DIR/system-prompt.txt" \
  --output-format text \
  --max-turns 15 \
  "${ALLOWED_TOOLS_FLAG[@]}" \
  > "$WORK_DIR/raw-output.txt"

# Extract the JSON object — Claude sometimes emits prose before/after it
python3 -c "
import sys, json
text = open(sys.argv[1]).read()
start = text.index('{')
end = text.rindex('}') + 1
obj = json.loads(text[start:end])
json.dump(obj, open(sys.argv[2], 'w'))
json.dump(obj, sys.stdout, indent=2)
" "$WORK_DIR/raw-output.txt" "$OUTPUT_FILE"

echo ""
echo "── Done: $OUTPUT_FILE"
