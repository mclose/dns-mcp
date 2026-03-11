#!/usr/bin/env bash
# soc_email_forensics.sh
# Forensic phishing analysis of a raw email (.eml / .txt) via the
# soc_email_forensics MCP prompt. Spins up a fresh dns-mcp container per run.
#
# Output (written to the directory you called this script from):
#   forensics-<timestamp>.txt  — full narrative analysis
#   forensics-<timestamp>.json — structured summary (verdict, from, dates, confidence)
#
# Usage:
#   ./tools/soc_email_forensics.sh [options] email.txt
#   cat email.txt | ./tools/soc_email_forensics.sh [options] -
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROMPT_FILE="$SCRIPT_DIR/../prompts/soc_email_forensics.txt"

# ── Parse flags ───────────────────────────────────────────────────────────────
AUTO_APPROVE=false
POSITIONAL=()
for arg in "$@"; do
  case "$arg" in
    -y|--yes) AUTO_APPROVE=true ;;
    -h|--help)
      echo "Usage: $(basename "$0") [options] <email.txt|->"
      echo ""
      echo "Forensic phishing analysis of a raw email with full headers."
      echo "Writes a narrative .txt report and a structured .json summary."
      echo ""
      echo "Options:"
      echo "  -y, --yes    Auto-approve dns-mcp tool permissions (skip prompt)"
      echo "  -h, --help   Show this help"
      echo ""
      echo "Input:"
      echo "  email.txt    Raw email file with headers (.eml or .txt)"
      echo "  -            Read from stdin"
      echo ""
      echo "Examples:"
      echo "  $(basename "$0") -y spam/phishing_email.txt"
      echo "  $(basename "$0") spam/email1.txt spam/email2.txt"
      echo "  cat email.eml | $(basename "$0") -"
      exit 0
      ;;
    *) POSITIONAL+=("$arg") ;;
  esac
done

if [ ${#POSITIONAL[@]} -eq 0 ]; then
  echo "ERROR: no email file specified. Use -h for help." >&2
  exit 1
fi

# ── Sanity checks ─────────────────────────────────────────────────────────────
if ! command -v claude >/dev/null 2>&1; then
  echo "ERROR: claude CLI not found in PATH" >&2
  exit 1
fi
if ! docker image inspect dns-mcp >/dev/null 2>&1; then
  echo "ERROR: dns-mcp image not found. Run: make build" >&2
  exit 1
fi
if [ ! -f "$PROMPT_FILE" ]; then
  echo "ERROR: prompt file not found: $PROMPT_FILE" >&2
  exit 1
fi

ORIG_DIR="$(pwd)"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

# ── Temp workspace — cleaned up on exit ───────────────────────────────────────
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

# ── MCP config ────────────────────────────────────────────────────────────────
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

# ── Permissions ───────────────────────────────────────────────────────────────
ALLOWED_TOOLS_FLAG=()
if [ "$AUTO_APPROVE" = true ]; then
  echo "── Auto-approving dns-mcp tool permissions (--yes)"
  ALLOWED_TOOLS_FLAG=(--allowedTools "mcp__dns-mcp__*")
else
  echo ""
  echo "This script uses MCP tools from the dns-mcp server."
  echo "These are read-only DNS lookups with no side effects."
  echo ""
  read -r -p "Allow all dns-mcp tools for this run? [y/N] " response
  case "$response" in
    [yY]|[yY][eE][sS])
      ALLOWED_TOOLS_FLAG=(--allowedTools "mcp__dns-mcp__*")
      ;;
    *)
      echo "Proceeding without pre-approved permissions."
      echo "Claude will prompt for each tool individually."
      ;;
  esac
fi

# ── Process each email file ───────────────────────────────────────────────────
analyze_email() {
  local email_input="$1"
  local label="$2"   # display name (filename or "stdin")

  # Read email content
  local email_content
  if [ "$email_input" = "-" ]; then
    email_content=$(cat)
  else
    if [ ! -f "$email_input" ]; then
      echo "ERROR: file not found: $email_input" >&2
      return 1
    fi
    email_content=$(cat "$email_input")
  fi

  if [ -z "$email_content" ]; then
    echo "ERROR: empty input for $label" >&2
    return 1
  fi

  local file_ts="${TIMESTAMP}"
  # If processing multiple files, disambiguate with an index
  local txt_out="${ORIG_DIR}/forensics-${file_ts}.txt"
  local json_out="${ORIG_DIR}/forensics-${file_ts}.json"
  local raw_out="$WORK_DIR/raw-${file_ts}.txt"

  echo ""
  echo "── Input:  $label"
  echo "── Report: $txt_out"
  echo "── JSON:   $json_out"
  echo ""

  # Build user message: instruct the model to analyze the provided email.
  # The soc_email_forensics prompt already defines the full workflow.
  local user_msg
  user_msg=$(cat <<MSG
Analyze the following raw email. Apply the full soc_email_forensics workflow.
Use dns-mcp tools to validate all claims against live DNS.

---BEGIN EMAIL---
${email_content}
---END EMAIL---
MSG
)

  claude \
    -p "$user_msg" \
    --model claude-sonnet-4-6 \
    --mcp-config "$WORK_DIR/mcp.json" \
    --system-prompt-file "$PROMPT_FILE" \
    --output-format text \
    --max-turns 30 \
    "${ALLOWED_TOOLS_FLAG[@]}" \
    > "$raw_out"

  # Write full narrative
  cp "$raw_out" "$txt_out"

  # Extract the JSON block delimited by ---BEGIN-FORENSICS-JSON--- / ---END-FORENSICS-JSON---
  # Falls back to header-line parsing if the block is absent.
  python3 - "$raw_out" "$json_out" <<'PYEOF'
import sys, json, re

text = open(sys.argv[1]).read()
data = None

# Primary: sentinel-delimited JSON block
m = re.search(
    r'---BEGIN-FORENSICS-JSON---\s*(.*?)\s*---END-FORENSICS-JSON---',
    text, re.DOTALL
)
if m:
    # Strip markdown code fence if Claude wrapped the block in ```json ... ```
    block = re.sub(r'^\s*```[a-z]*\s*', '', m.group(1).strip())
    block = re.sub(r'\s*```\s*$', '', block)
    try:
        data = json.loads(block)
    except json.JSONDecodeError as e:
        data = {"parse_error": str(e), "raw_block": block[:500]}

# Fallback: old one-liner {"date":...} line
if data is None:
    m2 = re.search(r'\{"date"\s*:.*?\}', text)
    if m2:
        try:
            data = json.loads(m2.group(0))
        except json.JSONDecodeError:
            data = {}

if data is None:
    data = {}

# Fallback: pull verdict from header line if still missing
if "verdict" not in data:
    hdr = re.search(
        r'^\d{8}\s*[–\-]\s*\S+\s*[–\-]\s*(TRUSTABLE|SUSPICIOUS|PHISHING|FURTHER ANALYSIS REQUIRED)',
        text, re.MULTILINE
    )
    if hdr:
        data["verdict"] = hdr.group(1)

# Fallback: confidence
if "confidence" not in data:
    conf = re.search(r'Confidence[:\s]+(High|Medium|Low)', text, re.IGNORECASE)
    if conf:
        data["confidence"] = conf.group(1).capitalize()

with open(sys.argv[2], "w") as f:
    json.dump(data, f, indent=2)

# Print summary to stdout
verdict = data.get("verdict", "UNKNOWN")
confidence = data.get("confidence", "")
from_addr = (data.get("identity") or {}).get("from_address") or data.get("from", "")
listed = (data.get("rbl") or {}).get("listed_count")
tools = (data.get("session_stats") or {}).get("total_tool_calls")

print(f"  Verdict:    {verdict}" + (f"  ({confidence} confidence)" if confidence else ""))
if from_addr:
    print(f"  From:       {from_addr}")
if listed is not None:
    print(f"  RBL hits:   {listed}")
if tools is not None:
    print(f"  Tool calls: {tools}")
PYEOF

  echo ""
  echo "── Done"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
if [ ${#POSITIONAL[@]} -eq 1 ] && [ "${POSITIONAL[0]}" = "-" ]; then
  analyze_email "-" "stdin"
else
  idx=0
  for f in "${POSITIONAL[@]}"; do
    if [ $idx -gt 0 ]; then
      # Disambiguate output filenames for multiple inputs
      TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
      sleep 1  # ensure unique timestamp
    fi
    analyze_email "$f" "$f"
    idx=$((idx + 1))
  done
fi
