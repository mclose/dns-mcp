#!/usr/bin/env bash
# soc_email_forensics.sh
# Forensic phishing analysis of a raw email (.eml / .txt) via the
# soc_email_forensics MCP prompt. Spins up a fresh dns-mcp container per run.
#
# Modes (mutually exclusive flags; default is --json):
#   --json          One run → writes forensics-<ts>.json only
#   --text          One run → writes forensics-<ts>.txt only
#   --json --text   Two runs → writes both files (same timestamp); warns about cost
#
# Usage:
#   ./tools/soc_email_forensics.sh [options] email.txt
#   cat email.txt | ./tools/soc_email_forensics.sh [options] -
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROMPT_FILE="$SCRIPT_DIR/../prompts/soc_email_forensics.txt"

# ── Parse flags ───────────────────────────────────────────────────────────────
AUTO_APPROVE=false
JSON_MODE=false
TEXT_MODE=false
MODEL=claude-sonnet-4-6
POSITIONAL=()
SKIP_NEXT=false
PREV_ARG=""
for arg in "$@"; do
  if [ "$SKIP_NEXT" = true ]; then
    SKIP_NEXT=false
    case "$PREV_ARG" in
      -m|--model) MODEL="$arg" ;;
    esac
    continue
  fi
  case "$arg" in
    -y|--yes)   AUTO_APPROVE=true ;;
    --json)     JSON_MODE=true ;;
    --text)     TEXT_MODE=true ;;
    -m|--model) PREV_ARG="$arg"; SKIP_NEXT=true ;;
    -h|--help)
      echo "Usage: $(basename "$0") [options] <email.txt|->"
      echo ""
      echo "Forensic phishing analysis of a raw email with full headers."
      echo ""
      echo "Modes (default: --json):"
      echo "  --json          One run  → structured JSON only  (forensics-<ts>.json)"
      echo "  --text          One run  → narrative report only (forensics-<ts>.txt)"
      echo "  --json --text   Two runs → both files, same timestamp (costs 2x — will ask)"
      echo ""
      echo "Options:"
      echo "  -y, --yes          Auto-approve dns-mcp tool permissions (skip prompt)"
      echo "  -m, --model MODEL  Claude model (default: claude-sonnet-4-6)"
      echo "  -h, --help         Show this help"
      echo ""
      echo "Input:"
      echo "  email.txt    Raw email file with headers (.eml or .txt)"
      echo "  -            Read from stdin"
      echo ""
      echo "Examples:"
      echo "  $(basename "$0") -y email.txt"
      echo "  $(basename "$0") --json -y email.txt"
      echo "  $(basename "$0") --text -y email.txt"
      echo "  $(basename "$0") --json --text -y email.txt"
      echo "  $(basename "$0") -m claude-haiku-4-5-20251001 --json -y email.txt"
      echo "  $(basename "$0") spam/email1.txt spam/email2.txt"
      echo "  cat email.eml | $(basename "$0") -"
      exit 0
      ;;
    *) POSITIONAL+=("$arg") ;;
  esac
done

# Default mode: --json
if [ "$JSON_MODE" = false ] && [ "$TEXT_MODE" = false ]; then
  JSON_MODE=true
fi
BOTH_MODE=false
if [ "$JSON_MODE" = true ] && [ "$TEXT_MODE" = true ]; then
  BOTH_MODE=true
fi

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

# ── Two-pass cost warning ──────────────────────────────────────────────────────
if [ "$BOTH_MODE" = true ]; then
  echo ""
  echo "WARNING: --json --text runs Claude TWICE per email (2x cost and time)."
  echo "  Model: $MODEL"
  echo "  Emails: ${#POSITIONAL[@]}"
  echo ""
  read -r -p "Continue with two-pass run? [y/N] " _confirm
  case "$_confirm" in
    [yY]|[yY][eE][sS]) ;;
    *) echo "Aborted."; exit 0 ;;
  esac
fi

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

# ── JSON schema block (shared by json mode) ───────────────────────────────────
JSON_SCHEMA='---BEGIN-FORENSICS-JSON---
{
  "verdict": "TRUSTABLE or SUSPICIOUS or PHISHING or FURTHER ANALYSIS REQUIRED",
  "confidence": "High or Medium or Low",
  "confidence_justification": "one sentence",
  "delivery_date": "YYYYMMDD",
  "delivery_date_source": "topmost Received header or Received header Nth or Date header sender-controlled lower confidence",
  "analysis_timestamp": "ISO-8601 UTC",
  "header_completeness": "FULL or PARTIAL or MINIMAL",
  "identity": {
    "from_address": "exact From address",
    "display_name": "display name or null",
    "subject": "Subject value",
    "return_path": "Return-Path or null",
    "return_path_matches_from": true,
    "message_id": "Message-ID or null"
  },
  "authentication": {
    "spf": { "header_result": "pass or fail or softfail or neutral or none or missing", "dns_record_exists": true, "sending_ip_authorized": true, "issues": [] },
    "dkim": { "header_result": "pass or fail or perm_fail or tempfail or none or missing", "selector": "s= value or null", "signing_domain": "d= value or null", "key_exists_in_dns": true, "algorithm": "rsa-sha256 or rsa-sha1 or ed25519-sha256 or null", "issues": [] },
    "dmarc": { "header_result": "pass or fail or missing", "policy": "none or quarantine or reject or missing", "pct": 100, "alignment_spf": "pass or fail or null", "alignment_dkim": "pass or fail or null", "record_exists": true, "issues": [] },
    "arc_present": false,
    "overall_auth_assessment": "one sentence"
  },
  "infrastructure": {
    "sending_ip": "IP or null",
    "ptr_hostname": "PTR or null",
    "fcrDNS": "pass or fail or null",
    "ehlo_hostname": "EHLO value or null",
    "ip_classification": "cloud_esp or datacenter or residential or vpn or unknown",
    "asn_org": "org name or null",
    "routing_hops": 1
  },
  "rbl": {
    "checked": true,
    "listed_count": 0,
    "listings": [],
    "analysis_date": "YYYY-MM-DD",
    "temporal_caveat_applies": false,
    "days_since_delivery": null
  },
  "domain_intel": {
    "from_domain": "domain",
    "domain_status": "active or serverHold or clientHold or pendingDelete or null",
    "mx_records_exist": true,
    "spf_record_exists": true,
    "dmarc_record_exists": true,
    "rdap_creation_date": "YYYY-MM-DD or null",
    "domain_age_days_at_delivery": null,
    "registrar": "name or null"
  },
  "urls": {
    "total_count": 0,
    "unique_domains": [],
    "suspicious_domains": [],
    "uses_http_only": false,
    "contains_tracking_pixel": false,
    "redirect_chains_present": false
  },
  "red_flags": [],
  "rationale_summary": "2-3 sentence plain-English summary",
  "session_stats": { "total_tool_calls": 0, "tool_breakdown": {}, "errors": 0, "uptime_seconds": 0.0 }
}
---END-FORENSICS-JSON---'

# ── Single analysis run ───────────────────────────────────────────────────────
# run_analysis <email_input> <label> <mode: json|text> <out_file>
run_analysis() {
  local email_input="$1"
  local label="$2"
  local mode="$3"      # json | text
  local out_file="$4"  # .json or .txt destination

  # Read email content
  local email_content
  if [ "$email_input" = "-" ]; then
    email_content=$(cat)
  else
    email_content=$(cat "$email_input")
  fi

  local raw_out="$WORK_DIR/raw-$(basename "$out_file").tmp"

  if [ "$mode" = "json" ]; then
    echo "── JSON:   $out_file"
    local user_msg
    user_msg=$(cat <<MSGEOF
Analyze the following raw email using the soc_email_forensics workflow.
Run all DNS tool checks. Call session_stats last. Then emit ONLY the
machine-readable JSON summary between the sentinel lines below.
No narrative prose. No code fence. Raw JSON only.

---BEGIN EMAIL---
${email_content}
---END EMAIL---

${JSON_SCHEMA}
MSGEOF
)
  else
    echo "── Report: $out_file"
    local user_msg
    user_msg=$(cat <<MSGEOF
Analyze the following raw email. Apply the full soc_email_forensics workflow.
Use dns-mcp tools to validate all claims against live DNS.
Write a complete forensic narrative report per the system prompt.

IMPORTANT: Your very first line of output MUST be the emoji title line exactly
as specified in the system prompt:
  🔴 PHISHING – short description (from_domain)
  🟢 TRUSTABLE – short description (from_domain)
  🟡 SUSPICIOUS – short description (from_domain)
  🟠 FURTHER ANALYSIS REQUIRED – short description (from_domain)
This line is mandatory. Do not skip it or move it.

---BEGIN EMAIL---
${email_content}
---END EMAIL---
MSGEOF
)
  fi

  claude \
    -p "$user_msg" \
    --model "$MODEL" \
    --mcp-config "$WORK_DIR/mcp.json" \
    --system-prompt-file "$PROMPT_FILE" \
    --output-format json \
    --max-turns 30 \
    "${ALLOWED_TOOLS_FLAG[@]}" \
    > "$raw_out"

  # Extract text + cost metadata from claude JSON wrapper, write output file
  python3 - "$raw_out" "$out_file" "$mode" <<'PYEOF'
import sys, json, re

raw_path, out_path, mode = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    wrapper = json.loads(open(raw_path).read())
except Exception:
    wrapper = {}

text      = wrapper.get("result", open(raw_path).read())
cost_usd  = wrapper.get("total_cost_usd")
dur_s     = wrapper.get("duration_ms", 0) / 1000
usage     = wrapper.get("usage", {})
in_tok    = usage.get("input_tokens", 0) + usage.get("cache_read_input_tokens", 0)
out_tok   = usage.get("output_tokens", 0)

if mode == "text":
    with open(out_path, "w") as f:
        f.write(text)
    # Echo title line to terminal (first non-empty line)
    for line in text.splitlines():
        if line.strip():
            print(f"  {line.strip()}")
            break
else:
    # Extract forensics JSON from sentinels
    data = None
    m = re.search(
        r'---BEGIN-FORENSICS-JSON---\s*(.*?)\s*---END-FORENSICS-JSON---',
        text, re.DOTALL
    )
    if m:
        block = re.sub(r'^\s*```[a-z]*\s*', '', m.group(1).strip())
        block = re.sub(r'\s*```\s*$', '', block)
        try:
            data = json.loads(block)
        except json.JSONDecodeError as e:
            data = {"parse_error": str(e), "raw_block": block[:500]}
    if data is None:
        data = {}
    # Fallbacks
    if "verdict" not in data:
        hdr = re.search(
            r'^\d{8}\s*[–\-]\s*\S+\s*[–\-]\s*(TRUSTABLE|SUSPICIOUS|PHISHING|FURTHER ANALYSIS REQUIRED)',
            text, re.MULTILINE
        )
        if hdr:
            data["verdict"] = hdr.group(1)
    if "confidence" not in data:
        conf = re.search(r'Confidence[:\s]+(High|Medium|Low)', text, re.IGNORECASE)
        if conf:
            data["confidence"] = conf.group(1).capitalize()
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)
    verdict    = data.get("verdict", "UNKNOWN")
    confidence = data.get("confidence", "")
    from_addr  = (data.get("identity") or {}).get("from_address") or ""
    listed     = (data.get("rbl") or {}).get("listed_count")
    tools      = (data.get("session_stats") or {}).get("total_tool_calls")
    print(f"  Verdict:    {verdict}" + (f"  ({confidence} confidence)" if confidence else ""))
    if from_addr:
        print(f"  From:       {from_addr}")
    if listed is not None:
        print(f"  RBL hits:   {listed}")
    if tools is not None:
        print(f"  Tool calls: {tools}")

print(f"  Cost:       ${cost_usd:.4f}" if cost_usd is not None else "  Cost:       unknown")
print(f"  Tokens:     {in_tok:,} in / {out_tok:,} out")
print(f"  Duration:   {dur_s:.1f}s")
PYEOF
}

# ── Process one email (one or two passes) ─────────────────────────────────────
analyze_email() {
  local email_input="$1"
  local label="$2"

  if [ "$email_input" != "-" ] && [ ! -f "$email_input" ]; then
    echo "ERROR: file not found: $email_input" >&2
    return 1
  fi

  local file_ts="${TIMESTAMP}"
  local txt_out="${ORIG_DIR}/forensics-${file_ts}.txt"
  local json_out="${ORIG_DIR}/forensics-${file_ts}.json"

  echo ""
  echo "── Input:  $label"

  if [ "$BOTH_MODE" = true ]; then
    echo ""
    echo "  [ text pass ]"
    run_analysis "$email_input" "$label" text "$txt_out"
    echo ""
    echo "  [ json pass ]"
    run_analysis "$email_input" "$label" json "$json_out"
  elif [ "$JSON_MODE" = true ]; then
    run_analysis "$email_input" "$label" json "$json_out"
  else
    run_analysis "$email_input" "$label" text "$txt_out"
  fi

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
      TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
      sleep 1  # ensure unique timestamp per file
    fi
    analyze_email "$f" "$f"
    idx=$((idx + 1))
  done
fi
