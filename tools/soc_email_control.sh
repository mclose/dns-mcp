#!/usr/bin/env bash
# soc_email_control.sh
# Control-condition phishing triage: no MCP tools, simple SOC system prompt.
# Use alongside soc_email_forensics.sh to compare raw model reasoning vs.
# model + dns-mcp tools + structured prompt.
#
# Usage:
#   ./tools/soc_email_control.sh email.txt
#   cat email.eml | ./tools/soc_email_control.sh -
set -euo pipefail

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
    -m|--model) PREV_ARG="$arg"; SKIP_NEXT=true ;;
    -h|--help)
      echo "Usage: $(basename "$0") [options] <email.txt|->"
      echo ""
      echo "Control-condition phishing triage — no tools, simple system prompt."
      echo "Compare output against soc_email_forensics.sh to see what dns-mcp adds."
      echo ""
      echo "Options:"
      echo "  -m, --model MODEL  Claude model (default: claude-sonnet-4-6)"
      echo "  -h, --help         Show this help"
      echo ""
      echo "Examples:"
      echo "  $(basename "$0") email.txt"
      echo "  cat email.eml | $(basename "$0") -"
      echo "  $(basename "$0") -m opus email.txt"
      exit 0
      ;;
    *) POSITIONAL+=("$arg") ;;
  esac
done

if [ ${#POSITIONAL[@]} -eq 0 ]; then
  echo "ERROR: no email file specified. Use - to read from stdin." >&2
  exit 1
fi

if ! command -v claude >/dev/null 2>&1; then
  echo "ERROR: claude CLI not found in PATH" >&2
  exit 1
fi

INPUT="${POSITIONAL[0]}"
if [ "$INPUT" = "-" ]; then
  EMAIL_CONTENT=$(cat)
elif [ -f "$INPUT" ]; then
  EMAIL_CONTENT=$(cat "$INPUT")
else
  echo "ERROR: file not found: $INPUT" >&2
  exit 1
fi

SYSTEM_PROMPT="I work in a SOC and I analyze email to see if it's phishing or trustable."

USER_MSG="$(cat <<MSGEOF
Analyze the following raw email and tell me if it is phishing or trustable.

---BEGIN EMAIL---
${EMAIL_CONTENT}
---END EMAIL---
MSGEOF
)"

echo "── Model:  $MODEL"
echo "── No MCP tools (control condition)"
echo ""

claude \
  -p "$USER_MSG" \
  --model "$MODEL" \
  --strict-mcp-config --mcp-config '' \
  --system-prompt "$SYSTEM_PROMPT"
