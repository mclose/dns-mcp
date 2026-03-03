#!/usr/bin/env bash
# email_security_posture_claude.sh
# Spins up a fresh dns-mcp container per run, audits a domain, emits JSON.
# All working files go to a temp dir and are cleaned up on exit.
# Output JSON is written to the directory you called this script from.
set -euo pipefail

DOMAIN="${1:-deflationhollow.net}"
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

# ── 4. Run ─────────────────────────────────────────────────────────────────────
echo "── Domain:  $DOMAIN"
echo "── Output:  $OUTPUT_FILE"
echo ""

claude \
  -p "Check the email security posture of ${DOMAIN}" \
  --model claude-sonnet-4-6 \
  --mcp-config "$WORK_DIR/mcp.json" \
  --system-prompt-file "$WORK_DIR/system-prompt.txt" \
  --output-format text \
  --max-turns 15 \
| tee "$OUTPUT_FILE" \
| python3 -m json.tool --indent 2

echo ""
echo "── Done: $OUTPUT_FILE"
