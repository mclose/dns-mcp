# Spec: `check_ct_logs` tool for dns-mcp

## Overview

Add a `check_ct_logs` tool to dns-mcp that queries Certificate Transparency logs
via the crt.sh JSON API. It enumerates all certificates and unique names for a
domain, cross-references issuers against the domain's CAA records, and surfaces
actionable findings without the false-positive bugs common in naive CT checkers.

This tool sits alongside `check_spf`, `check_dmarc`, `check_dkim_selector` etc.
as a domain intelligence tool — not a security scanner.

---

## crt.sh API

```
GET https://crt.sh/?q=%.{domain}&output=json
```

- `%` is the SQL ILIKE wildcard — matches all subdomains and the apex
- Returns a JSON array of certificate objects (see Data Model below)
- **crt.sh is notoriously unreliable**: timeouts, empty 200 responses, truncated
  JSON mid-array, and occasional HTML error page responses instead of JSON.
  Defensive handling is mandatory — see Error Handling section.

---

## Data Model

Each object in the crt.sh JSON array has these relevant fields:

```json
{
  "id": 12345678,
  "logged_at": "2025-11-03T14:22:01",
  "not_before": "2025-11-03T13:22:00",
  "not_after":  "2026-02-01T13:22:00",
  "common_name": "*.lab.example.com",
  "name_value":  "*.lab.example.com\nlab.example.com",
  "issuer_name": "C=US, O=Let's Encrypt, CN=E7"
}
```

Key points:
- `name_value` is newline-delimited and contains ALL SANs for the cert.
  Always split on `\n` to enumerate individual names. Do not treat `name_value`
  as a single name.
- `common_name` is typically one of the SANs, already present in `name_value`.
  Use `name_value` as the canonical source of names; `common_name` is secondary.
- `issuer_name` is a full RFC 4514 DN string. Parse the `O=` field to get the
  CA organization. Do NOT use `CN=` for CAA cross-reference — intermediates like
  `E7`, `E8`, `R11` are ephemeral. `O=` is stable across rotations.
- `id` is the crt.sh certificate ID. Use it to construct permalink:
  `https://crt.sh/?id={id}`

---

## CAA Cross-Reference

### The Problem This Solves

Naive CT checkers compare cert `issuer CN` (e.g. `E7`) directly against the CAA
`issue` tag value (e.g. `letsencrypt.org`). These never match. The checker then
incorrectly reports CAA violations. This tool does it correctly.

### Correct Approach: O= Field Mapping

Parse `O=` from `issuer_name` and map to CAA identity via a lookup table:

```python
ORG_TO_CAA_IDENTITY = {
    "Let's Encrypt":               "letsencrypt.org",
    "ZeroSSL":                     "sectigo.com",
    "Sectigo Limited":             "sectigo.com",
    "Google Trust Services LLC":   "pki.goog",
    "Google Trust Services":       "pki.goog",
    "DigiCert Inc":                "digicert.com",
    "GlobalSign nv-sa":            "globalsign.com",
    "GlobalSign":                  "globalsign.com",
    "Actalis S.p.A.":              "actalis.it",
    "SSL.com":                     "ssl.com",
    "Buypass AS":                  "buypass.com",
    "HARICA":                      "harica.gr",
    "Internet Security Research Group": "letsencrypt.org",  # ISRG root org
}
```

Parse `O=` from issuer_name:
```python
def parse_org(issuer_name: str) -> str | None:
    for part in issuer_name.split(","):
        part = part.strip()
        if part.startswith("O="):
            return part[2:].strip()
    return None
```

### CAA Lookup

Query CAA records for the domain using existing dns-mcp DNS infrastructure
(dnspython, same pattern as other tools). Collect all `issue` and `issuewild`
tag values. Wildcards (`*.example.com`) must be checked against `issuewild` tags.

### Mismatch Reporting

If a cert's resolved CAA identity does not appear in the domain's CAA `issue`
(or `issuewild` for wildcards) tags:

- Report as a WARNING, not an ERROR
- Include explanation: "This may indicate a cert issued before CAA was
  configured, or the CA identity mapping is incomplete. It is not necessarily
  a policy violation."
- Include the crt.sh ID and permalink so the user can inspect the cert
- If the `O=` value is not in the mapping table, report as
  `"unknown_org": true` and surface the raw `O=` value — do not silently
  drop it

### No CAA Record Case

If the domain has no CAA records: skip cross-reference, note
`"caa_configured": false` in output, do not generate warnings.

---

## Active vs Expired Classification

Compare `not_after` against current UTC timestamp:
- `not_after > now` → active
- `not_after <= now` → expired

By default return both. Provide `include_expired: bool = False` parameter to
filter expired certs from the main results (but always include in summary counts).

---

## Wildcard Detection

A cert is a wildcard if any name in its SANs starts with `*.`.
Report wildcard count in summary. Flag the specific names.

---

## Tool Parameters

```python
@mcp.tool()
async def check_ct_logs(
    domain: str,
    include_expired: bool = False,
) -> dict:
```

| Parameter        | Type   | Default | Description                                      |
|------------------|--------|---------|--------------------------------------------------|
| `domain`         | `str`  | —       | Apex domain to query (e.g. `deflationhollow.net`)|
| `include_expired`| `bool` | `False` | Include expired certs in results list            |

The query always uses `%.{domain}` to catch all subdomains. Do not expose the
query pattern as a parameter — it should always be the full subdomain wildcard.

---

## Return Structure

```python
{
    "timestamp": "2026-03-18T03:00:00Z",
    "domain": "deflationhollow.net",
    "query": "%.deflationhollow.net",
    "crtsh_url": "https://crt.sh/?q=%25.deflationhollow.net",

    # Summary counts
    "summary": {
        "total_certs": 9,
        "active_certs": 9,
        "expired_certs": 0,
        "wildcard_certs": 1,
        "unique_names": 10,        # split from name_value across all certs
        "unique_issuers": 2,       # distinct O= values seen
        "caa_configured": True,
        "caa_warnings": 0,
    },

    # Deduplicated sorted list of all names across all certs/SANs
    "unique_names": [
        "*.lab.deflationhollow.net",
        "deflationhollow.net",
        "dnsmcp.lab.deflationhollow.net",
        # ...
    ],

    # CAA cross-reference result
    "caa_check": {
        "issue_tags": ["letsencrypt.org"],
        "issuewild_tags": ["letsencrypt.org"],
        "warnings": [],            # list of warning dicts if any mismatches
    },

    # Per-cert detail (filtered by include_expired)
    "certificates": [
        {
            "id": 12345678,
            "permalink": "https://crt.sh/?id=12345678",
            "common_name": "*.lab.deflationhollow.net",
            "sans": ["*.lab.deflationhollow.net", "lab.deflationhollow.net"],
            "is_wildcard": True,
            "issuer_cn": "E7",
            "issuer_org": "Let's Encrypt",
            "caa_identity": "letsencrypt.org",
            "caa_identity_unknown": False,
            "not_before": "2026-01-15T10:00:00",
            "not_after":  "2026-04-15T10:00:00",
            "active": True,
            "logged_at": "2026-01-15T10:05:00",
        },
        # ...
    ],

    # Retry/reliability metadata
    "fetch_metadata": {
        "attempts": 2,
        "success_on_attempt": 2,
        "response_truncated": False,
        "error": None,
    },

    "errors": [],
}
```

---

## Error Handling

crt.sh is unreliable. Every failure mode has been observed in production:

| Failure Mode                        | Detection                          | Handling                        |
|-------------------------------------|------------------------------------|---------------------------------|
| HTTP timeout                        | `httpx.TimeoutException`           | Retry with backoff              |
| Empty body (200 + `""`)             | `response.text.strip() == ""`      | Retry                           |
| Truncated JSON mid-array            | `json.JSONDecodeError`             | Retry; if final attempt, parse partial with `ijson` or report partial |
| HTML error page instead of JSON     | `response.text.strip()[0] == "<"`  | Retry                           |
| HTTP 5xx                            | `response.status_code >= 500`      | Retry with backoff              |
| HTTP 429 rate limit                 | `response.status_code == 429`      | Retry with longer backoff       |
| Valid JSON but empty array `[]`     | `len(data) == 0`                   | Return empty result, not error  |

### Retry Policy

```python
MAX_RETRIES = 3
TIMEOUT_SECONDS = 20
BACKOFF = [0, 2, 5]   # seconds before each attempt (0 = immediate first try)
```

Use `httpx.AsyncClient` (already used elsewhere in dns-mcp) for consistency.

Always populate `fetch_metadata.attempts` and `fetch_metadata.success_on_attempt`
so the caller knows how reliable the result was. If all retries fail, return a
partial result with whatever was fetched plus an error in `fetch_metadata.error`
and `errors[]`. Do not raise an exception — return a structured error response.

---

## Implementation Notes

### Use Existing dns-mcp Infrastructure

- Use `httpx.AsyncClient` (already a dependency) for crt.sh HTTP requests
- Use `dnspython` (already a dependency) for CAA record lookup — same pattern
  as `check_spf`, `check_dmarc` etc.
- Follow existing tool patterns: `@mcp.tool()` decorator, return `dict`,
  populate `timestamp` with `datetime.utcnow().isoformat() + "Z"`
- Add to the same module as other check_* tools, or a new
  `tools/ct_log.py` if the project has moved to per-tool modules

### Parsing issuer_name

The `issuer_name` field from crt.sh is a comma-separated DN but field values
may themselves contain commas if quoted. Use a simple split-on-`, ` approach
for the `O=` field — in practice CA organization names don't contain commas.
If a more robust parser is needed, `cryptography` library's `x509.Name` parsing
is available but requires fetching the actual cert DER, which is overkill here.

### Deduplication of Names

Use a `set()` to collect all names across all certs. Split every `name_value`
on `\n`. Strip whitespace. Skip empty strings. Sort the final set for
deterministic output.

### Deduplication of Certs

crt.sh may return the same certificate multiple times (logged to multiple CT
logs). Deduplicate on `id` before processing. Keep the first occurrence.

---

## Tool Description (for MCP schema)

```
Query Certificate Transparency logs via crt.sh for a domain.

Returns all certificates logged for the domain and its subdomains,
including: unique names/SANs discovered (useful for subdomain enumeration),
per-cert details (issuer, validity, wildcard status), active vs expired
counts, and a CAA cross-reference that correctly maps intermediate CA
names to their parent CA identity (e.g. E7/E8 → letsencrypt.org) rather
than doing a naive string comparison that produces false positives.

Retries automatically — crt.sh is unreliable and frequently returns
empty responses or times out on the first attempt.
```

---

## Test Cases

After implementation, verify with:

```bash
# Basic query
echo '{"domain": "deflationhollow.net"}' | dns-mcp check_ct_logs

# Expected: 9 certs, 10 unique names, 0 CAA warnings, 1 wildcard
# Issuers: Let's Encrypt (O=), caa_identity=letsencrypt.org for all
# CAA issue tags: ["letsencrypt.org"]
# No false CAA warnings for E7/E8 intermediates

# Domain with no CAA records - should not generate CAA warnings
echo '{"domain": "example.com"}' | dns-mcp check_ct_logs
# Expected: caa_configured: false, caa_warnings: 0

# Domain with mixed issuers (find one that uses both LE and ZeroSSL)
# Expected: correct O= mapping for both, no false positives
```

---

## Out of Scope (Future Work)

- **CT monitoring / alerting**: polling crt.sh on a schedule and detecting new
  issuances. Requires statefulness (last-seen cert ID per domain). Separate tool
  or daemon, not part of this spec.
- **AIA chain walking**: fetching the actual cert DER and following the AIA
  `caIssuers` URI to the root. More correct than O= mapping but adds latency
  and external HTTP dependencies to CA infrastructure. The O= approach is
  sufficient for CAA cross-reference.
- **crt.sh ID-based single cert lookup**: useful but separate from domain
  enumeration. Could be a `ct_cert_detail(id: int)` tool later.
- **Precertificate deduplication**: crt.sh returns both the precert and the
  final cert for each issuance. They share the same SANs. Deduplicating on
  `id` is sufficient for now; a future version could deduplicate on
  (common_name, not_before, not_after) to collapse precert/cert pairs.

