# TODO

Working backlog. Items are roughly priority-ordered within each section.

---

## Bugs & UX Fixes

- [ ] **`check_rbl(ip)` tool** — query common RBLs (Spamhaus zen, SpamCop, SORBS, Barracuda,
  UCEProtect 1/2, Mailspike, PSBL) for a given IPv4/IPv6 address. Reverse the octets,
  query `{reversed}.{rbl}` for an A record. Return per-RBL listed/clean status and any
  returned TXT explanation records. Currently requires manual scripting outside dns-mcp.

- [ ] **`ptr_lookup(ip)` tool** — reverse DNS lookup for an IP address. Returns PTR record(s)
  and whether forward-confirmed rDNS (FCrDNS) passes (PTR → A resolves back to the original IP).
  Essential for verifying mail server identity; currently absent from the toolset.

- [x] **`check_dkim_selector` arg order** — swapped to `(domain, selector)` to match
  every other tool's `domain`-first convention. Tests updated. Was a silent wrong-result
  bug (args swapped, no error raised, wrong FQDN queried).

- [x] **Pydantic `Field(default=...)` breaks direct function calls** — fixed `check_bimi`
  `selector` and `dns_query_dot` `port` to use plain Python defaults instead of
  `Field(default=...)`. `Field(...)` now reserved for required params only.

---

## Scripts

- [ ] `tools/soc_email_forensics.sh` — wrap the `soc_email_forensics` MCP prompt;
  accept a raw `.eml` file as a positional argument (or stdin), pipe it into the
  prompt, return the verdict (TRUSTABLE / SUSPICIOUS / PHISHING / FURTHER ANALYSIS
  REQUIRED) as text. Mirror the structure of `email_security_posture_claude.sh`:
  temp dir, trap cleanup, `-y/--yes` flag, model flag.

---

## Infrastructure

- [x] **Logging** — per-tool invocation + result lines to stderr via `tracking.py`.
  Format: `[TOOL] → check_spf domain=example.com` / `[TOOL] ← check_spf ok (reject) 142ms`.
  Status: ok / ERR (soft error dict) / EXCEPTION. Summary from well-known result keys
  (overall_status, verdict, denial_type, policy). stdout stays clean for JSON-RPC.

- [ ] **DEFAULT_RESOLVER via env var** — `DEFAULT_RESOLVER` is currently the
  constant `"9.9.9.9"`. Read from `DNS_RESOLVER` env var at startup so operators
  can override without rebuilding the image.

---

## Encrypted DNS transports & EDNS

- [ ] **DNS over TLS (DoT)** — add `transport` param to `dns_dig_style` (or new tool)
  supporting `udp` (default), `dot`. Uses `dns.query.tls()` from dnspython, port 853.
  Surface TLS details: cipher suite, certificate CN, verification status.

- [ ] **DNS over HTTPS (DoH)** — `transport=doh`. Uses `dns.query.https()` from dnspython.
  Resolver configured as URL (e.g. `https://dns.quad9.net/dns-query`). Surface HTTP
  response metadata. Needs `requests` or `httpx` in container.

- [ ] **DNS over QUIC (DoQ)** — `transport=doq`. Needs `aioquic` or similar; assess
  dnspython support first. Port 853/8853. Lower priority — limited resolver support.

- [ ] **Cross-transport hijacking detection** — enhance `detect_hijacking` with a DoT
  check: query the same known record via plain UDP and via DoT, compare answers.
  Mismatch is definitive hijack evidence (DoT bypasses port-53 interception by
  captive portals and rogue WiFi routers). Cleaner signal than the current NXDOMAIN
  probe alone.

- [ ] **EDNS** — surface EDNS0 metadata in `dns_dig_style` and/or `dns_query`:
  buffer size, EDNS version, DO (DNSSEC OK) bit, extended RCODE. Optionally add
  EDNS Client Subnet (ECS, RFC 7871) option support to show/send subnet hints.

---

## New tools

- [ ] **`check_sshfp`** — query SSHFP records for a hostname; decode algorithm
  (RSA/DSA/ECDSA/Ed25519) and fingerprint type (SHA-1/SHA-256); flag zones
  where SSHFP is present but DNSSEC is not (records untrustworthy without it).

- [ ] **`check_caa`** — query CAA records; decode `issue`, `issuewild`, and `iodef`
  tags; flag absence (any CA can issue) and common misconfigurations.

- [ ] **`check_ct_logs`** — cross-reference a domain against Certificate Transparency
  logs (crt.sh API); surface recently-issued certs, unexpected SANs, and certs
  issued by unexpected CAs. Note: HTTP call like `rdap_lookup`, not pure DNS.

- [ ] **DKIM signature verification** — verify the cryptographic signature in a
  raw email's `DKIM-Signature` header against the published public key. Separate
  input pattern from domain-based tools (takes raw email/headers, not a domain).
  Privacy consideration: full email body must not leave the local environment.
  Candidate libs: `dkimpy`, `cryptography`. Scope TBD: full RFC 6376 vs structural.

---

## Observability

- [x] **`session_stats` tool + `tracking.py`** — per-tool call tracking for the
  container lifetime. In-process, zero-dependency, resets on container restart.
  Pattern fully documented in `~/projects/ping-lite/TOOL_CALL_TRACKING.md`.
  Implementation checklist:
  - Add `tracking.py` at repo root (standalone module, no imports from `server.py`)
  - Decorate all 19 tools with `@track("tool_name")` — inner decorator, `@mcp.tool()` outer
  - Add `session_stats` as tool #20: uptime, total calls, per-tool count/errors/mean_ms/max_ms
  - `Dockerfile`: add `tracking.py` to the `COPY` line (easy to forget)
  - Tests: add `TestSessionStats` class; import `session_stats` and `get_stats`
  - `test-mcp-stdio.sh`: bump count to 20, add `call_tool` for `session_stats`
  - `README.md`: add `session_stats` to Utility tools table

---

## Refactors

- [ ] **`quine` — outline mode default** — at ~2500 lines, dumping the full source
  into an LLM context is expensive and rarely what's wanted. Refactor to return a
  structured outline by default; require `full=True` to get the raw source.
  Default response should include: all tool names with line ranges, helper
  functions, prompt names, total line count, file path. Full source still
  available for genuine introspection use cases but opt-in.

---

## Prompt improvements

- [ ] **`soc_email_forensics` prompt** — currently untested against real phishing
  samples. Run against the test email folder and refine verdict logic / header
  extraction steps based on results.

---

## Done (recent)

- [x] `server_info` tool — expose resolver config, dnspython version
- [x] `detect_hijacking` — transparent proxy detection (Check 5)
- [x] `check_tlsa` — standalone TLSA lookup, any hostname/port/protocol
- [x] `DEFAULT_RESOLVER` constant — replaced 3 hardcoded `"9.9.9.9"` strings
- [x] `validate_port` helper
- [x] `_query_tlsa` shared helper (used by `check_dane` and `check_tlsa`)
- [x] MCP Registry listing (`io.github.mclose/dns-mcp`)
- [x] `email_security_audit` prompt — provider-aware DKIM, opaque selector handling
- [x] `tools/email_security_posture_claude.sh`
- [x] `CLAUDE.md` — public developer guide
- [x] `tracking.py` + `session_stats` + `reset_stats` — per-tool call stats, container lifetime
- [x] Per-tool stderr logging — `[TOOL] → name key=val` / `[TOOL] ← name ok (summary) Xms`
