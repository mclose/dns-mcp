# Task: Migrate dnsmcp to Docker-based development workflow and add email security analysis tools

## Context

I have an existing DNS MCP server (`claude-dnssec-mcp/` or `dns-mcp-server/`) built with
FastMCP and dnspython. It currently runs via CLI (direct Python execution) with these tools:

- `dns_query` — Standard DNS lookups (A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, SRV)
- `dns_dig_style` — Detailed dig-style queries with full response sections
- `reverse_dns` — PTR record lookups for IP addresses
- `dnssec_validate` — Full chain validation from root → TLD → domain
- `check_record` — Query specific record types with DNSSEC verification
- `compare_nameservers` — SOA serial sync across nameservers
- `analyze_zone` — Comprehensive zone health check
- `timestamp_converter` — Epoch/ISO/human-readable time conversion

The server uses dnspython (no subprocess/shell execution), strict domain validation regex,
query type allowlists, and runs as a non-root container user. These security properties
must be preserved.

Current infrastructure:
- Flask proxy with bearer token auth (port 8082) → FastMCP server (port 8083)
- ngrok tunnel to dnsmcp.lab.deflationhollow.net
- gunicorn with --timeout 0 for SSE streaming
- fail2ban integration for 4xx errors
- CORS headers for browser-based clients

## Phase 0: Migrate to Docker-based development workflow

### Goal
Move from "run Python directly on the host" to "build and test inside Docker" so that
iteration on new tools is containerized and reproducible.

### Requirements

1. Create a `Dockerfile` that:
   - Uses Alpine 3.19+ base
   - Installs: python3, py3-pip, bind-tools, drill, bind-dnssec-tools, jq, bash
   - Installs Python deps from requirements.txt (use --break-system-packages)
   - Creates non-root user `claude` (uid 1000)
   - Runs as non-root user
   - Entrypoint is the MCP server

2. Create a `docker-compose.yml` that:
   - Builds the server image
   - Exposes port 8083 (FastMCP) internally only
   - Runs the Flask auth proxy on port 8082 (exposed to host)
   - Sets PYTHONUNBUFFERED=1
   - Mounts a volume for the bearer token config (do NOT bake the token into the image)
   - Includes a healthcheck
   - Uses a bridge network for internal communication
   - Does NOT include ngrok — ngrok runs separately on the host

3. Create a `Makefile` or `justfile` with targets:
   - `build` — Build the Docker image
   - `up` — Start the stack (detached)
   - `down` — Stop the stack
   - `test` — Run tests inside the container
   - `logs` — Tail logs
   - `shell` — Drop into a shell in the running container
   - `rebuild` — Force rebuild and restart

4. Create a `test_tools.py` that:
   - Tests each existing tool with known-good inputs
   - Tests input validation (bad domains, invalid record types)
   - Tests each new email security tool (Phase 1)
   - Can run inside the container: `make test`
   - Uses pytest

5. Preserve the existing Flask proxy + bearer auth + gunicorn architecture.
   The proxy runs as a sidecar in docker-compose, not baked into the MCP server.

### What NOT to do
- Do not use Docker for ngrok. ngrok runs on the host and points to localhost:8082.
- Do not use Docker Hub or any registry. Local builds only.
- Do not change the MCP protocol interface. Existing clients must keep working.
- Do not introduce subprocess calls for DNS queries. Keep using dnspython.


## Phase 1: Add email security analysis tools

### Goal
Add tools that support email forensic analysis. These tools let an AI analyst actively
validate claims in email headers against live DNS records, rather than just parsing
what the headers say.

### New tools to implement

All new tools follow the same patterns as existing tools:
- Use dnspython directly (no subprocess)
- Strict input validation via the existing domain validation regex
- Return structured JSON
- Include timestamp metadata
- Handle errors gracefully (return error info, don't crash)

#### 1. `check_spf`

**Purpose:** Retrieve and recursively parse a domain's SPF policy to enumerate all
authorized sending IPs/networks.

**Parameters:**
```
domain: str — Domain to check (e.g., "example.com")
```

**Behavior:**
- Query TXT records for the domain
- Find the record starting with "v=spf1"
- Parse all mechanisms: ip4, ip6, a, mx, include, redirect, exists, all
- Recursively resolve `include:` mechanisms (follow the chain, max depth 10
  per RFC 7208 lookup limit)
- Return the complete list of authorized IP ranges/CIDRs

**Output (JSON):**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "raw_record": "v=spf1 include:_spf.google.com ~all",
  "mechanisms": [...],
  "authorized_networks": ["35.190.247.0/24", "64.233.160.0/19", ...],
  "all_qualifier": "softfail",
  "lookup_count": 4,
  "errors": []
}
```

#### 2. `check_dmarc`

**Purpose:** Retrieve and parse a domain's DMARC policy.

**Parameters:**
```
domain: str — Domain to check (the From: domain, not _dmarc.domain)
```

**Behavior:**
- Query TXT record for `_dmarc.{domain}`
- Parse all DMARC tags: v, p, sp, rua, ruf, adkim, aspf, pct, ri, fo
- If no record at the exact domain, check the organizational domain
  (e.g., if sub.example.com has no DMARC, check _dmarc.example.com)

**Output (JSON):**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "record_found_at": "_dmarc.example.com",
  "raw_record": "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:...",
  "policy": "reject",
  "subdomain_policy": null,
  "dkim_alignment": "strict",
  "spf_alignment": "strict",
  "percentage": 100,
  "rua": ["mailto:dmarc@example.com"],
  "ruf": [],
  "errors": []
}
```

#### 3. `check_dkim_selector`

**Purpose:** Verify a DKIM public key record exists for a given selector and domain.

**Parameters:**
```
selector: str — DKIM selector (the s= value from DKIM-Signature header)
domain: str — DKIM domain (the d= value from DKIM-Signature header)
```

**Behavior:**
- Query TXT record for `{selector}._domainkey.{domain}`
- Parse key parameters: v, k (key type), p (public key), t (flags), h (hash algorithms)
- Report whether the key exists and is valid (p= is not empty)
- An empty p= value means the key has been revoked

**Output (JSON):**
```json
{
  "timestamp": "2026-02-07T...",
  "selector": "s1",
  "domain": "example.com",
  "fqdn": "s1._domainkey.example.com",
  "record_exists": true,
  "raw_record": "v=DKIM1; k=rsa; p=MIIBIjAN...",
  "key_type": "rsa",
  "key_present": true,
  "key_revoked": false,
  "flags": [],
  "errors": []
}
```

#### 4. `check_bimi`

**Purpose:** Check for BIMI (Brand Indicators for Message Identification) record.

**Parameters:**
```
domain: str — Domain to check
selector: str = "default" — BIMI selector (almost always "default")
```

**Behavior:**
- Query TXT record for `{selector}._bimi.{domain}`
- Parse: v (version), l (logo SVG URL), a (VMC certificate URL)
- Report whether BIMI is configured and whether a VMC is present

**Output (JSON):**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "selector": "default",
  "fqdn": "default._bimi.example.com",
  "record_exists": true,
  "raw_record": "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
  "logo_url": "https://example.com/logo.svg",
  "vmc_url": "https://example.com/vmc.pem",
  "has_vmc": true,
  "errors": []
}
```

#### 5. `check_mta_sts`

**Purpose:** Check for MTA-STS (Mail Transfer Agent Strict Transport Security) DNS record.

**Parameters:**
```
domain: str — Domain to check
```

**Behavior:**
- Query TXT record for `_mta-sts.{domain}`
- Parse: v (version), id (policy identifier)
- Note: Do NOT fetch the HTTPS policy file (/.well-known/mta-sts.txt) —
  that would require an HTTP request outside our DNS scope. Just report
  the DNS record presence and the policy ID.

**Output (JSON):**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "fqdn": "_mta-sts.example.com",
  "record_exists": true,
  "raw_record": "v=STSv1; id=20260207T000000",
  "version": "STSv1",
  "policy_id": "20260207T000000",
  "errors": []
}
```

#### 6. `check_smtp_tlsrpt`

**Purpose:** Check for SMTP TLS Reporting record (often paired with MTA-STS).

**Parameters:**
```
domain: str — Domain to check
```

**Behavior:**
- Query TXT record for `_smtp._tls.{domain}`
- Parse: v (version), rua (reporting URIs)

**Output (JSON):**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "fqdn": "_smtp._tls.example.com",
  "record_exists": true,
  "raw_record": "v=TLSRPTv1; rua=mailto:tls-reports@example.com",
  "version": "TLSRPTv1",
  "reporting_uris": ["mailto:tls-reports@example.com"],
  "errors": []
}
```

#### 7. `rdap_lookup`

**Purpose:** Retrieve domain registration data via RDAP (the modern replacement for WHOIS).

**Parameters:**
```
domain: str — Domain to look up (registrable domain, not subdomain)
```

**Behavior:**
- Extract the registrable domain (e.g., "example.com" from "mail.sub.example.com").
  Use the public suffix list or a simple TLD split — don't over-engineer this.
- Fetch the IANA RDAP bootstrap file to find the correct RDAP server for the TLD:
  https://data.iana.org/rdap/dns.json
  Cache this in memory (it changes rarely). If fetch fails, fall back to a small
  hardcoded map of common TLDs (.com, .net, .org → rdap.verisign.com, etc.).
- Query the RDAP server: GET {rdap_base}/domain/{domain}
- Parse the JSON response for: registrar, creation date, expiration date, last
  updated date, status codes, registrant org/country (if available — many are
  redacted post-GDPR).
- Timeout: 10 seconds. RDAP servers can be slow.

**Dependencies:**
- `requests` library (add to requirements.txt if not already present)
- No other new dependencies needed

**Security:**
- Validate the domain input with the existing regex before making any HTTP request.
- Do not follow redirects beyond 3 hops.
- Do not send any authentication or cookies.

**Output (JSON):**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "rdap_server": "https://rdap.verisign.com/com/v1",
  "registrar": "Example Registrar, Inc.",
  "creation_date": "1995-08-14T00:00:00Z",
  "expiration_date": "2026-08-13T00:00:00Z",
  "last_updated": "2025-06-15T12:00:00Z",
  "status": ["clientTransferProhibited", "serverDeleteProhibited"],
  "registrant_org": "REDACTED FOR PRIVACY",
  "registrant_country": "US",
  "domain_age_days": 11134,
  "errors": []
}
```

**Notes:**
- `domain_age_days` is calculated from creation_date to now. This directly supports
  the SOC email analysis "domain age" risk assessment (< 30 days = HIGH RISK,
  < 90 days = ELEVATED RISK).
- If RDAP data is unavailable or redacted, return what's available and note
  the gaps in the errors array.
- This is an HTTP call, not a DNS query. It's the one tool in the server that
  reaches outside DNS. This is intentional and well-contained.


#### 8. `check_dane`

**Purpose:** Check for DANE TLSA records on a domain's mail servers. DANE binds TLS
certificates to DNS via TLSA records, providing cryptographic assurance that the TLS
certificate presented by a mail server is the one the domain owner intended. DANE
requires DNSSEC — without it, TLSA records are ignored by compliant implementations.

**Parameters:**
```
domain: str — Domain to check (the From: domain, not the MX hostname)
```

**Behavior:**
- Query MX records for the domain using dns_query.
- For each MX hostname:
  1. Query TLSA records at `_25._tcp.{mx_hostname}` using dns_query (type TLSA).
     If dnspython does not support TLSA as a named type, query using the numeric
     type code 52 (dns.rdatatype.RdataType(52)).
  2. If TLSA records exist, parse the TLSA fields:
     - Certificate usage (uint8):
       0 = PKIX-TA (CA constraint)
       1 = PKIX-EE (service certificate constraint)
       2 = DANE-TA (trust anchor assertion) — common for mail
       3 = DANE-EE (domain-issued certificate) — most common for mail
     - Selector (uint8):
       0 = full certificate
       1 = SubjectPublicKeyInfo only
     - Matching type (uint8):
       0 = exact match (full DER)
       1 = SHA-256 hash
       2 = SHA-512 hash
     - Certificate association data (hex-encoded hash or DER)
  3. Check DNSSEC status for the MX hostname's zone. DANE without DNSSEC is
     invalid — the TLSA record exists but will be ignored by compliant MTAs.
     Use dns_dig_style on the TLSA record and check for the AD (Authenticated
     Data) flag in the response header, OR use dns_dnssec_validate on the MX
     hostname's parent zone. Either approach is acceptable.
  4. Classify each MX host:
     - "dane_valid": TLSA records present AND DNSSEC validates
     - "dane_present_no_dnssec": TLSA records present but DNSSEC does not
       validate — this is a misconfiguration, not a trust signal
     - "no_dane": no TLSA records at _25._tcp.{mx_hostname}

**Output (JSON):**
```json
{
  "timestamp": "2026-02-07T...",
  "domain": "example.com",
  "mx_hosts": [
    {
      "hostname": "mail.example.com",
      "priority": 10,
      "tlsa_fqdn": "_25._tcp.mail.example.com",
      "has_tlsa": true,
      "dnssec_valid": true,
      "dane_status": "dane_valid",
      "tlsa_records": [
        {
          "usage": 3,
          "usage_name": "DANE-EE",
          "selector": 1,
          "selector_name": "SubjectPublicKeyInfo",
          "matching_type": 1,
          "matching_type_name": "SHA-256",
          "certificate_data": "2bb183af..."
        }
      ]
    },
    {
      "hostname": "mail2.example.com",
      "priority": 20,
      "tlsa_fqdn": "_25._tcp.mail2.example.com",
      "has_tlsa": false,
      "dnssec_valid": false,
      "dane_status": "no_dane",
      "tlsa_records": []
    }
  ],
  "dane_viable": true,
  "summary": "1 of 2 MX hosts have valid DANE (TLSA + DNSSEC)",
  "errors": []
}
```

**Notes:**
- `dane_viable` is true if at least one MX host has TLSA records with valid DNSSEC.
- DANE adoption is low globally but more common in European domains (Netherlands,
  Germany, Czech Republic) and privacy-focused mail providers. Most major US mail
  providers (Google, Microsoft) do not publish TLSA records.
- The tool should not attempt TLS connections to mail servers. DANE validation here
  means verifying that the DNS records exist and are DNSSEC-protected, not that the
  MX server's certificate matches. That would require an SMTP connection.
- For domains with many MX hosts (more than 5), process only the first 5 by priority
  to avoid excessive queries.
- This tool uses only dnspython. No new dependencies.


### Implementation notes

- All new tools share the existing `validate_domain()` function for input validation.
- The `rdap_lookup` tool requires the `requests` library. Add it to requirements.txt.
  All other tools use only dnspython.
- The `check_spf` recursive resolver must enforce the RFC 7208 10-lookup limit to
  avoid infinite loops or DoS via crafted SPF records.
- For `check_dkim_selector`, also validate the selector string (alphanumeric plus
  hyphens only, same pattern as a DNS label).
- All tools should catch dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
  dns.resolver.NoNameservers, and dns.exception.Timeout gracefully.
- Add the new tools to the existing FastMCP server alongside the current tools.
  Do not create a separate server.
- Update requirements.txt if any new dependencies are needed (unlikely — dnspython
  handles everything).


## Phase 2: Testing

### Test matrix

For each new tool, test:
1. Known-good domain with the record present (e.g., google.com for SPF, DMARC)
2. Domain with no record (should return record_exists: false, no errors)
3. Domain that doesn't exist (NXDOMAIN — should return graceful error)
4. Invalid input (empty string, special characters — should fail validation)
5. Edge cases specific to the tool:
   - check_spf: domain with deep include chain (test lookup limit)
   - check_dkim_selector: revoked key (empty p= value)
   - check_dmarc: subdomain with no record, falling back to org domain
   - rdap_lookup: well-known domain (e.g., google.com), recently registered
     domain if available, RDAP server timeout handling, domain with redacted
     WHOIS (most domains post-GDPR)
   - check_dane: domain with known DANE deployment (try bund.de, sidn.nl, or
     freebsd.org — these are known DANE adopters), domain with no DANE
     (google.com), domain with TLSA records but broken DNSSEC (if findable),
     domain with many MX hosts (test the 5-host cap)

### Running tests
```bash
make test
# or
docker compose exec dnsmcp pytest tests/ -v
```


## Deliverables

1. Updated `Dockerfile`
2. New or updated `docker-compose.yml`
3. `Makefile` with build/up/down/test/logs/shell/rebuild targets
4. New tool implementations added to the existing server
5. `tests/test_tools.py` with full coverage of new and existing tools
6. Updated `requirements.txt` (add `requests` for RDAP)
7. Updated `README.md` with new tool documentation
7. No changes to the bearer auth proxy, ngrok setup, or fail2ban config


## What to read first

Before making changes, read:
1. The existing `server.py` (or `mcp_server.py`) to understand the current tool pattern
2. The existing `server-proxy.py` to understand the auth proxy architecture
3. `requirements.txt` for current dependencies
4. Any existing `Dockerfile` or `docker-compose.yml`

Match the existing code style and patterns exactly for the new tools.
