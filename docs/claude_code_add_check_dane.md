# Task: Add `check_dane` tool to the existing dns-mcp server

Read the existing `server.py` to understand the current tool patterns, then add this
new tool following the same conventions. Do not modify any existing tools.

## Tool spec: `check_dane`

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

**Implementation notes:**
- `dane_viable` is true if at least one MX host has TLSA records with valid DNSSEC.
- For domains with many MX hosts (more than 5), process only the first 5 by priority
  to avoid excessive queries.
- The tool should not attempt TLS connections to mail servers. DANE validation here
  means verifying that the DNS records exist and are DNSSEC-protected, not that the
  MX server's certificate matches.
- This tool uses only dnspython. No new dependencies.
- Follow the same error handling pattern as the existing tools: catch
  dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
  and dns.exception.Timeout gracefully.
- Use the existing `validate_domain()` function for input validation.
- Summary should include what is missing from the configuration is dane is not valid.
  If it is not possible to identify the cause, just the summary of failure is find.

## Test cases

After implementing, verify with:
- `bund.de` — known DANE deployer (German federal government)
- `sidn.nl` — known DANE deployer (.nl registry)
- `freebsd.org` — known DANE deployer
- `google.com` — no DANE expected
- `thisisnotarealdomainxyz123.com` — NXDOMAIN, graceful error
- Empty string or invalid characters — should fail validation

## Other Requirements

Test Scripts
- update test-mcp-client.py, test-mcp-stdio.sh and test-mcp.sh to test/validate the new check tool is working
- encure all docker tests complete successfuly after make build 
