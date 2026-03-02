"""
Tests for DNS MCP Server tools.

Phase 0: existing tools (dns_query, dns_dig_style, timestamp_converter,
         reverse_dns, dns_dnssec_validate)
Phase 2: email security tools will be added alongside implementation.

Tests call tool functions directly — this tests logic, not MCP transport.
End-to-end protocol testing is handled by test-mcp.sh.

Note: Pydantic Field() defaults don't resolve when calling functions directly
(outside MCP). All parameters with Field() defaults must be passed explicitly.
"""

from server import (
    dns_query,
    dns_dig_style,
    timestamp_converter,
    reverse_dns,
    dns_dnssec_validate,
    nsec_info,
    quine,
    validate_domain,
    validate_selector,
    _parse_tag_value,
    _get_org_domain,
    check_spf,
    check_dmarc,
    check_dkim_selector,
    check_bimi,
    check_mta_sts,
    check_smtp_tlsrpt,
    rdap_lookup,
    check_dane,
    detect_hijacking,
    email_security_audit,
    dnssec_chain_audit,
    soc_email_forensics,
)


# ---------------------------------------------------------------------------
# validate_domain
# ---------------------------------------------------------------------------


class TestValidateDomain:
    def test_valid_domain(self):
        valid, result = validate_domain("example.com")
        assert valid is True
        assert result == "example.com"

    def test_valid_subdomain(self):
        valid, _ = validate_domain("sub.example.com")
        assert valid is True

    def test_empty_string(self):
        valid, _ = validate_domain("")
        assert valid is False

    def test_too_long(self):
        domain = "a" * 254
        valid, msg = validate_domain(domain)
        assert valid is False
        assert "too long" in msg.lower()

    def test_special_characters(self):
        valid, _ = validate_domain("exam ple.com")
        assert valid is False

    def test_leading_hyphen(self):
        valid, _ = validate_domain("-example.com")
        assert valid is False


# ---------------------------------------------------------------------------
# dns_query
# ---------------------------------------------------------------------------


class TestDnsQuery:
    def test_known_good_a_record(self):
        result = dns_query("google.com", "A", nameserver=None)
        assert "error" not in result
        assert result["domain"] == "google.com"
        assert result["record_type"] == "A"
        assert len(result["results"]) > 0

    def test_known_good_mx_record(self):
        result = dns_query("google.com", "MX", nameserver=None)
        assert "error" not in result
        assert len(result["results"]) > 0
        assert "exchange" in result["results"][0]

    def test_known_good_txt_record(self):
        result = dns_query("google.com", "TXT", nameserver=None)
        assert "error" not in result
        assert len(result["results"]) > 0

    def test_known_good_ns_record(self):
        result = dns_query("google.com", "NS", nameserver=None)
        assert "error" not in result
        assert len(result["results"]) > 0

    def test_nxdomain(self):
        result = dns_query(
            "this-domain-does-not-exist-xyzzy.invalid", "A", nameserver=None
        )
        assert "error" in result
        assert "NXDOMAIN" in result["error"] or "does not exist" in result["error"]

    def test_bad_domain_format(self):
        result = dns_query("not a valid domain!", "A", nameserver=None)
        assert "error" in result

    def test_empty_domain(self):
        result = dns_query("", "A", nameserver=None)
        assert "error" in result

    def test_custom_nameserver(self):
        result = dns_query("google.com", "A", nameserver="9.9.9.9")
        assert "error" not in result
        assert result["nameserver"] == "9.9.9.9"

    def test_invalid_nameserver(self):
        result = dns_query("google.com", "A", nameserver="not-an-ip")
        assert "error" in result


# ---------------------------------------------------------------------------
# dns_dig_style
# ---------------------------------------------------------------------------


class TestDnsDigStyle:
    def test_known_good_domain(self):
        result = dns_dig_style("google.com", "A", nameserver="9.9.9.9")
        assert "error" not in result
        assert result["query"]["domain"] == "google.com"
        assert "header" in result
        assert "sections" in result
        assert "dnssec" in result["header"]

    def test_nxdomain(self):
        result = dns_dig_style(
            "this-domain-does-not-exist-xyzzy.invalid", "A", nameserver="9.9.9.9"
        )
        # dig-style returns the response even for NXDOMAIN — check header status
        if "error" not in result:
            assert result["header"]["status"] == "NXDOMAIN"
        # If it errored, that's also acceptable

    def test_bad_domain_format(self):
        result = dns_dig_style("not valid!", "A", nameserver="9.9.9.9")
        assert "error" in result

    def test_invalid_nameserver(self):
        result = dns_dig_style("google.com", "A", nameserver="bad")
        assert "error" in result

    def test_denial_of_existence_field(self):
        """Query a nonexistent .com domain to get NSEC3 from the DNSSEC-signed TLD"""
        result = dns_dig_style(
            "nonexistent-probe-test-xyz-123456.com", "A", nameserver="9.9.9.9"
        )
        assert "error" not in result
        assert result["header"]["status"] == "NXDOMAIN"
        assert "denial_of_existence" in result
        doe = result["denial_of_existence"]
        assert doe["present"] is True
        assert doe["type"] in ("NSEC", "NSEC3")
        assert doe["record_count"] > 0


# ---------------------------------------------------------------------------
# nsec_info
# ---------------------------------------------------------------------------


class TestNsecInfo:
    # Test zones on deflationhollow.net (controlled by project owner):
    #   nsec-test.deflationhollow.net       — plain NSEC, zone walkable
    #   nsec3-weak.deflationhollow.net      — NSEC3 iter=0, no salt (RFC 9276 default)
    #   nsec3-salted.deflationhollow.net    — NSEC3 iter=0, 8-byte salt
    #   nsec3-optout.deflationhollow.net    — NSEC3 opt-out flag set
    # All served by ns1/ns2/ns3.deflationhollow.net with DS records in parent.

    def test_response_structure(self):
        """All expected keys present in result (cloudflare.com as stable DNSSEC zone)"""
        result = nsec_info("cloudflare.com")
        expected_keys = [
            "timestamp",
            "domain",
            "zone",
            "authoritative_ns",
            "authoritative_ip",
            "probe_name",
            "response_code",
            "denial_type",
            "nsec3_params",
            "nsec_records",
            "zone_walkable",
            "walkability_risk",
            "walkability_note",
            "nsec3param",
            "nsec3_consistency",
            "errors",
        ]
        for key in expected_keys:
            assert key in result, f"Missing key: {key}"
        assert result["denial_type"] in ("nsec", "nsec3")
        assert len(result["errors"]) == 0

    def test_nsec_zone(self):
        """Plain NSEC zone: walkable, high risk, no NSEC3PARAM"""
        result = nsec_info("nsec-test.deflationhollow.net")
        assert result["denial_type"] == "nsec"
        assert result["zone_walkable"] is True
        assert result["walkability_risk"] == "high"
        assert result["nsec3_params"] is None
        assert result["nsec3param"] is None
        assert result["nsec3_consistency"] is None
        assert result["authoritative_ns"] is not None
        assert result["authoritative_ip"] is not None
        assert result["response_code"] in ("NXDOMAIN", "NOERROR")
        assert len(result["errors"]) == 0

    def test_nsec3_no_salt(self):
        """NSEC3 with iterations=0 and no salt (RFC 9276 recommended)"""
        result = nsec_info("nsec3-weak.deflationhollow.net")
        assert result["denial_type"] == "nsec3"
        assert result["zone_walkable"] is False
        assert result["walkability_risk"] == "moderate"
        params = result["nsec3_params"]
        assert params["algorithm"] == 1  # SHA-1
        assert params["iterations"] == 0
        assert params["salt"] == ""
        assert params["salt_length"] == 0
        assert params["opt_out"] is False

    def test_nsec3_salted(self):
        """NSEC3 with iterations=0 and 8-byte salt"""
        result = nsec_info("nsec3-salted.deflationhollow.net")
        assert result["denial_type"] == "nsec3"
        assert result["zone_walkable"] is False
        assert result["walkability_risk"] == "moderate"
        params = result["nsec3_params"]
        assert params["algorithm"] == 1
        assert params["iterations"] == 0
        assert params["salt_length"] == 8
        assert len(params["salt"]) == 16  # 8 bytes = 16 hex chars

    def test_nsec3_optout(self):
        """NSEC3 with opt-out flag: low walkability risk"""
        result = nsec_info("nsec3-optout.deflationhollow.net")
        assert result["denial_type"] == "nsec3"
        assert result["zone_walkable"] is False
        assert result["walkability_risk"] == "low"
        assert result["nsec3_params"]["opt_out"] is True

    def test_nsec3param_present(self):
        """NSEC3 zones should have NSEC3PARAM at apex with correct values"""
        result = nsec_info("nsec3-weak.deflationhollow.net")
        param = result["nsec3param"]
        assert param is not None
        assert param["algorithm"] == 1
        assert param["flags"] == 0
        assert param["iterations"] == 0
        assert param["salt"] == ""
        assert param["salt_length"] == 0

    def test_nsec3param_salted(self):
        """Salted NSEC3 zone: NSEC3PARAM reflects the salt"""
        result = nsec_info("nsec3-salted.deflationhollow.net")
        param = result["nsec3param"]
        assert param is not None
        assert param["salt_length"] == 8
        assert len(param["salt"]) == 16

    def test_nsec3_consistency_match(self):
        """NSEC3PARAM and NSEC3 denial records should agree"""
        result = nsec_info("nsec3-weak.deflationhollow.net")
        consistency = result["nsec3_consistency"]
        assert consistency is not None
        assert consistency["consistent"] is True
        assert consistency["mismatches"] == []
        assert result["nsec3param"]["algorithm"] == result["nsec3_params"]["algorithm"]
        assert (
            result["nsec3param"]["iterations"] == result["nsec3_params"]["iterations"]
        )
        assert result["nsec3param"]["salt"] == result["nsec3_params"]["salt"]

    def test_nsec3_consistency_salted(self):
        """Salted zone consistency: NSEC3PARAM salt matches NSEC3 records"""
        result = nsec_info("nsec3-salted.deflationhollow.net")
        assert result["nsec3_consistency"]["consistent"] is True
        assert result["nsec3param"]["salt"] == result["nsec3_params"]["salt"]

    def test_unsigned_zone(self):
        """Unsigned zone: no crash, no NSEC3PARAM"""
        result = nsec_info("example.com")
        assert "error" not in result
        assert isinstance(result["errors"], list)

    def test_invalid_domain(self):
        """Bad input returns error gracefully"""
        result = nsec_info("not valid!")
        assert "error" in result


# ---------------------------------------------------------------------------
# timestamp_converter
# ---------------------------------------------------------------------------


class TestTimestampConverter:
    def test_epoch_input(self):
        result = timestamp_converter(0)
        assert "error" not in result
        assert result["conversions"]["iso"] == "1970-01-01T00:00:00+00:00"
        assert result["conversions"]["epoch"] == 0

    def test_iso_input(self):
        result = timestamp_converter("2024-01-15T10:30:00Z")
        assert "error" not in result
        # Verify round-trip: epoch back to ISO date should match
        assert result["conversions"]["date"] == "2024-01-15"

    def test_date_string(self):
        result = timestamp_converter("2024-01-15")
        assert "error" not in result
        assert "2024-01-15" in result["conversions"]["date"]

    def test_us_date_format(self):
        result = timestamp_converter("01/15/2024")
        assert "error" not in result

    def test_invalid_string(self):
        result = timestamp_converter("not a timestamp")
        assert "error" in result

    def test_float_epoch(self):
        result = timestamp_converter(1705312200.5)
        assert "error" not in result


# ---------------------------------------------------------------------------
# reverse_dns
# ---------------------------------------------------------------------------


class TestReverseDns:
    def test_known_good_ip(self):
        result = reverse_dns(ip_address="8.8.8.8")
        assert "error" not in result
        assert result["ip_address"] == "8.8.8.8"
        assert len(result["ptr_records"]) > 0
        assert "dns.google" in result["ptr_records"][0].lower()

    def test_invalid_ip(self):
        result = reverse_dns(ip_address="not-an-ip")
        assert "error" in result

    def test_empty_string(self):
        result = reverse_dns(ip_address="")
        assert "error" in result

    def test_ipv6(self):
        # Google public DNS IPv6
        result = reverse_dns(ip_address="2001:4860:4860::8888")
        # May or may not have PTR, but shouldn't crash
        assert "ip_address" in result or "error" in result


# ---------------------------------------------------------------------------
# dns_dnssec_validate
# ---------------------------------------------------------------------------


class TestDnssecValidate:
    def test_signed_domain(self):
        """cloudflare.com is DNSSEC-signed"""
        result = dns_dnssec_validate("cloudflare.com", "A", nameserver="9.9.9.9")
        assert "error" not in result
        assert result["domain"] == "cloudflare.com"
        assert "chain_of_trust" in result
        assert len(result["chain_of_trust"]) > 0
        # Root should be secure
        assert result["chain_of_trust"][0]["status"] == "secure"

    def test_unsigned_domain(self):
        """example.com — result depends on DNSSEC chain state"""
        result = dns_dnssec_validate("example.com", "A", nameserver="9.9.9.9")
        assert "error" not in result
        assert result["overall_status"] in ("insecure", "fully validated", "bogus")

    def test_nxdomain(self):
        result = dns_dnssec_validate(
            "this-domain-does-not-exist-xyzzy.invalid", "A", nameserver="9.9.9.9"
        )
        assert "error" not in result or "does not exist" in result.get("error", "")

    def test_bad_domain(self):
        result = dns_dnssec_validate("not valid!", "A", nameserver="9.9.9.9")
        assert "error" in result

    def test_invalid_nameserver(self):
        result = dns_dnssec_validate("cloudflare.com", "A", nameserver="bad")
        assert "error" in result


# ===========================================================================
# Phase 2: Helper functions
# ===========================================================================


class TestValidateSelector:
    def test_valid_selector(self):
        valid, result = validate_selector("selector1")
        assert valid is True
        assert result == "selector1"

    def test_valid_with_hyphens(self):
        valid, _ = validate_selector("my-selector-2")
        assert valid is True

    def test_valid_single_char(self):
        valid, _ = validate_selector("s")
        assert valid is True

    def test_empty_string(self):
        valid, msg = validate_selector("")
        assert valid is False

    def test_too_long(self):
        valid, msg = validate_selector("a" * 64)
        assert valid is False

    def test_special_characters(self):
        valid, _ = validate_selector("sel ector")
        assert valid is False

    def test_leading_hyphen(self):
        valid, _ = validate_selector("-selector")
        assert valid is False

    def test_underscore_invalid(self):
        valid, _ = validate_selector("sel_ector")
        assert valid is False


class TestParseTagValue:
    def test_basic_tags(self):
        result = _parse_tag_value("v=DMARC1; p=reject; adkim=s")
        assert result["v"] == "DMARC1"
        assert result["p"] == "reject"
        assert result["adkim"] == "s"

    def test_empty_value(self):
        result = _parse_tag_value("v=DKIM1; p=")
        assert result["v"] == "DKIM1"
        assert result["p"] == ""

    def test_whitespace_handling(self):
        result = _parse_tag_value("  v = DMARC1 ;  p = none  ")
        assert result["v"] == "DMARC1"
        assert result["p"] == "none"

    def test_empty_string(self):
        result = _parse_tag_value("")
        assert result == {}


class TestGetOrgDomain:
    def test_two_part(self):
        assert _get_org_domain("example.com") == "example.com"

    def test_three_part(self):
        assert _get_org_domain("sub.example.com") == "example.com"

    def test_four_part(self):
        assert _get_org_domain("deep.sub.example.com") == "example.com"

    def test_single_label(self):
        assert _get_org_domain("localhost") == "localhost"


# ===========================================================================
# Phase 2: check_spf
# ===========================================================================


class TestCheckSpf:
    def test_happy_path(self):
        """google.com has a well-known SPF record"""
        result = check_spf("google.com")
        assert "error" not in result
        assert result["domain"] == "google.com"
        assert result["raw_record"] is not None
        assert result["raw_record"].startswith("v=spf1")
        assert len(result["mechanisms"]) > 0
        assert result["all_qualifier"] is not None
        assert isinstance(result["errors"], list)

    def test_authorized_networks(self):
        """SPF should resolve some authorized networks"""
        result = check_spf("google.com")
        assert "error" not in result
        assert isinstance(result["authorized_networks"], list)
        assert result["lookup_count"] >= 1

    def test_no_spf_record(self):
        """Domain that exists but has no SPF record"""
        # example.invalid won't work (NXDOMAIN), use a subdomain pattern
        # Many subdomains of large domains lack their own SPF
        result = check_spf("www.example.com")
        # Should not crash; either finds a record or reports none
        assert result["domain"] == "www.example.com"
        assert isinstance(result["errors"], list)

    def test_nxdomain(self):
        result = check_spf("this-domain-does-not-exist-xyzzy.invalid")
        assert result["domain"] == "this-domain-does-not-exist-xyzzy.invalid"
        assert len(result["errors"]) > 0

    def test_bad_input_empty(self):
        result = check_spf("")
        assert "error" in result

    def test_bad_input_special_chars(self):
        result = check_spf("not valid!")
        assert "error" in result

    def test_response_structure(self):
        """Verify all expected keys are present"""
        result = check_spf("google.com")
        for key in [
            "timestamp",
            "domain",
            "raw_record",
            "mechanisms",
            "authorized_networks",
            "all_qualifier",
            "lookup_count",
            "errors",
        ]:
            assert key in result, f"Missing key: {key}"


# ===========================================================================
# Phase 2: check_dmarc
# ===========================================================================


class TestCheckDmarc:
    def test_happy_path(self):
        """google.com has a DMARC record"""
        result = check_dmarc("google.com")
        assert "error" not in result
        assert result["domain"] == "google.com"
        assert result["raw_record"] is not None
        assert result["raw_record"].startswith("v=DMARC1")
        assert result["record_found_at"] == "_dmarc.google.com"
        assert result["policy"] is not None

    def test_alignment_defaults(self):
        """DMARC alignment should default to relaxed per RFC"""
        result = check_dmarc("google.com")
        assert "error" not in result
        assert result["dkim_alignment"] in ("relaxed", "strict")
        assert result["spf_alignment"] in ("relaxed", "strict")

    def test_percentage_field(self):
        result = check_dmarc("google.com")
        assert "error" not in result
        assert isinstance(result["percentage"], int)
        assert 0 <= result["percentage"] <= 100

    def test_rua_field(self):
        result = check_dmarc("google.com")
        assert "error" not in result
        assert isinstance(result["rua"], list)

    def test_no_dmarc_record(self):
        """Domain without DMARC should return structured 'not found' response"""
        result = check_dmarc("this-domain-does-not-exist-xyzzy.invalid")
        assert result["record_found_at"] is None
        assert result["raw_record"] is None
        assert result["policy"] is None
        assert len(result["errors"]) > 0

    def test_nxdomain(self):
        result = check_dmarc("this-domain-does-not-exist-xyzzy.invalid")
        assert result["domain"] == "this-domain-does-not-exist-xyzzy.invalid"
        assert len(result["errors"]) > 0

    def test_bad_input_empty(self):
        result = check_dmarc("")
        assert "error" in result

    def test_bad_input_special_chars(self):
        result = check_dmarc("not valid!")
        assert "error" in result

    def test_subdomain_fallback(self):
        """Subdomain should fall back to org domain's DMARC"""
        result = check_dmarc("mail.google.com")
        assert "error" not in result
        # Should either find at _dmarc.mail.google.com or fall back to _dmarc.google.com
        assert result["record_found_at"] is not None
        assert result["raw_record"] is not None

    def test_response_structure(self):
        result = check_dmarc("google.com")
        for key in [
            "timestamp",
            "domain",
            "record_found_at",
            "raw_record",
            "policy",
            "subdomain_policy",
            "dkim_alignment",
            "spf_alignment",
            "percentage",
            "rua",
            "ruf",
            "errors",
        ]:
            assert key in result, f"Missing key: {key}"


# ===========================================================================
# Phase 2: check_dkim_selector
# ===========================================================================


class TestCheckDkimSelector:
    def test_known_good_selector(self):
        """Google publishes DKIM keys at well-known selectors"""
        # Google uses selectors like "20230601" — try a known pattern
        result = check_dkim_selector("20230601", "gmail.com")
        # Record may or may not exist depending on rotation, check structure
        assert result["selector"] == "20230601"
        assert result["domain"] == "gmail.com"
        assert result["fqdn"] == "20230601._domainkey.gmail.com"
        assert isinstance(result["record_exists"], bool)
        assert isinstance(result["errors"], list)

    def test_no_record(self):
        """Non-existent selector should return record_exists=False"""
        result = check_dkim_selector("nonexistent99", "google.com")
        assert result["record_exists"] is False
        assert result["key_present"] is False
        assert len(result["errors"]) > 0

    def test_nxdomain(self):
        result = check_dkim_selector(
            "selector1", "this-domain-does-not-exist-xyzzy.invalid"
        )
        assert result["record_exists"] is False
        assert len(result["errors"]) > 0

    def test_invalid_selector_chars(self):
        """Selector with special chars should fail validation"""
        result = check_dkim_selector("bad selector!", "google.com")
        assert "error" in result

    def test_empty_selector(self):
        result = check_dkim_selector("", "google.com")
        assert "error" in result

    def test_invalid_domain(self):
        result = check_dkim_selector("selector1", "not valid!")
        assert "error" in result

    def test_response_structure_found(self):
        """Check all expected keys on any DKIM lookup"""
        result = check_dkim_selector("selector1", "google.com")
        for key in [
            "timestamp",
            "selector",
            "domain",
            "fqdn",
            "record_exists",
            "raw_record",
            "key_type",
            "key_present",
            "key_revoked",
            "flags",
            "errors",
        ]:
            assert key in result, f"Missing key: {key}"


# ===========================================================================
# Phase 2: check_bimi
# ===========================================================================


class TestCheckBimi:
    def test_no_bimi_record(self):
        """Most domains don't have BIMI — example.com almost certainly doesn't"""
        result = check_bimi("example.com", selector="default")
        assert result["domain"] == "example.com"
        assert result["selector"] == "default"
        assert result["fqdn"] == "default._bimi.example.com"
        assert result["record_exists"] is False
        assert isinstance(result["errors"], list)

    def test_nxdomain(self):
        result = check_bimi(
            "this-domain-does-not-exist-xyzzy.invalid", selector="default"
        )
        assert result["record_exists"] is False
        assert len(result["errors"]) > 0

    def test_bad_input_empty(self):
        result = check_bimi("", selector="default")
        assert "error" in result

    def test_bad_input_special_chars(self):
        result = check_bimi("not valid!", selector="default")
        assert "error" in result

    def test_invalid_selector(self):
        result = check_bimi("google.com", selector="bad selector!")
        assert "error" in result

    def test_response_structure(self):
        result = check_bimi("example.com", selector="default")
        for key in [
            "timestamp",
            "domain",
            "selector",
            "fqdn",
            "record_exists",
            "raw_record",
            "logo_url",
            "vmc_url",
            "has_vmc",
            "errors",
        ]:
            assert key in result, f"Missing key: {key}"

    def test_happy_path_if_exists(self):
        """Try a domain known for BIMI — CNN, PayPal, etc.
        This is a best-effort test; the record may not always be present."""
        result = check_bimi("cnn.com", selector="default")
        assert result["domain"] == "cnn.com"
        # Whether or not the record exists, structure should be valid
        assert isinstance(result["record_exists"], bool)
        if result["record_exists"]:
            assert result["raw_record"] is not None
            assert result["raw_record"].startswith("v=BIMI1")


# ===========================================================================
# Phase 2: check_mta_sts
# ===========================================================================


class TestCheckMtaSts:
    def test_happy_path(self):
        """google.com has MTA-STS"""
        result = check_mta_sts("google.com", fetch_policy=True)
        assert result["domain"] == "google.com"
        assert result["fqdn"] == "_mta-sts.google.com"
        # Google has MTA-STS, but be defensive
        if result["record_exists"]:
            assert result["raw_record"] is not None
            assert result["version"] == "STSv1"
            assert result["policy_id"] is not None

    def test_no_mta_sts(self):
        """Domain without MTA-STS"""
        result = check_mta_sts("example.com", fetch_policy=False)
        assert result["domain"] == "example.com"
        assert isinstance(result["record_exists"], bool)
        if not result["record_exists"]:
            assert len(result["errors"]) > 0

    def test_nxdomain(self):
        result = check_mta_sts(
            "this-domain-does-not-exist-xyzzy.invalid", fetch_policy=False
        )
        assert result["record_exists"] is False
        assert len(result["errors"]) > 0

    def test_bad_input_empty(self):
        result = check_mta_sts("", fetch_policy=False)
        assert "error" in result

    def test_bad_input_special_chars(self):
        result = check_mta_sts("not valid!", fetch_policy=False)
        assert "error" in result

    def test_response_structure(self):
        result = check_mta_sts("google.com", fetch_policy=False)
        for key in [
            "timestamp",
            "domain",
            "fqdn",
            "record_exists",
            "raw_record",
            "version",
            "policy_id",
            "policy",
            "errors",
        ]:
            assert key in result, f"Missing key: {key}"

    def test_dns_only_no_policy(self):
        """fetch_policy=False should return policy=None"""
        result = check_mta_sts("google.com", fetch_policy=False)
        if result["record_exists"]:
            assert result["policy"] is None

    def test_policy_fetch_happy_path(self):
        """google.com serves an MTA-STS policy file"""
        result = check_mta_sts("google.com", fetch_policy=True)
        if result["record_exists"] and result["policy"] is not None:
            policy = result["policy"]
            assert "url" in policy
            assert "mta-sts.google.com" in policy["url"]
            assert policy.get("mode") in ("enforce", "testing", "none")
            assert isinstance(policy.get("mx"), list)
            assert len(policy["mx"]) > 0
            assert isinstance(policy.get("max_age"), int)
            assert policy["max_age"] > 0

    def test_policy_fetch_no_record(self):
        """Domain without MTA-STS DNS record should not attempt policy fetch"""
        result = check_mta_sts("example.com", fetch_policy=True)
        if not result["record_exists"]:
            assert result["policy"] is None

    def test_policy_mx_patterns(self):
        """Policy MX entries should be valid patterns (may include wildcards)"""
        result = check_mta_sts("google.com", fetch_policy=True)
        if result.get("policy") and result["policy"].get("mx"):
            for mx in result["policy"]["mx"]:
                # MX patterns are like "*.google.com" or "smtp.google.com"
                assert isinstance(mx, str)
                assert len(mx) > 0


# ===========================================================================
# Phase 2: check_smtp_tlsrpt
# ===========================================================================


class TestCheckSmtpTlsrpt:
    def test_happy_path(self):
        """google.com has TLSRPT"""
        result = check_smtp_tlsrpt("google.com")
        assert result["domain"] == "google.com"
        assert result["fqdn"] == "_smtp._tls.google.com"
        if result["record_exists"]:
            assert result["raw_record"] is not None
            assert result["version"] == "TLSRPTv1"
            assert isinstance(result["reporting_uris"], list)
            assert len(result["reporting_uris"]) > 0

    def test_no_tlsrpt(self):
        """Domain without TLSRPT"""
        result = check_smtp_tlsrpt("example.com")
        assert result["domain"] == "example.com"
        assert isinstance(result["record_exists"], bool)

    def test_nxdomain(self):
        result = check_smtp_tlsrpt("this-domain-does-not-exist-xyzzy.invalid")
        assert result["record_exists"] is False
        assert len(result["errors"]) > 0

    def test_bad_input_empty(self):
        result = check_smtp_tlsrpt("")
        assert "error" in result

    def test_bad_input_special_chars(self):
        result = check_smtp_tlsrpt("not valid!")
        assert "error" in result

    def test_response_structure(self):
        result = check_smtp_tlsrpt("google.com")
        for key in [
            "timestamp",
            "domain",
            "fqdn",
            "record_exists",
            "raw_record",
            "version",
            "reporting_uris",
            "errors",
        ]:
            assert key in result, f"Missing key: {key}"


# ===========================================================================
# Phase 2: rdap_lookup
# ===========================================================================


class TestRdapLookup:
    def test_happy_path(self):
        """google.com should return RDAP data"""
        result = rdap_lookup("google.com")
        assert "error" not in result
        assert result["domain"] == "google.com"
        assert result["rdap_server"] is not None
        assert result["creation_date"] is not None
        assert result["status"] is not None
        assert isinstance(result["status"], list)
        assert isinstance(result["errors"], list)

    def test_domain_age(self):
        """google.com is old; domain_age_days should be large"""
        result = rdap_lookup("google.com")
        assert "error" not in result
        assert result["domain_age_days"] is not None
        # Google was registered in 1997; should be > 10000 days
        assert result["domain_age_days"] > 10000

    def test_registrar(self):
        result = rdap_lookup("google.com")
        assert "error" not in result
        # Google's registrar should be present (MarkMonitor typically)
        assert result["registrar"] is not None

    def test_subdomain_extracts_registrable(self):
        """Subdomain should be stripped to registrable domain"""
        result = rdap_lookup("mail.google.com")
        assert result["domain"] == "google.com"

    def test_nxdomain_tld(self):
        """Domain with unknown TLD might not have RDAP server"""
        result = rdap_lookup("this-domain-does-not-exist-xyzzy.invalid")
        # Should get errors (no RDAP server for .invalid or HTTP error)
        assert len(result.get("errors", [])) > 0 or result.get("rdap_server") is None

    def test_bad_input_empty(self):
        result = rdap_lookup("")
        assert "error" in result

    def test_bad_input_special_chars(self):
        result = rdap_lookup("not valid!")
        assert "error" in result

    def test_response_structure(self):
        result = rdap_lookup("google.com")
        for key in [
            "timestamp",
            "domain",
            "rdap_server",
            "registrar",
            "creation_date",
            "expiration_date",
            "last_updated",
            "status",
            "registrant_org",
            "registrant_country",
            "domain_age_days",
            "errors",
        ]:
            assert key in result, f"Missing key: {key}"

    def test_redacted_privacy(self):
        """Most domains have redacted registrant info post-GDPR"""
        result = rdap_lookup("google.com")
        assert "error" not in result
        # registrant_org should be present (possibly "REDACTED FOR PRIVACY" or actual value)
        assert result["registrant_org"] is not None


# ===========================================================================
# check_dane
# ===========================================================================


class TestCheckDane:
    def test_known_dane_deployer(self):
        """bund.de (German federal government) is a known DANE deployer"""
        result = check_dane("bund.de")
        assert "error" not in result
        assert result["domain"] == "bund.de"
        assert isinstance(result["mx_hosts"], list)
        assert len(result["mx_hosts"]) > 0
        statuses = [h["dane_status"] for h in result["mx_hosts"]]
        assert "dane_valid" in statuses
        assert result["dane_viable"] is True

    def test_sidn_nl(self):
        """sidn.nl (.nl registry) — structural check on MX host entries"""
        result = check_dane("sidn.nl")
        assert "error" not in result
        assert isinstance(result["mx_hosts"], list)
        assert len(result["mx_hosts"]) > 0
        for host in result["mx_hosts"]:
            assert "hostname" in host
            assert "priority" in host
            assert "tlsa_fqdn" in host
            assert "dane_status" in host

    def test_freebsd_org(self):
        """freebsd.org — known DANE deployer, has MX hosts with TLSA"""
        result = check_dane("freebsd.org")
        assert "error" not in result
        assert isinstance(result["mx_hosts"], list)
        assert len(result["mx_hosts"]) > 0
        # At least check structural validity
        has_tlsa = any(h["has_tlsa"] for h in result["mx_hosts"])
        assert has_tlsa is True

    def test_no_dane_google(self):
        """google.com — no DANE expected, all hosts should be no_dane"""
        result = check_dane("google.com")
        assert "error" not in result
        assert result["domain"] == "google.com"
        assert len(result["mx_hosts"]) > 0
        for host in result["mx_hosts"]:
            assert host["dane_status"] == "no_dane"
        assert result["dane_viable"] is False

    def test_nxdomain(self):
        """Non-existent domain should return graceful error"""
        result = check_dane("thisisnotarealdomainxyz123.com")
        assert result["dane_viable"] is False
        assert len(result["errors"]) > 0

    def test_bad_input_empty(self):
        """Empty string should fail validation"""
        result = check_dane("")
        assert "error" in result

    def test_bad_input_special_chars(self):
        """Special characters should fail validation"""
        result = check_dane("not valid!")
        assert "error" in result

    def test_response_structure(self):
        """Verify all top-level keys present"""
        result = check_dane("google.com")
        for key in [
            "timestamp",
            "domain",
            "mx_hosts",
            "dane_viable",
            "summary",
            "errors",
        ]:
            assert key in result, f"Missing key: {key}"

    def test_mx_host_structure(self):
        """Verify all per-host keys present"""
        result = check_dane("google.com")
        assert len(result["mx_hosts"]) > 0
        host = result["mx_hosts"][0]
        for key in [
            "hostname",
            "priority",
            "tlsa_fqdn",
            "has_tlsa",
            "dnssec_valid",
            "dane_status",
            "tlsa_records",
        ]:
            assert key in host, f"Missing host key: {key}"

    def test_dane_viable_is_bool(self):
        """dane_viable should always be a boolean"""
        result = check_dane("google.com")
        assert isinstance(result["dane_viable"], bool)


# ---------------------------------------------------------------------------
# quine
# ---------------------------------------------------------------------------


class TestQuine:
    def test_returns_source(self):
        """quine() should return source containing FastMCP (proves it read server.py)"""
        result = quine()
        assert "error" not in result
        assert "source" in result
        assert "FastMCP" in result["source"]
        assert "def quine" in result["source"]

    def test_metadata(self):
        """quine() should return file path and positive line count"""
        result = quine()
        assert "file" in result
        assert "lines" in result
        assert result["lines"] > 0
        assert result["file"].endswith("server.py")


# ---------------------------------------------------------------------------
# detect_hijacking
# ---------------------------------------------------------------------------


class TestDetectHijacking:
    def test_invalid_ip(self):
        """Invalid IP returns an error dict without crashing"""
        result = detect_hijacking(resolver="not-an-ip")
        assert "error" in result
        assert "resolver_tested" in result

    def test_response_structure(self):
        """Top-level response keys are all present for a valid resolver"""
        result = detect_hijacking(resolver="9.9.9.9")
        for key in [
            "timestamp",
            "resolver_tested",
            "resolver_identity",
            "checks",
            "verdict",
            "findings",
            "errors",
        ]:
            assert key in result, f"Missing top-level key: {key}"

    def test_checks_structure(self):
        """All four check sub-dicts are present with their required keys"""
        result = detect_hijacking(resolver="9.9.9.9")
        checks = result["checks"]
        assert "nxdomain_probe" in checks
        assert "known_record" in checks
        assert "dnssec_validation" in checks
        assert "resolver_identity" in checks

        nx = checks["nxdomain_probe"]
        for key in ["domain", "expected", "got", "answer_ips", "passed"]:
            assert key in nx, f"Missing nxdomain_probe key: {key}"

        kr = checks["known_record"]
        for key in ["domain", "expected_ip", "got_ips", "passed"]:
            assert key in kr, f"Missing known_record key: {key}"

        dv = checks["dnssec_validation"]
        for key in ["domain", "ad_flag", "note"]:
            assert key in dv, f"Missing dnssec_validation key: {key}"

        ri = checks["resolver_identity"]
        for key in ["query", "result"]:
            assert key in ri, f"Missing resolver_identity key: {key}"

    def test_known_good_8888(self):
        """8.8.8.8 (Google) should return verdict=clean with no findings"""
        result = detect_hijacking(resolver="8.8.8.8")
        assert result["verdict"] == "clean", (
            f"Expected clean, got {result['verdict']}: {result['findings']}"
        )
        assert result["findings"] == []

    def test_known_good_1111(self):
        """1.1.1.1 (Cloudflare) should return verdict=clean"""
        result = detect_hijacking(resolver="1.1.1.1")
        assert result["verdict"] == "clean", (
            f"Expected clean, got {result['verdict']}: {result['findings']}"
        )
        assert result["findings"] == []

    def test_dnssec_ad_flag_9999(self):
        """9.9.9.9 (Quad9) should set the AD flag for cloudflare.com (validates DNSSEC)"""
        result = detect_hijacking(resolver="9.9.9.9")
        assert result["checks"]["dnssec_validation"]["ad_flag"] is True


# ---------------------------------------------------------------------------
# Analyst prompts
# ---------------------------------------------------------------------------


class TestPrompts:
    def test_email_security_audit_returns_string(self):
        """email_security_audit() returns a non-empty string"""
        result = email_security_audit()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_email_security_audit_content(self):
        """email_security_audit() content identifies it as the correct prompt"""
        result = email_security_audit()
        assert "email security auditor" in result
        assert "DMARC" in result
        assert "DKIM" in result

    def test_dnssec_chain_audit_returns_string(self):
        """dnssec_chain_audit() returns a non-empty string"""
        result = dnssec_chain_audit()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_dnssec_chain_audit_content(self):
        """dnssec_chain_audit() content identifies it as the correct prompt"""
        result = dnssec_chain_audit()
        assert "chain-of-trust" in result
        assert "dns_dnssec_validate" in result
        assert "nsec_info" in result

    def test_soc_email_forensics_returns_string(self):
        """soc_email_forensics() returns a non-empty string"""
        result = soc_email_forensics()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_soc_email_forensics_content(self):
        """soc_email_forensics() content identifies it as the correct prompt"""
        result = soc_email_forensics()
        assert "phishing" in result.lower()
        assert "DKIM" in result
        assert "TRUSTABLE" in result
