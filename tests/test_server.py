"""Tests for create_server() wiring + Pydantic schema enforcement.

Verifies the FastMCP app advertises the expected tools/prompts/resources
and that type-alias constraints (Domain regex, DnsQType enum, Port range,
DkimSelector pattern, etc.) are enforced at the MCP boundary — i.e. before
any tool handler runs.

No live network. ping/whoami are called directly because they don't touch
DNS; other tool handlers are exercised through the schema layer only.
"""

from __future__ import annotations

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from dns_mcp.server import create_server

EXPECTED_TOOLS_MIN = {
    # Meta
    "ping",
    "whoami",
    "session_stats",
    "reset_stats",
    # DNS / DNSSEC
    "dns_query",
    "dnssec_validate",
    "nsec_info",
    "detect_hijacking",
    # Email security
    "check_spf",
    "check_dmarc",
    "check_dkim",
    "enumerate_dkim_selectors",
    "check_smtp_tlsrpt",
    "check_mta_sts",
    "check_dane",
    "check_tlsa",
    "check_bimi",
    # PKI / CAA
    "check_caa",
    # Threat intel
    "check_rbl",
    "check_dbl",
    "cymru_asn",
    "check_fast_flux",
    "rdap_lookup",
}

EXPECTED_PROMPTS = {
    "dnssec_chain_audit",
    "email_security_audit",
    "nist_800_81r3_audit",
    "soc_email_forensics",
    "soc_email_forensics_batch",
}


@pytest.fixture
def app():
    return create_server()


# ── Registration counts ──────────────────────────────────────────────────


async def test_all_expected_tools_registered(app) -> None:
    names = {t.name for t in await app.list_tools()}
    missing = EXPECTED_TOOLS_MIN - names
    assert not missing, f"missing expected tools: {missing}"


async def test_no_resources_registered(app) -> None:
    """v2 dns-mcp ships no MCP resources (the legacy 3 were stdio-only)."""
    resources = await app.list_resources()
    assert resources == []


async def test_all_prompt_txt_files_registered(app) -> None:
    """Every prompts/*.txt registers as an MCP prompt."""
    names = {p.name for p in await app.list_prompts()}
    assert names == EXPECTED_PROMPTS


# ── Tool descriptions reach the LLM ──────────────────────────────────────


async def test_every_tool_has_a_description(app) -> None:
    """The docstring → tool description contract: no tool ships unlabeled."""
    for t in await app.list_tools():
        assert t.description, f"{t.name} has no description"


# ── Pydantic schema: Domain ──────────────────────────────────────────────


async def test_dns_query_schema_advertises_domain_constraints(app) -> None:
    tools = {t.name: t for t in await app.list_tools()}
    schema = tools["dns_query"].inputSchema
    name_prop = schema["properties"]["name"]
    assert name_prop["maxLength"] == 253
    assert "pattern" in name_prop
    assert "name" in schema["required"]


async def test_dns_query_schema_advertises_qtype_enum(app) -> None:
    tools = {t.name: t for t in await app.list_tools()}
    schema = tools["dns_query"].inputSchema
    qtype = schema["properties"]["qtype"]
    assert "A" in qtype["enum"]
    assert "NSEC3" in qtype["enum"]
    assert "BOGUS" not in qtype["enum"]
    assert qtype["default"] == "A"


async def test_dns_query_dnssec_default_true(app) -> None:
    tools = {t.name: t for t in await app.list_tools()}
    schema = tools["dns_query"].inputSchema
    assert schema["properties"]["dnssec"]["default"] is True


async def test_check_tlsa_port_range(app) -> None:
    tools = {t.name: t for t in await app.list_tools()}
    schema = tools["check_tlsa"].inputSchema
    port = schema["properties"]["port"]
    assert port["minimum"] == 1
    assert port["maximum"] == 65535
    assert port["default"] == 25


async def test_check_tlsa_proto_enum(app) -> None:
    tools = {t.name: t for t in await app.list_tools()}
    schema = tools["check_tlsa"].inputSchema
    proto = schema["properties"]["proto"]
    assert set(proto["enum"]) == {"tcp", "udp"}


async def test_check_dkim_selector_schema(app) -> None:
    tools = {t.name: t for t in await app.list_tools()}
    schema = tools["check_dkim"].inputSchema
    sel = schema["properties"]["selector"]
    assert sel["maxLength"] == 63
    assert sel["pattern"] == r"^[a-zA-Z0-9_-]+$"


# ── Pydantic enforcement at the MCP boundary ─────────────────────────────


async def test_invalid_domain_rejected_at_boundary(app) -> None:
    with pytest.raises(ToolError, match="pattern"):
        await app.call_tool("dns_query", {"name": "not a domain!"})


async def test_invalid_qtype_rejected_at_boundary(app) -> None:
    with pytest.raises(ToolError):
        await app.call_tool("dns_query", {"name": "example.com", "qtype": "BOGUS"})


async def test_overlong_domain_rejected(app) -> None:
    too_long = ".".join(["a" * 60, "b" * 60, "c" * 60, "d" * 60, "e" * 60]) + ".tld"
    assert len(too_long) > 253
    with pytest.raises(ToolError):
        await app.call_tool("dns_query", {"name": too_long})


async def test_invalid_dkim_selector_rejected(app) -> None:
    with pytest.raises(ToolError):
        await app.call_tool("check_dkim", {"domain": "example.com", "selector": "bad selector!"})


async def test_port_out_of_range_rejected(app) -> None:
    with pytest.raises(ToolError):
        await app.call_tool("check_tlsa", {"host": "example.com", "port": 70000})


async def test_invalid_proto_rejected(app) -> None:
    with pytest.raises(ToolError):
        await app.call_tool("check_tlsa", {"host": "example.com", "port": 443, "proto": "sctp"})


# ── Direct tool calls (no network) ───────────────────────────────────────


async def test_ping_returns_uptime_and_version(app) -> None:
    content, structured = await app.call_tool("ping", {})
    assert "timestamp" in structured
    assert "uptime_seconds" in structured
    assert "dns_tool_version" in structured


async def test_whoami_without_token_returns_error_shape(app) -> None:
    """whoami called outside an MCP request context has no access token."""
    content, structured = await app.call_tool("whoami", {})
    # No JWT in context → returns {"error": "no identity available"}
    assert "error" in structured


async def test_session_stats_returns_stats_envelope(app) -> None:
    content, structured = await app.call_tool("session_stats", {})
    assert "session_start" in structured
    assert "session_age_seconds" in structured or "tools" in structured


async def test_ping_increments_track_counter(app) -> None:
    """Confirm @track wires through @app.tool — every call_tool bumps stats."""
    from dns_mcp.tracking import get_stats, reset_stats

    reset_stats()
    await app.call_tool("ping", {})
    await app.call_tool("ping", {})
    stats = get_stats()
    assert stats["ping"]["count"] == 2


# ── Prompts return their file body ───────────────────────────────────────


async def test_prompt_returns_file_body(app) -> None:
    """Each prompt loaded from prompts/*.txt should return its content."""
    from pathlib import Path

    prompts_dir = Path(__file__).resolve().parent.parent / "prompts"
    for prompt_name in EXPECTED_PROMPTS:
        expected = (prompts_dir / f"{prompt_name}.txt").read_text()
        result = await app.get_prompt(prompt_name, {})
        # FastMCP wraps the handler return value into a GetPromptResult with
        # a single user message whose text is the file body.
        messages = result.messages
        assert len(messages) >= 1
        # The handler returns a plain string → first message content.text
        text = messages[0].content.text
        assert text == expected, f"{prompt_name} body mismatch"
