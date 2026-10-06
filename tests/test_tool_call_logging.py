"""Per-call structured logging (issue #10) and the reverse_dns tool.

Every @track'd tool call must emit exactly one JSON line on the
`dns_mcp.tool_call` logger carrying tool / subject / duration_ms / outcome /
verdict / errors / session_id — and never the full argument set (in
particular never check_dkim's `headers`, which can hold private mail).

No live network: dns_tool entry points are monkeypatched on dns_mcp.server.
"""

from __future__ import annotations

import asyncio
import json
import logging

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from dns_mcp import server as server_mod
from dns_mcp import tracking
from dns_mcp.server import create_server
from dns_mcp.tracking import track

REQUIRED_FIELDS = {
    "event",
    "ts",
    "tool",
    "subject",
    "duration_ms",
    "outcome",
    "verdict",
    "errors",
    "session_id",
}


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def tool_log():
    """Capture raw lines from the (non-propagating) tool_call logger."""
    logger = logging.getLogger("dns_mcp.tool_call")
    h = _ListHandler()
    logger.addHandler(h)
    tracking.reset_stats()
    yield h
    logger.removeHandler(h)
    tracking.reset_stats()


def _lines(h: _ListHandler) -> list[dict]:
    return [json.loads(r.getMessage()) for r in h.records]


@pytest.fixture
def app():
    return create_server()


# ── Decorator-level ──────────────────────────────────────────────────────


def test_async_call_emits_one_json_line(tool_log) -> None:
    @track("demo")
    async def fn(domain: str) -> dict:
        return {"verdict": "pass", "errors": ["a", "b"]}

    asyncio.run(fn(domain="example.com"))
    [line] = _lines(tool_log)
    assert REQUIRED_FIELDS <= line.keys()
    assert line["event"] == "tool_call"
    assert line["tool"] == "demo"
    assert line["subject"] == "example.com"
    assert line["outcome"] == "ok"
    assert line["verdict"] == "pass"
    assert line["errors"] == 2
    assert isinstance(line["duration_ms"], float)
    assert line["session_id"] is None  # no MCP request in a unit test


def test_sync_call_emits_one_json_line(tool_log) -> None:
    @track("demo_sync")
    def fn(ip: str) -> str:
        return "not a dict"

    fn(ip="192.0.2.1")
    [line] = _lines(tool_log)
    assert line["subject"] == "192.0.2.1"
    assert line["verdict"] is None and line["errors"] is None


def test_return_value_is_passed_through_unchanged(tool_log) -> None:
    sentinel = {"verdict": "pass"}

    @track("demo_ident")
    async def fn(domain: str) -> dict:
        return sentinel

    assert asyncio.run(fn(domain="example.com")) is sentinel


def test_exception_path_logged_and_reraised(tool_log) -> None:
    @track("demo_boom")
    async def fn(domain: str) -> dict:
        raise RuntimeError("upstream exploded")

    with pytest.raises(RuntimeError, match="upstream exploded"):
        asyncio.run(fn(domain="example.com"))
    [line] = _lines(tool_log)
    assert tool_log.records[0].levelno == logging.ERROR
    assert line["outcome"] == "exception"
    assert line["exc_type"] == "RuntimeError"
    assert line["exc"] == "upstream exploded"
    assert "Traceback" in line["traceback"] and "upstream exploded" in line["traceback"]
    assert line["subject"] == "example.com"


def test_non_subject_arguments_never_logged(tool_log) -> None:
    secret = "From: alice@example.com\r\nSubject: quarterly layoffs\r\n"

    @track("demo_priv")
    async def fn(domain: str, selector: str, headers: str) -> dict:
        return {}

    asyncio.run(fn(domain="example.com", selector="s1", headers=secret))
    raw = tool_log.records[0].getMessage()
    assert "layoffs" not in raw and "alice@" not in raw and "s1" not in raw
    assert "headers" not in json.loads(raw)


def test_session_id_read_from_request_header(tool_log) -> None:
    from mcp.server.lowlevel.server import request_ctx
    from mcp.shared.context import RequestContext

    class _Req:
        headers = {"mcp-session-id": "sess-abc123"}

    @track("demo_sess")
    async def fn() -> dict:
        return {}

    async def run() -> None:
        tok = request_ctx.set(
            RequestContext(
                request_id=1, meta=None, session=None, lifespan_context=None, request=_Req()
            )
        )
        try:
            await fn()
        finally:
            request_ctx.reset(tok)

    asyncio.run(run())
    assert _lines(tool_log)[0]["session_id"] == "sess-abc123"


# ── Through the FastMCP app ──────────────────────────────────────────────


async def test_call_tool_emits_line_with_verdict(app, tool_log, monkeypatch) -> None:
    monkeypatch.setattr(server_mod, "_check_dmarc", lambda d, e: {"verdict": "pass", "errors": []})
    _, structured = await app.call_tool("check_dmarc", {"domain": "reallyclose.com"})
    assert structured == {"verdict": "pass", "errors": []}
    [line] = _lines(tool_log)
    assert line["tool"] == "check_dmarc"
    assert line["subject"] == "reallyclose.com"
    assert (line["outcome"], line["verdict"], line["errors"]) == ("ok", "pass", 0)


async def test_check_dkim_headers_never_logged(app, tool_log, monkeypatch) -> None:
    monkeypatch.setattr(server_mod, "_check_dkim", lambda *a, **k: {"verdict": "pass"})
    headers = (
        "Received: from mx.private-host.internal\r\n"
        "DKIM-Signature: v=1; d=example.com; s=fe-abc123; b=x\r\n"
    )
    await app.call_tool("check_dkim", {"domain": "example.com", "headers": headers})
    monkeypatch.setattr(server_mod, "_enumerate_dkim_selectors", lambda *a, **k: {})
    await app.call_tool("enumerate_dkim_selectors", {"domain": "example.com", "headers": headers})
    assert len(tool_log.records) == 2
    for r in tool_log.records:
        raw = r.getMessage()
        assert "private-host" not in raw and "fe-abc123" not in raw and "DKIM" not in raw


async def test_call_tool_exception_logged(app, tool_log, monkeypatch) -> None:
    def boom(d, e):
        raise ConnectionError("doh unreachable")

    monkeypatch.setattr(server_mod, "_check_dmarc", boom)
    with pytest.raises(ToolError):
        await app.call_tool("check_dmarc", {"domain": "example.com"})
    [line] = _lines(tool_log)
    assert line["outcome"] == "exception"
    assert line["exc_type"] == "ConnectionError"
    assert "doh unreachable" in line["traceback"]


# ── reverse_dns ──────────────────────────────────────────────────────────


def test_reverse_name_ipv4() -> None:
    assert server_mod._reverse_name("8.8.4.4") == "4.4.8.8.in-addr.arpa"


def test_reverse_name_ipv6() -> None:
    assert server_mod._reverse_name("2001:db8::1") == (
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    )


@pytest.mark.parametrize("bad", ["example.com", "999.1.1.1", "abc.def", "1.2.3", ":::"])
def test_reverse_name_rejects_non_ip(bad) -> None:
    with pytest.raises(ValueError):
        server_mod._reverse_name(bad)


async def test_reverse_dns_tool_queries_ptr_via_dns_query_path(app, tool_log, monkeypatch) -> None:
    seen = []

    def fake_doh(name, qtype, endpoint, dnssec, subnet=None):
        seen.append((name, qtype, dnssec))
        return "MSG"

    monkeypatch.setattr(server_mod, "doh_query", fake_doh)
    monkeypatch.setattr(
        server_mod, "parse_response", lambda m, n, q, subnet=None: {"query": {"name": n, "type": q}}
    )
    _, structured = await app.call_tool("reverse_dns", {"ip": "8.8.8.8"})
    assert seen == [("8.8.8.8.in-addr.arpa", "PTR", True)]
    assert structured == {"query": {"name": "8.8.8.8.in-addr.arpa", "type": "PTR"}}
    assert _lines(tool_log)[0]["subject"] == "8.8.8.8"

    _, structured = await app.call_tool("reverse_dns", {"ip": "2001:db8::1", "dnssec": False})
    assert seen[-1][0].endswith(".ip6.arpa") and seen[-1][1:] == ("PTR", False)


@pytest.mark.parametrize("bad", ["example.com", "999.1.1.1", "abc.def"])
async def test_reverse_dns_tool_rejects_non_ip(app, monkeypatch, bad) -> None:
    def fail(*a, **k):
        raise AssertionError("must not query")

    monkeypatch.setattr(server_mod, "doh_query", fail)
    with pytest.raises(ToolError) as excinfo:
        await app.call_tool("reverse_dns", {"ip": bad})
    # An unregistered tool also raises ToolError; make sure this is validation.
    assert "unknown tool" not in str(excinfo.value).lower()
