"""
Data-plane tests for dns_mcp.tracking.

Tests only the tracking module's pure-Python surface (track decorator,
get_stats, reset_stats). MCP-tool registration is covered by integration
tests against a running server, not here.
"""

import asyncio

import pytest

from dns_mcp import tracking
from dns_mcp.tracking import get_stats, reset_stats, track


@pytest.fixture(autouse=True)
def _reset():
    """Each test starts with empty stats."""
    reset_stats()
    yield
    reset_stats()


def test_sync_call_recorded():
    @track("demo")
    def fn():
        return "ok"

    fn()
    fn()
    stats = get_stats()
    assert stats["demo"]["count"] == 2
    assert stats["demo"]["error_count"] == 0


def test_async_call_recorded():
    @track("demo_async")
    async def fn():
        return "ok"

    asyncio.run(fn())
    stats = get_stats()
    assert stats["demo_async"]["count"] == 1


def test_error_counted_and_reraised():
    @track("demo_err")
    def fn():
        raise ValueError("boom")

    with pytest.raises(ValueError):
        fn()

    stats = get_stats()
    assert stats["demo_err"]["count"] == 1
    assert stats["demo_err"]["error_count"] == 1


def test_timing_recorded():
    import time

    @track("demo_slow")
    def fn():
        time.sleep(0.01)

    fn()
    stats = get_stats()
    assert stats["demo_slow"]["mean_ms"] >= 10.0
    assert stats["demo_slow"]["max_ms"] >= 10.0


def test_first_and_last_called_timestamps():
    @track("demo_ts")
    def fn():
        pass

    fn()
    fn()
    stats = get_stats()
    assert stats["demo_ts"]["first_called"] is not None
    assert stats["demo_ts"]["last_called"] is not None
    # last_called should be >= first_called
    assert stats["demo_ts"]["last_called"] >= stats["demo_ts"]["first_called"]


def test_get_stats_strips_internal_sum_ms():
    @track("demo_clean")
    def fn():
        pass

    fn()
    stats = get_stats()
    assert "_sum_ms" not in stats["demo_clean"]


def test_reset_clears_counters():
    @track("demo_reset")
    def fn():
        pass

    fn()
    fn()
    assert get_stats()["demo_reset"]["count"] == 2
    reset_stats()
    assert get_stats() == {}


def test_reset_advances_session_start():
    start_before = tracking._session_start
    # Spin briefly to ensure clock advances
    import time

    time.sleep(0.001)
    reset_stats()
    assert tracking._session_start > start_before


def test_decorator_preserves_signature_and_docstring():
    @track("demo_sig")
    def fn(x: int, y: int = 5) -> int:
        """Add two integers."""
        return x + y

    # @wraps preservation — FastMCP relies on these
    assert fn.__name__ == "fn"
    assert fn.__doc__ == "Add two integers."
    assert fn(2, 3) == 5
