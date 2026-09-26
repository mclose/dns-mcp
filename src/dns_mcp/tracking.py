"""
Per-tool call statistics for dns-mcp.

Module-level state resets on every process start (i.e. every container restart).
Imported by server.py — do not import server from here (circular).

Pattern: see ~/projects/ping-lite/TOOL_CALL_TRACKING.md.

Besides the in-memory counters, every tracked call emits exactly one JSON line
to stderr on the `dns_mcp.tool_call` logger (issue #10), so a single call can
be correlated with the gateway access log / fleet-sink by time + MCP session
id. Only the call's *subject* (domain / host / ip / zone) is logged — never the
full argument set. In particular `headers` (check_dkim /
enumerate_dkim_selectors) can hold private mail headers and is never logged:
the subject is picked from an explicit allow-list of argument names.
"""

import inspect
import json
import logging
import sys
import time
import traceback
from collections import defaultdict
from datetime import UTC, datetime
from functools import wraps

_session_start = datetime.now(UTC)

_call_stats: dict[str, dict] = defaultdict(
    lambda: {
        "count": 0,
        "error_count": 0,
        "first_called": None,
        "last_called": None,
        "_sum_ms": 0.0,
        "max_ms": 0.0,
    }
)


# ── Per-call structured log ──────────────────────────────────────────────
# Dedicated logger with its own plain stderr handler. FastMCP's
# configure_logging() installs a RichHandler on the root logger, which
# prefixes and line-wraps messages — that would split a JSON line. So this
# logger formats as bare "%(message)s" and does not propagate.
logger = logging.getLogger("dns_mcp.tool_call")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

# Argument names that identify what a call is *about*. First match wins.
# Allow-list, not deny-list: anything not named here (headers, selector,
# flags, ...) never reaches the log.
SUBJECT_ARGS: tuple[str, ...] = ("domain", "name", "host", "zone", "ip", "resolver_ip")

# Cap so a pathological value can't produce a giant log line. Every subject
# arg is already length-limited by its Pydantic type; this is belt-and-braces.
_SUBJECT_MAX = 253
_EXC_MSG_MAX = 500


def _subject(kwargs: dict) -> str | None:
    for key in SUBJECT_ARGS:
        val = kwargs.get(key)
        if isinstance(val, str) and val:
            return val[:_SUBJECT_MAX]
    return None


def _session_id() -> str | None:
    """MCP session id of the in-flight request, if any.

    Read from the `mcp-session-id` header of the HTTP request that carried
    the CallToolRequest — the same id as the transport's "Created new
    transport with session ID" line. None outside a request (unit tests,
    stdio).
    """
    try:
        from mcp.server.lowlevel.server import request_ctx

        req = request_ctx.get().request
        if req is None:
            return None
        return req.headers.get("mcp-session-id")
    except Exception:  # LookupError outside a request; never fail a call over logging
        return None


def _emit(
    name: str,
    kwargs: dict,
    duration_ms: float,
    result=None,
    exc: BaseException | None = None,
) -> None:
    record: dict = {
        "event": "tool_call",
        "ts": datetime.now(UTC).isoformat(),
        "tool": name,
        "subject": _subject(kwargs),
        "duration_ms": round(duration_ms, 1),
        "outcome": "exception" if exc is not None else "ok",
        "session_id": _session_id(),
    }
    if exc is None:
        if isinstance(result, dict):
            verdict = result.get("verdict")
            errors = result.get("errors")
            record["verdict"] = verdict if isinstance(verdict, str) else None
            record["errors"] = len(errors) if isinstance(errors, list) else None
        else:
            record["verdict"] = None
            record["errors"] = None
    else:
        record["exc_type"] = type(exc).__name__
        record["exc"] = str(exc)[:_EXC_MSG_MAX]
        record["traceback"] = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    try:
        line = json.dumps(record, default=str)
    except Exception:  # never let logging change a tool's behavior
        return
    if exc is None:
        logger.info(line)
    else:
        logger.error(line)


def track(name: str):
    """Decorator factory. Records count, timing, and errors per tool call,
    and emits one JSON `tool_call` log line per call (see module docstring).

    Must sit *inside* `@app.tool()` so FastMCP sees the wrapped function's
    original signature (preserved via @wraps). FastMCP passes tool arguments
    as keyword arguments, which is what the subject lookup reads. The return
    value and any exception pass through unchanged.
    """

    def decorator(fn):
        if inspect.iscoroutinefunction(fn):

            @wraps(fn)
            async def async_wrapper(*args, **kwargs):
                stats = _call_stats[name]
                now = datetime.now(UTC).isoformat()
                stats["count"] += 1
                if stats["first_called"] is None:
                    stats["first_called"] = now
                stats["last_called"] = now
                t0 = time.perf_counter()
                result = None
                exc: BaseException | None = None
                try:
                    result = await fn(*args, **kwargs)
                    return result
                except Exception as e:
                    stats["error_count"] += 1
                    exc = e
                    raise
                finally:
                    ms = (time.perf_counter() - t0) * 1000
                    stats["_sum_ms"] += ms
                    if ms > stats["max_ms"]:
                        stats["max_ms"] = ms
                    _emit(name, kwargs, ms, result, exc)

            return async_wrapper
        else:

            @wraps(fn)
            def sync_wrapper(*args, **kwargs):
                stats = _call_stats[name]
                now = datetime.now(UTC).isoformat()
                stats["count"] += 1
                if stats["first_called"] is None:
                    stats["first_called"] = now
                stats["last_called"] = now
                t0 = time.perf_counter()
                result = None
                exc: BaseException | None = None
                try:
                    result = fn(*args, **kwargs)
                    return result
                except Exception as e:
                    stats["error_count"] += 1
                    exc = e
                    raise
                finally:
                    ms = (time.perf_counter() - t0) * 1000
                    stats["_sum_ms"] += ms
                    if ms > stats["max_ms"]:
                        stats["max_ms"] = ms
                    _emit(name, kwargs, ms, result, exc)

            return sync_wrapper

    return decorator


def get_stats() -> dict:
    """Return a clean stats snapshot (no internal _sum_ms key)."""
    result = {}
    for tool_name, s in _call_stats.items():
        count = s["count"]
        result[tool_name] = {
            "count": count,
            "error_count": s["error_count"],
            "first_called": s["first_called"],
            "last_called": s["last_called"],
            "mean_ms": round(s["_sum_ms"] / count, 1) if count > 0 else 0.0,
            "max_ms": round(s["max_ms"], 1),
        }
    return result


def reset_stats() -> None:
    """Clear all accumulated stats. Session start time is reset to now."""
    global _session_start
    _call_stats.clear()
    _session_start = datetime.now(UTC)
