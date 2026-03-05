"""
Per-tool call statistics for mcp-ping-lite.

Module-level state resets on every process start (i.e. every container restart).
Imported by server.py — do not import server from here (circular).
"""

import inspect
import time
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps

_session_start = datetime.now(timezone.utc)

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


def track(name: str):
    """Decorator factory. Records count, timing, and errors per tool call."""

    def decorator(fn):
        if inspect.iscoroutinefunction(fn):

            @wraps(fn)
            async def async_wrapper(*args, **kwargs):
                stats = _call_stats[name]
                now = datetime.now(timezone.utc).isoformat()
                stats["count"] += 1
                if stats["first_called"] is None:
                    stats["first_called"] = now
                stats["last_called"] = now
                t0 = time.perf_counter()
                try:
                    return await fn(*args, **kwargs)
                except Exception:
                    stats["error_count"] += 1
                    raise
                finally:
                    ms = (time.perf_counter() - t0) * 1000
                    stats["_sum_ms"] += ms
                    if ms > stats["max_ms"]:
                        stats["max_ms"] = ms

            return async_wrapper
        else:

            @wraps(fn)
            def sync_wrapper(*args, **kwargs):
                stats = _call_stats[name]
                now = datetime.now(timezone.utc).isoformat()
                stats["count"] += 1
                if stats["first_called"] is None:
                    stats["first_called"] = now
                stats["last_called"] = now
                t0 = time.perf_counter()
                try:
                    return fn(*args, **kwargs)
                except Exception:
                    stats["error_count"] += 1
                    raise
                finally:
                    ms = (time.perf_counter() - t0) * 1000
                    stats["_sum_ms"] += ms
                    if ms > stats["max_ms"]:
                        stats["max_ms"] = ms

            return sync_wrapper

    return decorator


def get_stats() -> dict:
    """Return a clean stats snapshot (no internal _sum_ms key) for session_stats."""
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
    _session_start = datetime.now(timezone.utc)
