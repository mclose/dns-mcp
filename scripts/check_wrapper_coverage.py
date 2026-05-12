"""Check that every tool-shaped function in dns_tool has an MCP wrapper.

Used by `make bump-dns_tool`. Exits non-zero on missing wrappers and prints
the list, so a dns_tool bump can't silently land new capabilities without a
matching @app.tool() wrapper in src/dns_mcp/server.py.

Tool-shaped: public functions in dns_tool's submodules whose names match a
known prefix convention (check_*, cymru_*, detect_*, enumerate_*, nsec_*)
or are explicit one-offs (rdap_lookup, validate). Print formatters
(`print_*`), exception classes, and infrastructure helpers (doh_query,
parse_response, build_root_trust_anchor) are excluded.

Run directly:
    venv/bin/python scripts/check_wrapper_coverage.py
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys

# Settings reads required env at import time. Provide dummies so create_server
# can instantiate inside this script (no real Pocket ID is contacted).
os.environ.setdefault("POCKET_ID_BASE_URL", "https://dummy.example.com")
os.environ.setdefault("POCKET_ID_API_KEY", "dummy")
os.environ.setdefault("SERVER_URL", "https://dummy.example.com")

DNS_TOOL_SUBMODULES = (
    "dns_tool.cert",
    "dns_tool.email",
    "dns_tool.intel",
    "dns_tool.rdap",
    "dns_tool.validate",
)

# Functions whose names match these prefixes are MCP tool candidates.
TOOL_NAME_PREFIXES = ("check_", "cymru_", "detect_", "enumerate_", "nsec_")
# Explicit additions for names that don't match a prefix but are tools.
TOOL_NAME_EXPLICIT = {"rdap_lookup", "validate"}


def _is_tool_name(name: str) -> bool:
    if name.startswith("_") or name.startswith("print_"):
        return False
    if name in TOOL_NAME_EXPLICIT:
        return True
    return any(name.startswith(p) for p in TOOL_NAME_PREFIXES)


def enumerate_dns_tool_functions() -> set[str]:
    """Walk dns_tool's submodules and collect tool-shaped public functions."""
    found: set[str] = set()
    for modname in DNS_TOOL_SUBMODULES:
        try:
            mod = importlib.import_module(modname)
        except ImportError:
            continue
        for name in dir(mod):
            obj = getattr(mod, name, None)
            if not callable(obj):
                continue
            # Restrict to functions defined IN this module (not re-imports)
            if getattr(obj, "__module__", "") != modname:
                continue
            if _is_tool_name(name):
                # dns_tool.validate.validate is wrapped as `dnssec_validate`
                if modname == "dns_tool.validate" and name == "validate":
                    found.add("dnssec_validate")
                else:
                    found.add(name)
    return found


async def enumerate_mcp_wrappers() -> set[str]:
    from dns_mcp.server import create_server

    app = create_server()
    tools = await app.list_tools()
    return {t.name for t in tools}


def main() -> int:
    dns_tool_funcs = enumerate_dns_tool_functions()
    mcp_tools = asyncio.run(enumerate_mcp_wrappers())

    missing = sorted(dns_tool_funcs - mcp_tools)
    extra = sorted(mcp_tools - dns_tool_funcs)

    import dns_tool

    print(f"dns_tool {dns_tool.__version__}: {len(dns_tool_funcs)} tool-shaped functions")
    print(f"dns_mcp:              {len(mcp_tools)} @app.tool wrappers registered")

    if missing:
        print()
        print(f"MISSING wrappers for {len(missing)} dns_tool function(s):")
        for name in missing:
            print(f"  - {name}")
        print()
        print("Add a one-line @app.tool() wrapper for each in src/dns_mcp/server.py")
        print("(see CLAUDE.md § 'Adding a tool'), then re-run.")
        return 1

    if extra:
        # Extra wrappers are adapter-only (ping, whoami, session_stats,
        # reset_stats, etc.) — not a problem. List them for context.
        # dns_query is a thin layer over dns_tool.core.doh_query + parse_response
        # (infrastructure helpers, not tool-shaped), so it's adapter-owned here.
        adapter_owned = {"ping", "whoami", "session_stats", "reset_stats", "dns_query"}
        unexpected = [n for n in extra if n not in adapter_owned]
        if unexpected:
            print()
            print(f"note: {len(unexpected)} wrapper(s) have no dns_tool counterpart:")
            for name in unexpected:
                print(f"  - {name}")
            print("(adapter-only tools are fine; verify these aren't typos.)")

    print()
    print("OK — every dns_tool function has a wrapper.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
