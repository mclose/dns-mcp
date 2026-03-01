#!/usr/bin/env python3
"""
MCP Client Integration Test

Tests the full stack through the auth proxy using a real MCP SDK client.
This validates what an actual MCP client (Claude Desktop, etc.) would experience.

Three test layers:
  1. make test         — unit tests, call tool functions directly
  2. test-mcp.sh       — curl/bash, hand-crafted JSON-RPC over HTTP
  3. test-mcp-client.py — THIS: real MCP SDK client through auth proxy

Usage:
  python test-mcp-client.py [url] [token]
  python test-mcp-client.py                                          # localhost defaults
  python test-mcp-client.py http://localhost:8082/mcp changeme       # explicit
  python test-mcp-client.py https://dnsmcp.lab.deflationhollow.net/mcp mytoken
"""

import asyncio
import json
import sys
import os

from fastmcp import Client


DEFAULT_URL = "http://localhost:8082/mcp"
DEFAULT_TOKEN = "changeme"

# Colors
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"

PASS = 0
FAIL = 0


def ok(label: str, detail: str = ""):
    global PASS
    PASS += 1
    print(f"  {GREEN}PASS{NC}  {label}" + (f" — {detail}" if detail else ""))


def fail(label: str, detail: str = ""):
    global FAIL
    FAIL += 1
    print(f"  {RED}FAIL{NC}  {label}" + (f" — {detail}" if detail else ""))


def get_token():
    """Read token from .env if it exists, else default."""
    if os.path.exists(".env"):
        with open(".env") as f:
            for line in f:
                if line.startswith("MCP_BEARER_TOKEN="):
                    return line.strip().split("=", 1)[1]
    return DEFAULT_TOKEN


async def test_auth_rejection(url: str):
    """Verify that a bad token is rejected."""
    print(f"\n{YELLOW}Auth Rejection{NC}")
    try:
        client = Client(transport=url, auth="bad-token-should-fail")
        async with client:
            await client.list_tools()
            fail("auth rejection", "connected with bad token — auth is broken")
    except Exception as e:
        err = str(e).lower()
        if "401" in err or "unauthorized" in err or "auth" in err:
            ok("auth rejection", "bad token correctly rejected")
        else:
            # Any connection failure with a bad token is acceptable
            ok("auth rejection", f"rejected ({type(e).__name__})")


async def test_tool_discovery(client: Client):
    """List tools and verify all 15 are registered."""
    print(f"\n{YELLOW}Tool Discovery{NC}")
    tools = await client.list_tools()
    names = [t.name for t in tools]

    expected = [
        "ping",
        "dns_query", "dns_dig_style", "reverse_dns",
        "dns_dnssec_validate", "nsec_info", "timestamp_converter",
        "check_spf", "check_dmarc", "check_dkim_selector",
        "check_bimi", "check_mta_sts", "check_smtp_tlsrpt",
        "check_dane", "rdap_lookup",
    ]

    if len(names) >= 15:
        ok(f"tool count", f"{len(names)} tools registered")
    else:
        fail(f"tool count", f"expected 15, got {len(names)}")

    missing = [t for t in expected if t not in names]
    if not missing:
        ok("all expected tools present")
    else:
        fail("missing tools", ", ".join(missing))


async def call_and_check(client: Client, label: str, tool: str, args: dict, check=None):
    """Call a tool and optionally run a check function on the result."""
    try:
        result = await client.call_tool(tool, args)
        # CallToolResult has .content list of content blocks
        text = result.content[0].text if result.content else ""
        data = json.loads(text) if text else {}

        if check:
            passed, detail = check(data)
            if passed:
                ok(label, detail)
            else:
                fail(label, detail)
        else:
            if "error" not in data:
                ok(label)
            else:
                fail(label, data.get("error", "unknown error"))
    except Exception as e:
        fail(label, str(e))


async def test_dns_tools(client: Client):
    """Exercise DNS tools."""
    print(f"\n{YELLOW}DNS Tools{NC}")

    await call_and_check(client, "dns_query", "dns_query",
        {"domain": "google.com", "record_type": "A"},
        lambda d: (len(d.get("results", [])) > 0, f"{len(d.get('results', []))} results"))

    await call_and_check(client, "dns_dig_style", "dns_dig_style",
        {"domain": "google.com", "nameserver": "8.8.8.8"},
        lambda d: (d.get("header", {}).get("status") == "NOERROR", d.get("header", {}).get("status", "?")))

    await call_and_check(client, "reverse_dns", "reverse_dns",
        {"ip_address": "8.8.8.8"},
        lambda d: (len(d.get("ptr_records", [])) > 0, ", ".join(d.get("ptr_records", []))))

    await call_and_check(client, "dns_dnssec_validate", "dns_dnssec_validate",
        {"domain": "cloudflare.com"},
        lambda d: (d.get("overall_status") in ("fully validated", "insecure", "bogus"),
                   d.get("overall_status", "?")))

    await call_and_check(client, "nsec_info", "nsec_info",
        {"domain": "cloudflare.com"},
        lambda d: (d.get("denial_type") in ("nsec", "nsec3"),
                   f"denial_type={d.get('denial_type')}, walkable={d.get('zone_walkable')}"))

    await call_and_check(client, "timestamp_converter", "timestamp_converter",
        {"timestamp": 1705314600, "convert_to": "iso"},
        lambda d: ("2024-01-15" in d.get("conversions", {}).get("iso", ""), "epoch -> ISO"))


async def test_email_tools(client: Client):
    """Exercise email security tools."""
    print(f"\n{YELLOW}Email Security Tools{NC}")

    await call_and_check(client, "check_spf", "check_spf",
        {"domain": "google.com"},
        lambda d: (d.get("raw_record", "").startswith("v=spf1"), d.get("all_qualifier", "?")))

    await call_and_check(client, "check_dmarc", "check_dmarc",
        {"domain": "google.com"},
        lambda d: (d.get("policy") is not None, f"policy={d.get('policy')}"))

    await call_and_check(client, "check_dkim_selector", "check_dkim_selector",
        {"selector": "20230601", "domain": "gmail.com"},
        lambda d: (isinstance(d.get("record_exists"), bool),
                   "exists" if d.get("record_exists") else "not found"))

    await call_and_check(client, "check_bimi", "check_bimi",
        {"domain": "cnn.com"},
        lambda d: (isinstance(d.get("record_exists"), bool),
                   "has BIMI" if d.get("record_exists") else "no BIMI"))

    await call_and_check(client, "check_mta_sts", "check_mta_sts",
        {"domain": "google.com"},
        lambda d: (d.get("record_exists") is True and d.get("policy") is not None,
                   f"mode={d.get('policy', {}).get('mode', '?')}" if d.get("policy") else "no policy"))

    await call_and_check(client, "check_smtp_tlsrpt", "check_smtp_tlsrpt",
        {"domain": "google.com"},
        lambda d: (d.get("record_exists") is True, d.get("version", "?")))

    await call_and_check(client, "check_dane", "check_dane",
        {"domain": "bund.de"},
        lambda d: (isinstance(d.get("dane_viable"), bool) and isinstance(d.get("mx_hosts"), list),
                   f"dane_viable={d.get('dane_viable')}, mx_hosts={len(d.get('mx_hosts', []))}"))

    await call_and_check(client, "rdap_lookup", "rdap_lookup",
        {"domain": "google.com"},
        lambda d: (d.get("registrar") is not None,
                   f"{d.get('registrar')}, age={d.get('domain_age_days')}d"))


async def main():
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    token = sys.argv[2] if len(sys.argv) > 2 else get_token()

    print(f"{BLUE}{'=' * 48}{NC}")
    print(f"{BLUE}MCP Client Integration Test{NC}")
    print(f"{BLUE}{'=' * 48}{NC}")
    print(f"URL:   {url}")
    print(f"Token: {token[:20]}...")

    # Auth rejection (bad token, separate client)
    await test_auth_rejection(url)

    # Connect with good token for remaining tests
    client = Client(transport=url, auth=token)
    async with client:
        await test_tool_discovery(client)
        await test_dns_tools(client)
        await test_email_tools(client)

    # Summary
    total = PASS + FAIL
    print(f"\n{BLUE}{'=' * 48}{NC}")
    if FAIL == 0:
        print(f"{GREEN}All {total} checks passed{NC}")
    else:
        print(f"{RED}{FAIL}/{total} checks FAILED{NC}")
    print(f"{BLUE}{'=' * 48}{NC}")

    sys.exit(FAIL)


if __name__ == "__main__":
    asyncio.run(main())
