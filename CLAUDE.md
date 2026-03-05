# DNS MCP Server — Developer Guide

FastMCP server exposing DNS security analysis tools via stdio transport.
One Docker container per session, spawned by the MCP client, no ports or auth.

See `README.md` for usage. This file is for working in the codebase.

## Key files

| File | Purpose |
|------|---------|
| `server.py` | All tools, helpers, and prompts — the whole server (~2400 lines) |
| `tests/test_tools.py` | pytest unit tests (call tool functions directly) |
| `test-mcp-stdio.sh` | End-to-end MCP protocol test over stdin/stdout |
| `Makefile` | `make build` / `make test` / `make shell` |
| `prompts/` | MCP analyst prompt text files |

## Build & test

```bash
make build          # rebuild Docker image (required after any code change)
make test           # pytest in container (177 tests)
./test-mcp-stdio.sh # end-to-end MCP protocol test (27 tests)
make shell          # interactive shell inside the container
```

**Always run `make build` before `make test` or `./test-mcp-stdio.sh`** — tests
run inside the container, so a stale image means stale code under test.

## Allowed commands

These run without confirmation (saved in `~/.claude/settings.json`):
- `make build` / `make test` / `make shell` / `make rebuild`
- `./test-mcp-stdio.sh`
- `git add` / `git commit` / `git push` / `git pull` / `git status` / `git diff` / `git log` / `git stash`
- `docker run --rm dns-mcp python -c "..."` — debug snippets in container
- `gh release view/list`, `gh pr view/list/diff`, `gh issue view/list`, `gh run view/list`, `gh api`

**Always confirm before running:**
- `git tag` — creating a version tag
- `gh release create` — publishing a GitHub release
- Any `git push --force` or destructive git operation

## Adding a new tool — checklist

When you add a tool, update **all** of these or the tests and e2e will fail:

1. `server.py` — implement the tool with `@mcp.tool()`
2. `server.py` — bump the tool count in the module docstring banner
3. `tests/test_tools.py` — add the tool to the import list
4. `tests/test_tools.py` — add a `TestCheckFoo` class
5. `README.md` — add a row to the appropriate tools table; update count in Architecture section and file structure comment
6. `test-mcp-stdio.sh` — increment expected tool count; add a `call_tool` invocation (renumber subsequent tests)
7. Run `make build && make test && ./test-mcp-stdio.sh` to verify

## Tool structure

Every tool follows this pattern:

```python
@mcp.tool()
def check_foo(
    domain: str = Field(description="..."),
    nameserver: str | None = Field(default=None, description=f"Nameserver IP (default: {DEFAULT_RESOLVER})"),
) -> dict:
    valid, result = validate_domain(domain)
    if not valid:
        return {"error": result, "domain": domain}
    ns = nameserver if nameserver is not None else DEFAULT_RESOLVER
    # ... do the work ...
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        # ... results ...
        "errors": [],
    }
```

Key conventions:
- **Validation first** — `validate_domain`, `validate_selector`, `validate_port` before any I/O
- **Error key** — return `{"error": "..."}` (singular) on validation failure; use `"errors": []` (list) on query failures
- **`DEFAULT_RESOLVER`** — use the constant, never hardcode `"9.9.9.9"`
- **No shell execution** — all DNS via dnspython, RDAP via `requests`, nothing else
- **Nameserver validation** — if a caller-supplied nameserver is accepted, validate it with `ipaddress.ip_address()`
- **TXT lookups** — use shared `_query_all_txt_records()` helper (returns list of strings)

## Testing conventions

Tests call tool functions directly — **not** via the MCP protocol. This means:

- Pydantic `Field(default=...)` values do **not** inject automatically
- Always pass every parameter explicitly, including those with defaults:
  ```python
  # Wrong — nameserver won't default to DEFAULT_RESOLVER
  result = check_foo("example.com")
  # Right
  result = check_foo("example.com", nameserver="9.9.9.9")
  ```
- Tests run against live DNS — they must tolerate intercepted/proxied networks
- Use `detect_hijacking("9.9.9.9")["checks"]` → `transparent_proxy.passed` as
  the signal to relax DNSSEC-dependent assertions (intercepting proxies strip
  the AD flag, turning `dane_valid` into `dane_present_no_dnssec`)
- Check structure and types rather than exact record values

## Coding standards

- `ruff` runs on every commit (pre-commit hook) — it will auto-format staged files; stage the result and commit again if it fires
- Security-first: no `eval`, `exec`, `os.system`, or `shell=True`
- Input validation via explicit allow-lists (`validate_domain` regex, `validate_selector` regex, `validate_port` range check)

## NSEC/NSEC3 test zones

Live zones on `deflationhollow.net` for testing denial-of-existence tools:

| Zone | Type | Notes |
|------|------|-------|
| `nsec-test.deflationhollow.net` | NSEC | Plain NSEC, zone walkable |
| `nsec3-weak.deflationhollow.net` | NSEC3 | iter=0, no salt (RFC 9276 default) |
| `nsec3-salted.deflationhollow.net` | NSEC3 | iter=0, 8-byte salt |
| `nsec3-optout.deflationhollow.net` | NSEC3 | opt-out flag set |

All four zones are DNSSEC-signed with DS records in the parent. Use them as
primary targets in `TestNsecInfo` — avoid zones you don't control (Cloudflare
wildcard responses return NOERROR instead of NXDOMAIN, breaking NSEC probes).

## `remote` branch

The `remote` branch is a separate variant with HTTP/Streamable transport,
a Flask auth proxy, bearer token auth, fail2ban, and ngrok instructions.
Do not merge remote-branch concerns into main.
