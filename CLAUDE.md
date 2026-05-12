# DNS MCP Server — Developer Guide

FastMCP Streamable HTTP server. OAuth via Pocket ID. Tool implementations are
thin wrappers around the `dns_tool` library — `dns_tool` owns all DNS logic;
this server owns auth bootstrap and tool/prompt registration.

See `README.md` for usage and architecture. This file is for working in the
codebase.

## Layout

```
src/dns_mcp/
├── __init__.py
├── __main__.py     # entrypoint — `python -m dns_mcp`
├── config.py       # pydantic-settings Settings class
├── auth.py         # JWKSTokenVerifier (validates JWTs from Pocket ID JWKS)
└── server.py       # FastMCP app: OAuth routes + 16 tools + 4 prompts
```

`server.py.legacy` is the pre-2.0.0 stdio server kept as a reference for
porting the remaining deferred tools. Do not modify it; new tool work
goes in `dns_tool` and re-registers a one-line wrapper here. Migration
status, phase plan, and per-tool gap analysis live in
`~/projects/claude-packages/MIGRATION.md`.

## Build & test

```bash
make build           # rebuild Docker image
make lint            # pre-commit run --all-files (ruff check + format)
make import-check    # verify create_server() registers all tools
make test            # pytest tests/ — unit tests, all externalities mocked
make smoke           # scripts/smoke.sh — curl-based e2e against prod by default
make shell           # interactive shell inside the container

make bump-dns_tool V=X.Y.Z   # rewrite pin → install → coverage → build → test → import-check → commit
make verify-prod             # curl /health, confirm prod's dns_tool_version matches the local pin
make coverage-check          # standalone: every dns_tool tool-shaped function has an @app.tool() wrapper
```

Unit tests in `tests/` cover auth (JWKSTokenVerifier), the three OAuth
bootstrap routes, `create_server()` wiring and Pydantic-schema enforcement,
config loading, tracking, and prompt registration. No live network — JWKS
and the Pocket ID admin API are stubbed via httpx monkeypatch.

`scripts/smoke.sh` exercises the live HTTP surface (health, discovery,
authorize redirect, MCP protocol). Each step prints the curl command, so
the script doubles as usage documentation. Pass `DNS_MCP_TOKEN=<jwt>` to
run the authenticated MCP path (initialize → tools/list → tools/call).

## Adding a tool

**Full per-port release pipeline:** see
`~/projects/claude-packages/MIGRATION.md` §6 (single source of truth for
test → PR → bump → build → deploy → pin → wrap → import-check). Do not
duplicate the steps here; they have drifted before.

**Triggered from claude-packages:** `make release-dns_tool V=X.Y.Z` in
claude-packages runs its bump → build → deploy chain, then automatically
runs `make bump-dns_tool V=X.Y.Z` here. That target hard-fails (via
`scripts/check_wrapper_coverage.py`) if dns_tool ships tool-shaped
functions you haven't wrapped yet — so the workflow surfaces the
"register a wrapper" step naturally rather than relying on an `@echo
reminder` you read at the wrong moment.

The server-side responsibility is step 9 — register a thin wrapper in
`src/dns_mcp/server.py`:

```python
@app.tool()
async def check_foo(domain: Domain) -> dict[str, Any]:
    """Tool-level description for the LLM. One paragraph minimum.

    Explain what this checks, what the structured return looks like, and
    when an analyst should reach for it.
    """
    return await asyncio.to_thread(_check_foo, domain, DOH_ENDPOINT)
```

Key conventions for the wrapper:

- **Type aliases at module top** — `Domain`, `DnsQType`, `IPv4`, `IPAddress`,
  `DkimSelector`, `Port`, `Proto`. Reuse, do not redefine. They carry
  Pydantic `Field` metadata (descriptions, regex patterns, ranges) that
  flows into the JSON Schema the LLM sees.
- **`asyncio.to_thread`** wraps every synchronous `dns_tool` call so the
  FastMCP event loop is not blocked by network I/O.
- **Docstring is the tool description** — FastMCP introspects the function
  and uses the docstring as the tool descriptor `description` field. Write
  for the LLM: what it does, what comes back, when to use it.
- **No business logic in this layer** — anything beyond a one-line
  `to_thread` wrapper is a sign the function belongs in `dns_tool`.

## Pydantic Field pattern

Every parameter that is not a primitive bool gets an `Annotated[T, Field(...)]`
type. Define type aliases at module top to avoid repetition:

```python
DnsQType = Literal["A", "AAAA", "MX", "TXT", ...]

Domain = Annotated[
    str,
    Field(
        description="Fully-qualified domain name (e.g. 'example.com').",
        pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?...",
        max_length=253,
    ),
]
```

Three benefits:

1. **Schema enforcement at MCP boundary** — FastMCP rejects malformed input
   before `dns_tool` is called.
2. **Better LLM accuracy** — `Literal[...]` enums let the tool-use sampler
   pick from the exact valid set; descriptions and regex patterns are
   surfaced in the tool descriptor.
3. **Single source of truth** — no drift between docstring and runtime
   behavior; the annotation is the doc, the validation, and the schema.

Why `str` and not Pydantic IP types: `dns_tool` functions take strings.
`pydantic.IPvAnyAddress` would coerce to `IPv4Address` objects and require
`str()` at the call site. Patterns + `str` is clearer and matches what the
library wants.

## OAuth bootstrap

Three custom routes mounted by FastMCP, lifted verbatim from tiny-mcp:

| Route | Purpose |
|-------|---------|
| `GET /.well-known/oauth-authorization-server` | Discovery doc — issuer is Pocket ID, authorization & registration endpoints proxy through us, token & jwks endpoints point straight at Pocket ID |
| `GET /oauth/authorize` | Inject `scope=openid profile email` if Claude.ai omits it, then 302 to Pocket ID |
| `POST /oauth/register` | Dynamic Client Registration — creates a new OIDC client on Pocket ID via admin API, returns DCR-shaped response to the MCP client |

`POST /mcp` (the tool endpoint) is auth-gated: bearer JWT verified against
Pocket ID JWKS by `JWKSTokenVerifier` before any `@app.tool()` handler runs.

## Allowed commands

These run without confirmation (saved in `~/.claude/settings.json`):

- `make build` / `make lint` / `make import-check` / `make rebuild` / `make shell`
- `make deploy` / `make logs` / `make status`
- `git add` / `git commit` / `git push` / `git pull` / `git status` / `git diff` / `git log` / `git stash`
- `gh release view/list`, `gh pr view/list/diff`, `gh issue view/list`, `gh run view/list`, `gh api`

**Always confirm before running:**

- `git tag` — creating a version tag
- `gh release create` — publishing a GitHub release
- Any `git push --force` or destructive git operation

## Coding standards

- `ruff` runs on every commit (pre-commit hook) — auto-formats staged Python
  files. Stage the result and commit again if it fires.
- CI runs `pre-commit run --all-files` (lint job) plus a build + import-check
  job that instantiates `create_server()` and asserts ≥16 tools register.
- Snyk runs on every PR for vulnerability scanning.
- Security-first: no `eval`, `exec`, `os.system`, or `shell=True`.
- Input validation via Pydantic `Field` constraints at the MCP boundary.

## Deployment

`make deploy` pushes to two remotes:

- `origin` (GitHub, source of truth)
- `vps` (bare repo on docker-nyc3 — post-receive hook checks out main and
  runs `docker compose up -d`)

Container runs as part of the `gateway` (Caddy on docker-nyc3) `proxy-net`
Docker bridge. Caddy vhost lives in `mclose/gateway:conf.d/dns-mcp.conf`.

## Pre-2.0.0 notes (porting reference)

The 11 tools listed in README "Open work" still live in `server.py.legacy`.
When porting:

- The legacy implementations include extensive risk-flag enumerations,
  DNSSEC validation patterns, and test zone references — preserve them.
- Move the implementation into the appropriate `dns_tool` module; the MCP
  wrapper here is one line.
- The `~/.claude/projects/-home-mclose-projects-dns-mcp/memory/MEMORY.md`
  index has detailed notes on `check_caa`, `check_zone_transfer`, NSEC3
  test zones, and other pre-2.0.0 implementation details. Read it before
  starting a port.

## NSEC/NSEC3 test zones

Live zones on `deflationhollow.net` for testing denial-of-existence tools:

| Zone | Type | Notes |
|------|------|-------|
| `nsec-test.deflationhollow.net` | NSEC | Plain NSEC, zone walkable |
| `nsec3-weak.deflationhollow.net` | NSEC3 | iter=0, no salt (RFC 9276 default) |
| `nsec3-salted.deflationhollow.net` | NSEC3 | iter=0, 8-byte salt |
| `nsec3-optout.deflationhollow.net` | NSEC3 | opt-out flag set |

All four zones are DNSSEC-signed with DS records in the parent. Use them as
primary targets in tests for `nsec_info` (and the deferred port of
`check_caa`'s NSEC3 logic).
