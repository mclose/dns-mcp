# DNS MCP Server — Developer Guide

## Standard (2026-11, dns-mcp #14)

This server follows `~/projects/project-guides/docs/mcp-server-target-shape.md`,
with mcp-ping-lite as the reference implementation:

- **Standalone `fastmcp` >= 4.1.6** on `mcp` 2.x. The vendored
  `mcp.server.fastmcp` (capped `<2`) and the hand-rolled python-jose JWKS
  verifier are gone.
- **Auth, three layers, all fail closed:** the shared Claude CIMD client is
  restricted to Pocket ID group `mcp_users`; `aud` must equal
  `https://dns-mcp.lab.deflationhollow.net/mcp`; `ALLOWED_SUBS` (Pocket ID user
  ids) is a per-server allowlist where empty = nobody. Missing
  `POCKET_ID_BASE_URL`/`SERVER_URL` stops the process at startup.
- **Resource = `<SERVER_URL>/mcp`** (was the bare origin until this port).
  Metadata at `/.well-known/oauth-protected-resource/mcp`; the Pocket ID API is
  registered under that URI; cowmon pins it. Move all three together.
- **uv** + committed `uv.lock`, floors only; digest-pinned base/uv images;
  Dependabot. `make bump-dns_tool` re-locks (`uv lock --upgrade-package dns-tool`).
- Every tool: `title` + `readOnlyHint`/`destructiveHint`/`openWorldHint`.
  `reset_stats` is the one tool marked not-read-only/destructive (it clears this
  server's own counters), so Claude.ai always asks before calling it.
- Result size: Claude.ai rejects results over ~150k chars. `check_ct_logs`
  caps `certificates` (google.com was 285k) and links to crt.sh; other tools
  measured well under (largest dnssec_validate ~11k).
- SSRF: `detect_hijacking` takes public resolver IPs only. MTA-STS/BIMI fetches
  in dns_tool are HTTPS with `verify=True` and no redirects, so an internal
  target can't present a valid cert. AXFR (`check_zone_transfer`) follows the
  zone's NS records inside dns_tool on port 53 only — low risk, tracked there.
- **`check_zone_transfer` run from claude reports deflationhollow.net AXFR
  "open":** claude reaches the nameservers over WireGuard, which is in BIND's
  `allow-transfer` ACL. From the public internet (docker-nyc3, caddy-nyc3, and so
  the production connector) all three NS refuse. Judge exposure from docker-nyc3.
- Every call logs one JSON line (`tracking.py`): tool, subject, duration,
  outcome, verdict, session id and the caller's `sub`.

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
├── config.py       # pydantic-settings Settings (required URLs, ALLOWED_SUBS)
├── auth.py         # fastmcp JWTVerifier + fail-closed sub allowlist
├── tracking.py     # per-call JSON log lines + session stats
└── server.py       # fastmcp app: 26 tools + 4 prompts + /health
```

`server.py.legacy` is the pre-2.0.0 stdio server kept as a reference for
porting the remaining deferred tools. Do not modify it; new tool work
goes in `dns_tool` and re-registers a one-line wrapper here. Migration
status, phase plan, and per-tool gap analysis live in
`~/projects/claude-packages/MIGRATION.md`.

## Build & test

```bash
make install         # uv sync --locked → .venv
make check           # ruff + format check + pytest + wrapper coverage (git hook runs this)
make upgrade         # uv lock --upgrade, then check — the only way versions move
make build           # rebuild Docker image
make lint            # ruff check + format check
make import-check    # verify create_server() registers all tools
make test            # pytest tests/ — unit tests, all externalities mocked
make smoke           # scripts/smoke.sh — curl-based e2e against prod by default
make shell           # interactive shell inside the container

make bump-dns_tool V=X.Y.Z   # rewrite pin → install → coverage → build → test → import-check → commit
make verify-prod             # curl /health, confirm prod's dns_tool_version matches the local pin
make coverage-check          # standalone: every dns_tool tool-shaped function has an @app.tool() wrapper
```

Unit tests in `tests/` cover auth (audience incl. the old bare-origin resource,
issuer, expiry, forgery, allowlist, metadata, 401), `/health`, schema
enforcement, annotations, the CT result cap, the resolver guard, tracking and
prompts. Server tests go through fastmcp's in-memory `Client` (`ClientApp` in
conftest), so they see what an MCP client sees. No live network; tokens are
signed locally.

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

## Auth

`auth.build_auth()`: fastmcp `JWTVerifier` (Pocket ID JWKS, issuer, `aud` =
`<SERVER_URL>/mcp`, RS256) wrapped by `AllowlistJWTVerifier` for `ALLOWED_SUBS`,
inside a `RemoteAuthProvider` whose `authorization_servers` is Pocket ID — so
clients read Pocket ID's discovery and use CIMD. No `/oauth/*` routes, no admin
key. `/health` is the only unauthenticated route.

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
- CI (uv, SHA-pinned actions): ruff, pytest, wrapper coverage, and an image
  build + import-check that lists exactly 26 tools through a fastmcp Client.
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
