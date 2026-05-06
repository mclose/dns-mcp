# Coding Guidelines

## New Project Checklist
Wire these up on day one, before writing feature code:
- [ ] `README.md` — architecture overview, quickstart, env vars
- [ ] `CLAUDE.md` — key commands, gotchas, deployment steps (see style guide below)
- [ ] `docs/coding-guide.md` and `docs/release-process.md` — copy from template
- [ ] Pre-commit hook — ruff + test suite
- [ ] `CHANGELOG.md` — start with `## Unreleased` section
- [ ] GitHub Actions CI — at minimum, run `make test` on push/PR
- [ ] `requirements.txt` + `requirements.lock` (pip-compile) — pinned lockfile from day one
- [ ] `make test` — unit tests runnable locally without external deps
- [ ] `make smoke` — post-deploy sanity check against the live service
- [ ] `.env.example` — document all required env vars; `.env` stays out of git

---

## Security
- When possible, use "latest" tagged versions. LLMs tend to "pick an exact version" that is not current.
- Heavily prefer official distributions over "popular" user repos
- Central tools not actively being maintained should be called out

## Git Workflow
- Two remotes: `origin` → GitHub (source of truth, private (occasionally public) repo); `vps` (or `prod`) → production server (push triggers deploy)
- Deploy via `git push vps main` → post-receive hook rebuilds the service
- Tag known-good states (`git tag pre-<major-change>`) before risky refactors
- `.env` is NOT in git — document required vars in `.env.example`; copy to server separately after any rebuild from scratch

## Pre-commit Hook
- Runs linter (ruff) + full test suite before every commit — fail fast, no exceptions
- Tests must pass before any commit is allowed
- Pydantic will be used on function-to-function inputs to guarantee consistency, accuracy, and input validation for security
- e2e tests consisting of command line tools such as curl, cut, tr, sed, awk, grep, ls, find, xargs and tar should be created as a bash script that can be run on commits
- **ruff restage gotcha**: ruff auto-formats staged files in place — if it fires, `git add` the reformatted files and commit again; the original commit did not happen

## Testing
- Tests run without external dependencies when env vars are unset — use env-conditional setup so the suite is always runnable locally
- Quarantine flaky network tests rather than tolerating intermittent CI failures
- **Own your test targets**: for network-dependent tests, use hosts or zones you control. Third-party domains change TTLs, DNS records, and response behavior without notice. Tests that assert exact values against uncontrolled targets will eventually break.

## CI (GitHub Actions)
- Every project gets a CI workflow that runs `make test` on every push and PR to `main`
- A one-job workflow is enough to start — the goal is catching regressions before they merge, not a full pipeline
- Secrets (API keys, env vars) go in GitHub repository secrets, not in the workflow file
- `make smoke` may also run in CI against a staging environment if one exists

## Input Validation
- **Validate before I/O**: check all inputs and return early *before* any network call, file access, or subprocess. Never pass unvalidated input into a query or command.
- Use explicit allow-lists (regex patterns, port ranges, enum values) rather than block-lists
- Pydantic for inter-function contracts; manual validation helpers for external inputs at system boundaries
- Return a clear error immediately on validation failure — don't attempt partial execution

## Return Value Contracts
- Tools and API handlers should return a consistent shape regardless of success or failure
- Distinguish validation failures from query/runtime failures in the schema:
  - `{"error": "..."}` — singular string, returned immediately on bad input (no I/O attempted)
  - `{"errors": [...]}` — list, accumulated during execution (partial results may be present)
- Include a `timestamp` (UTC ISO 8601) and an echo of key input parameters in every structured response — makes logs and downstream consumers self-contained

## Named Constants
- Never hardcode IPs, URLs, hostnames, ports, or magic values inline. Name them at module level.
- This makes configuration changes a one-line edit and makes the intent of the value clear at every use site.

## Changelog
- Every project maintains a `CHANGELOG.md` with an `## Unreleased` section at the top
- When cutting a release, rename `## Unreleased` to `## vX.Y.Z — YYYY-MM-DD` and add a fresh `## Unreleased` above it
- Entries go under one of: `Added`, `Changed`, `Fixed`, `Removed`
- `gh release create --generate-notes` is a fallback, not a substitute — release notes should reflect intent, not just PR titles

## Versioning
- Bump **patch** for bug fixes and non-breaking changes
- Bump **minor** for new features or tools (backwards compatible)
- Bump **major** for removed, renamed, or breaking changes to public interfaces
- State this policy in `CLAUDE.md` so it's clear what a version bump means in this project

## Dependency Management
- `requirements.txt` — unpinned or loosely pinned (e.g. `requests>=2.28`) — expresses intent
- `requirements.lock` — pip-compile output, fully pinned — used for installs; committed to git
- Regenerate the lockfile deliberately when updating deps, not passively on every install
- This satisfies both "use latest" (update the lockfile intentionally) and reproducible installs

## Adding a Feature — Checklist
- Before starting, identify every file that must change for the feature to be complete and tested
- Common set: implementation, unit tests, e2e test script, README/docs, CLAUDE.md if behavior changes, CHANGELOG.md
- The feature is not done until all of these are updated — a passing unit test with a broken e2e is not done

## Python Environment
- venv always at `./venv` — use `venv/bin/python`, `venv/bin/pip`
- Keep `requirements.txt` current on every dependency change

## CLI / Tool Design
- Mutating commands require `--dry-run` — show what would change without doing it
- Lead with `--dry-run` in any demo or documentation

## Docker
- Named volumes for writable state (DBs, token stores, generated files) — keeps `/config` mountable `:ro`
- Document volume ownership: Docker only initializes a named volume from the image on first creation — pre-create dirs as the correct user in the Dockerfile
- If containers make outbound calls that hairpin through a public address, verify IPv6 NAT is configured in the Docker daemon
- Use `docker compose` to maintain data, network space and container naming — this also makes `docker compose logs -f -t` consistent for the user

## Health Check / Smoke Test
- Every service exposes a health check — a lightweight endpoint or command that returns success if the service is running correctly
- `make smoke` runs a minimal end-to-end query against the live service: one known-good input, assert a known-good output shape
- Smoke tests are separate from unit tests — they run post-deploy against the real service, not a mock
- A deploy is not confirmed until `make smoke` passes

## Logging
- Structured logging from day one — emit JSON (`{"ts": ..., "level": ..., "event": ..., "key": "value"}`) rather than free-form strings
- This costs nothing upfront and makes grep, jq, and future log aggregation trivially easy to add
- `--quiet` should suppress startup noise but never suppress errors or warnings
- Log each significant operation: what was called, key parameters, outcome, duration

## CLAUDE.md Style
- Include: architecture overview, key commands, gotchas, deployment steps
- Omit: tutorials, rationale that belongs in git history, anything derivable from reading the code
- Keep it short enough that it fits in context without scrolling

## Docstring-as-Instruction Pattern (MCP / AI tools)
- Tool docstrings are sent to the model as part of the tool definition — behavioral hints work there
- Use this to control output formatting, e.g. "Always display the result wrapped in a markdown code fence in your response."
- Especially useful when the tool result drawer doesn't render markdown but the main chat does
