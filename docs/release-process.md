# Release & Deployment Process

## Purpose

This document describes how releases are cut for this project — what the
current process is, what invariants must hold, and what the Makefile enforces.

---

## Single source of truth

The canonical version lives in **one place** (`<VERSION_FILE>`). All other
version references — git tags, image tags, registry identifiers — are derived
from it. They are never set independently.

If the version appears more than once in `<VERSION_FILE>` (e.g., both a
`"version"` field and an embedded identifier string), both must be updated
together. The `bump` target handles this.

---

## Invariants

- **Tests pass before tagging.** The `tag` target depends on `test`. A tag is
  never created against a commit that hasn't passed the test suite.
- **Tag matches manifest version.** The git tag `vX.Y.Z` is always derived
  from `<VERSION_FILE>` — never typed by hand.
- **Commit before tag.** The version bump is committed before the tag is
  applied, so the tag points to the bump commit.
- **Tag and push are one operation.** `git tag` and `git push origin main
  vX.Y.Z` run together so a local-only tag is never left dangling.

---

## Current process (manual)

1. Edit `<VERSION_FILE>` — bump the version field (and any derived fields)
2. `git add <VERSION_FILE> && git commit -m "Bump version to X.Y.Z"`
3. `git tag vX.Y.Z`
4. `git push origin main vX.Y.Z` (or separate push + push --tags)
5. `gh release create vX.Y.Z --title "vX.Y.Z" --notes "..."`

Steps 3–5 are currently free-form shell commands. They are not guarded and
not in the Makefile.

---

## Makefile targets

```makefile
VERSION := $(shell jq -r '.version' <VERSION_FILE>)

# Bump version in <VERSION_FILE>, then commit
# Usage: make bump V=X.Y.Z
bump:
	@test -n "$(V)" || (echo "usage: make bump V=X.Y.Z"; exit 1)
	<update VERSION_FILE with V>
	git add <VERSION_FILE>
	git commit -m "Bump version to $(V)"

# Run full test suite (prerequisite for tag)
test:
	<run tests>

# Tag current commit and push — requires tests to pass first
tag: test
	git tag v$(VERSION)
	git push origin main v$(VERSION)

# Create GitHub release from current tag
gh-release:
	gh release create v$(VERSION) --title "v$(VERSION)" --generate-notes
```

The `<update VERSION_FILE with V>` step is project-specific (e.g., a `jq`
one-liner for JSON, `sed` for a plain text file, `npm version` for Node).

---

## Git workflow

```
main
  └─ commit: "Bump version to X.Y.Z"
       └─ tag: vX.Y.Z  ← pushed in same operation
```

Releases are tags on `main`. No release branches.

---

## Failure modes this process prevents

| Risk | Guard |
|---|---|
| Tagging before tests pass | `tag` depends on `test` |
| Tag/manifest version mismatch | `VERSION` extracted from manifest, never typed |
| Tag exists locally but not on remote | push is part of `tag`, not a separate step |
| Forgetting the GitHub release | `gh-release` is a named target, not a free-form command |
| Version fields drifting within manifest | `bump` updates all fields atomically |
