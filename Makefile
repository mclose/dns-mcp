.PHONY: build rebuild lint import-check shell deploy logs status test smoke bump-dns_tool verify-prod coverage-check

build:
	docker build -t dns-mcp:dev .

rebuild:
	docker build --no-cache -t dns-mcp:dev .

lint:
	pre-commit run --all-files

import-check: build
	docker run --rm \
		-e POCKET_ID_BASE_URL=https://dummy.example.com \
		-e POCKET_ID_API_KEY=dummy \
		-e SERVER_URL=https://dummy.example.com \
		--entrypoint python dns-mcp:dev \
		-c "import asyncio; from dns_mcp.server import create_server; \
		    app = create_server(); tools = asyncio.run(app.list_tools()); \
		    print(f'OK: {len(tools)} tools')"

shell:
	docker run --rm -it --entrypoint /bin/bash dns-mcp:dev

deploy:
	git push origin main
	git push vps main

logs:
	ssh docker-nyc3 'docker logs -f dns-mcp'

status:
	ssh docker-nyc3 'docker compose -f ~/dns-mcp/compose.yaml ps'

# Local unit tests. Hits no network — all externalities (JWKS endpoint,
# Pocket ID admin API, DoH) are mocked.
test:
	venv/bin/pytest tests/ -v

# End-to-end curl-based smoke. Doubles as usage documentation; defaults to
# production. Pass DNS_MCP_TOKEN=<jwt> to exercise the authenticated MCP
# protocol path (initialize → tools/list → tools/call).
smoke:
	scripts/smoke.sh

# Standalone wrapper-coverage check: every tool-shaped function in dns_tool
# must have a matching @app.tool() in server.py. Run on its own to audit,
# or as part of `make bump-dns_tool`.
coverage-check:
	venv/bin/python scripts/check_wrapper_coverage.py

# One-shot dns_tool version bump. Drives the full pre-deploy cycle so the
# work doesn't depend on remembering steps:
#   1. Rewrite the URL pin in pyproject.toml
#   2. Install the new tarball into the local venv
#   3. Wrapper-coverage check — hard-fails if dns_tool has new tool-shaped
#      functions that aren't wrapped here yet (you must add the @app.tool()
#      wrappers manually before re-running)
#   4. make build — rebuild the Docker image (pulls the new tarball)
#   5. make test — full pytest suite (64 tests)
#   6. make import-check — final sanity inside the built image
#   7. Commit the pin bump. Does NOT push; review the diff and `make deploy`
#      when ready.
#
# Usage: make bump-dns_tool V=X.Y.Z
bump-dns_tool:
	@test -n "$(V)" || (echo "usage: make bump-dns_tool V=X.Y.Z"; exit 1)
	@echo "→ Rewriting URL pin to dns_tool-$(V)"
	sed -i 's|dns_tool-[0-9][^"]*\.tar\.gz|dns_tool-$(V).tar.gz|' pyproject.toml
	@grep "dns-tool @" pyproject.toml
	@echo "→ Installing dns_tool $(V) into venv"
	venv/bin/pip install --upgrade "dns-tool @ https://dist.lab.deflationhollow.net/dns_tool-$(V).tar.gz"
	@echo "→ Wrapper-coverage check"
	$(MAKE) coverage-check
	@echo "→ Rebuilding Docker image"
	$(MAKE) build
	@echo "→ Running pytest"
	$(MAKE) test
	@echo "→ Import-check inside image"
	$(MAKE) import-check
	@echo "→ Committing pin bump"
	git add pyproject.toml
	@git diff --cached --quiet && echo "pin already at $(V)" || \
	    git commit -m "pin: bump dns_tool to $(V)"
	@echo
	@echo "✓ dns_tool $(V) ready. Review with: git log -p HEAD"
	@echo "  Deploy with:                  make deploy"
	@echo "  Verify after deploy with:     make verify-prod"

# Post-deploy verification: curl /health, confirm dns_tool_version matches
# the local pin. Exits non-zero on mismatch so it's safe to chain.
verify-prod:
	@PIN=$$(grep -oP 'dns_tool-\K[0-9.]+(?=\.tar\.gz)' pyproject.toml); \
	 HEALTH=$$(curl -sf https://dns-mcp.lab.deflationhollow.net/health); \
	 LIVE_VER=$$(echo "$$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['dns_tool_version'])"); \
	 UPTIME=$$(echo "$$HEALTH"   | python3 -c "import sys,json; print(json.load(sys.stdin)['uptime_seconds'])"); \
	 echo "→ Local pin:    $$PIN"; \
	 echo "→ Live version: $$LIVE_VER"; \
	 echo "→ Uptime:       $$UPTIME seconds"; \
	 if [ "$$PIN" = "$$LIVE_VER" ]; then \
	   echo "✓ Pin matches live"; \
	 else \
	   echo "✗ MISMATCH — local pin $$PIN, live $$LIVE_VER"; exit 1; \
	 fi
