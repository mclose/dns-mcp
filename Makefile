.PHONY: build rebuild lint import-check shell deploy logs status test smoke

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
