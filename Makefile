.PHONY: build rebuild lint import-check shell deploy logs status

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

# `test` target: dropped during the 2.0.0 rewrite. Will return once
# tests/ is rewritten against the new FastMCP architecture.
