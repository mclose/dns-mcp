.PHONY: build rebuild test shell

build:
	docker compose build

rebuild:
	docker compose build --no-cache

test:
	docker compose run --rm dns-mcp pytest tests/ -v

shell:
	docker compose run --rm dns-mcp /bin/bash
