.PHONY: build test shell

build:
	docker compose build

test:
	docker compose run --rm dns-mcp pytest tests/ -v

shell:
	docker compose run --rm dns-mcp /bin/bash
