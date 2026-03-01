.PHONY: build up down test logs shell rebuild

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

test:
	docker compose exec mcp pytest tests/ -v

logs:
	docker compose logs -f

shell:
	docker compose exec mcp /bin/bash

rebuild:
	docker compose down
	docker compose up -d --build
