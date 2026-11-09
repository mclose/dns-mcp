# Base and uv pinned by digest (target shape §2); Dependabot (docker) moves them.
FROM ghcr.io/astral-sh/uv:0.12.19@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424 AS uv
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
LABEL io.modelcontextprotocol.server.name="io.github.mclose/dns-mcp"

COPY --from=uv /uv /usr/local/bin/uv
RUN adduser --disabled-password --gecos "" appuser
WORKDIR /app

# Install exactly what uv.lock says — a rebuild can never pull a new major.
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY src/ src/
COPY prompts/ prompts/
RUN uv sync --locked --no-dev --no-editable

ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1

# Exec form, no shell: a shell-form probe that times out orphans its child, and
# only an init reaps it (funes-mcp #5). compose sets `init: true`.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"]

RUN chown -R appuser /app
USER appuser
CMD ["python", "-m", "dns_mcp"]
