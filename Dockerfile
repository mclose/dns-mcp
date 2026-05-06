FROM python:3.12-slim
LABEL io.modelcontextprotocol.server.name="io.github.mclose/dns-mcp"

WORKDIR /app

RUN adduser --disabled-password --gecos "" appuser

COPY pyproject.toml .
COPY src/ src/
COPY prompts/ prompts/

RUN pip install --no-cache-dir .

USER appuser

CMD ["python", "-m", "dns_mcp"]
