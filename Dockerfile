FROM python:3.12-alpine3.21
LABEL io.modelcontextprotocol.server.name="io.github.mclose/dns-mcp"

# System packages for DNS operations
RUN apk add --no-cache \
    bind-tools \
    drill \
    bind-dnssec-tools \
    bash

# Create non-root user
RUN adduser -D -u 1000 claude

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

# Copy application code, prompts, and tests
COPY server.py ./
COPY prompts/ prompts/
COPY tests/ tests/

RUN chown -R claude:claude /app
USER claude

CMD ["python", "server.py"]
