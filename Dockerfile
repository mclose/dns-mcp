FROM python:3.12-alpine3.21

# System packages for DNS debugging and runtime
RUN apk add --no-cache \
    bind-tools \
    drill \
    bind-dnssec-tools \
    jq \
    bash \
    curl

# Create non-root user
RUN adduser -D -u 1000 claude

# Working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

# Copy application code and tests
COPY server.py server-proxy.py ./
COPY tests/ tests/

# Own app dir
RUN chown -R claude:claude /app

# Switch to non-root user
USER claude

# Default: run the FastMCP server
EXPOSE 8083
CMD ["python", "server.py"]
