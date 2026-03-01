#!/usr/bin/env bash

#
# DNS MCP Server Startup Script
# Brings up the Docker Compose stack (FastMCP + auth proxy)
#
# Usage:
#   ./startup.sh          Start the stack in detached mode
#   ./startup.sh -f       Start and follow logs
#   ./startup.sh --logs   Start and follow logs
#
# Test:
#   ./test-mcp.sh <url> <token>
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure log directory exists on host for fail2ban
LOG_PATH="${LOG_PATH:-/var/log/mcp-proxy}"
if [ ! -d "$LOG_PATH" ]; then
    echo "Creating log directory: $LOG_PATH"
    sudo mkdir -p "$LOG_PATH"
    sudo chown "$USER" "$LOG_PATH"
fi

# Build and start
echo "Starting DNS MCP stack..."
docker compose up -d --build

# Show status
echo ""
docker compose ps
echo ""
echo "Proxy:  http://localhost:${PROXY_PORT:-8082}"
echo "MCP:    http://localhost:${MCP_PORT:-8083} (internal)"
echo "Logs:   $LOG_PATH"
echo ""

# Follow logs if requested
if [[ "${1:-}" == "-f" || "${1:-}" == "--logs" ]]; then
    docker compose logs -f
fi
