import logging

from .config import settings
from .server import create_server

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    # `settings` raised at import if POCKET_ID_BASE_URL or SERVER_URL is missing.
    # 0.0.0.0 inside the container: no published port; Caddy reaches it on proxy-net.
    create_server(settings).run(
        transport="http",
        host="0.0.0.0",  # noqa: S104
        port=8000,
        path="/mcp",
    )
