"""`/health` is the one unauthenticated route (the Docker healthcheck probes it).

The DCR shim routes it used to sit beside were removed 2026-08-26 (CIMD).
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from dns_mcp.server import create_server


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_server().http_app(path="/mcp"))


def test_health_returns_status(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "uptime_seconds" in body
    assert "dns_tool_version" in body
