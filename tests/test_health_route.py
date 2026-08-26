"""Tests for the three custom OAuth bootstrap routes mounted on FastMCP.

  GET  /.well-known/oauth-authorization-server  — discovery doc
  GET  /oauth/authorize                          — scope-inject + 302
  POST /oauth/register                           — DCR proxy to Pocket ID

`/health` is also tested here as a fourth no-auth custom route.

Pocket ID admin API calls (POST .../api/oidc/clients) are stubbed via an
httpx.AsyncClient.post monkeypatch.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from dns_mcp.server import create_server


@pytest.fixture
def client() -> TestClient:
    app = create_server().streamable_http_app()
    return TestClient(app)


# ── /.well-known/oauth-authorization-server ──────────────────────────────


# The DCR shim (/.well-known/oauth-authorization-server, /oauth/authorize,
# /oauth/register) was removed 2026-08-26 in favour of Pocket ID's Client ID
# Metadata Document support, so the twelve tests that covered those routes went
# with it. Git history has them if a non-CIMD client ever needs the shim back.


def test_health_returns_status(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "uptime_seconds" in body
    assert "dns_tool_version" in body
