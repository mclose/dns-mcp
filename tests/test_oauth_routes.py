"""Tests for the three custom OAuth bootstrap routes mounted on FastMCP.

  GET  /.well-known/oauth-authorization-server  — discovery doc
  GET  /oauth/authorize                          — scope-inject + 302
  POST /oauth/register                           — DCR proxy to Pocket ID

`/health` is also tested here as a fourth no-auth custom route.

Pocket ID admin API calls (POST .../api/oidc/clients) are stubbed via an
httpx.AsyncClient.post monkeypatch.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from starlette.testclient import TestClient

from dns_mcp.server import create_server
from tests.conftest import TEST_POCKET_ID, TEST_SERVER_URL


@pytest.fixture
def client() -> TestClient:
    app = create_server().streamable_http_app()
    return TestClient(app)


# ── /.well-known/oauth-authorization-server ──────────────────────────────


def test_discovery_doc_shape(client: TestClient) -> None:
    r = client.get("/.well-known/oauth-authorization-server")
    assert r.status_code == 200
    doc = r.json()

    assert doc["issuer"] == TEST_POCKET_ID
    assert doc["authorization_endpoint"] == f"{TEST_SERVER_URL}/oauth/authorize"
    assert doc["token_endpoint"] == f"{TEST_POCKET_ID}/api/oidc/token"
    assert doc["jwks_uri"] == f"{TEST_POCKET_ID}/.well-known/jwks.json"
    assert doc["registration_endpoint"] == f"{TEST_SERVER_URL}/oauth/register"

    assert "openid" in doc["scopes_supported"]
    assert "code" in doc["response_types_supported"]
    assert "authorization_code" in doc["grant_types_supported"]
    assert "S256" in doc["code_challenge_methods_supported"]


def test_discovery_doc_is_json(client: TestClient) -> None:
    r = client.get("/.well-known/oauth-authorization-server")
    assert "application/json" in r.headers["content-type"]


# ── /oauth/authorize ─────────────────────────────────────────────────────


def test_authorize_injects_scope_when_missing(client: TestClient) -> None:
    r = client.get(
        "/oauth/authorize",
        params={
            "client_id": "abc",
            "response_type": "code",
            "redirect_uri": "https://claude.ai/cb",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    loc = urlparse(r.headers["location"])
    assert loc.netloc == urlparse(TEST_POCKET_ID).netloc
    assert loc.path == "/authorize"

    qs = parse_qs(loc.query)
    assert qs["scope"] == ["openid profile email"]
    assert qs["client_id"] == ["abc"]


def test_authorize_preserves_provided_scope(client: TestClient) -> None:
    r = client.get(
        "/oauth/authorize",
        params={"client_id": "abc", "scope": "openid"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    loc = urlparse(r.headers["location"])
    qs = parse_qs(loc.query)
    assert qs["scope"] == ["openid"]


def test_authorize_redirects_to_pocket_id_authorize(client: TestClient) -> None:
    r = client.get(
        "/oauth/authorize",
        params={"client_id": "abc"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["location"].startswith(f"{TEST_POCKET_ID}/authorize?")


# ── /oauth/register ──────────────────────────────────────────────────────


@pytest.fixture
def patch_pocket_id_register(monkeypatch: pytest.MonkeyPatch):
    """Stub Pocket ID admin POST /api/oidc/clients."""
    calls: list[dict[str, Any]] = []

    class _Resp:
        def __init__(self, status: int, payload: dict[str, Any]) -> None:
            self.status_code = status
            self._payload = payload

        def json(self) -> dict[str, Any]:
            return self._payload

    state: dict[str, Any] = {"status": 201, "payload": {"id": "client-xyz"}}

    async def fake_post(self, url, *args, **kwargs):  # noqa: ARG001
        calls.append(
            {
                "url": url,
                "headers": kwargs.get("headers"),
                "content": kwargs.get("content"),
            }
        )
        return _Resp(state["status"], state["payload"])

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    return {"calls": calls, "state": state}


def test_register_creates_client_and_returns_dcr_response(
    client: TestClient, patch_pocket_id_register
) -> None:
    body = {
        "redirect_uris": ["https://claude.ai/cb"],
        "client_name": "Claude",
        "scope": "openid profile email",
    }
    r = client.post("/oauth/register", json=body)
    assert r.status_code == 201

    resp = r.json()
    assert resp["client_id"] == "client-xyz"
    assert resp["redirect_uris"] == ["https://claude.ai/cb"]
    assert resp["client_name"] == "Claude"
    assert resp["token_endpoint_auth_method"] == "none"
    assert "client_id_issued_at" in resp


def test_register_calls_pocket_id_admin_api_with_api_key(
    client: TestClient, patch_pocket_id_register
) -> None:
    client.post(
        "/oauth/register",
        json={"redirect_uris": ["https://claude.ai/cb"], "client_name": "Claude"},
    )

    calls = patch_pocket_id_register["calls"]
    assert len(calls) == 1
    assert calls[0]["url"] == f"{TEST_POCKET_ID}/api/oidc/clients"
    assert calls[0]["headers"]["X-API-Key"] == "test-api-key"

    import json

    payload = json.loads(calls[0]["content"])
    assert payload["name"] == "Claude"
    assert payload["callbackURLs"] == ["https://claude.ai/cb"]
    assert payload["isPublic"] is True
    assert payload["pkceEnabled"] is True


def test_register_truncates_long_client_name(client: TestClient, patch_pocket_id_register) -> None:
    long_name = "x" * 100
    client.post(
        "/oauth/register",
        json={"redirect_uris": ["https://claude.ai/cb"], "client_name": long_name},
    )
    import json

    payload = json.loads(patch_pocket_id_register["calls"][0]["content"])
    assert len(payload["name"]) == 50


def test_register_synthesizes_client_name_when_missing(
    client: TestClient, patch_pocket_id_register
) -> None:
    client.post("/oauth/register", json={"redirect_uris": ["https://claude.ai/cb"]})
    import json

    payload = json.loads(patch_pocket_id_register["calls"][0]["content"])
    assert payload["name"].startswith("dcr-")
    assert len(payload["name"]) <= 50


def test_register_invalid_json_returns_400(client: TestClient) -> None:
    r = client.post(
        "/oauth/register",
        content=b"not-json",
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"


def test_register_non_list_redirect_uris_returns_400(
    client: TestClient,
) -> None:
    r = client.post(
        "/oauth/register",
        json={"redirect_uris": "https://claude.ai/cb"},  # string, not list
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"


def test_register_pocket_id_failure_returns_500(
    client: TestClient, patch_pocket_id_register
) -> None:
    patch_pocket_id_register["state"]["status"] = 502
    patch_pocket_id_register["state"]["payload"] = {"error": "upstream"}

    r = client.post(
        "/oauth/register",
        json={"redirect_uris": ["https://claude.ai/cb"]},
    )
    assert r.status_code == 500
    assert r.json()["error"] == "server_error"


# ── /health ──────────────────────────────────────────────────────────────


def test_health_returns_status(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "uptime_seconds" in body
    assert "dns_tool_version" in body
