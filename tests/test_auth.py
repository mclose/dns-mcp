"""Auth on fastmcp's JWTVerifier + the fail-closed sub allowlist.

Signature/JWKS mechanics (caching, kid lookup) are fastmcp's job and tested
there; these tests pin dns-mcp's contract: audience = <server_url>/mcp, issuer,
expiry, forgery, the allowlist, and the advertised metadata.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from starlette.testclient import TestClient

from dns_mcp.auth import AllowlistJWTVerifier
from dns_mcp.config import Settings
from dns_mcp.server import create_server
from tests.conftest import TEST_POCKET_ID, TEST_RESOURCE, TEST_SERVER_URL

ISS = TEST_POCKET_ID
_KP = RSAKeyPair.generate()


def _load(token, allowed=frozenset({"user-123"})):
    v = AllowlistJWTVerifier(
        public_key=_KP.public_key,
        issuer=ISS,
        audience=TEST_RESOURCE,
        algorithm="RS256",
        allowed_subs=allowed,
    )
    return asyncio.run(v.load_access_token(token))


def _token(sub="user-123", aud=TEST_RESOURCE, iss=ISS, **kw):
    return _KP.create_token(subject=sub, issuer=iss, audience=aud, **kw)


def test_valid_token_accepted_with_claims():
    exp_before = int(time.time()) + 3000
    at = _load(_token(additional_claims={"client_id": "https://claude.ai/x"}))
    assert at is not None
    assert at.claims["sub"] == "user-123"
    assert at.client_id == "https://claude.ai/x"
    assert at.expires_at and at.expires_at >= exp_before


def test_aud_as_bare_string_or_list_accepted():
    assert _load(_token(aud=TEST_RESOURCE)) is not None
    assert _load(_token(aud=[TEST_RESOURCE])) is not None


@pytest.mark.parametrize(
    "aud",
    [
        "https://tiny-mcp.test.example/mcp",  # another MCP server on the same IdP
        ["some-client-uuid", ISS],  # plain login token
        None,  # no aud
        TEST_SERVER_URL,  # the OLD bare-origin resource, rejected after the move
    ],
)
def test_wrong_or_missing_audience_rejected(aud):
    assert _load(_token(aud=aud)) is None


def test_issuer_expiry_forgery_and_garbage_rejected():
    assert _load(_token(iss="https://evil.example")) is None
    assert _load(_token(expires_in_seconds=-60)) is None
    forged = RSAKeyPair.generate().create_token(
        subject="user-123", issuer=ISS, audience=TEST_RESOURCE
    )
    assert _load(forged) is None
    assert _load("not.a.jwt") is None


def test_sub_allowlist_fails_closed():
    assert _load(_token(sub="intruder")) is None
    assert _load(_token(), allowed=frozenset()) is None


def test_settings_resource_and_allowlist():
    s = Settings(
        pocket_id_base_url=ISS,
        server_url=TEST_SERVER_URL + "/",
        allowed_subs=" a, b ,",
        _env_file=None,
    )
    assert s.resource == TEST_RESOURCE
    assert s.allowed_sub_set == {"a", "b"}


def test_metadata_points_at_pocket_id_and_tokenless_is_401():
    app = create_server().http_app(path="/mcp")
    with TestClient(app) as client:
        meta = client.get("/.well-known/oauth-protected-resource/mcp")
        tokenless = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert meta.status_code == 200
    assert meta.json()["resource"] == TEST_RESOURCE
    assert [s.rstrip("/") for s in meta.json()["authorization_servers"]] == [ISS]
    assert tokenless.status_code == 401
