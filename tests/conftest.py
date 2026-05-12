"""Shared fixtures for dns-mcp tests.

Covers the bits of the environment dns-mcp normally pulls from outside its
own process: the Pocket ID JWKS endpoint, signed JWTs, and pydantic-settings
env. Tests never hit the real network.

Note: env vars are set at conftest import time, BEFORE any `from dns_mcp...`
import in a test module. `dns_mcp.config.Settings()` runs at module import,
so the env must be in place first. Pytest imports conftest.py before test
modules, so this works.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from typing import Any

# ── Env (set before any dns_mcp import) ──────────────────────────────────
_TEST_POCKET_ID = "https://id.test.example"
_TEST_SERVER_URL = "https://dns-mcp.test.example"

os.environ.setdefault("POCKET_ID_BASE_URL", _TEST_POCKET_ID)
os.environ.setdefault("POCKET_ID_API_KEY", "test-api-key")
os.environ.setdefault("SERVER_URL", _TEST_SERVER_URL)

import httpx  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from jose import jwk as jose_jwk  # noqa: E402
from jose import jwt as jose_jwt  # noqa: E402

TEST_POCKET_ID = _TEST_POCKET_ID
TEST_SERVER_URL = _TEST_SERVER_URL


# ── JWT signing material ─────────────────────────────────────────────────
# Generate an RSA and an EC keypair once per session; expose the public
# halves as a JWKS dict, and the private halves as PEM bytes for signing
# test tokens.


@pytest.fixture(scope="session")
def rsa_keypair() -> dict[str, Any]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwk_dict = jose_jwk.construct(pub_pem, algorithm="RS256").to_dict()
    jwk_dict["kid"] = "test-rsa-kid"
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    return {"private_pem": pem, "jwk": jwk_dict, "kid": "test-rsa-kid", "alg": "RS256"}


@pytest.fixture(scope="session")
def ec_keypair() -> dict[str, Any]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwk_dict = jose_jwk.construct(pub_pem, algorithm="ES256").to_dict()
    jwk_dict["kid"] = "test-ec-kid"
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "ES256"
    return {"private_pem": pem, "jwk": jwk_dict, "kid": "test-ec-kid", "alg": "ES256"}


@pytest.fixture
def jwks(rsa_keypair) -> dict[str, Any]:
    """JWKS dict containing the test RSA public key (default for tests).

    Note: python-jose's `jwt.decode()` does not reliably do kid-based lookup
    when a JWKS contains mixed key types (RSA + EC). Real Pocket ID serves a
    single key type, so we mirror that. EC tests use `ec_jwks`.
    """
    return {"keys": [rsa_keypair["jwk"]]}


@pytest.fixture
def ec_jwks(ec_keypair) -> dict[str, Any]:
    """JWKS containing only the test EC public key — for ES256 tests."""
    return {"keys": [ec_keypair["jwk"]]}


def sign_jwt(
    keypair: dict[str, Any],
    *,
    sub: str = "user-123",
    issuer: str = TEST_POCKET_ID,
    extra: dict[str, Any] | None = None,
    expires_in: int = 3600,
) -> str:
    """Sign a JWT with the test keypair. Helper, not a fixture — call from tests."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": sub,
        "iat": now,
        "exp": now + expires_in,
        "scope": "openid profile email",
    }
    if extra:
        claims.update(extra)
    return jose_jwt.encode(
        claims,
        keypair["private_pem"],
        algorithm=keypair["alg"],
        headers={"kid": keypair["kid"]},
    )


# ── Mock JWKS endpoint ───────────────────────────────────────────────────
# Patch httpx.AsyncClient.get so any GET to /.well-known/jwks.json returns
# the test JWKS. Auth tests reset the module-level cache before each test.


def _make_jwks_patch(monkeypatch: pytest.MonkeyPatch, jwks_payload: dict[str, Any]) -> list[str]:
    """Replace httpx.AsyncClient.get with a stub that returns the given JWKS.

    Returns the list that records every GET URL — tests assert cache behavior
    by checking len(calls).
    """
    calls: list[str] = []

    class _Resp:
        def __init__(self, payload: dict[str, Any]) -> None:
            self._payload = payload
            self.status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self._payload

    async def fake_get(self, url, *args, **kwargs):  # noqa: ARG001
        calls.append(url)
        if url.endswith("/.well-known/jwks.json"):
            return _Resp(jwks_payload)
        raise AssertionError(f"unexpected GET in test: {url}")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    return calls


@pytest.fixture
def patch_jwks_endpoint(
    monkeypatch: pytest.MonkeyPatch, jwks: dict[str, Any]
) -> Iterator[list[str]]:
    """Stub httpx.AsyncClient.get to return the default (RSA) JWKS."""
    yield _make_jwks_patch(monkeypatch, jwks)


@pytest.fixture
def patch_jwks_endpoint_ec(
    monkeypatch: pytest.MonkeyPatch, ec_jwks: dict[str, Any]
) -> Iterator[list[str]]:
    """Stub httpx.AsyncClient.get to return an EC-only JWKS."""
    yield _make_jwks_patch(monkeypatch, ec_jwks)


@pytest.fixture
def reset_jwks_cache() -> Iterator[None]:
    """Reset auth module's global JWKS cache before/after each auth test."""
    from dns_mcp import auth

    auth._jwks_cache = None
    auth._jwks_cache_at = 0
    yield
    auth._jwks_cache = None
    auth._jwks_cache_at = 0
