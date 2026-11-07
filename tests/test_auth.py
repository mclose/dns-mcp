"""Tests for dns_mcp.auth.JWKSTokenVerifier.

Mocks httpx so no real network is used. Test JWTs are signed locally with
RSA and EC keypairs whose public halves are served via the mocked JWKS
endpoint.
"""

from __future__ import annotations

import time

import pytest

from dns_mcp.auth import JWKSTokenVerifier, JWTAccessToken
from tests.conftest import TEST_POCKET_ID, TEST_SERVER_URL, sign_jwt


@pytest.mark.asyncio
async def test_valid_rsa_token_accepted(patch_jwks_endpoint, reset_jwks_cache, rsa_keypair):
    token = sign_jwt(rsa_keypair, sub="alice")
    result = await JWKSTokenVerifier().verify_token(token)

    assert isinstance(result, JWTAccessToken)
    assert result.claims["sub"] == "alice"
    assert result.client_id == "unknown"  # neither client_id nor azp set
    assert "openid" in result.scopes
    assert "profile" in result.scopes


@pytest.mark.asyncio
async def test_valid_ec_token_accepted(patch_jwks_endpoint_ec, reset_jwks_cache, ec_keypair):
    token = sign_jwt(ec_keypair, sub="bob")
    result = await JWKSTokenVerifier().verify_token(token)

    assert isinstance(result, JWTAccessToken)
    assert result.claims["sub"] == "bob"


@pytest.mark.asyncio
async def test_expired_token_rejected(patch_jwks_endpoint, reset_jwks_cache, rsa_keypair):
    token = sign_jwt(rsa_keypair, expires_in=-60)
    result = await JWKSTokenVerifier().verify_token(token)
    assert result is None


@pytest.mark.asyncio
async def test_wrong_issuer_rejected(patch_jwks_endpoint, reset_jwks_cache, rsa_keypair):
    token = sign_jwt(rsa_keypair, issuer="https://attacker.example")
    result = await JWKSTokenVerifier().verify_token(token)
    assert result is None


@pytest.mark.asyncio
async def test_malformed_token_rejected(patch_jwks_endpoint, reset_jwks_cache):
    result = await JWKSTokenVerifier().verify_token("not-a-jwt")
    assert result is None


@pytest.mark.asyncio
async def test_token_signed_by_unknown_key_rejected(
    patch_jwks_endpoint, reset_jwks_cache, rsa_keypair
):
    # Sign with a fresh key whose JWK is NOT in the test JWKS
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    rogue = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_pem = rogue.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    rogue_kp = {"private_pem": rogue_pem, "alg": "RS256", "kid": "rogue-kid"}

    token = sign_jwt(rogue_kp)
    result = await JWKSTokenVerifier().verify_token(token)
    assert result is None


@pytest.mark.asyncio
async def test_client_id_from_claim(patch_jwks_endpoint, reset_jwks_cache, rsa_keypair):
    token = sign_jwt(rsa_keypair, extra={"client_id": "claude-ai"})
    result = await JWKSTokenVerifier().verify_token(token)
    assert result is not None
    assert result.client_id == "claude-ai"


@pytest.mark.asyncio
async def test_client_id_falls_back_to_azp(patch_jwks_endpoint, reset_jwks_cache, rsa_keypair):
    token = sign_jwt(rsa_keypair, extra={"azp": "azp-fallback"})
    result = await JWKSTokenVerifier().verify_token(token)
    assert result is not None
    assert result.client_id == "azp-fallback"


@pytest.mark.asyncio
async def test_empty_scope_yields_empty_list(patch_jwks_endpoint, reset_jwks_cache, rsa_keypair):
    token = sign_jwt(rsa_keypair, extra={"scope": ""})
    result = await JWKSTokenVerifier().verify_token(token)
    assert result is not None
    assert result.scopes == []


@pytest.mark.asyncio
async def test_jwks_cached_across_calls(patch_jwks_endpoint, reset_jwks_cache, rsa_keypair):
    """Second verify_token within TTL must not refetch JWKS."""
    verifier = JWKSTokenVerifier()
    await verifier.verify_token(sign_jwt(rsa_keypair))
    await verifier.verify_token(sign_jwt(rsa_keypair, sub="user-2"))

    jwks_calls = [u for u in patch_jwks_endpoint if u.endswith("/.well-known/jwks.json")]
    assert len(jwks_calls) == 1


@pytest.mark.asyncio
async def test_jwks_refetched_after_ttl(
    patch_jwks_endpoint, reset_jwks_cache, rsa_keypair, monkeypatch
):
    """After _JWKS_TTL, the next call refetches."""
    from dns_mcp import auth

    verifier = JWKSTokenVerifier()
    await verifier.verify_token(sign_jwt(rsa_keypair))

    # Push the cached-at timestamp into the past
    auth._jwks_cache_at = time.monotonic() - auth._JWKS_TTL - 1

    await verifier.verify_token(sign_jwt(rsa_keypair, sub="user-3"))

    jwks_calls = [u for u in patch_jwks_endpoint if u.endswith("/.well-known/jwks.json")]
    assert len(jwks_calls) == 2


@pytest.mark.asyncio
async def test_jwks_url_uses_pocket_id_base(patch_jwks_endpoint, reset_jwks_cache, rsa_keypair):
    await JWKSTokenVerifier().verify_token(sign_jwt(rsa_keypair))
    assert patch_jwks_endpoint == [f"{TEST_POCKET_ID}/.well-known/jwks.json"]


@pytest.mark.asyncio
async def test_expires_at_propagated(patch_jwks_endpoint, reset_jwks_cache, rsa_keypair):
    token = sign_jwt(rsa_keypair, expires_in=1234)
    before = int(time.time())
    result = await JWKSTokenVerifier().verify_token(token)
    after = int(time.time())

    assert result is not None
    assert result.expires_at is not None
    assert before + 1230 <= result.expires_at <= after + 1240


# ── Audience pinning (RFC 8707) ──────────────────────────────────────────
# Pocket ID stamps the requested resource into `aud`. A token minted for a
# sibling MCP server on the same IdP must not be accepted here.


@pytest.mark.asyncio
async def test_token_for_other_resource_rejected(
    patch_jwks_endpoint, reset_jwks_cache, rsa_keypair
):
    token = sign_jwt(rsa_keypair, audience=["https://tiny-mcp.test.example"])
    assert await JWKSTokenVerifier().verify_token(token) is None


@pytest.mark.asyncio
async def test_token_without_aud_rejected(patch_jwks_endpoint, reset_jwks_cache, rsa_keypair):
    token = sign_jwt(rsa_keypair, audience=None)
    assert await JWKSTokenVerifier().verify_token(token) is None


@pytest.mark.asyncio
async def test_plain_login_token_rejected(patch_jwks_endpoint, reset_jwks_cache, rsa_keypair):
    """A no-resource token has aud=[client_id, issuer] -- not ours."""
    token = sign_jwt(rsa_keypair, audience=["some-client-uuid", TEST_POCKET_ID])
    assert await JWKSTokenVerifier().verify_token(token) is None


@pytest.mark.asyncio
async def test_aud_as_bare_string_accepted(patch_jwks_endpoint, reset_jwks_cache, rsa_keypair):
    token = sign_jwt(rsa_keypair, audience=TEST_SERVER_URL)
    assert await JWKSTokenVerifier().verify_token(token) is not None


@pytest.mark.asyncio
async def test_aud_list_containing_ours_accepted(
    patch_jwks_endpoint, reset_jwks_cache, rsa_keypair
):
    token = sign_jwt(rsa_keypair, audience=[TEST_SERVER_URL, TEST_POCKET_ID])
    assert await JWKSTokenVerifier().verify_token(token) is not None


def test_expected_audience_strips_trailing_slash():
    from dns_mcp.auth import expected_audience

    assert expected_audience() == TEST_SERVER_URL
    assert not expected_audience().endswith("/")
