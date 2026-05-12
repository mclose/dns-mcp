import time
from typing import Any

import httpx
from jose import JWTError
from jose import jwt as jose_jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier

from .config import settings

# Pocket-ID OIDC client UUID for dns-mcp (confirmed 2026-05-12). Treated as
# this service's identity, not a secret — hardcoding follows the project-
# guides Pocket-ID integration playbook (Flavor B, resource server).
_AUDIENCE = "2cff201e-24d4-47b8-bd7c-fe7decb2bf4a"
# Single-tenant: only Matthew's user UUID is accepted. For multi-tenant the
# right move is a claim other than sub (e.g. isAdmin or a group lookup).
_EXPECTED_SUB = "312826c0-2fec-43ee-9c93-2fc383183111"
_ALGORITHMS = ["RS256", "ES256"]

_jwks_cache: dict[str, Any] | None = None
_jwks_cache_at: float = 0
_JWKS_TTL = 3600  # refresh JWKS once per hour


async def _fetch_jwks() -> dict[str, Any]:
    global _jwks_cache, _jwks_cache_at
    now = time.monotonic()
    if _jwks_cache is not None and now - _jwks_cache_at < _JWKS_TTL:
        return _jwks_cache
    base = str(settings.pocket_id_base_url).rstrip("/")
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{base}/.well-known/jwks.json")
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_cache_at = now
        return _jwks_cache


class JWTAccessToken(AccessToken):
    """AccessToken extended with the full decoded JWT claims."""

    claims: dict[str, Any] = {}


class JWKSTokenVerifier(TokenVerifier):
    """Validates Bearer JWTs against Pocket ID's JWKS endpoint.

    Enforces (per the Pocket-ID integration playbook, Flavor B):
      - RS256/ES256 signature against the live JWKS
      - issuer = configured `pocket_id_base_url`
      - audience = this service's OIDC client UUID (`_AUDIENCE`)
      - subject = Matthew's user UUID (`_EXPECTED_SUB`, single-tenant)
      - presence of exp / iat / iss / sub claims
    """

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            jwks = await _fetch_jwks()
            expected_issuer = str(settings.pocket_id_base_url).rstrip("/")
            claims: dict[str, Any] = jose_jwt.decode(
                token,
                jwks,
                algorithms=_ALGORITHMS,
                audience=_AUDIENCE,
                issuer=expected_issuer,
                options={
                    "require_exp": True,
                    "require_iat": True,
                    "require_iss": True,
                    "require_sub": True,
                },
            )
        except JWTError:
            return None

        if claims.get("sub") != _EXPECTED_SUB:
            return None

        scope_str: str = claims.get("scope", "")
        return JWTAccessToken(
            token=token,
            client_id=claims.get("client_id") or claims.get("azp") or "unknown",
            scopes=scope_str.split() if scope_str else [],
            expires_at=claims.get("exp"),
            claims=claims,
        )
