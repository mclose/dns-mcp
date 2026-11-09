"""Pocket ID auth on fastmcp's JWTVerifier — no hand-rolled JWKS code.

Three layers, all fail closed (project-guides mcp-server-target-shape.md §3):
  1. IdP: the shared Claude CIMD client is restricted to the `mcp_users` group.
  2. Audience: `aud` must equal this server's resource, <server_url>/mcp.
  3. ALLOWED_SUBS: per-server allowlist of Pocket ID user ids. Empty = nobody.
"""

import logging

from fastmcp.server.auth import JWTVerifier, RemoteAuthProvider
from fastmcp.server.auth.auth import AccessToken
from pydantic import AnyHttpUrl

from .config import Settings

log = logging.getLogger("dns_mcp.auth")


class AllowlistJWTVerifier(JWTVerifier):
    """fastmcp's JWTVerifier plus a fail-closed `sub` allowlist.

    Signature, issuer, expiry and audience (list-aware; a missing `aud` is
    rejected) are fastmcp's job. This adds only the per-server "which users"
    layer, which the IdP group gate cannot express — one shared CIMD client
    serves every connector.
    """

    def __init__(self, *, allowed_subs: frozenset[str], **kwargs) -> None:
        super().__init__(**kwargs)
        self._allowed_subs = frozenset(allowed_subs)

    async def load_access_token(self, token: str) -> AccessToken | None:
        access = await super().load_access_token(token)
        if access is None:
            return None
        sub = access.claims.get("sub")
        if not sub or sub not in self._allowed_subs:
            log.warning("token rejected: sub=%r not in ALLOWED_SUBS", sub)
            return None
        return access


def build_auth(settings: Settings) -> RemoteAuthProvider:
    if not settings.allowed_sub_set:
        log.warning("ALLOWED_SUBS is empty: every token will be rejected")
    verifier = AllowlistJWTVerifier(
        jwks_uri=f"{settings.issuer}/.well-known/jwks.json",
        issuer=settings.issuer,
        algorithm="RS256",
        # Pocket ID stamps the RFC 8707 resource into `aud`. fastmcp advertises
        # <base_url>/mcp as the resource, so the pin is derived from the same value.
        audience=settings.resource,
        allowed_subs=settings.allowed_sub_set,
    )
    return RemoteAuthProvider(
        token_verifier=verifier,
        # Pocket ID, NOT this server: clients read its discovery, see CIMD and
        # no registration_endpoint, and never attempt DCR.
        authorization_servers=[AnyHttpUrl(settings.issuer)],
        base_url=AnyHttpUrl(settings.base_url),
    )
