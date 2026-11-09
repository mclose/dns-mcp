from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Required fields fail at startup, so a missing URL can never mean 'no auth'."""

    # extra="ignore": don't choke on legacy or unrelated env vars in .env / the
    # deploy environment. Required fields are still enforced by type.
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    pocket_id_base_url: AnyHttpUrl  # e.g. https://pocketid.lab.deflationhollow.net
    server_url: AnyHttpUrl  # public base URL; the resource is <server_url>/mcp
    # Pocket ID user ids (JWT `sub`) allowed to call tools. EMPTY = nobody.
    allowed_subs: str = ""

    @property
    def issuer(self) -> str:
        return str(self.pocket_id_base_url).rstrip("/")

    @property
    def base_url(self) -> str:
        return str(self.server_url).rstrip("/")

    @property
    def resource(self) -> str:
        """RFC 9728 resource and the `aud` a token must carry (target shape §7)."""
        return f"{self.base_url}/mcp"

    @property
    def allowed_sub_set(self) -> frozenset[str]:
        return frozenset(s.strip() for s in self.allowed_subs.split(",") if s.strip())


settings = Settings()
