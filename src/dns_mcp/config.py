from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # extra="ignore": don't choke on legacy or unrelated env vars in .env / the
    # deploy environment. Required fields are still enforced by type.
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    pocket_id_base_url: AnyHttpUrl  # e.g. https://id.deflationhollow.net
    pocket_id_api_key: str  # admin API key (X-API-Key header)
    server_url: AnyHttpUrl  # our public URL e.g. https://tiny-mcp.deflationhollow.net


settings = Settings()
