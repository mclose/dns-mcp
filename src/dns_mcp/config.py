from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    pocket_id_base_url: AnyHttpUrl  # e.g. https://id.deflationhollow.net
    pocket_id_api_key: str  # admin API key (X-API-Key header)
    server_url: AnyHttpUrl  # our public URL e.g. https://tiny-mcp.deflationhollow.net


settings = Settings()
