"""Application configuration values."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    """Environment-driven application settings."""

    database_url: str = Field(default="sqlite:///./data/aegisflow.db", alias="AF_DB_URL")
    artifacts_dir: Path = Field(default=Path("artifacts"), alias="AF_ARTIFACTS_DIR")
    cors_allow_origins: List[str] = Field(default_factory=lambda: ["*"])
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""

    settings = Settings()
    settings.artifacts_dir.mkdir(parents=True, exist_ok=True)
    return settings


settings = get_settings()
