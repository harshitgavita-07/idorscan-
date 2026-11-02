"""Central configuration for BountyGang (pydantic-settings, env/.env driven)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- paths -------------------------------------------------------------
    data_dir: Path = Path("./data")
    db_path: Path = Path("./data/bountygang.db")
    reports_dir: Path = Path("./data/reports")
    log_file: Path = Path("./data/logs/bountygang.log")
    log_level: str = "INFO"

    # --- telegram (the only user-facing interface) --------------------------
    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    telegram_allowed_user_ids: str = ""

    # --- burp / browser automation -----------------------------------------
    burp_api_url: str = "http://127.0.0.1:9866"
    burp_api_token: str = ""
    burp_jar_path: Path | None = None
    burp_project_file: Path | None = None
    chromium_proxy_host: str = "127.0.0.1"
    chromium_proxy_port: int = 8080
    headless: bool = True  # tests use headless; Windows desktop runs set false

    # --- discovery -----------------------------------------------------------
    discovery_platforms: str = "hackerone,bugcrowd,intigriti,yeswehack"
    discovery_fetch_timeout: float = 20.0
    discovery_offline_mode: bool = False

    # --- scope / safety ------------------------------------------------------
    require_approval: bool = True
    max_requests_per_minute: int = 30
    idor_max_validation_requests: int = 12

    # --- AI -------------------------------------------------------------------
    llm_provider: str = "none"  # openai | anthropic | gemini | ollama | none
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-1.5-flash"
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.1"

    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    @property
    def platforms(self) -> list[str]:
        return [p.strip().lower() for p in self.discovery_platforms.split(",") if p.strip()]

    @property
    def allowed_telegram_users(self) -> set[int]:
        out: set[int] = set()
        for chunk in self.telegram_allowed_user_ids.replace(";", ",").split(","):
            chunk = chunk.strip()
            if chunk:
                try:
                    out.add(int(chunk))
                except ValueError:
                    continue
        return out

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    """Clear cached settings (used by tests after monkeypatching env vars)."""
    get_settings.cache_clear()
    return get_settings()
