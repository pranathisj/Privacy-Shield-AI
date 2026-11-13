"""Environment-backed application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values, load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def dashboard_api_url() -> str:
    """Read the public backend URL without loading backend configuration into Streamlit."""
    return os.getenv("PRIVACYSHIELD_API_URL", "http://127.0.0.1:8000").rstrip("/")


def _configured_api_key() -> str | None:
    """Resolve the shared backend key from process environment or project .env."""
    process_key = os.getenv("PRIVACYSHIELD_API_KEY")
    if process_key and process_key.strip():
        return process_key
    env_key = dotenv_values(PROJECT_ROOT / ".env").get("PRIVACYSHIELD_API_KEY")
    if isinstance(env_key, str) and env_key.strip():
        return env_key
    return None


def dashboard_api_key() -> str | None:
    """Read the backend key server-side for Streamlit's backend requests only."""
    return _configured_api_key()


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_path: Path
    encryption_key: str | None = field(repr=False)
    llm_provider: str
    llm_api_key: str | None = field(repr=False)
    llm_base_url: str
    llm_model: str
    llm_timeout_seconds: float
    presidio_enabled: bool
    presidio_model: str
    api_key: str | None = field(repr=False)
    retention_days: int = 30

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(PROJECT_ROOT / ".env")
        data_dir = Path(os.getenv("PRIVACYSHIELD_DATA_DIR", str(PROJECT_ROOT / "data")))
        if not data_dir.is_absolute():
            data_dir = PROJECT_ROOT / data_dir
        database_path = Path(
            os.getenv("PRIVACYSHIELD_DATABASE_PATH", str(data_dir / "privacyshield.db"))
        )
        if not database_path.is_absolute():
            database_path = PROJECT_ROOT / database_path

        retention_days = int(os.getenv("PRIVACYSHIELD_RETENTION_DAYS", "30"))
        if retention_days < 0:
            raise ValueError("PRIVACYSHIELD_RETENTION_DAYS must be zero or greater.")

        return cls(
            data_dir=data_dir,
            database_path=database_path,
            encryption_key=os.getenv("PRIVACYSHIELD_ENCRYPTION_KEY") or None,
            llm_provider=os.getenv("LLM_PROVIDER", "mock").strip().lower(),
            llm_api_key=os.getenv("LLM_API_KEY") or None,
            llm_base_url=os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
            llm_model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
            llm_timeout_seconds=float(os.getenv("LLM_TIMEOUT_SECONDS", "45")),
            presidio_enabled=os.getenv("PRESIDIO_ENABLED", "true").strip().lower()
            in {"1", "true", "yes", "on"},
            presidio_model=os.getenv("PRESIDIO_MODEL", "en_core_web_sm"),
            api_key=_configured_api_key(),
            retention_days=retention_days,
        )
