"""Type-safe configuration loaded from environment / ``.env``.

Uses ``pydantic-settings`` when available; otherwise falls back to a small stdlib
loader so the package imports cleanly even before dependencies are installed. No
secret ever has a hardcoded default value (HF-003).
"""

from __future__ import annotations

import os
from pathlib import Path

# Load a local .env into os.environ if python-dotenv is installed. This is a no-op
# in production where real environment variables are injected by the platform.
try:  # pragma: no cover - trivial import guard
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass


try:
    from pydantic import Field
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class Settings(BaseSettings):
        """Pipeline configuration. All values may be overridden via environment."""

        model_config = SettingsConfigDict(
            env_file=".env", env_file_encoding="utf-8", extra="ignore"
        )

        # --- LLM provider (secrets have NO default) ---
        anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
        openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
        llm_provider: str = Field(default="anthropic", alias="LLM_PROVIDER")
        llm_model: str = Field(default="claude-3-5-sonnet-20241022", alias="LLM_MODEL")

        # --- Storage ---
        vault_db_path: str = Field(default="./data/vault.db", alias="VAULT_DB_PATH")
        store_db_path: str = Field(default="./data/documents.db", alias="STORE_DB_PATH")
        store_encryption_key_path: str = Field(
            default="./data/master.key", alias="STORE_ENCRYPTION_KEY_PATH"
        )

        # --- Session / obfuscation ---
        session_timeout_minutes: int = Field(default=30, alias="SESSION_TIMEOUT_MINUTES")
        confidence_threshold: float = Field(default=0.60, alias="CONFIDENCE_THRESHOLD")
        obfuscation_strategy: str = Field(
            default="tokenization", alias="OBFUSCATION_STRATEGY"
        )

        # --- Logging ---
        log_level: str = Field(default="INFO", alias="LOG_LEVEL")
        audit_log_path: str = Field(default="./data/audit.jsonl", alias="AUDIT_LOG_PATH")

except Exception:  # pragma: no cover - fallback when pydantic isn't installed

    class Settings:  # type: ignore[no-redef]
        """Minimal stdlib fallback mirroring the pydantic Settings fields."""

        def __init__(self) -> None:
            g = os.environ.get
            self.anthropic_api_key = g("ANTHROPIC_API_KEY")
            self.openai_api_key = g("OPENAI_API_KEY")
            self.llm_provider = g("LLM_PROVIDER", "anthropic")
            self.llm_model = g("LLM_MODEL", "claude-3-5-sonnet-20241022")
            self.vault_db_path = g("VAULT_DB_PATH", "./data/vault.db")
            self.store_db_path = g("STORE_DB_PATH", "./data/documents.db")
            self.store_encryption_key_path = g("STORE_ENCRYPTION_KEY_PATH", "./data/master.key")
            self.session_timeout_minutes = int(g("SESSION_TIMEOUT_MINUTES", "30"))
            self.confidence_threshold = float(g("CONFIDENCE_THRESHOLD", "0.60"))
            self.obfuscation_strategy = g("OBFUSCATION_STRATEGY", "tokenization")
            self.log_level = g("LOG_LEVEL", "INFO")
            self.audit_log_path = g("AUDIT_LOG_PATH", "./data/audit.jsonl")


# The confidence threshold below which an entity is redacted instead of tokenized.
# A module-level constant so hot paths avoid re-instantiating Settings.
CONFIDENCE_THRESHOLD: float = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.60"))


def get_settings() -> "Settings":
    """Return a fresh Settings instance (reads current environment)."""
    return Settings()


def ensure_data_dir(path: str) -> None:
    """Create the parent directory for a data file path if it does not exist."""
    parent = Path(path).expanduser().resolve().parent
    parent.mkdir(parents=True, exist_ok=True)
