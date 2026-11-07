"""Application settings, read from environment variables (and a local .env file in dev).

Security timings (session lifetime, lockout, rate limits) are constants in app/security/,
not settings, so a wrong environment variable can't quietly weaken them.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_BCRYPT_ROUNDS = 12


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    env: Literal["development", "test", "production"] = "development"
    # SecretStr: an Atlas URI contains a password, so it must never show up in logs or reprs.
    mongodb_uri: SecretStr = SecretStr("mongodb://127.0.0.1:27017")
    mongodb_db: str = Field(default="netmap", pattern=r"^[A-Za-z0-9_-]{1,63}$")
    mongodb_timeout_ms: int = Field(default=5000, ge=100, le=30000)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # First admin, created only when the users collection is empty (CLAUDE.md 7.1).
    admin_username: str | None = Field(default=None, pattern=r"^[a-z0-9._-]{3,32}$")
    admin_password: SecretStr | None = None

    # Fernet key(s) that encrypt agent API keys at rest. Comma-separated: the first one encrypts,
    # all of them can decrypt, which allows key rotation. Required: the app won't start without it.
    agent_key_encryption_key: SecretStr | None = None

    bcrypt_rounds: int = Field(default=MIN_BCRYPT_ROUNDS, ge=4, le=15)

    # IPAM (Phase 3). An IP not seen for IP_STALE_DAYS counts as free again (unless reserved).
    ip_stale_days: int = Field(default=30, ge=1, le=365)
    # Two MACs seen for one IP within this window = a duplicate IP.
    duplicate_ip_window_minutes: int = Field(default=60, ge=5, le=10080)
    subnet_usage_alert_percent: int = Field(default=80, ge=50, le=100)

    # The built React app (npm run build), served from the same origin as the API. None, or a
    # folder without index.html, means API only (in development Vite serves the UI instead).
    frontend_dist: Path | None = Path(__file__).resolve().parents[2] / "frontend" / "dist"

    @model_validator(mode="after")
    def check_bcrypt_rounds(self) -> "Settings":
        # Low cost factors exist only to keep the test suite fast. Anywhere else they would make
        # stolen password hashes much faster to crack, so they are refused.
        if self.env != "test" and self.bcrypt_rounds < MIN_BCRYPT_ROUNDS:
            raise ValueError(f"BCRYPT_ROUNDS must be at least {MIN_BCRYPT_ROUNDS}")
        return self

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
