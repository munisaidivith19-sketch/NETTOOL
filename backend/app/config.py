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
LOCAL_DB_HOSTS = {"127.0.0.1", "localhost", "::1"}


def uses_tls(uri: str) -> bool:
    """True if a MongoDB connection string is encrypted, or only reaches this machine.
    mongodb+srv:// (Atlas) turns TLS on by default; plain mongodb:// needs tls=true."""
    if uri.startswith("mongodb+srv://"):
        return "tls=false" not in uri.lower() and "ssl=false" not in uri.lower()
    rest = uri.removeprefix("mongodb://")
    hosts_part, _, query = rest.partition("?")
    hosts_part = hosts_part.split("/", 1)[0].rsplit("@", 1)[-1]
    hosts = set()
    for host in hosts_part.split(","):
        if host.startswith("["):  # [::1]:27017
            hosts.add(host[1:].split("]", 1)[0])
        else:
            hosts.add(host.split(":", 1)[0])
    if hosts <= LOCAL_DB_HOSTS:
        return True
    params = query.lower().replace("&", ";").split(";")
    return "tls=true" in params or "ssl=true" in params


class Settings(BaseSettings):
    # env_ignore_empty: "TELEGRAM_CHAT_ID=" in .env means "not set", not an invalid empty value.
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore",
                                      env_ignore_empty=True)

    env: Literal["development", "test", "production"] = "development"
    # SecretStr: an Atlas URI contains a password, so it must never show up in logs or reprs.
    mongodb_uri: SecretStr = SecretStr("mongodb://127.0.0.1:27017")
    mongodb_db: str = Field(default="netmap", pattern=r"^[A-Za-z0-9_-]{1,63}$")
    mongodb_timeout_ms: int = Field(default=5000, ge=100, le=30000)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # Phase 9: how many reverse proxies sit in front of the app and append to X-Forwarded-For
    # (security/client_ip.py). 0 = no proxy: use the connecting address. Render: 2 (Cloudflare
    # and Render's own proxy).
    trusted_proxy_hops: int = Field(default=0, ge=0, le=5)

    # First admin, created only when the users collection is empty (CLAUDE.md 7.1).
    admin_username: str | None = Field(default=None, pattern=r"^[a-z0-9._-]{3,32}$")
    admin_password: SecretStr | None = None

    # Fernet key(s) that encrypt agent API keys at rest. Comma-separated: the first one encrypts,
    # all of them can decrypt, which allows key rotation. Required: the app won't start without it.
    agent_key_encryption_key: SecretStr | None = None
    # Phase 8: Fernet key(s) that encrypt users' TOTP secrets (same format and rotation rule).
    # Separate from the agent key, so one leaked key exposes only one kind of secret.
    mfa_encryption_key: SecretStr | None = None

    bcrypt_rounds: int = Field(default=MIN_BCRYPT_ROUNDS, ge=4, le=15)

    # IPAM (Phase 3). An IP not seen for IP_STALE_DAYS counts as free again (unless reserved).
    ip_stale_days: int = Field(default=30, ge=1, le=365)
    # Two MACs seen for one IP within this window = a duplicate IP.
    duplicate_ip_window_minutes: int = Field(default=60, ge=5, le=10080)
    subnet_usage_alert_percent: int = Field(default=80, ge=50, le=100)

    # Monitoring (Phase 5). New-MAC alerts start this many hours after the first MAC table
    # arrives; until then every MAC counts as part of the existing network.
    new_mac_learning_hours: int = Field(default=24, ge=0, le=24 * 30)
    # Phase 6: folder with the Jinja2 device templates (default: <repo>/templates).
    templates_dir: str = ""

    # Notifications (Phase 5), sent by the backend. A channel with missing settings is off.
    notify_min_severity: Literal["info", "warning", "critical"] = "warning"
    telegram_bot_token: SecretStr | None = None
    telegram_chat_id: str | None = Field(default=None,
                                         pattern=r"^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$")
    # Only changed for tests or a local stand-in; must be https (or http on localhost).
    telegram_api_base: str = Field(default="https://api.telegram.org", max_length=200)
    smtp_host: str | None = Field(default=None, pattern=r"^[A-Za-z0-9.-]{1,253}$")
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_security: Literal["starttls", "ssl"] = "starttls"  # plain SMTP is not offered
    smtp_username: str | None = Field(default=None, max_length=254)
    smtp_password: SecretStr | None = None
    smtp_from: str | None = Field(default=None, pattern=r"^[^@\s,;<>]{1,64}@[A-Za-z0-9.-]{1,253}$")
    # Comma-separated list of recipients.
    smtp_to: str | None = Field(default=None, max_length=1000,
                                pattern=r"^[^@\s,;<>]{1,64}@[A-Za-z0-9.-]{1,253}"
                                        r"(\s*,\s*[^@\s,;<>]{1,64}@[A-Za-z0-9.-]{1,253})*$")

    # Phase 7: AI. "none" = only the built-in question parser and template explanations.
    # gemini / groq are free-tier cloud APIs (key needed); ollama runs a model on this machine.
    llm_provider: Literal["none", "gemini", "groq", "ollama"] = "none"
    llm_api_key: SecretStr | None = None
    llm_model: str = Field(default="", max_length=100, pattern=r"^[A-Za-z0-9._:/-]*$")
    llm_base_url: str = Field(default="", max_length=200)
    llm_timeout_seconds: float = Field(default=20, ge=2, le=120)
    # Connection string of the read-only database user for Ask NetMap (Atlas: netmap_ai_ro).
    # Empty: the main connection is used and the UI says so (development only).
    ai_mongodb_uri: SecretStr | None = None
    ai_calls_per_10_minutes: int = Field(default=20, ge=1, le=1000)

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

    @model_validator(mode="after")
    def check_telegram_api_base(self) -> "Settings":
        # The bot token is part of the request URL, so it must never travel over plain HTTP to
        # another machine.
        base = self.telegram_api_base
        local = base.startswith(("http://127.0.0.1:", "http://localhost:"))
        if not (base.startswith("https://") or local) or any(c in base for c in "?#@ "):
            raise ValueError("TELEGRAM_API_BASE must be an https:// URL")
        return self

    @model_validator(mode="after")
    def check_llm(self) -> "Settings":
        base = self.llm_base_url
        if base:
            local = base.startswith(("http://127.0.0.1:", "http://localhost:"))
            if not (base.startswith("https://") or local) or any(c in base for c in "?#@ "):
                raise ValueError("LLM_BASE_URL must be an https:// URL (or http://localhost)")
        if self.llm_provider in ("gemini", "groq") and self.llm_api_key is None:
            raise ValueError(f"LLM_PROVIDER={self.llm_provider} needs LLM_API_KEY")
        return self

    @model_validator(mode="after")
    def check_production(self) -> "Settings":
        # Phase 9: mistakes that would otherwise only show up as a half-working deployment.
        if self.env != "production":
            return self
        if "mongodb_uri" not in self.model_fields_set:
            raise ValueError("MONGODB_URI must be set in production (the Atlas connection "
                             "string); the localhost default is for development only")
        for name in ("mongodb_uri", "ai_mongodb_uri"):
            value = getattr(self, name)
            if value is not None and not uses_tls(value.get_secret_value()):
                raise ValueError(f"{name.upper()} must use TLS in production: use the "
                                 "mongodb+srv:// string from Atlas, or add tls=true")
        if self.frontend_dist is not None and not (self.frontend_dist / "index.html").is_file():
            # A failed or skipped `npm run build` must fail the deploy, not quietly serve an
            # API without its dashboard.
            raise ValueError(f"No frontend build at {self.frontend_dist}: run npm run build")
        return self

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def templates_path(self) -> Path:
        from app.config_mgmt.templates import DEFAULT_TEMPLATES_DIR

        return Path(self.templates_dir) if self.templates_dir else DEFAULT_TEMPLATES_DIR


@lru_cache
def get_settings() -> Settings:
    return Settings()
