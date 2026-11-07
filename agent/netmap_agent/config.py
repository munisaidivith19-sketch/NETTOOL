"""Agent settings, read from environment variables (and a local .env file).

Lists are comma-separated in .env, e.g. SCAN_RANGES=10.0.10.0/24,10.0.20.0/24
"""

import ipaddress
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

CommaList = Annotated[list[str], NoDecode]


class AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    api_url: str = "https://localhost:8000"
    agent_id: str = ""
    agent_key: SecretStr = SecretStr("")
    # Only for talking to a backend on this same machine during development (CLAUDE.md 7.3).
    allow_insecure_local: bool = False

    scan_ranges: CommaList = Field(default_factory=list)
    snmp_targets: CommaList = Field(default_factory=list)

    snmp_version: Literal["v3", "v2c"] = "v3"
    snmp_v3_user: str = ""
    snmp_v3_auth_key: SecretStr = SecretStr("")
    snmp_v3_priv_key: SecretStr = SecretStr("")
    snmp_v2c_community: SecretStr = SecretStr("")

    poll_interval_seconds: int = Field(default=300, ge=30, le=86400)

    @field_validator("scan_ranges", "snmp_targets", mode="before")
    @classmethod
    def split_commas(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("scan_ranges")
    @classmethod
    def validate_cidrs(cls, value: list[str]) -> list[str]:
        # Reject anything that is not a real network before it ever reaches a ping command.
        return [str(ipaddress.ip_network(item, strict=False)) for item in value]


@lru_cache
def get_settings() -> AgentSettings:
    return AgentSettings()
