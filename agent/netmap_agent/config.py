"""Agent settings, read from environment variables (and a local .env file).

Lists are comma-separated in .env, e.g. SCAN_RANGES=10.0.10.0/24,10.0.20.0/24
"""

import logging
from functools import lru_cache
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from netmap_agent.discovery.net import MAX_TOTAL_SCAN_ADDRESSES, parse_scan_range, parse_target

logger = logging.getLogger("netmap_agent")

CommaList = Annotated[list[str], NoDecode]
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    api_url: str = "https://localhost:8000"
    agent_id: str = Field(default="", pattern=r"^(agt_[a-f0-9]{16})?$")
    agent_key: SecretStr = SecretStr("")
    # Only for talking to a backend on this same machine during development (CLAUDE.md 7.3).
    allow_insecure_local: bool = False

    scan_ranges: CommaList = Field(default_factory=list)
    snmp_targets: CommaList = Field(default_factory=list)

    snmp_version: Literal["v3", "v2c"] = "v3"
    snmp_v3_user: str = ""
    snmp_v3_auth_key: SecretStr = SecretStr("")
    snmp_v3_priv_key: SecretStr = SecretStr("")
    snmp_v3_auth_protocol: Literal["SHA", "SHA256", "SHA512"] = "SHA"
    snmp_v3_priv_protocol: Literal["AES", "AES256"] = "AES"
    # Usually empty. The simulator selects its data file by context name.
    snmp_v3_context: str = Field(default="", max_length=64)
    snmp_v2c_community: SecretStr = SecretStr("")
    snmp_timeout_seconds: float = Field(default=2.0, ge=0.5, le=30)
    snmp_retries: int = Field(default=1, ge=0, le=5)

    ping_timeout_ms: int = Field(default=1000, ge=100, le=10000)
    poll_interval_seconds: int = Field(default=300, ge=30, le=86400)

    @field_validator("scan_ranges", "snmp_targets", mode="before")
    @classmethod
    def split_commas(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("scan_ranges")
    @classmethod
    def validate_ranges(cls, value: list[str]) -> list[str]:
        # Reject anything that isn't a real, reasonably small network before it ever reaches ping.
        networks = [parse_scan_range(item) for item in value]
        if sum(n.num_addresses for n in networks) > MAX_TOTAL_SCAN_ADDRESSES:
            raise ValueError(f"SCAN_RANGES cover more than {MAX_TOTAL_SCAN_ADDRESSES} addresses "
                             "in total")
        return [str(n) for n in networks]

    @field_validator("snmp_targets")
    @classmethod
    def validate_targets(cls, value: list[str]) -> list[str]:
        return [item for item in value if parse_target(item)]

    @field_validator("api_url")
    @classmethod
    def validate_api_url(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ValueError("API_URL must be an https:// URL")
        return value.rstrip("/")

    @model_validator(mode="after")
    def check_transport(self) -> "AgentSettings":
        host = (urlsplit(self.api_url).hostname or "").lower()
        if urlsplit(self.api_url).scheme == "http":
            # Plain HTTP would expose every report (and the HMAC-signed requests) on the network.
            if not (self.allow_insecure_local and host in LOCAL_HOSTS):
                raise ValueError(
                    "API_URL must use https://. Plain http:// is allowed only for localhost "
                    "with ALLOW_INSECURE_LOCAL=true."
                )
        return self

    def warn_if_weak(self) -> None:
        if self.snmp_version == "v2c":
            logger.warning(
                "SNMPv2c sends the community string in clear text. Use it only in a lab; "
                "prefer SNMPv3 authPriv (SHA + AES)."
            )

    @property
    def targets(self) -> list[tuple[str, int]]:
        return [parse_target(item) for item in self.snmp_targets]


@lru_cache
def get_settings() -> AgentSettings:
    return AgentSettings()
