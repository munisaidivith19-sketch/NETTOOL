"""The discovery report an agent sends to POST /api/agent/report.

Everything in it came from network devices, so it is untrusted input (CLAUDE.md 7.4/7.5):
- every object forbids unknown keys, which also blocks "$where"-style keys reaching MongoDB
- every list has a maximum length and every string a maximum size
- addresses are parsed as real IPs, MACs and OIDs must match strict patterns
- free text from devices (sysDescr, ifAlias, ...) has control characters replaced
"""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, IPvAnyAddress, StringConstraints, model_validator

from app.models.agents import AgentVersion
from app.models.common import StrictModel

MAX_DEVICES = 500
MAX_INTERFACES = 2048
MAX_ADDRESSES = 8192
MAX_NEIGHBORS = 20000
MAX_PING = 8192
INT32 = 2**31 - 1


def _clean(text: str) -> str:
    # Keep printable characters only: a sysDescr can't smuggle terminal escapes or NULs into
    # logs, and the UI renders it as plain text anyway (no dangerouslySetInnerHTML).
    return "".join(ch if ch.isprintable() else " " for ch in text).strip()


def DeviceText(max_length: int):  # noqa: N802 - reads as a type in the models below
    return Annotated[str, StringConstraints(max_length=max_length), AfterValidator(_clean)]


Mac = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")]
Oid = Annotated[str, StringConstraints(pattern=r"^[0-9]+(\.[0-9]+){1,127}$", max_length=512)]
IfIndex = Annotated[int, Field(ge=1, le=INT32)]
IfStatus = Literal["up", "down", "testing", "unknown", "dormant", "notPresent", "lowerLayerDown"]
NeighborKind = Literal["other", "invalid", "dynamic", "static", "local"]


class ReportInterface(StrictModel):
    if_index: IfIndex
    name: DeviceText(256) | None = None
    descr: DeviceText(256) | None = None
    alias: DeviceText(256) | None = None
    if_type: Annotated[int, Field(ge=0, le=INT32)] | None = None
    mtu: Annotated[int, Field(ge=0, le=INT32)] | None = None
    speed_mbps: Annotated[int, Field(ge=0, le=10_000_000)] | None = None
    mac: Mac | None = None
    admin_status: IfStatus | None = None
    oper_status: IfStatus | None = None


class ReportAddress(StrictModel):
    ip: IPvAnyAddress
    if_index: IfIndex | None = None
    prefixlen: Annotated[int, Field(ge=0, le=128)] | None = None

    @model_validator(mode="after")
    def prefix_fits_family(self) -> "ReportAddress":
        if self.prefixlen is not None and self.ip.version == 4 and self.prefixlen > 32:
            raise ValueError("IPv4 prefix length must be 0-32")
        return self


class ReportNeighbor(StrictModel):
    ip: IPvAnyAddress
    mac: Mac
    if_index: IfIndex
    kind: NeighborKind = "other"


class ReportDevice(StrictModel):
    mgmt_ip: IPvAnyAddress
    snmp_port: Annotated[int, Field(ge=1, le=65535)] = 161
    snmp_version: Literal["v3", "v2c"]
    reachable: bool
    error: DeviceText(200) | None = None
    sys_name: DeviceText(255) | None = None
    sys_descr: DeviceText(1024) | None = None
    sys_location: DeviceText(255) | None = None
    sys_object_id: Oid | None = None
    vendor: DeviceText(64) = "unknown"
    uptime_seconds: Annotated[int, Field(ge=0)] | None = None
    interfaces: Annotated[list[ReportInterface], Field(max_length=MAX_INTERFACES)] = []
    addresses: Annotated[list[ReportAddress], Field(max_length=MAX_ADDRESSES)] = []
    neighbors: Annotated[list[ReportNeighbor], Field(max_length=MAX_NEIGHBORS)] = []


class PingResult(StrictModel):
    ip: IPvAnyAddress
    up: bool


class DiscoveryReport(StrictModel):
    agent_version: AgentVersion
    collected_at: datetime
    ping: Annotated[list[PingResult], Field(max_length=MAX_PING)] = []
    devices: Annotated[list[ReportDevice], Field(max_length=MAX_DEVICES)] = []


class KnownDevice(StrictModel):
    mgmt_ip: str
    snmp_port: int
    status: str
