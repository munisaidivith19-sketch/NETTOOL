"""Response models for devices and the dashboard summary."""

from datetime import datetime

from pydantic import BaseModel

from app.models.ipam import IpRow, Usage


class DeviceOut(BaseModel):
    id: str
    mgmt_ip: str
    sys_name: str | None = None
    vendor: str | None = None
    sys_location: str | None = None
    status: str
    status_changed_at: datetime | None = None
    snmp_version: str | None = None
    # SNMPv2c sends the community string in clear text; the UI shows a warning (CLAUDE.md 7.6).
    snmp_v2c: bool = False
    last_seen: datetime | None = None
    last_polled_at: datetime | None = None


class InterfaceOut(BaseModel):
    if_index: int
    name: str | None = None
    descr: str | None = None
    alias: str | None = None
    speed_mbps: int | None = None
    mac: str | None = None
    admin_status: str | None = None
    oper_status: str | None = None
    # Latest traffic rates from the last two counter readings (services/metrics.py).
    rates: dict | None = None


class LinkOut(BaseModel):
    """An LLDP/CDP neighbour on one of this device's ports."""

    protocol: str
    if_index: int | None = None
    local_port: str | None = None
    remote_name: str | None = None
    remote_port: str | None = None
    remote_mgmt_ip: str | None = None
    remote_platform: str | None = None
    remote_device_id: str | None = None  # set when the neighbour is a NetMap device
    status: str  # active | lost
    last_seen: datetime


class MetricPoint(BaseModel):
    ts: datetime
    in_bps: int | None = None
    out_bps: int | None = None
    in_errors: int | None = None
    out_errors: int | None = None


class DeviceDetail(DeviceOut):
    sys_descr: str | None = None
    sys_object_id: str | None = None
    uptime_seconds: int | None = None
    last_error: str | None = None
    first_seen: datetime | None = None
    agent_id: str | None = None
    interfaces: list[InterfaceOut]
    addresses: list[IpRow]
    links: list[LinkOut] = []


class SubnetSummary(BaseModel):
    id: str
    network: str
    name: str | None = None
    usage: Usage


class AgentCheckIn(BaseModel):
    name: str
    last_seen_at: datetime


class DashboardSummary(BaseModel):
    devices: dict[str, int]  # total, up, snmp_error, down
    subnets: int
    fullest_subnets: list[SubnetSummary]
    alerts_open: int
    alerts_by_severity: dict[str, int]
    alerts_by_type: dict[str, int]
    duplicate_ips: int
    last_agent_check_in: AgentCheckIn | None
