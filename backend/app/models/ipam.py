"""Request and response models for subnets, IP addresses, reservations and alerts.

Request bodies forbid unknown keys (so no "$where" or "a.b" keys can reach a query) and every
IP/network is parsed by pydantic's ipaddress-backed types before any code sees it.
"""

import ipaddress
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, IPvAnyAddress, StringConstraints, model_validator

from app.models.common import StrictModel

MAX_RESERVED_RANGES = 64

Name = Annotated[str, StringConstraints(min_length=1, max_length=64,
                                        pattern=r"^[A-Za-z0-9 ._()/#&+-]+$")]
# Free text typed by users: no control characters (newlines and tabs are fine).
_NO_CONTROL = r"^[^\x00-\x08\x0b-\x1f\x7f]*$"
Description = Annotated[str, StringConstraints(max_length=500, pattern=_NO_CONTROL)]
Hostname = Annotated[str, StringConstraints(
    min_length=1, max_length=253,
    pattern=r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")]
Note = Annotated[str, StringConstraints(max_length=100, pattern=_NO_CONTROL)]
Vlan = Annotated[int, Field(ge=1, le=4094)]
# Network as text; parsed strictly in the model validator so the error can suggest the fix.
NetworkText = Annotated[str, StringConstraints(min_length=3, max_length=49,
                                               pattern=r"^[0-9A-Fa-f.:]+/[0-9]{1,3}$")]
MacText = Annotated[str, StringConstraints(max_length=20)]


class ReservedRange(StrictModel):
    start: IPvAnyAddress
    end: IPvAnyAddress
    note: Note = ""

    @model_validator(mode="after")
    def ordered(self) -> "ReservedRange":
        if self.start.version != self.end.version or int(self.start) > int(self.end):
            raise ValueError("start must be the lower address and the same IP version as end")
        return self


class SubnetFields(StrictModel):
    name: Name | None = None
    description: Description | None = None
    vlan: Vlan | None = None
    gateway: IPvAnyAddress | None = None
    reserved_ranges: Annotated[
        list[ReservedRange], Field(max_length=MAX_RESERVED_RANGES)] | None = None


class SubnetCreate(SubnetFields):
    network: NetworkText

    @model_validator(mode="after")
    def strict_network(self) -> "SubnetCreate":
        try:
            ipaddress.ip_network(self.network, strict=True)
        except ValueError:
            try:
                fixed = ipaddress.ip_network(self.network, strict=False)
            except ValueError:
                raise ValueError("network must be a CIDR such as 10.0.10.0/24") from None
            raise ValueError(f"network has host bits set; did you mean {fixed}?") from None
        return self


class SubnetUpdate(SubnetFields):
    """Any field may be set; send null to clear it. The network itself can't change."""


class Usage(BaseModel):
    # Strings: an IPv6 /64 has 2**64 addresses, beyond JavaScript's safe integer range.
    size: str
    usable: str
    used: str
    free: str
    percent: float


class SubnetOut(BaseModel):
    id: str
    network: str
    version: int
    prefixlen: int
    source: str
    name: str | None = None
    description: str | None = None
    vlan: int | None = None
    gateway: str | None = None
    reserved_ranges: list[dict] = []
    usage: Usage
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_discovered_at: datetime | None = None


class ReservationCreate(StrictModel):
    ip: IPvAnyAddress
    hostname: Hostname | None = None
    description: Description = ""
    mac: MacText | None = None


class IpRow(BaseModel):
    ip: str
    version: int
    status: Literal["used", "reserved", "stale"]
    mac: str | None = None
    sources: list[str] = []
    device: dict | None = None
    reservation: dict | None = None
    ping_up: bool | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class IpPage(BaseModel):
    items: list[IpRow]
    # Pass as `after` to get the next page.
    next_after: str | None


class NextFree(BaseModel):
    subnet: str
    ip: str | None


class AlertOut(BaseModel):
    id: str
    key: str
    type: str
    severity: str
    status: str
    message: str
    target: dict
    details: dict
    opened_at: datetime
    last_seen: datetime
    resolved_at: datetime | None = None
    resolved_by: str | None = None  # set only when a person resolved it
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None
    occurrences: int
