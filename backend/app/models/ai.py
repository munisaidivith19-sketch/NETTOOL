"""Request bodies for Phase 7 AI routes (user and agent). Every list and string is capped."""

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from app.models.common import StrictModel
from app.models.configs import ObjectIdStr

Mac = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")]
ShortText = Annotated[str, StringConstraints(max_length=300)]
DeviceType = Literal["pc", "printer", "phone", "camera", "access_point", "network_device",
                     "server_vm", "unknown"]
Number = Annotated[float, Field(ge=0, le=1e13)]


# ---------------------------------------------------------------- user routes
class AskRequest(StrictModel):
    question: Annotated[str, StringConstraints(min_length=2, max_length=300,
                                               strip_whitespace=True)]


class ExplainRequest(StrictModel):
    kind: Literal["alert", "finding", "diff"]
    id: ObjectIdStr  # the alert id, or the device id for findings and diffs
    rule: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,40}$")] | None = None
    from_version: int | None = Field(None, ge=1, le=10_000_000)
    to_version: int | None = Field(None, ge=1, le=10_000_000)


class TypeCorrection(StrictModel):
    type: DeviceType


# ---------------------------------------------------------------- agent uploads
class SubnetPoint(StrictModel):
    ts: date
    yhat: Number
    lo: Number
    hi: Number


class UplinkPoint(StrictModel):
    ts: datetime
    yhat: Number
    lo: Number
    hi: Number


class SubnetPrediction(StrictModel):
    kind: Literal["subnet_exhaustion"]
    subnet_id: ObjectIdStr
    status: Literal["insufficient_data", "growing", "stable"]
    method: Literal["prophet", "linear"] | None
    usable: int = Field(ge=0, le=10**7)
    current_used: int = Field(ge=0, le=10**7)
    points: int = Field(ge=0, le=10_000)
    growth_per_day: float | None = Field(None, ge=-1e7, le=1e7)
    full_on: date | None = None
    warn_on: date | None = None
    days_until_full: int | None = Field(None, ge=-1000, le=10_000)
    series: list[SubnetPoint] = Field(default_factory=list, max_length=120)


class UplinkPrediction(StrictModel):
    kind: Literal["uplink_bandwidth"]
    device_id: ObjectIdStr
    if_index: int = Field(ge=0, le=2**31)
    status: Literal["insufficient_data", "busy", "ok"]
    method: Literal["prophet", "linear"] | None
    speed_mbps: int | None = Field(None, ge=0, le=10**7)
    points: int = Field(ge=0, le=100_000)
    current_bps: Number | None = None
    peak_bps: Number | None = None
    peak_at: datetime | None = None
    busy_from: datetime | None = None
    series: list[UplinkPoint] = Field(default_factory=list, max_length=200)


Prediction = Annotated[SubnetPrediction | UplinkPrediction, Field(discriminator="kind")]


class PredictionUpload(StrictModel):
    predictions: list[Prediction] = Field(max_length=2000)


class InterfaceRef(StrictModel):
    device_id: ObjectIdStr
    if_index: int = Field(ge=0, le=2**31)


class Anomaly(InterfaceRef):
    ts: datetime
    score: float = Field(ge=-10, le=10)
    metric: Literal["in_bps", "out_bps", "errors"]
    value: Number
    typical: Number
    explanation: ShortText


class AnomalyUpload(StrictModel):
    checked: list[InterfaceRef] = Field(max_length=2000)
    anomalies: list[Anomaly] = Field(max_length=500)


class Classification(StrictModel):
    mac: Mac
    type: DeviceType
    confidence: float = Field(ge=0, le=1)
    reasons: list[Annotated[str, StringConstraints(max_length=200)]] = Field(max_length=8)


class ClassificationUpload(StrictModel):
    items: list[Classification] = Field(max_length=5000)
