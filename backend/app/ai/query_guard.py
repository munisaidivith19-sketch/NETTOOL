"""The gate every AI-generated query must pass before it touches the database (CLAUDE.md 7.9).

The language model (or the built-in question parser) returns a *proposal*:

    {"collection": "devices", "pipeline": [{"$match": {"status": "down"}}, ...]}
or  {"tool": "locate", "q": "PC-HR-23"}                       (the Phase 5 port lookup)

`validate()` accepts it only if every part is on an allowlist. Anything else is rejected:
unknown collections (users, sessions, audit_log, agents, configs, change_requests...),
unknown fields (password_hash, config text...), and any stage or operator that could write,
join another collection or run code ($out, $merge, $lookup, $where, $function, $expr...).
It is deny-by-default: we list what is allowed, not what is forbidden, so a new MongoDB
operator is refused until someone adds it on purpose.

The text the model produced is treated like any other untrusted input: it may have been
steered by a malicious question or by device names it was shown, so it gets no more trust
than a request from an anonymous user.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

MAX_STAGES = 10
MAX_DEPTH = 6
MAX_BYTES = 4096
MAX_IN_LIST = 50
MAX_STRING = 200
MAX_REGEX = 64
MAX_SORT_KEYS = 3
RESULT_LIMIT = 100

# What Ask NetMap may read: no users, sessions, audit log, agents, configs or change requests,
# and from each collection only fields a viewer may already see in the UI.
ALLOWED_FIELDS: dict[str, frozenset[str]] = {
    "devices": frozenset({
        "_id", "sys_name", "mgmt_ip", "vendor", "status", "sys_location", "sys_descr",
        "first_seen", "last_seen", "status_changed_at", "uptime_seconds", "snmp_version",
        "config_vendor", "compliance.score", "unconfigured.flag", "classification.type"}),
    "interfaces": frozenset({
        "device_id", "if_index", "name", "descr", "alias", "oper_status", "admin_status",
        "speed_mbps", "mac", "if_type", "last_seen", "rates.in_bps", "rates.out_bps"}),
    "subnets": frozenset({"_id", "network", "version", "prefixlen", "name", "vlan", "gateway",
                          "source"}),
    "ip_addresses": frozenset({"ip", "version", "mac", "device_id", "if_index", "sources",
                               "first_seen", "last_seen", "ping_up", "reservation.hostname"}),
    "alerts": frozenset({"type", "severity", "status", "message", "opened_at", "last_seen",
                         "resolved_at", "occurrences", "target.type", "target.network"}),
    "links": frozenset({"device_id", "if_index", "protocol", "local_port", "remote_name",
                        "remote_port", "remote_device_id", "status", "last_seen"}),
    "mac_entries": frozenset({"mac", "device_id", "if_index", "vlan", "first_seen",
                              "last_seen"}),
    "mac_addresses": frozenset({"mac", "first_seen", "last_seen", "ips", "classification.type",
                                "classification.confidence"}),
    "predictions": frozenset({"kind", "label", "network", "status", "method", "generated_at",
                              "days_until_full", "full_on", "warn_on", "growth_per_day",
                              "percent", "current_used", "usable", "busy_from", "peak_bps",
                              "speed_mbps"}),
}

STAGES = frozenset({"$match", "$project", "$sort", "$limit", "$count", "$group"})
COMPARE = frozenset({"$eq", "$ne", "$gt", "$gte", "$lt", "$lte"})
LIST_OPS = frozenset({"$in", "$nin"})
LOGICAL = frozenset({"$and", "$or"})
ACCUMULATORS = frozenset({"$sum", "$avg", "$min", "$max", "$first", "$last"})
# Same characters as /api/topology/locate accepts.
LOCATE_TEXT = re.compile(r"^[A-Za-z0-9.:_-]{1,100}$")
FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}(\.[A-Za-z_][A-Za-z0-9_]{0,40})?$")
OUTPUT_NAME = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
# Nested quantifiers like (a+)+ or (.*)* can take exponential time (ReDoS).
NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*}][^)]*\)\s*[+*{?]")


class QueryRejected(ValueError):
    """The proposal broke a rule. The message is safe to show to the user."""


@dataclass(frozen=True)
class Query:
    collection: str | None
    pipeline: list[dict]
    tool: str | None = None
    q: str | None = None

    def display(self) -> dict:
        if self.tool:
            return {"tool": self.tool, "q": self.q}
        return {"collection": self.collection, "pipeline": self.pipeline}


def _depth(value, level: int = 0) -> int:
    if isinstance(value, dict):
        return max((_depth(v, level + 1) for v in value.values()), default=level + 1)
    if isinstance(value, list):
        return max((_depth(v, level + 1) for v in value), default=level + 1)
    return level


def _scalar(value, where: str):
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise QueryRejected(f"{where}: text value too long")
        if value.startswith("$"):
            raise QueryRejected(f"{where}: values may not start with '$'")
        return value
    raise QueryRejected(f"{where}: only plain values are allowed here")


def _field(name, available: frozenset[str], where: str) -> str:
    if not isinstance(name, str) or not FIELD.match(name):
        raise QueryRejected(f"{where}: invalid field name")
    if name not in available:
        raise QueryRejected(f"{where}: field '{name}' is not available")
    return name


def _regex(pattern, options) -> None:
    if not isinstance(pattern, str) or len(pattern) > MAX_REGEX:
        raise QueryRejected(f"$regex: at most {MAX_REGEX} characters")
    if NESTED_QUANTIFIER.search(pattern) or re.search(r"\\[1-9]", pattern):
        raise QueryRejected("$regex: nested repetition and back-references are not allowed")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise QueryRejected("$regex: invalid pattern") from exc
    if options not in (None, "", "i"):
        raise QueryRejected("$options: only 'i' (ignore case) is allowed")


def _condition(value, where: str) -> None:
    if not isinstance(value, dict):
        _scalar(value, where)
        return
    if not value:
        raise QueryRejected(f"{where}: empty condition")
    if "$options" in value and "$regex" not in value:
        raise QueryRejected(f"{where}: $options needs $regex")
    for op, arg in value.items():
        if op in COMPARE:
            _scalar(arg, f"{where}.{op}")
        elif op in LIST_OPS:
            if not isinstance(arg, list) or len(arg) > MAX_IN_LIST:
                raise QueryRejected(f"{where}.{op}: a list of at most {MAX_IN_LIST} values")
            for item in arg:
                _scalar(item, f"{where}.{op}")
        elif op == "$exists":
            if not isinstance(arg, bool):
                raise QueryRejected(f"{where}.$exists: true or false")
        elif op == "$regex":
            _regex(arg, value.get("$options"))
        elif op == "$options":
            continue
        else:
            raise QueryRejected(f"{where}: operator '{op}' is not allowed")


def _filter(spec, available: frozenset[str], level: int = 0) -> None:
    if not isinstance(spec, dict):
        raise QueryRejected("$match: must be an object")
    if level > 3:
        raise QueryRejected("$match: nested too deeply")
    for key, value in spec.items():
        if key in LOGICAL:
            if not isinstance(value, list) or not 1 <= len(value) <= 10:
                raise QueryRejected(f"{key}: a list of 1-10 conditions")
            for part in value:
                _filter(part, available, level + 1)
        elif isinstance(key, str) and key.startswith("$"):
            raise QueryRejected(f"$match: operator '{key}' is not allowed")
        else:
            _field(key, available, "$match")
            _condition(value, f"$match.{key}")


def _group(spec, available: frozenset[str]) -> frozenset[str]:
    if not isinstance(spec, dict) or "_id" not in spec:
        raise QueryRejected("$group: needs an _id")

    def reference(value, where: str) -> None:
        if value is None:
            return
        if isinstance(value, str) and value.startswith("$"):
            _field(value[1:], available, where)
            return
        raise QueryRejected(f"{where}: use '$field' or null")

    group_id = spec["_id"]
    outputs = {"_id"}
    if isinstance(group_id, dict):
        if not 1 <= len(group_id) <= 3:
            raise QueryRejected("$group._id: 1-3 parts")
        for name, value in group_id.items():
            if not OUTPUT_NAME.match(str(name)):
                raise QueryRejected("$group._id: invalid name")
            reference(value, "$group._id")
            outputs.add(f"_id.{name}")
    else:
        reference(group_id, "$group._id")
    for name, acc in spec.items():
        if name == "_id":
            continue
        if not OUTPUT_NAME.match(str(name)):
            raise QueryRejected("$group: invalid output name")
        if not isinstance(acc, dict) or len(acc) != 1:
            raise QueryRejected(f"$group.{name}: one accumulator")
        (op, arg), = acc.items()
        if op not in ACCUMULATORS:
            raise QueryRejected(f"$group: accumulator '{op}' is not allowed")
        if op == "$sum" and arg == 1:
            pass
        else:
            reference(arg, f"$group.{name}")
        outputs.add(name)
    return frozenset(outputs)


def _validate_pipeline(collection: str, pipeline) -> list[dict]:
    if not isinstance(pipeline, list) or not 1 <= len(pipeline) <= MAX_STAGES:
        raise QueryRejected(f"pipeline: 1-{MAX_STAGES} stages")
    available = ALLOWED_FIELDS[collection]
    for stage in pipeline:
        if not isinstance(stage, dict) or len(stage) != 1:
            raise QueryRejected("pipeline: each stage is an object with one key")
        (name, spec), = stage.items()
        if name not in STAGES:
            raise QueryRejected(f"stage '{name}' is not allowed")
        if name == "$match":
            _filter(spec, available)
        elif name == "$project":
            if not isinstance(spec, dict) or not spec:
                raise QueryRejected("$project: an object of field: 1")
            for field, flag in spec.items():
                _field(field, available, "$project")
                if flag not in (0, 1) or isinstance(flag, float):
                    raise QueryRejected("$project: only 1 (keep) or 0 (drop)")
            kept = {f for f, flag in spec.items() if flag}
            if kept:
                available = frozenset(kept | ({"_id"} if "_id" in available else set()))
        elif name == "$sort":
            if not isinstance(spec, dict) or not 1 <= len(spec) <= MAX_SORT_KEYS:
                raise QueryRejected(f"$sort: 1-{MAX_SORT_KEYS} fields")
            for field, order in spec.items():
                _field(field, available, "$sort")
                if order not in (1, -1) or isinstance(order, bool):
                    raise QueryRejected("$sort: 1 or -1")
        elif name == "$limit":
            if not isinstance(spec, int) or isinstance(spec, bool) or not 1 <= spec <= RESULT_LIMIT:
                raise QueryRejected(f"$limit: 1-{RESULT_LIMIT}")
        elif name == "$count":
            if not isinstance(spec, str) or not OUTPUT_NAME.match(spec):
                raise QueryRejected("$count: a short lower-case name")
            available = frozenset({spec})
        elif name == "$group":
            available = _group(spec, available)
    return pipeline


def validate(proposal) -> Query:
    if not isinstance(proposal, dict):
        raise QueryRejected("The answer was not a query object")
    if len(json.dumps(proposal, default=str)) > MAX_BYTES:
        raise QueryRejected("The query is too large")
    if _depth(proposal) > MAX_DEPTH + 2:
        raise QueryRejected("The query is nested too deeply")
    if "tool" in proposal:
        if set(proposal) != {"tool", "q"} or proposal["tool"] != "locate":
            raise QueryRejected("Unknown tool")
        q = proposal["q"]
        if not isinstance(q, str) or not LOCATE_TEXT.match(q):
            raise QueryRejected("locate: an IP, MAC or host name")
        return Query(None, [], tool="locate", q=q)
    if set(proposal) != {"collection", "pipeline"}:
        raise QueryRejected("Expected exactly 'collection' and 'pipeline'")
    collection = proposal["collection"]
    if not isinstance(collection, str) or collection not in ALLOWED_FIELDS:
        raise QueryRejected(f"Collection '{str(collection)[:40]}' is not available to Ask "
                            "NetMap")
    return Query(collection, _validate_pipeline(collection, proposal["pipeline"]))


def executable(query: Query) -> list[dict]:
    """The pipeline that actually runs: first strip every field that isn't allowlisted, so even
    a query that only filters can't return other fields; then the user's stages; then a hard
    result cap."""
    keep = {field: 1 for field in sorted(ALLOWED_FIELDS[query.collection])}
    if "_id" not in keep:
        keep["_id"] = 0
    return [{"$project": keep}, *query.pipeline, {"$limit": RESULT_LIMIT}]
