"""Turns ping results and SNMP polls into the report JSON sent to POST /api/agent/report.

The report never contains credentials: only what the devices told us and what answered ping.
"""

from dataclasses import asdict
from datetime import datetime, timezone

from netmap_agent import __version__
from netmap_agent.discovery.snmp import DevicePoll


def device_entry(poll: DevicePoll, snmp_version: str) -> dict:
    entry = {
        "mgmt_ip": poll.target,
        "snmp_port": poll.port,
        "snmp_version": snmp_version,
        "reachable": poll.ok,
        "error": poll.error,
    }
    if poll.ok:
        entry.update(
            sys_name=poll.sys_name,
            sys_descr=poll.sys_descr,
            sys_location=poll.sys_location,
            sys_object_id=poll.sys_object_id,
            vendor=poll.vendor,
            uptime_seconds=poll.uptime_seconds,
            interfaces=[asdict(i) for i in poll.interfaces],
            addresses=[{"ip": a.ip, "if_index": a.if_index, "prefixlen": a.prefixlen}
                       for a in poll.addresses],
            neighbors=[{"ip": n.ip, "mac": n.mac, "if_index": n.if_index, "kind": n.kind}
                       for n in poll.neighbors],
        )
    return entry


def build_report(ping_results: dict[str, bool], polls: list[DevicePoll], snmp_version: str) -> dict:
    return {
        "agent_version": __version__,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "ping": [{"ip": ip, "up": up} for ip, up in ping_results.items()],
        "devices": [device_entry(p, snmp_version) for p in polls],
    }
