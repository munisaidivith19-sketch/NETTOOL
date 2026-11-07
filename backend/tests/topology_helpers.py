"""A two-switch campus for the Phase 5 tests.

CORE-SW-1 (10.10.99.1)  Gi1/0/2  ==LLDP==  port 9  ACCESS-SW-1 (10.10.99.11)
CORE-SW-1               Gi1/0/1  --LLDP--  isp-pe-01 (external, not managed by NetMap)
A staff PC (00:14:22:1a:20:14, 10.10.10.20) is on ACCESS-SW-1 port 1, VLAN 10. The core sees
it too, on its trunk Gi1/0/2: the location logic must ignore that sighting.
"""

import copy
from datetime import datetime, timedelta, timezone

from tests.test_ingest import core_switch

PC = "00:14:22:1a:20:14"
PC2 = "00:14:22:1a:20:15"
CORE_MAC = "00:00:0c:c0:00:01"
ACCESS_MGMT_MAC = "3c:d9:2b:99:00:11"


def _port(if_index: int, name: str, mac: str, oper: str = "up", descr: str | None = None) -> dict:
    return {"if_index": if_index, "name": name, "descr": descr or name, "if_type": 6,
            "speed_mbps": 1000, "mac": mac, "admin_status": "up", "oper_status": oper}


def core(**overrides) -> dict:
    device = core_switch()
    device["interfaces"].append(_port(2, "Gi1/0/2", "00:00:0c:c0:00:02",
                                       descr="GigabitEthernet1/0/2"))
    device["links"] = [
        {"protocol": "lldp", "if_index": 2, "local_port": "Gi1/0/2", "remote_name": "ACCESS-SW-1",
         "remote_port": "9", "remote_chassis_id": ACCESS_MGMT_MAC, "remote_mgmt_ip": "10.10.99.11"},
        {"protocol": "lldp", "if_index": 1, "local_port": "Gi1/0/1",
         "remote_name": "isp-pe-01.example.net", "remote_port": "xe-0/0/7",
         "remote_chassis_id": "00:00:0c:ee:00:01", "remote_mgmt_ip": "203.0.113.1"},
    ]
    device["mac_table"] = [
        {"mac": PC, "if_index": 2, "vlan": 10},
        {"mac": PC2, "if_index": 2, "vlan": 10},
        {"mac": ACCESS_MGMT_MAC, "if_index": 2, "vlan": 99},
    ]
    device.update(overrides)
    return device


def access(port9: str = "up", links: bool = True, **overrides) -> dict:
    device = {
        "mgmt_ip": "10.10.99.11", "snmp_port": 161, "snmp_version": "v3", "reachable": True,
        "sys_name": "ACCESS-SW-1", "vendor": "HP", "uptime_seconds": 1000,
        "interfaces": [
            _port(1, "1", "3c:d9:2b:99:01:01"), _port(2, "2", "3c:d9:2b:99:01:02"),
            _port(9, "9", "3c:d9:2b:99:01:09", oper=port9),
            {"if_index": 99, "name": "VLAN99", "mac": ACCESS_MGMT_MAC, "admin_status": "up",
             "oper_status": "up", "speed_mbps": 1000},
        ],
        "addresses": [{"ip": "10.10.99.11", "if_index": 99, "prefixlen": 24}],
        "links": [{"protocol": "lldp", "if_index": 9, "local_port": "9",
                   "remote_name": "CORE-SW-1", "remote_port": "Gi1/0/2",
                   "remote_chassis_id": "00:00:0c:c0:99:00", "remote_mgmt_ip": "10.10.99.1"}]
        if links else [],
        "mac_table": [
            {"mac": PC, "if_index": 1, "vlan": 10},
            {"mac": PC2, "if_index": 2, "vlan": 10},
            {"mac": "00:00:0c:c0:10:00", "if_index": 9, "vlan": 10},
        ],
    }
    device.update(overrides)
    return device


def with_counters(device: dict, octets: int, at: datetime) -> dict:
    """The same octet count on every interface of the device, read at `at`."""
    device = copy.deepcopy(device)
    device["counters"] = [{"if_index": i["if_index"], "in_octets": octets,
                           "out_octets": octets // 2, "in_errors": 0, "out_errors": 0,
                           "bits": 64} for i in device["interfaces"]]
    device["counters_at"] = at.isoformat()
    return device


def utc_now() -> datetime:
    # Whole seconds: MongoDB keeps milliseconds, so microseconds would skew exact rate checks.
    return datetime.now(timezone.utc).replace(microsecond=0)


__all__ = ["PC", "PC2", "CORE_MAC", "access", "core", "timedelta", "utc_now", "with_counters"]
