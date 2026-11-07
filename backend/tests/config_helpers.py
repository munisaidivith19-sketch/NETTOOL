"""Shared setup for the Phase 6 tests: a reported core switch with config backups."""

import hashlib
import json

from tests.conftest import signed_headers
from tests.ipam_helpers import seed_report
from tests.topology_helpers import core

# A small but realistic IOS config, as an agent would upload it (already masked).
CORE_CONFIG = """\
!
version 17.9
service password-encryption
hostname CORE-SW-1
!
enable secret 9 <masked>
username netmap privilege 15 secret 9 <masked>
ip domain-name campus.example
ip ssh version 2
!
archive
 path flash:archive
!
vlan 10
 name STAFF
!
interface GigabitEthernet1/0/1
 description Uplink to EDGE-RTR-1
 ip address 10.10.0.2 255.255.255.252
!
interface GigabitEthernet1/0/2
 description Trunk to ACCESS-SW-1
 switchport mode trunk
!
interface Vlan10
 ip address 10.10.10.1 255.255.255.0
!
banner login ^Authorised access only.^
line con 0
 exec-timeout 10 0
line vty 0 4
 exec-timeout 10 0
 transport input ssh
!
end
"""

WEAK_CONFIG = """\
no service password-encryption
hostname EDGE-RTR-1
enable secret 9 $9$NotMaskedByTheAgent
snmp-server community public RO
interface GigabitEthernet0/2
 switchport mode access
line con 0
 exec-timeout 0 0
line vty 0 4
 transport input telnet ssh
end
"""


def fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def agent_call(client, agent, method: str, path: str, body: dict | None = None):
    payload = b"" if body is None else json.dumps(body).encode()
    client.cookies.clear()
    headers = signed_headers(agent["id"], agent["key"], method, path, payload)
    return client.request(method, path, content=payload or None, headers=headers)


def upload(client, agent, device_id: str, text: str | None, *, hash_: str | None = None,
           source: str = "scheduled", facts: dict | None = None, vendor: str = "cisco_ios",
           change_id: str | None = None, error: str | None = None):
    body: dict = {"device_id": device_id, "source": source}
    if error:
        body["error"] = error
    else:
        body |= {"vendor": vendor, "hash": hash_ or fingerprint(text or ""),
                 "facts": facts or {"snmp_default_community": False}}
        if text is not None:
            body["text"] = text
    if change_id:
        body["change_id"] = change_id
    return agent_call(client, agent, "POST", "/api/agent/configs", body)


def seed_core(client, sync_db, *, config: str | None = CORE_CONFIG) -> tuple[dict, str]:
    """Report CORE-SW-1 (with LLDP links on Gi1/0/1 and Gi1/0/2) and upload its config."""
    agent = seed_report(client, sync_db, core())
    device_id = str(sync_db.devices.find_one({"mgmt_ip": "10.10.99.1"})["_id"])
    if config is not None:
        response = upload(client, agent, device_id, config)
        assert response.status_code == 200, response.text
    return agent, device_id
