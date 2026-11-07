"""Configuration compliance: hardening checks with a score and a fix for every finding.

The checks run on the *masked* config (the backend never sees secrets). The one check that
needs a secret - "is the SNMP community public/private?" - is answered by the agent before
masking and arrives as a yes/no fact.

Score = 100 minus the weight of every failed rule (never below 0). Each finding explains the
risk in plain words and suggests the commands that fix it. Suggestions marked `needs_input`
contain a <placeholder> the engineer must fill in before using them in a change request.

Cisco IOS is parsed with ciscoconfparse2, imported only when a check runs (it costs ~38 MB).
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from app.config_mgmt.denylist import same_interface

PHYSICAL = re.compile(r"^(GigabitEthernet|FastEthernet|TenGigabitEthernet|TwentyFiveGigE|"
                      r"Ethernet)\d", re.IGNORECASE)
MAX_LISTED = 20


@dataclass
class Finding:
    rule: str
    title: str
    severity: str  # high | medium | low
    weight: int
    why: str
    fix: str
    items: list[str] = field(default_factory=list)
    needs_input: bool = False


@dataclass
class Report:
    score: int
    vendor: str
    findings: list[Finding]
    rules_checked: int

    def as_dict(self) -> dict:
        return {"score": self.score, "vendor": self.vendor, "rules_checked": self.rules_checked,
                "findings": [asdict(f) for f in self.findings]}


def _parse(text: str):
    from loguru import logger as ccp_logger

    ccp_logger.disable("ciscoconfparse2")  # never let the parser log config text
    from ciscoconfparse2 import CiscoConfParse

    return CiscoConfParse(text.splitlines(), syntax="ios")


def _children(obj) -> list[str]:
    return [c.text.strip() for c in obj.children]


def _ios_rules(text: str, facts: dict, interfaces: list[dict]) -> tuple[list[Finding], int]:
    parsed = _parse(text)
    top = [o.text.strip() for o in parsed.objs if o.indent == 0]
    findings: list[Finding] = []
    vty = parsed.find_objects(r"^line vty")
    con = parsed.find_objects(r"^line con")

    telnet = []
    for line in vty:
        transport = [c for c in _children(line) if c.startswith("transport input")]
        if not transport or re.search(r"\b(telnet|all)\b", transport[-1]):
            telnet.append(line.text.strip())
    if telnet:
        findings.append(Finding(
            "telnet_enabled", "Telnet is allowed on remote logins", "high", 20,
            "Telnet sends usernames, passwords and every command in clear text.",
            "\n".join(f"{name}\n transport input ssh" for name in telnet), telnet))

    if "service password-encryption" not in top:
        findings.append(Finding(
            "no_password_encryption", "Passwords are stored in clear text in the config",
            "medium", 10, "Without `service password-encryption`, line and user passwords are "
            "readable by anyone who sees a config file or a screen.",
            "service password-encryption"))

    communities = [t for t in top if t.startswith("snmp-server community")]
    if facts.get("snmp_default_community"):
        findings.append(Finding(
            "snmp_default_community", "SNMP uses a default community (public/private)", "high",
            20, "Default communities are the first thing attackers try; with RW they can change "
            "the configuration.",
            "no snmp-server community <community-name>\nsnmp-server group NETMAP v3 priv\n"
            "snmp-server user <user> NETMAP v3 auth sha <auth-key> priv aes 128 <priv-key>",
            needs_input=True))
    elif communities:
        findings.append(Finding(
            "snmp_v1_v2c", "SNMP v1/v2c is enabled", "medium", 10,
            "v1/v2c sends the community string in clear text. Use SNMPv3 with authentication "
            "and encryption (authPriv).",
            "no snmp-server community <community-name>\nsnmp-server group NETMAP v3 priv",
            [f"{len(communities)} community line(s)"], needs_input=True))

    if not any(t.startswith("ip ssh version 2") for t in top):
        findings.append(Finding(
            "no_ssh_v2", "SSH version 1 is still allowed", "medium", 10,
            "SSH v1 has known weaknesses; force version 2.", "ip ssh version 2"))

    if not any(re.match(r"^banner (login|motd)\b", t) for t in top):
        findings.append(Finding(
            "no_login_banner", "No login banner", "low", 5,
            "A warning banner supports legal action against unauthorised access.",
            "banner login ^Authorised access only. Activity is logged.^"))

    no_timeout = []
    for line in [*con, *vty]:
        timeouts = [c for c in _children(line) if c.startswith("exec-timeout")]
        if not timeouts or re.fullmatch(r"exec-timeout 0( 0)?", timeouts[-1]):
            no_timeout.append(line.text.strip())
    if no_timeout:
        findings.append(Finding(
            "no_exec_timeout", "Idle sessions never time out", "medium", 10,
            "A forgotten logged-in session stays open for anyone who walks up to it.",
            "\n".join(f"{name}\n exec-timeout 10 0" for name in no_timeout), no_timeout))

    down = [i for i in interfaces if i.get("oper_status") == "down"
            and i.get("admin_status") == "up"]
    unused = []
    for obj in parsed.find_objects(r"^interface "):
        name = obj.text.split(None, 1)[1].strip()
        children = _children(obj)
        if not PHYSICAL.match(name) or "shutdown" in children or \
                any(c.startswith("ip address") for c in children):
            continue
        if any(same_interface(name, i.get("descr") or "") or
               same_interface(name, i.get("name") or "") for i in down):
            unused.append(name)
    if unused:
        findings.append(Finding(
            "unused_ports_up", "Unused ports are not shut down", "medium", 10,
            "A free, enabled port lets anyone plug in a device and join the network.",
            "\n".join(f"interface {n}\n description Unused\n shutdown"
                      for n in unused[:MAX_LISTED]), unused[:MAX_LISTED]))

    no_security = []
    for obj in parsed.find_objects(r"^interface "):
        children = _children(obj)
        if "switchport mode access" in children and \
                not any(c.startswith("switchport port-security") for c in children):
            no_security.append(obj.text.split(None, 1)[1].strip())
    if no_security:
        findings.append(Finding(
            "access_port_security", "Access ports without port security", "medium", 10,
            "Without port security, a hub or rogue switch on an access port can connect many "
            "devices, and MAC flooding attacks are easier.",
            "\n".join(f"interface {n}\n switchport port-security\n switchport port-security "
                      "maximum 2\n switchport port-security violation restrict"
                      for n in no_security[:MAX_LISTED]), no_security[:MAX_LISTED]))
    return findings, 8


def _routeros_rules(text: str, facts: dict) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    disabled = set(re.findall(r"^\s*(?:/ip service )?set (\w+) [^\n]*disabled=yes", text,
                              re.MULTILINE))
    insecure = [s for s in ("telnet", "ftp", "www") if s not in disabled]
    if insecure:
        weight = 20 if "telnet" in insecure else 10
        findings.append(Finding(
            "insecure_services", "Clear-text management services are enabled",
            "high" if "telnet" in insecure else "medium", weight,
            "Telnet, FTP and plain HTTP send passwords in clear text.",
            "\n".join(f"/ip service set {s} disabled=yes" for s in insecure), insecure))
    if facts.get("snmp_default_community"):
        findings.append(Finding(
            "snmp_default_community", "SNMP uses the default community (public)", "high", 20,
            "Default communities are the first thing attackers try.",
            "/snmp community set [ find default=yes ] name=<new-name>", needs_input=True))
    if not re.search(r"strong-crypto=yes", text):
        findings.append(Finding(
            "ssh_weak_crypto", "SSH strong crypto is off", "low", 5,
            "Older, weaker SSH ciphers stay allowed.", "/ip ssh set strong-crypto=yes"))
    return findings, 3


def evaluate(text: str, vendor: str, facts: dict | None = None,
             interfaces: list[dict] | None = None) -> Report:
    facts = facts or {}
    if vendor == "mikrotik_routeros":
        findings, checked = _routeros_rules(text, facts)
    else:
        findings, checked = _ios_rules(text, facts, interfaces or [])
    score = max(0, 100 - sum(f.weight for f in findings))
    return Report(score, vendor, findings, checked)
