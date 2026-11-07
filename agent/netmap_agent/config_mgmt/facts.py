"""Facts the backend needs for compliance but that can only be seen *before* masking.

The backend checks compliance on the masked config, so it can't see the community string
itself. The agent looks at the raw config and sends only a yes/no answer: "is a default
community (public / private) configured?". The value never leaves the agent.
"""

import re

WEAK_COMMUNITIES = {"public", "private"}
_IOS_COMMUNITY = re.compile(r"^\s*snmp-server\s+community\s+(\S+)", re.IGNORECASE)
_ROUTEROS_NAME = re.compile(r'\bname="?([^"\s]+)"?')


def _routeros_default_community(lines: list[str]) -> bool:
    path = ""
    snmp_enabled = False
    default_renamed = False
    weak = False
    for raw in lines:
        line = raw.strip()
        if line.startswith("/"):
            path = " ".join(t for t in line.split() if "=" not in t)
        if path == "/snmp" and re.search(r"\benabled=yes\b", line):
            snmp_enabled = True
        if path.startswith("/snmp community"):
            name = _ROUTEROS_NAME.search(line)
            if name and name.group(1).lower() in WEAK_COMMUNITIES:
                weak = True
            if name and "default=yes" in line:
                default_renamed = name.group(1).lower() not in WEAK_COMMUNITIES
    # RouterOS ships with a community called "public"; /export only shows it if changed.
    return weak or (snmp_enabled and not default_renamed)


def config_facts(text: str, vendor: str) -> dict[str, bool]:
    lines = text.splitlines()
    if vendor == "mikrotik_routeros":
        default_community = _routeros_default_community(lines)
    else:
        default_community = any(
            (m := _IOS_COMMUNITY.match(line)) and m.group(1).lower() in WEAK_COMMUNITIES
            for line in lines
        )
    return {"snmp_default_community": default_community}
