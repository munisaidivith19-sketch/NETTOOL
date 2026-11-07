"""Command denylist for configuration changes (CLAUDE.md 7.5).

SHARED FILE: identical copies live in agent/netmap_agent/config_mgmt/ and
backend/app/config_mgmt/ (a test checks), so edit both or neither. The backend runs it on
preview, submit and approval; the agent runs it again just before pushing, so a change that
was tampered with in the database is still blocked.

How it works, in plain words:
- Every line is split into words. Network devices accept abbreviations (`wr er` means
  `write erase`, `rel` means `reload`), so a word matches a keyword when it is the *start* of
  that keyword. That blocks every abbreviation, at the cost of also blocking a few harmless
  ambiguous ones.
- Cisco IOS: ciscoconfparse2 parses the indentation, so we know which `interface` block a
  `shutdown` belongs to. On a *protected* interface (the management interface and uplinks,
  supplied by the caller) only a short allowlist of safe commands is accepted.
- Interface commands must be indented under their interface line, so a `shutdown` can't
  silently land on whatever interface the device happens to be in.
- MikroTik RouterOS: scripting (`:`, `{}`, `$`, `;`) is rejected outright, because a script
  can do anything; menu commands are matched like the Cisco ones.
This is a safety net, not a full parser: it is deliberately strict, and a blocked line can
always be done by hand by an engineer at the console.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

MAX_COMMAND_LINES = 500
MAX_LINE_LENGTH = 512

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class Violation:
    line: int  # 1-based line number in the submitted text
    text: str
    reason: str

    def as_dict(self) -> dict:
        return {"line": self.line, "text": self.text, "reason": self.reason}


def _starts(tokens: list[str], pattern: tuple[str, ...], at: int = 0) -> bool:
    """True when tokens[at:] begin with (abbreviations of) the pattern keywords."""
    if len(tokens) - at < len(pattern):
        return False
    pairs = zip(tokens[at:], pattern, strict=False)
    return all(tok and word.startswith(tok) for tok, word in pairs)


# ---------------------------------------------------------------- Cisco IOS

_IOS_DENY: list[tuple[tuple[str, ...], str]] = [
    (("write", "erase"), "erases the saved configuration"),
    (("erase",), "erases a file system or the saved configuration"),
    (("reload",), "restarts the device"),
    (("delete",), "deletes files from the device"),
    (("format",), "formats a file system"),
    (("squeeze",), "permanently removes deleted files"),
    (("crypto", "key", "zeroize"), "destroys the SSH keys, cutting off remote access"),
    (("no", "username"), "removes a login account, which can lock everyone out"),
    (("copy",), "copies files over the configuration (the agent saves the config itself)"),
    (("configure",), "the agent controls configuration mode itself"),
    (("boot",), "changes what the device boots"),
    (("config-register",), "changes how the device boots"),
    (("no", "archive"), "turns off the archive that automatic rollback depends on"),
    (("alias",), "aliases can hide what a command really does"),
    (("event", "manager"), "EEM applets can run any command later"),
    (("kron",), "scheduled commands bypass review"),
    (("tclsh",), "scripts bypass review"),
    (("no", "ip", "routing"), "can cut the management path"),
    (("no", "ip", "default-gateway"), "can cut the management path"),
]
# Interface commands that must be indented under an `interface` line.
_IOS_INTERFACE_ONLY: list[tuple[str, ...]] = [
    ("shutdown",), ("no", "shutdown"), ("ip", "address"), ("no", "ip", "address"),
    ("ipv6", "address"), ("no", "ipv6", "address"), ("switchport",), ("no", "switchport"),
    ("channel-group",), ("no", "channel-group"),
]
# The only commands accepted inside a protected interface.
_IOS_PROTECTED_ALLOW: list[tuple[str, ...]] = [
    ("description",), ("no", "shutdown"), ("switchport", "trunk", "allowed", "vlan", "add"),
    ("load-interval",), ("exit",),
]
_IFACE_NAME = re.compile(r"^([a-z][a-z-]*?)(\d[\d/.:]*)$")
_RANGE_PART = re.compile(r"^([a-z][a-z-]*?)((?:\d+/)*)(\d+)(?:-(\d+))?$")


def _iface_parts(name: str) -> tuple[str, str]:
    compact = name.lower().replace(" ", "")
    match = _IFACE_NAME.match(compact)
    return (match.group(1), match.group(2)) if match else (compact, "")


def same_interface(a: str, b: str) -> bool:
    """`Gi0/1` and `GigabitEthernet0/1` are the same port; so are `Vlan99` and `vl99`."""
    (ta, na), (tb, nb) = _iface_parts(a), _iface_parts(b)
    if not na or not nb:
        return a.strip().lower() == b.strip().lower()
    return na == nb and (ta.startswith(tb) or tb.startswith(ta))


def _range_covers(spec: str, protected: list[str]) -> bool | None:
    """Does `interface range gi0/1 - 4, gi0/10` include a protected port? None = can't tell."""
    for piece in spec.lower().replace(" ", "").split(","):
        match = _RANGE_PART.match(piece)
        if not match:
            return None
        kind, path, start, end = match.group(1), match.group(2), int(match.group(3)), \
            int(match.group(4) or match.group(3))
        for item in protected:
            p_kind, p_num = _iface_parts(item)
            p_path, _, p_last = p_num.rpartition("/")
            p_path = f"{p_path}/" if p_path else ""
            if not p_last.isdigit():
                continue
            if (p_kind.startswith(kind) or kind.startswith(p_kind)) and p_path == path \
                    and start <= int(p_last) <= end:
                return True
    return False


def _ios_interface_of(tokens: list[str]) -> tuple[str, bool] | None:
    """For an `interface ...` line return (name or range spec, is_range); else None."""
    if not tokens or len(tokens[0]) < 2 or not "interface".startswith(tokens[0]):
        return None
    rest = tokens[1:]
    if rest and rest[0].isalpha() and len(rest[0]) >= 2 and "range".startswith(rest[0]):
        return " ".join(rest[1:]), True
    return " ".join(rest), False


def _parse_ios(lines: list[str]):  # -> ciscoconfparse2.CiscoConfParse
    # Imported here so the backend only pays for ciscoconfparse2 (about 38 MB) when a change
    # is actually checked. It logs through loguru; silence it so config text is never logged.
    from loguru import logger as ccp_logger

    ccp_logger.disable("ciscoconfparse2")
    from ciscoconfparse2 import CiscoConfParse

    return CiscoConfParse(lines, syntax="ios", ignore_blank_lines=False)


def _check_ios(lines: list[str], protected: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    parsed = _parse_ios(lines)
    for obj in parsed.objs:
        text = obj.text
        tokens = text.lower().split()
        if not tokens or tokens[0].startswith("!"):
            continue
        number = obj.linenum + 1
        if tokens[0] == "do":
            tokens = tokens[1:]
        for pattern, reason in _IOS_DENY:
            if _starts(tokens, pattern):
                violations.append(Violation(number, text, f"Blocked: {reason}."))
                break
        else:
            # Commands that name an interface from global mode.
            if (_starts(tokens, ("no", "interface")) or _starts(tokens, ("default", "interface"))):
                name = " ".join(tokens[2:])
                if any(same_interface(name, p) for p in protected):
                    violations.append(Violation(number, text, "Blocked: removes or resets a "
                                                "management or uplink interface."))
            elif _starts(tokens, ("no", "vlan")) and len(tokens) >= 3:
                if any(same_interface(f"vlan{tokens[2]}", p) for p in protected):
                    violations.append(Violation(number, text, "Blocked: removes the VLAN of "
                                                "the management interface."))
            iface = _ios_interface_of(tokens)
            if iface and iface[1]:
                covers = _range_covers(iface[0], protected)
                if covers is None:
                    violations.append(Violation(number, text, "Blocked: this interface range "
                                                "could not be checked; list the ports instead."))
            if obj.indent == 0 and any(_starts(tokens, p) for p in _IOS_INTERFACE_ONLY):
                violations.append(Violation(number, text, "Indent interface commands under "
                                            "their `interface` line."))
                continue
            # Every interface block this line sits in (nested `interface` lines switch ports
            # on a real device, so all of them count).
            on_protected = False
            node = obj
            while node.parent is not node:
                node = node.parent
                found = _ios_interface_of(node.text.lower().split())
                if not found:
                    continue
                name, is_range = found
                if (is_range and _range_covers(name, protected) is not False) or (
                        not is_range and any(same_interface(name, p) for p in protected)):
                    on_protected = True
            if on_protected and not _ios_interface_of(tokens) and \
                    not any(_starts(tokens, p) for p in _IOS_PROTECTED_ALLOW):
                violations.append(Violation(number, text, "Blocked: only a description, `no "
                                            "shutdown` or adding trunk VLANs is allowed on a "
                                            "management or uplink interface."))
    return violations


# ---------------------------------------------------------------- MikroTik RouterOS

_ROS_VERBS = {
    "add", "set", "remove", "disable", "enable", "print", "export", "reset-configuration",
    "reboot", "shutdown", "edit", "unset", "comment", "move", "import", "run", "load", "upgrade",
}
_ROS_DENY: list[tuple[tuple[str, ...], str]] = [
    (("system", "reset-configuration"), "wipes the whole configuration"),
    (("system", "reboot"), "restarts the device"),
    (("system", "shutdown"), "turns the device off"),
    (("system", "script"), "scripts bypass review"),
    (("system", "scheduler"), "scheduled commands bypass review"),
    (("system", "package"), "changes the installed software"),
    (("system", "backup", "load"), "replaces the whole configuration"),
    (("file", "remove"), "deletes files from the device"),
    (("user", "remove"), "removes a login account, which can lock everyone out"),
    (("import",), "runs a script file"),
    (("ip", "address", "remove"), "can remove the management address"),
    (("ip", "route", "remove"), "can cut the management path"),
]
_ROS_FIND = re.compile(r"\[\s*find(?:\s+[\w.-]+=(?:\"[^\"\[\]{}$;]*\"|[^\s\[\]{}$;\"]+))*\s*\]")


def _check_routeros(lines: list[str], protected: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    path: list[str] = []
    protected_low = {p.lower() for p in protected}
    for index, raw in enumerate(lines, start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        selector = bool(_ROS_FIND.search(text))
        cleaned = _ROS_FIND.sub(" [find] ", text)
        if text.startswith(":") or any(ch in cleaned for ch in "{}$;") or \
                re.search(r"\[(?!find\])", cleaned):
            violations.append(Violation(index, text, "Blocked: RouterOS scripting is not "
                                        "allowed in a change request."))
            continue
        tokens = [t for t in re.split(r"[\s/]+", cleaned.lower()) if t]
        if text.startswith("/"):
            verb_at = next((i for i, t in enumerate(tokens) if t in _ROS_VERBS), len(tokens))
            path = tokens[:verb_at]
            full = tokens
        else:
            full = path + tokens
        denied = next((reason for pattern, reason in _ROS_DENY if _starts(full, pattern)), None)
        if denied:
            violations.append(Violation(index, text, f"Blocked: {denied}."))
            continue
        verb_at = next((i for i, t in enumerate(full) if t in _ROS_VERBS), None)
        if verb_at is None:
            continue
        verb, args = full[verb_at], full[verb_at + 1:]
        menu = full[:verb_at]
        targets = [a for a in args if "=" not in a and a != "[find]"]
        unknown_target = selector or not targets
        hits_protected = unknown_target or any(t in protected_low for t in targets)
        if _starts(menu, ("interface",)) and hits_protected and (
                verb in ("disable", "remove")
                or (verb == "set" and any(a in ("disabled=yes", "disabled=true") for a in args))):
            violations.append(Violation(index, text, "Blocked: disables or removes a management "
                                        "or uplink interface (or one that can't be identified)."))
        elif _starts(menu, ("ip", "service")) and verb in ("set", "disable") and (
                "ssh" in targets or unknown_target):
            if verb == "disable" or any(a.startswith(("disabled=yes", "port=", "address="))
                                        for a in args):
                violations.append(Violation(index, text, "Blocked: changes the SSH service the "
                                            "agent uses to reach the device."))
    return violations


# ---------------------------------------------------------------- entry point

def check_commands(
    text: str, vendor: str, protected_interfaces: Iterable[str] = ()
) -> list[Violation]:
    """Return every reason the command text must not be pushed (empty list = allowed)."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    violations: list[Violation] = []
    if not any(line.strip() for line in lines):
        return [Violation(0, "", "The change has no commands.")]
    if len(lines) > MAX_COMMAND_LINES:
        return [Violation(0, "", f"Too many lines (maximum {MAX_COMMAND_LINES}).")]
    for index, line in enumerate(lines, start=1):
        if _CONTROL.search(line):
            violations.append(Violation(index, line.encode("unicode_escape").decode()[:80],
                                        "Control characters (tabs, carriage returns, escape "
                                        "codes) are not allowed."))
        elif len(line) > MAX_LINE_LENGTH:
            violations.append(Violation(index, line[:80], "Line is too long."))
    if violations:
        return violations
    protected = [p for p in protected_interfaces if p]
    if vendor == "mikrotik_routeros":
        return _check_routeros(lines, protected)
    if vendor == "cisco_ios":
        return _check_ios(lines, protected)
    return [Violation(0, "", f"Unsupported device type {vendor!r}.")]
