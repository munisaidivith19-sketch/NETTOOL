"""A tiny fake Cisco IOS SSH server, so config backups and pushes can be demoed without a lab.

It is just enough IOS for Netmiko and NetMap: login, `enable`, `terminal length 0`,
`show running-config`, `configure terminal [revert timer N]`, config lines (indentation is
used to tell interface commands from global ones), `configure confirm`, `configure revert now`
and `write memory`. Each simulated Cisco device listens on its own 127.0.0.x, TCP port 2222.

Run from the agent folder:   python -m simulation.ssh_sim [--break-after-push]
Then, once:                  python -m simulation.setup_credentials
  --break-after-push   after a change is pushed with a revert timer, refuse new SSH logins
                       until it is reverted: shows NetMap rolling a bad change back.

Lab-only login: user "netmap", password "netmap-sim-ssh", enable secret "netmap-sim-enable".
They only open this simulator; never use them on real equipment. The SSH host keys are
generated at start and written to a known_hosts file, so the agent can check them strictly.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import logging
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import paramiko

from simulation.topology import CORE_SWITCH, EDGE_ROUTER, NEW_SWITCH, Iface, SimDevice

SSH_PORT = 2222
SIM_SSH_USER = "netmap"
SIM_SSH_PASSWORD = "netmap-sim-ssh"  # noqa: S105  # nosec B105 - simulation-only, documented
SIM_ENABLE_SECRET = "netmap-sim-enable"  # noqa: S105  # nosec B105 - simulation-only
DEFAULT_KNOWN_HOSTS = Path(__file__).parent / "ssh_known_hosts"

logger = logging.getLogger("simulation.ssh")

_ABBREVIATIONS = {
    "gi": "GigabitEthernet", "fa": "FastEthernet", "te": "TenGigabitEthernet",
    "vl": "Vlan", "lo": "Loopback", "po": "Port-channel", "tu": "Tunnel",
}
# Commands that only make sense inside an interface / line block, even when not indented.
_CHILD_ONLY = re.compile(
    r"^(no\s+)?(shutdown|description|ip address|ipv6 address|switchport|spanning-tree portfast|"
    r"exec-timeout|transport|login|password|path|maximum|name|storm-control)\b"
)
# Global commands that may appear only once; the key is how many words identify them.
_SINGLE_GLOBAL = [
    (re.compile(r"^hostname\b"), 1), (re.compile(r"^enable secret\b"), 2),
    (re.compile(r"^ip domain[- ]name\b"), 2), (re.compile(r"^ip default-gateway\b"), 2),
    (re.compile(r"^ip ssh version\b"), 3), (re.compile(r"^snmp-server (location|contact)\b"), 2),
    (re.compile(r"^banner \w+"), 2), (re.compile(r"^clock timezone\b"), 2),
]
_SINGLE_CHILD = re.compile(
    r"^(description|ip address|switchport mode|switchport access vlan|exec-timeout|"
    r"transport input|path|maximum|name|switchport port-security maximum)\b"
)


def canonical_interface(name: str) -> str:
    compact = name.replace(" ", "")
    match = re.match(r"^([A-Za-z-]+)([\d/.:]+)$", compact)
    if not match:
        return name.strip()
    kind, number = match.groups()
    low = kind.lower()
    for short, full in _ABBREVIATIONS.items():
        if full.lower().startswith(low) and low.startswith(short):
            return f"{full}{number}"
    return f"{kind}{number}"


def _mask(cidr: str) -> tuple[str, str]:
    iface = ipaddress.ip_interface(cidr)
    return str(iface.ip), str(iface.network.netmask)


def _interface_block(iface: Iface, switch_port_mode: str | None = None) -> list[str]:
    block = [f"interface {iface.descr}"]
    if iface.alias:
        block.append(f" description {iface.alias}")
    if switch_port_mode:
        block.append(f" switchport mode {switch_port_mode}")
    for cidr in iface.ipv4:
        ip, mask = _mask(cidr)
        block.append(f" ip address {ip} {mask}")
    for cidr in iface.ipv6:
        block.append(f" ipv6 address {cidr}")
    if not iface.admin_up:
        block.append(" shutdown")
    return block


def _hashed(secret: str) -> str:
    # Looks like an IOS type-9 hash; it is only a fingerprint of the simulation value.
    return "$9$" + hashlib.sha256(secret.encode()).hexdigest()[:30]


def initial_config(device: SimDevice) -> list[list[str]]:
    """Starting configs: one weak router, one hardened core switch and one factory default."""
    common_login = [[f"username {SIM_SSH_USER} privilege 15 secret 9 {_hashed(SIM_SSH_PASSWORD)}"]]
    if device is EDGE_ROUTER:
        # Deliberately weak, so compliance has something to report.
        blocks = [["version 15.9"], ["no service password-encryption"],
                  [f"hostname {device.sys_name}"],
                  [f"enable secret 9 {_hashed(SIM_ENABLE_SECRET)}"], *common_login,
                  ["ip domain-name campus.example"]]
        blocks += [_interface_block(i) for i in device.interfaces]
        blocks += [["snmp-server community public RO"],
                   [f"snmp-server location {device.sys_location}"],
                   ["line con 0", " exec-timeout 0 0"],
                   ["line vty 0 4", " exec-timeout 0 0", " login local",
                    " transport input telnet ssh"]]
        return blocks
    if device is CORE_SWITCH:
        blocks = [["version 17.9"], ["service password-encryption"],
                  [f"hostname {device.sys_name}"],
                  [f"enable secret 9 {_hashed(SIM_ENABLE_SECRET)}"], *common_login,
                  ["ip domain-name campus.example"], ["ip ssh version 2"],
                  ["archive", " path flash:archive", " maximum 5"]]
        for vlan, name in ((10, "STAFF"), (20, "STUDENTS"), (30, "PRINTERS"), (99, "MGMT")):
            blocks.append([f"vlan {vlan}", f" name {name}"])
        for iface in device.interfaces:
            mode = "trunk" if iface.if_type == 6 and not iface.ipv4 else None
            blocks.append(_interface_block(iface, mode))
        blocks += [["snmp-server group NETMAP v3 priv"],
                   [f"snmp-server location {device.sys_location}"],
                   ["banner login ^Authorised access only. Activity is logged.^"],
                   ["line con 0", " exec-timeout 10 0"],
                   ["line vty 0 4", " exec-timeout 10 0", " login local", " transport input ssh"]]
        return blocks
    # Factory default plus the bare minimum someone typed to reach it over SSH.
    blocks = [["version 15.2"], ["no service password-encryption"], ["hostname Switch"],
              *common_login, ["ip domain-name campus.example"]]
    for iface in device.interfaces:
        if iface.if_type == 53:
            blocks.append([f"interface {iface.descr}", " ip address dhcp"])
        else:
            blocks.append([f"interface {iface.descr}"])
    blocks += [["line con 0"], ["line vty 0 4", " login local", " transport input ssh"]]
    return blocks


@dataclass
class FakeIOS:
    device: SimDevice
    break_after_push: bool = False
    seconds_per_minute: float = 1.0
    blocks: list[list[str]] = field(default_factory=list)
    broken: bool = False
    _snapshot: list[list[str]] | None = None
    _timer: threading.Timer | None = None
    lock: threading.RLock = field(default_factory=threading.RLock)
    changed_at: str = ""

    def __post_init__(self) -> None:
        if not self.blocks:
            self.blocks = initial_config(self.device)

    # ---------------------------------------------------------- state
    @property
    def hostname(self) -> str:
        for block in self.blocks:
            if block[0].startswith("hostname "):
                return block[0].split(None, 1)[1]
        return "Switch"

    def has_archive(self) -> bool:
        return any(b[0] == "archive" and any(c.startswith(" path ") for c in b[1:])
                   for b in self.blocks)

    def running_config(self) -> str:
        body = []
        for block in self.blocks:
            body.extend(block)
            body.append("!")
        text = "\n".join(body)
        header = ["Building configuration...", "", f"Current configuration : {len(text)} bytes",
                  "!", f"! Last configuration change at {self.changed_at or '00:00:00 UTC'}", "!"]
        return "\r\n".join([*header, *body, "end"]) + "\r\n"

    # ---------------------------------------------------------- revert timer
    def start_revert_timer(self, minutes: int) -> None:
        with self.lock:
            self.cancel_timer()
            self._snapshot = [list(b) for b in self.blocks]
            self._timer = threading.Timer(minutes * self.seconds_per_minute, self.revert)
            self._timer.daemon = True
            self._timer.start()

    def cancel_timer(self) -> None:
        if self._timer:
            self._timer.cancel()
        self._timer = None

    def confirm(self) -> bool:
        with self.lock:
            had = self._timer is not None
            self.cancel_timer()
            self._snapshot = None
            return had

    def revert(self) -> bool:
        with self.lock:
            if self._snapshot is None:
                return False
            self.blocks = self._snapshot
            self._snapshot = None
            self.cancel_timer()
            self.broken = False
            self.changed_at = time.strftime("%H:%M:%S UTC", time.gmtime())
            logger.info("%s: configuration reverted", self.device.sys_name)
            return True

    def push_finished(self) -> None:
        with self.lock:
            if self.break_after_push and self._snapshot is not None:
                self.broken = True

    # ---------------------------------------------------------- applying config lines
    def _find_block(self, first: str) -> list[str] | None:
        return next((b for b in self.blocks if b[0] == first), None)

    def apply(self, raw: str, context: list[str] | None) -> tuple[list[str] | None, str]:
        """Apply one config line. Returns the new sub-mode block (or None) and any output."""
        line = raw.strip()
        if not line or line.startswith("!"):
            return context, ""
        if "invalid-command" in line:
            return context, "% Invalid input detected at '^' marker."
        self.changed_at = time.strftime("%H:%M:%S UTC", time.gmtime())
        indented = raw[:1].isspace()
        if context is not None and (indented or _CHILD_ONLY.match(line)):
            return context, self._apply_child(context, line)
        return self._apply_global(line)

    def _apply_child(self, block: list[str], line: str) -> str:
        if line == "exit":
            return ""
        if line.startswith("no "):
            rest = line[3:]
            block[1:] = [c for c in block[1:] if not c.strip().startswith(rest)]
            return ""
        if line.startswith(("password ", "secret ")) and not re.match(r"^\w+ \d ", line):
            word, value = line.split(None, 1)
            line = f"{word} 7 {hashlib.sha256(value.encode()).hexdigest()[:12].upper()}"
        key = _SINGLE_CHILD.match(line)
        if key:
            block[1:] = [c for c in block[1:] if not c.strip().startswith(key.group(1))]
        elif f" {line}" in block:
            return ""
        block.append(f" {line}")
        return ""

    def _apply_global(self, line: str) -> tuple[list[str] | None, str]:
        words = line.split()
        head = words[0].lower()
        if head in ("exit", "end"):
            return None, ""
        if len(words) >= 2 and "interface".startswith(head) and len(head) >= 3:
            name = canonical_interface(" ".join(words[1:]))
            block = self._find_block(f"interface {name}")
            if block is None:
                block = [f"interface {name}"]
                self.blocks.append(block)
            return block, ""
        if head in ("line", "vlan", "archive", "router") or line.startswith("ip access-list"):
            block = self._find_block(line)
            if block is None:
                block = [line]
                self.blocks.append(block)
            return block, ""
        if head == "crypto" and "generate" in line:
            return None, "The name for the keys will be: simulated\n% Generating keys ... [OK]"
        if head == "no" and len(words) >= 2:
            rest = " ".join(words[1:])
            if rest.startswith("interface "):
                rest = f"interface {canonical_interface(rest[10:])}"
            if rest.startswith("service "):
                self._replace_global(f"service {rest[8:]}", f"no service {rest[8:]}")
                return None, ""
            self.blocks = [b for b in self.blocks if not b[0].startswith(rest)]
            return None, ""
        if head == "service" and len(words) >= 2:
            self._replace_global(line, line)
            return None, ""
        if head in ("username", "enable"):
            line = re.sub(r"\b(secret)\s+(?!\d\s)(\S+)",
                          lambda m: f"{m.group(1)} 9 {_hashed(m.group(2))}", line)
        for pattern, words_in_key in _SINGLE_GLOBAL:
            if pattern.match(line):
                prefix = " ".join(words[:words_in_key])
                existing = next((b for b in self.blocks if b[0].startswith(prefix)), None)
                if existing is not None:
                    existing[:] = [line]  # replaced where it was, like IOS does
                    return None, ""
                break
        if not self._find_block(line):
            self.blocks.append([line])
        return None, ""

    def _replace_global(self, on: str, line: str) -> None:
        setting = on.split(None, 1)[1]
        for block in self.blocks:
            if block[0] in (f"service {setting}", f"no service {setting}"):
                block[0] = line
                return
        self.blocks.append([line])


class _Server(paramiko.ServerInterface):
    def __init__(self, ios: FakeIOS) -> None:
        self.ios = ios

    def check_auth_password(self, username: str, password: str) -> int:
        if self.ios.broken:
            return paramiko.AUTH_FAILED
        if username == SIM_SSH_USER and password == SIM_SSH_PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        return True


class _Shell:
    """One interactive CLI session on a channel."""

    def __init__(self, ios: FakeIOS, channel: paramiko.Channel) -> None:
        self.ios = ios
        self.chan = channel
        self.privileged = False
        self.config_mode = False
        self.context: list[str] | None = None
        self.awaiting_secret = False
        self.timer_session = False

    def prompt(self) -> str:
        name = self.ios.hostname
        if not self.config_mode:
            return f"{name}{'#' if self.privileged else '>'}"
        if self.context is None:
            return f"{name}(config)#"
        first = self.context[0].split()[0]
        sub = {"interface": "if", "line": "line", "vlan": "vlan", "archive": "archive"}
        return f"{name}(config-{sub.get(first, 'sub')})#"

    def send(self, text: str) -> None:
        self.chan.sendall(text.replace("\r\n", "\n").replace("\n", "\r\n").encode())

    def run(self) -> None:
        self.send(f"\n{self.prompt()}")
        buffer = ""
        last = ""
        while True:
            data = self.chan.recv(4096)
            if not data:
                return
            for char in data.decode(errors="replace"):
                if char == "\n" and last == "\r":
                    last = char
                    continue
                last = char
                if char in "\r\n":
                    if not self.awaiting_secret:
                        self.send("\n")
                    line, buffer = buffer, ""
                    if not self.handle(line):
                        return
                elif char.isprintable():
                    buffer += char
                    if not self.awaiting_secret:
                        self.send(char)

    def handle(self, line: str) -> bool:
        if self.awaiting_secret:
            self.awaiting_secret = False
            if line == SIM_ENABLE_SECRET:
                self.privileged = True
                self.send(self.prompt())
            else:
                self.send(f"% Access denied\n\n{self.prompt()}")
            return True
        if self.config_mode:
            return self.handle_config(line)
        output = self.handle_exec(line.strip())
        if output is None:
            return False
        if output != "\0":
            self.send(f"{output}\n{self.prompt()}" if output else self.prompt())
        return True

    def handle_exec(self, cmd: str) -> str | None:
        low = cmd.lower()
        if not cmd:
            return ""
        if low in ("exit", "quit", "logout"):
            return None
        if low in ("en", "enable"):
            if self.privileged:
                return ""
            self.awaiting_secret = True
            self.send("Password: ")
            return "\0"
        if low.startswith("terminal "):
            return ""
        if low in ("show version", "sh ver"):
            return self.ios.device.sys_descr
        if not self.privileged:
            return "% Invalid input detected at '^' marker."
        if low in ("show running-config", "sh run", "show run"):
            with self.ios.lock:
                return self.ios.running_config().rstrip("\r\n")
        match = re.fullmatch(r"conf(?:igure)?(?: t(?:erminal)?)?(?: revert timer (\d+))?", low)
        if match and low not in ("configure confirm",):
            if match.group(1):
                if not self.ios.has_archive():
                    return "% Archive feature is not configured. Configure 'archive' first."
                self.ios.start_revert_timer(int(match.group(1)))
                self.timer_session = True
            self.config_mode = True
            self.context = None
            return "Enter configuration commands, one per line.  End with CNTL/Z."
        if low == "configure confirm":
            return "" if self.ios.confirm() else "% No rollback timer is running."
        if low == "configure revert now":
            return "Rollback Done" if self.ios.revert() else "% No rollback timer is running."
        if low in ("write memory", "wr mem", "wr", "copy running-config startup-config"):
            return "Building configuration...\n[OK]"
        return "% Invalid input detected at '^' marker."

    def handle_config(self, line: str) -> bool:
        stripped = line.strip().lower()
        if stripped == "end":
            self.config_mode = False
            self.context = None
            if self.timer_session:
                self.timer_session = False
                self.ios.push_finished()
            self.send(self.prompt())
            return True
        if stripped == "exit":
            if self.context is None:
                self.config_mode = False
            self.context = None
            self.send(self.prompt())
            return True
        with self.ios.lock:
            self.context, output = self.ios.apply(line, self.context)
        self.send(f"{output}\n{self.prompt()}" if output else self.prompt())
        return True


def _serve_client(sock: socket.socket, ios: FakeIOS, host_key: paramiko.PKey) -> None:
    transport = paramiko.Transport(sock)
    transport.add_server_key(host_key)
    try:
        transport.start_server(server=_Server(ios))
        channel = transport.accept(20)
        if channel is None:
            return
        _Shell(ios, channel).run()
    except (paramiko.SSHException, OSError, EOFError):
        pass
    finally:
        transport.close()


def serve(ios: FakeIOS, host_key: paramiko.PKey, port: int = SSH_PORT) -> threading.Thread:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((ios.device.listen, port))
    listener.listen(8)

    def loop() -> None:
        while True:
            client, _ = listener.accept()
            threading.Thread(target=_serve_client, args=(client, ios, host_key),
                             daemon=True).start()

    thread = threading.Thread(target=loop, daemon=True, name=f"ssh-{ios.device.slug}")
    thread.start()
    return thread


SSH_DEVICES = [EDGE_ROUTER, CORE_SWITCH, NEW_SWITCH]


def start(break_after_push: bool = False, seconds_per_minute: float = 1.0,
          known_hosts: Path = DEFAULT_KNOWN_HOSTS, port: int = SSH_PORT) -> list[FakeIOS]:
    keys = paramiko.HostKeys()
    devices = []
    for device in SSH_DEVICES:
        host_key = paramiko.ECDSAKey.generate()
        ios = FakeIOS(device, break_after_push=break_after_push,
                      seconds_per_minute=seconds_per_minute)
        serve(ios, host_key, port)
        keys.add(f"[{device.listen}]:{port}", host_key.get_name(), host_key)
        devices.append(ios)
    keys.save(str(known_hosts))
    return devices


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--break-after-push", action="store_true")
    parser.add_argument("--seconds-per-minute", type=float, default=12.0,
                        help="how long one revert-timer minute lasts (default 12 s, so the "
                             "agent's 5-minute timer is one real minute)")
    parser.add_argument("--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    devices = start(args.break_after_push, args.seconds_per_minute, args.known_hosts)
    for ios in devices:
        print(f"  SSH {ios.device.sys_name:<12} {ios.device.listen}:{SSH_PORT}")
    print(f"Host keys written to {args.known_hosts}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
