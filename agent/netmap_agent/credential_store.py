"""Encrypted local credential store for SSH logins (CLAUDE.md 7.6).

Device passwords live only here, on the agent machine, inside one Fernet-encrypted file
(`credentials.enc`, git-ignored). They are never sent to the backend, written to logs or
given to an LLM: the backend only ever sees *which* devices can be backed up.

Where the encryption key comes from:
1. `CREDENTIAL_STORE_KEY` (a Fernet key) if set - e.g. from a secrets manager, or on Linux.
2. Otherwise, on Windows, a random key in `credentials.key` that is itself encrypted with
   Windows DPAPI for the current user. Copying the two files to another PC or user account
   is not enough to read the passwords.

Command line (run inside the agent folder, passwords are typed, never passed as arguments
because those end up in shell history and process lists):
    python -m netmap_agent.credential_store init
    python -m netmap_agent.credential_store add --name core --match 10.10.0.0/24 \
        --device-type cisco_ios --username netmap
    python -m netmap_agent.credential_store list
    python -m netmap_agent.credential_store remove --name core
    python -m netmap_agent.credential_store test 10.10.0.2
"""

from __future__ import annotations

import argparse
import ctypes
import getpass
import ipaddress
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

DEVICE_TYPES = ("cisco_ios", "mikrotik_routeros")
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_USERNAME = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_HOST = re.compile(r"^[A-Za-z0-9.:-]{1,253}$")


class CredentialError(Exception):
    pass


@dataclass
class Profile:
    """One set of login details, used for every device whose management IP is in `match`."""

    name: str
    match: str  # an IP address or a CIDR range
    device_type: str
    username: str
    password: str = field(repr=False)
    secret: str = field(default="", repr=False)  # Cisco enable secret
    ssh_host: str = ""  # connect here instead of the device IP (used by the simulation)
    ssh_port: int = 22

    def __post_init__(self) -> None:
        if not _NAME.match(self.name):
            raise CredentialError("name: letters, digits, . _ - only (max 64)")
        try:
            ipaddress.ip_network(self.match, strict=False)
        except ValueError as exc:
            raise CredentialError("match must be an IP address or CIDR range") from exc
        if self.device_type not in DEVICE_TYPES:
            raise CredentialError(f"device_type must be one of {', '.join(DEVICE_TYPES)}")
        if not _USERNAME.match(self.username):
            raise CredentialError("username: letters, digits, . _ @ - only (max 64)")
        if not self.password or len(self.password) > 256 or len(self.secret) > 256:
            raise CredentialError("password is required (max 256 characters)")
        if self.ssh_host and not _HOST.match(self.ssh_host):
            raise CredentialError("ssh_host must be a host name or IP address")
        if not 1 <= int(self.ssh_port) <= 65535:
            raise CredentialError("ssh_port must be 1-65535")

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(self.match, strict=False)

    def public(self) -> dict:
        """Everything except the secrets: safe to print and to log."""
        return {"name": self.name, "match": self.match, "device_type": self.device_type,
                "username": self.username, "ssh_host": self.ssh_host, "ssh_port": self.ssh_port,
                "has_enable_secret": bool(self.secret)}


# ---------------------------------------------------------------- Windows DPAPI

class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    """Encrypt / decrypt with CryptProtectData for the current Windows user (no extra library)."""
    if sys.platform != "win32":  # pragma: no cover - only reached without CREDENTIAL_STORE_KEY
        raise CredentialError("Set CREDENTIAL_STORE_KEY (DPAPI is only available on Windows)")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buffer = ctypes.create_string_buffer(data, len(data))
    source = _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    result = _Blob()
    function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    # Flag 0x1 = CRYPTPROTECT_UI_FORBIDDEN: never pop up a dialog on a headless agent.
    ok = function(ctypes.byref(source), None, None, None, None, 0x1, ctypes.byref(result))
    if not ok:
        raise CredentialError("Windows DPAPI could not " + ("protect" if protect else
                              "unprotect") + " the key (different user or PC?)")
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        kernel32.LocalFree(result.pbData)


# ---------------------------------------------------------------- the store

class CredentialStore:
    def __init__(self, path: str | Path, env_key: str = "") -> None:
        self.path = Path(path)
        self.key_path = self.path.with_suffix(".key")
        self._env_key = env_key

    def _key(self, create: bool = False) -> bytes:
        if self._env_key:
            return self._env_key.encode()
        if self.key_path.exists():
            return _dpapi(self.key_path.read_bytes(), protect=False)
        if not create:
            raise CredentialError("No credential key: run `init` or set CREDENTIAL_STORE_KEY")
        key = Fernet.generate_key()
        self.key_path.write_bytes(_dpapi(key, protect=True))
        return key

    def _fernet(self, create: bool = False) -> Fernet:
        try:
            return Fernet(self._key(create))
        except ValueError as exc:
            raise CredentialError("CREDENTIAL_STORE_KEY is not a valid Fernet key") from exc

    def exists(self) -> bool:
        return self.path.exists()

    def init(self) -> None:
        if self.path.exists():
            raise CredentialError(f"{self.path} already exists")
        self.save([], create=True)

    def load(self) -> list[Profile]:
        if not self.path.exists():
            return []
        try:
            raw = self._fernet().decrypt(self.path.read_bytes())
        except InvalidToken as exc:
            raise CredentialError("Credential file can't be decrypted with this key") from exc
        data = json.loads(raw)
        return [Profile(**item) for item in data.get("profiles", [])]

    def save(self, profiles: list[Profile], create: bool = False) -> None:
        payload = json.dumps({"version": 1, "profiles": [asdict(p) for p in profiles]}).encode()
        token = self._fernet(create).encrypt(payload)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(token)
        os.replace(tmp, self.path)  # atomic: a crash never leaves a half-written file

    def add(self, profile: Profile) -> None:
        profiles = [p for p in self.load() if p.name != profile.name]
        profiles.append(profile)
        self.save(profiles, create=True)

    def remove(self, name: str) -> bool:
        profiles = self.load()
        kept = [p for p in profiles if p.name != name]
        self.save(kept)
        return len(kept) != len(profiles)

    def for_ip(self, ip: str, profiles: list[Profile] | None = None) -> Profile | None:
        """The most specific profile whose range contains this IP (a /32 beats a /24)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        matches = [p for p in (self.load() if profiles is None else profiles)
                   if addr.version == p.network.version and addr in p.network]
        return max(matches, key=lambda p: p.network.prefixlen, default=None)


# ---------------------------------------------------------------- command line

def _read_secret(prompt: str, from_stdin: bool, required: bool = True) -> str:
    value = sys.stdin.readline().rstrip("\r\n") if from_stdin else getpass.getpass(prompt)
    if required and not value:
        raise CredentialError("A password is required")
    return value


def _store_from_env() -> CredentialStore:
    from netmap_agent.config import get_settings

    settings = get_settings()
    return CredentialStore(settings.credential_store_path,
                           settings.credential_store_key.get_secret_value())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m netmap_agent.credential_store",
                                     description="Manage the agent's encrypted SSH credentials.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create an empty store (and a DPAPI-protected key on Windows)")
    add = sub.add_parser("add", help="add or replace a credential profile")
    add.add_argument("--name", required=True)
    add.add_argument("--match", required=True, help="device IP or CIDR range, e.g. 10.10.0.0/24")
    add.add_argument("--device-type", required=True, choices=DEVICE_TYPES)
    add.add_argument("--username", required=True)
    add.add_argument("--ssh-host", default="")
    add.add_argument("--ssh-port", type=int, default=22)
    add.add_argument("--no-enable-secret", action="store_true")
    add.add_argument("--password-stdin", action="store_true",
                     help="read the password (and enable secret) from stdin lines")
    sub.add_parser("list", help="show profiles (never shows passwords)")
    remove = sub.add_parser("remove", help="delete a profile")
    remove.add_argument("--name", required=True)
    test = sub.add_parser("test", help="log in to a device with its matching profile")
    test.add_argument("ip")
    args = parser.parse_args(argv)

    store = _store_from_env()
    try:
        if args.command == "init":
            store.init()
            print(f"Created {store.path}")
        elif args.command == "add":
            password = _read_secret("SSH password: ", args.password_stdin)
            secret = "" if args.no_enable_secret or args.device_type != "cisco_ios" else \
                _read_secret("Enable secret (empty = same as the password): ",
                             args.password_stdin, required=False) or password
            store.add(Profile(name=args.name, match=args.match, device_type=args.device_type,
                              username=args.username, password=password, secret=secret,
                              ssh_host=args.ssh_host, ssh_port=args.ssh_port))
            print(f"Saved profile {args.name!r}")
        elif args.command == "list":
            for profile in store.load():
                print(json.dumps(profile.public()))
        elif args.command == "remove":
            print("Removed" if store.remove(args.name) else "No such profile")
        elif args.command == "test":
            from netmap_agent.config_mgmt.connection import open_session

            profile = store.for_ip(args.ip)
            if profile is None:
                raise CredentialError("No profile matches that IP")
            with open_session(args.ip, profile) as session:
                print(f"Logged in to {args.ip} as {profile.username}: prompt {session.prompt()!r}")
    except CredentialError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
