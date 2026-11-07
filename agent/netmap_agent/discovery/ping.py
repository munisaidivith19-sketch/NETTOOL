"""ICMP ping sweep using the operating system's ping command (no raw sockets, no admin rights).

Command-injection safety (CLAUDE.md 7.4):
- every target is parsed with `ipaddress` first, so only a literal IP can reach the command
- subprocess gets an argument list and shell=False, so nothing is ever interpreted by a shell
- the ping binary is resolved to a full path once, so a planted "ping.exe" in the working
  directory can't be picked up
"""

import ipaddress
import logging
import shutil
import subprocess  # nosec B404 - used only with fixed argument lists, see build_command
import sys
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("netmap_agent.ping")

MAX_WORKERS = 32


def ping_binary() -> str:
    path = shutil.which("ping")
    if path is None:
        raise RuntimeError("The 'ping' command was not found on this system")
    return path


def build_command(
    binary: str, target: str, timeout_ms: int, platform: str | None = None
) -> list[str]:
    platform = platform or sys.platform
    address = ipaddress.ip_address(target)  # raises ValueError for anything that isn't an IP
    family = "-6" if address.version == 6 else "-4"
    if platform.startswith("win"):
        # -n count, -w timeout in milliseconds
        return [binary, family, "-n", "1", "-w", str(timeout_ms), str(address)]
    # Linux iputils: -c count, -W timeout in whole seconds
    seconds = max(1, round(timeout_ms / 1000))
    return [binary, family, "-c", "1", "-W", str(seconds), str(address)]


def is_reply(returncode: int, output: str, version: int, platform: str | None = None) -> bool:
    platform = platform or sys.platform
    if returncode != 0:
        return False
    if not platform.startswith("win"):
        return True  # Linux ping exits non-zero unless a real echo reply arrived
    # Windows exits 0 for "Destination host unreachable" sent by a router, so look at the text.
    text = output.lower()
    if "unreachable" in text or "timed out" in text:
        return False
    if version == 4:
        return "ttl=" in text
    return "time" in text


def ping_one(binary: str, target: str, timeout_ms: int) -> bool:
    command = build_command(binary, target, timeout_ms)
    try:
        # Argument list built from a validated IP; no shell is involved.
        result = subprocess.run(  # nosec B603  # noqa: S603
            command,
            capture_output=True,
            text=True,
            timeout=timeout_ms / 1000 + 2,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return is_reply(result.returncode, result.stdout, ipaddress.ip_address(target).version)


def sweep(targets: Iterable[str], timeout_ms: int = 1000) -> dict[str, bool]:
    """Ping every target concurrently. Returns {ip: answered}."""
    addresses = {ipaddress.ip_address(t) for t in targets}  # validates every target first
    unique = [str(a) for a in sorted(addresses, key=lambda a: (a.version, int(a)))]
    if not unique:
        return {}
    binary = ping_binary()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        answers = pool.map(lambda ip: ping_one(binary, ip, timeout_ms), unique)
        results = dict(zip(unique, answers, strict=True))
    logger.info("Ping sweep: %d of %d addresses answered", sum(results.values()), len(results))
    return results
