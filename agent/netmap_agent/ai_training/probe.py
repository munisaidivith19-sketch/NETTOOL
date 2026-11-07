"""Optional open-port check for device classification (CLASSIFY_PORT_PROBE=true only).

This is active scanning, which some networks forbid, so it is off by default. When on it does
a plain TCP connect to 8 fixed ports, only for IPv4 addresses inside SCAN_RANGES, with a
short timeout and at most 32 connections at once. Nothing is sent after the connection opens.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from netmap_agent.ai_training.classify import PROBE_PORTS

MAX_HOSTS = 256
MAX_PARALLEL = 32


def in_ranges(ip: str, ranges: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(r, strict=False) for r in ranges)


def _open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe(ips: list[str], ranges: list[str], timeout_ms: int = 500) -> dict[str, list[int]]:
    """{ip: [open ports]} for the in-range IPv4 addresses (first MAX_HOSTS of them)."""
    targets = []
    for ip in ips:
        try:
            if ipaddress.ip_address(ip).version == 4 and in_ranges(ip, ranges):
                targets.append(ip)
        except ValueError:
            continue
    targets = sorted(set(targets))[:MAX_HOSTS]
    jobs = [(ip, port) for ip in targets for port in PROBE_PORTS]
    timeout = timeout_ms / 1000
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
        results = list(pool.map(lambda job: _open(job[0], job[1], timeout), jobs))
    found: dict[str, list[int]] = {ip: [] for ip in targets}
    for (ip, port), is_open in zip(jobs, results, strict=True):
        if is_open:
            found[ip].append(port)
    return found
