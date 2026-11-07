"""Start the simulated campus: one snmpsim responder per device, each on its own 127.0.0.x:1161.

Run from the agent folder (venv active):   python -m simulation.run_simulation
Stop with Ctrl+C. Only some devices:       python -m simulation.run_simulation core-switch ap-1

SNMPv3 user "netmap-sim" with SHA authentication and AES privacy. The keys below are
simulation-only lab values, printed so you can copy them into the agent's .env. Never reuse them
on real equipment.
"""

import shutil
import subprocess  # nosec B404 - fixed argument lists only
import sys
import tempfile
import time
from pathlib import Path

from simulation.build_snmprec import DATA_DIR, build
from simulation.topology import DEVICES, SIM_PORT

SIM_USER = "netmap-sim"
SIM_AUTH_KEY = "sim-auth-key-not-secret"  # noqa: S105 - simulation-only, documented
SIM_PRIV_KEY = "sim-priv-key-not-secret"  # noqa: S105 - simulation-only, documented
SIM_CONTEXT = "netmap-sim"


def responder_command(data_dir: Path, listen: str, port: int = SIM_PORT,
                      cache_dir: Path | None = None) -> list[str]:
    exe = shutil.which("snmpsim-command-responder", path=str(Path(sys.executable).parent))
    if exe is None:
        raise RuntimeError("snmpsim is not installed: pip install -r requirements-dev.txt")
    command = [
        exe,
        "--v3-engine-id", "auto",
        "--v3-user", SIM_USER,
        "--v3-auth-key", SIM_AUTH_KEY, "--v3-auth-proto", "SHA",
        "--v3-priv-key", SIM_PRIV_KEY, "--v3-priv-proto", "AES",
        "--data-dir", str(data_dir),
        "--agent-udpv4-endpoint", f"{listen}:{port}",
    ]
    if cache_dir is not None:
        command += ["--cache-dir", str(cache_dir)]
    return command


def start(slugs: list[str] | None = None) -> list[subprocess.Popen]:
    build()
    cache = Path(tempfile.mkdtemp(prefix="netmap-snmpsim-"))
    processes = []
    for device in DEVICES:
        if slugs and device.slug not in slugs:
            continue
        command = responder_command(DATA_DIR / device.slug, device.listen, cache_dir=cache)
        processes.append(subprocess.Popen(  # nosec B603  # noqa: S603 - fixed argument list
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        print(f"  {device.sys_name:<14} {device.listen}:{SIM_PORT}")
    return processes


def main() -> None:
    print("Starting simulated devices (SNMPv3 authPriv, user netmap-sim):")
    processes = start(sys.argv[1:] or None)
    targets = ",".join(f"{d.listen}:{SIM_PORT}" for d in DEVICES
                       if not sys.argv[1:] or d.slug in sys.argv[1:])
    print("\nAgent .env settings for the simulation:")
    print(f"  SNMP_TARGETS={targets}")
    print("  SCAN_RANGES=127.0.0.8/29")
    print(f"  SNMP_VERSION=v3\n  SNMP_V3_USER={SIM_USER}\n  SNMP_V3_AUTH_KEY={SIM_AUTH_KEY}")
    print(f"  SNMP_V3_PRIV_KEY={SIM_PRIV_KEY}\n  SNMP_V3_CONTEXT={SIM_CONTEXT}")
    print("\nPress Ctrl+C to stop.")
    try:
        while all(p.poll() is None for p in processes):
            time.sleep(1)
        print("A responder exited unexpectedly.")
    except KeyboardInterrupt:
        pass
    finally:
        for p in processes:
            p.terminate()


if __name__ == "__main__":
    main()
