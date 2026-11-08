"""MAC address → manufacturer (OUI lookup).

The first three bytes of a MAC address (the OUI) are assigned by the IEEE to a manufacturer.
A small built-in table covers common network, printer, camera, phone, PC and VM vendors, so
classification works offline. For the full list, download the IEEE's free MA-L file once:

    python -m netmap_agent.ai_training.oui update      (saves oui.csv next to the agent)

The file is public data (no secrets); it is read only, never executed.
"""

from __future__ import annotations

import csv
import io
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

IEEE_URL = "https://standards-oui.ieee.org/oui/oui.csv"
DEFAULT_PATH = Path("oui.csv")
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024

# Prefix → manufacturer, as the IEEE registry names them (shortened).
BUILTIN: dict[str, str] = {
    # network equipment
    "00000c": "Cisco Systems", "000585": "Juniper Networks",
    "4c5e0c": "Routerboard.com (MikroTik)", "6c3b6b": "Routerboard.com (MikroTik)",
    "e48d8c": "Routerboard.com (MikroTik)",
    # wireless access points
    "000b86": "Aruba Networks", "24dec6": "Aruba Networks",
    "24a43c": "Ubiquiti", "44d9e7": "Ubiquiti", "788a20": "Ubiquiti", "fcecda": "Ubiquiti",
    # PCs and laptops
    "001422": "Dell", "180373": "Dell", "b8ca3a": "Dell", "001b21": "Intel Corporate",
    "f01898": "Apple", "001b63": "Apple", "3c0754": "Apple", "a483e7": "Apple",
    # HP makes both PCs and printers
    "3cd92b": "Hewlett Packard", "a0d3c1": "Hewlett Packard",
    # printers
    "008077": "Brother Industries", "001ba9": "Brother Industries", "000085": "Canon",
    "001e8f": "Canon", "0026ab": "Seiko Epson", "0000aa": "Xerox", "002000": "Lexmark",
    # cameras
    "4419b6": "Hikvision", "4cbd8f": "Hikvision", "c056e3": "Hikvision",
    "3cef8c": "Dahua Technology", "00408c": "Axis Communications",
    "accc8e": "Axis Communications",
    # VoIP phones
    "0004f2": "Polycom", "001565": "Yealink",
    # virtual machines and small computers
    "005056": "VMware", "000c29": "VMware", "000569": "VMware",
    "080027": "PCS Systemtechnik (VirtualBox)", "00155d": "Microsoft (Hyper-V)",
    "525400": "QEMU/KVM virtual NIC", "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi",
}


def prefix(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").replace(".", "").lower()[:6]


def is_private(mac: str) -> bool:
    """Locally administered MAC (bit 2 of the first byte): phones and laptops randomise these."""
    try:
        return bool(int(prefix(mac)[:2], 16) & 0x02)
    except ValueError:
        return False


class OuiTable:
    def __init__(self, extra: dict[str, str] | None = None) -> None:
        self._table = dict(BUILTIN)
        if extra:
            self._table.update(extra)

    @classmethod
    def load(cls, path: Path = DEFAULT_PATH) -> OuiTable:
        if not path.exists():
            return cls()
        try:
            return cls(parse_ieee_csv(path.read_text(encoding="utf-8", errors="replace")))
        except (OSError, csv.Error) as exc:
            logger.warning("Could not read %s (%s); using the built-in OUI list", path,
                           type(exc).__name__)
            return cls()

    def vendor(self, mac: str) -> str | None:
        return self._table.get(prefix(mac))

    def __len__(self) -> int:
        return len(self._table)


def parse_ieee_csv(text: str) -> dict[str, str]:
    """IEEE MA-L CSV: Registry,Assignment,Organization Name,Organization Address."""
    table = {}
    for row in csv.DictReader(io.StringIO(text)):
        assignment = (row.get("Assignment") or "").strip().lower()
        name = (row.get("Organization Name") or "").strip()
        if len(assignment) == 6 and all(c in "0123456789abcdef" for c in assignment) and name:
            table[assignment] = name[:80]
    return table


def update(path: Path = DEFAULT_PATH) -> int:
    import httpx

    with httpx.stream("GET", IEEE_URL, timeout=60, follow_redirects=True) as response:
        # Every hop must be HTTPS: a redirect through plain http would let anyone on the path
        # swap the file (it decides how endpoints are labelled).
        hops = [r.url for r in response.history] + [response.url]
        if any(url.scheme != "https" for url in hops):
            raise ValueError("OUI download was redirected to a non-HTTPS address; not saved")
        response.raise_for_status()
        chunks, size = [], 0
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > MAX_DOWNLOAD_BYTES:
                raise ValueError("OUI file is larger than expected; not saved")
            chunks.append(chunk)
    text = b"".join(chunks).decode("utf-8", errors="replace")
    table = parse_ieee_csv(text)
    if len(table) < 1000:
        raise ValueError("Downloaded file doesn't look like the IEEE OUI list; not saved")
    path.write_text(text, encoding="utf-8")
    return len(table)


if __name__ == "__main__":
    if sys.argv[1:] == ["update"]:
        print(f"Saved {update()} manufacturer prefixes to {DEFAULT_PATH.resolve()}")
    else:
        print("usage: python -m netmap_agent.ai_training.oui update")
