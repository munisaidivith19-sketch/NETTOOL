"""Interface traffic rates from SNMP octet counters.

A switch doesn't report "Mbit/s". It reports a counter of bytes since boot (ifHCInOctets).
The rate is the difference between two readings divided by the time between them:

    bits per second = (octets_now - octets_before) * 8 / seconds_between_readings

Edge cases, each of which would otherwise show an absurd number:
- 32-bit counters (old devices) wrap back to 0 after 4 GB, which on a busy 1 Gbit/s port is
  every ~34 seconds. One wrap between readings can be corrected; several can't be detected.
- A reboot or "clear counters" resets them to 0. That interval gets no rate.
- A rate faster than the port's speed means one of the above was missed, so it is dropped.
"""

from datetime import datetime, timezone

WRAP_32 = 2**32
# Longer gaps make wraps undetectable and the average meaningless.
MAX_INTERVAL_SECONDS = 6 * 60 * 60
# Allow some slack over the nominal port speed (counter timing jitter).
SPEED_SLACK = 1.1


def counter_delta(old: int | None, new: int | None, bits: int) -> int | None:
    """How much a counter grew, or None if that can't be known."""
    if old is None or new is None:
        return None
    if new >= old:
        return new - old
    if bits == 32 and old - new > WRAP_32 // 2:
        return new + WRAP_32 - old  # it passed 2^32 once and started again from 0
    return None  # counter went backwards: reset (reboot, cleared), no honest value


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def compute_rates(previous: dict | None, current: dict, speed_mbps: int | None) -> dict | None:
    """Rates between two samples, each {"at", "bits", "uptime", "in_octets", ...}.

    Returns {"in_bps", "out_bps", "in_errors", "out_errors", "interval_s"} or None.
    """
    if not previous or previous.get("bits") != current["bits"]:
        return None
    if (previous.get("uptime") is not None and current.get("uptime") is not None
            and current["uptime"] < previous["uptime"]):
        return None  # the device rebooted between the two readings
    seconds = (as_utc(current["at"]) - as_utc(previous["at"])).total_seconds()
    if not 0 < seconds <= MAX_INTERVAL_SECONDS:
        return None
    bits = current["bits"]
    d_in = counter_delta(previous.get("in_octets"), current.get("in_octets"), bits)
    d_out = counter_delta(previous.get("out_octets"), current.get("out_octets"), bits)
    if d_in is None and d_out is None:
        return None
    in_bps = d_in * 8 / seconds if d_in is not None else None
    out_bps = d_out * 8 / seconds if d_out is not None else None
    if speed_mbps:
        limit = speed_mbps * 1_000_000 * SPEED_SLACK
        if any(v is not None and v > limit for v in (in_bps, out_bps)):
            return None
    return {
        "in_bps": round(in_bps) if in_bps is not None else None,
        "out_bps": round(out_bps) if out_bps is not None else None,
        "in_errors": counter_delta(previous.get("in_errors"), current.get("in_errors"), 32),
        "out_errors": counter_delta(previous.get("out_errors"), current.get("out_errors"), 32),
        "interval_s": round(seconds, 1),
    }
