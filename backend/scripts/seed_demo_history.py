"""DEV ONLY: write synthetic history so the Phase 7 forecasts have something to learn from.

The simulator has no past, and a forecast needs weeks of subnet usage and days of traffic.
This script writes, into the database named by MONGODB_URI / MONGODB_DB:
- 60 days of daily usage for every IPv4/small subnet (the fullest one grows towards full),
- 7 days of 5-minute traffic samples for every uplink (links collection), with a day/night
  cycle; the second uplink trends upwards, and the first gets a traffic spike in the last
  30 minutes (for the anomaly detector).
Run an agent report first (so subnets and links exist), then from the backend folder:
    python scripts/seed_demo_history.py
and then the agent's AI step:  python -m netmap_agent.main --ai-only
It refuses to run when ENV=production, and it replaces existing metrics of those uplinks.
"""

import argparse
import hashlib
import ipaddress
import math
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pymongo import MongoClient, UpdateOne

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import get_settings  # noqa: E402
from app.services import ipam  # noqa: E402
from app.services.alerts import MAX_USABLE_FOR_HISTORY, MIN_USABLE_FOR_USAGE_ALERT  # noqa: E402

DAYS = 60
TRAFFIC_DAYS = 7
STEP = timedelta(minutes=5)


def rng_for(text: str) -> random.Random:
    # Same input → same history, so repeated runs give the same demo.
    return random.Random(int(hashlib.sha256(text.encode()).hexdigest()[:8], 16))  # noqa: S311


def seed_usage(db, now: datetime) -> int:
    subnets = []
    for subnet in db.subnets.find({}, {"network": 1}):
        usable = ipam.usable_count(ipaddress.ip_network(subnet["network"]))
        if MIN_USABLE_FOR_USAGE_ALERT <= usable <= MAX_USABLE_FOR_HISTORY:
            latest = db.subnet_usage.find_one({"subnet_id": subnet["_id"]}, sort=[("day", -1)])
            current = (latest or {}).get("used") or max(2, usable // 10)
            subnets.append((subnet, usable, current))
    if not subnets:
        return 0
    fullest = max(subnets, key=lambda s: s[2] / s[1])[0]["_id"]
    ops = []
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    for subnet, usable, current in subnets:
        rng = rng_for(subnet["network"])
        if subnet["_id"] == fullest:
            # Make it fill up about 40 days from now, so the dashboard has a warning to show.
            current = max(current, int(usable * 0.6))
            slope = (usable - current) / 40
        else:
            slope = rng.uniform(0.0, 0.25) * usable / DAYS
        # Up to and including today; later reports only raise today's value ($max).
        for days_ago in range(DAYS, -1, -1):
            day = today - timedelta(days=days_ago)
            weekday_bump = 0.04 * usable if day.weekday() < 5 else 0
            used = current - slope * days_ago + weekday_bump * rng.uniform(0.5, 1.0)
            used = int(min(max(used, 1), usable))
            ops.append(UpdateOne(
                {"subnet_id": subnet["_id"], "day": day.date().isoformat()},
                {"$set": {"used": used, "usable": usable, "network": subnet["network"],
                          "at": day}}, upsert=True))
    db.subnet_usage.bulk_write(ops, ordered=False)
    return len(subnets)


def seed_traffic(db, now: datetime) -> int:
    uplinks = sorted({(link["device_id"], link["if_index"]) for link in db.links.find(
        {"if_index": {"$ne": None}}, {"device_id": 1, "if_index": 1})}, key=str)
    start = now - timedelta(days=TRAFFIC_DAYS) + timedelta(hours=1)  # stay inside the TTL
    for n, (device_id, if_index) in enumerate(uplinks):
        iface = db.interfaces.find_one({"device_id": device_id, "if_index": if_index},
                                       {"speed_mbps": 1}) or {}
        capacity = (iface.get("speed_mbps") or 1000) * 1e6
        rng = rng_for(f"{device_id}:{if_index}")
        docs = []
        ts = start
        step = 0
        total = int((now - start) / STEP)
        while ts < now:
            cycle = 1 + 0.6 * math.sin(2 * math.pi * (ts.hour - 8) / 24)
            share = 0.12 if n != 1 else 0.35 + 0.35 * step / total  # uplink 2 keeps growing
            in_bps = capacity * share * cycle * rng.uniform(0.9, 1.1)
            errors = 0
            if n == 0 and now - ts <= timedelta(minutes=30):
                in_bps = capacity * 0.9  # the spike the anomaly detector should find
                errors = 400
            in_bps = min(in_bps, capacity)
            docs.append({"device_id": device_id, "if_index": if_index, "ts": ts,
                         "in_bps": round(in_bps), "out_bps": round(in_bps * 0.4),
                         "in_errors": errors, "out_errors": 0, "interval_s": 300.0})
            ts += STEP
            step += 1
        db.metrics.delete_many({"device_id": device_id, "if_index": if_index})
        db.metrics.insert_many(docs)
    return len(uplinks)


def main() -> None:
    argparse.ArgumentParser(description=__doc__.splitlines()[0]).parse_args()
    settings = get_settings()
    if settings.is_production:
        sys.exit("Refusing to write synthetic history: ENV=production.")
    client = MongoClient(settings.mongodb_uri.get_secret_value(), tz_aware=True)
    db = client[settings.mongodb_db]
    now = datetime.now(timezone.utc)
    subnets = seed_usage(db, now)
    uplinks = seed_traffic(db, now)
    print(f"Seeded {DAYS} days of usage for {subnets} subnet(s) and {TRAFFIC_DAYS} days of "
          f"traffic for {uplinks} uplink(s) in database '{settings.mongodb_db}'.")
    client.close()


if __name__ == "__main__":
    main()
