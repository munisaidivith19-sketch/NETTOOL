"""MongoDB connection and index setup.

The same code works for local MongoDB and MongoDB Atlas; only MONGODB_URI changes.
"""

from pymongo import ASCENDING, DESCENDING, AsyncMongoClient, IndexModel
from pymongo.asynchronous.database import AsyncDatabase

from app.config import Settings
from app.security.agent_auth import NONCE_TTL_SECONDS
from app.security.rate_limit import IP_WINDOW

METRICS_TTL_SECONDS = 7 * 24 * 60 * 60
LOGIN_ATTEMPTS_TTL_SECONDS = int(IP_WINDOW.total_seconds()) * 3

# CLAUDE.md section 6. Unique indexes are what actually stop duplicates (e.g. two records for the
# same IP); TTL indexes make MongoDB delete old metrics and expired sessions on its own.
INDEXES: dict[str, list[IndexModel]] = {
    "devices": [
        IndexModel([("mgmt_ip", ASCENDING)], unique=True, name="mgmt_ip_unique"),
        IndexModel([("status", ASCENDING)], name="status"),
        IndexModel([("agent_id", ASCENDING), ("mgmt_ip_key", ASCENDING)], name="agent_ip"),
    ],
    "interfaces": [
        IndexModel([("device_id", ASCENDING), ("if_index", ASCENDING)], unique=True,
                   name="device_ifindex_unique"),
    ],
    "ip_addresses": [
        IndexModel([("ip_key", ASCENDING)], unique=True, name="ip_key_unique"),
        IndexModel([("mac", ASCENDING)], name="mac"),
        IndexModel([("reservation.hostname", ASCENDING)], sparse=True, name="reservation_host"),
    ],
    "subnets": [
        IndexModel([("network", ASCENDING)], unique=True, name="network_unique"),
        # Overlap and "which subnet contains this IP" lookups (services/ipam.py).
        IndexModel([("version", ASCENDING), ("start_key", ASCENDING), ("end_key", ASCENDING)],
                   name="version_range"),
    ],
    "arp_entries": [
        # One row per (IP, MAC, reporting device); two MACs on one IP = a duplicate IP (Phase 3).
        IndexModel([("ip_key", ASCENDING), ("mac", ASCENDING), ("device_id", ASCENDING)],
                   unique=True, name="ip_mac_device_unique"),
        IndexModel([("mac", ASCENDING)], name="mac"),
        IndexModel([("last_seen", DESCENDING)], name="last_seen_desc"),
    ],
    "alerts": [
        IndexModel([("key", ASCENDING)], unique=True, name="key_unique"),
        IndexModel([("status", ASCENDING), ("type", ASCENDING), ("last_seen", DESCENDING)],
                   name="status_type_seen"),
    ],
    "users": [IndexModel([("username", ASCENDING)], unique=True, name="username_unique")],
    "metrics": [
        IndexModel([("ts", ASCENDING)], expireAfterSeconds=METRICS_TTL_SECONDS, name="ts_ttl"),
    ],
    "sessions": [
        # expireAfterSeconds=0: each document is deleted once its own expires_at time has passed.
        IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0, name="expires_at_ttl"),
        IndexModel([("token_hash", ASCENDING)], unique=True, name="token_hash_unique"),
        IndexModel([("user_id", ASCENDING)], name="user_id"),
    ],
    "login_attempts": [
        IndexModel([("ip", ASCENDING), ("at", DESCENDING)], name="ip_at"),
        IndexModel([("at", ASCENDING)], expireAfterSeconds=LOGIN_ATTEMPTS_TTL_SECONDS,
                   name="at_ttl"),
    ],
    "agent_nonces": [
        # The unique pair is the replay protection: a second insert of the same nonce fails.
        IndexModel([("agent_id", ASCENDING), ("nonce", ASCENDING)], unique=True,
                   name="agent_nonce_unique"),
        IndexModel([("created_at", ASCENDING)], expireAfterSeconds=NONCE_TTL_SECONDS,
                   name="created_at_ttl"),
    ],
    "audit_log": [
        IndexModel([("at", DESCENDING)], name="at_desc"),
        IndexModel([("action", ASCENDING), ("at", DESCENDING)], name="action_at"),
        IndexModel([("actor.username", ASCENDING), ("at", DESCENDING)], name="actor_at"),
    ],
}


def create_client(settings: Settings) -> AsyncMongoClient:
    return AsyncMongoClient(
        settings.mongodb_uri.get_secret_value(),
        tz_aware=True,  # datetimes come back timezone-aware (UTC), never naive
        serverSelectionTimeoutMS=settings.mongodb_timeout_ms,  # fail fast, don't hang requests
        appname="netmap-backend",
    )


async def ensure_indexes(db: AsyncDatabase) -> None:
    for collection, indexes in INDEXES.items():
        await db[collection].create_indexes(indexes)


async def ping(client: AsyncMongoClient) -> bool:
    try:
        await client.admin.command("ping")
    except Exception:
        return False
    return True
