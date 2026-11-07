"""MongoDB connection and index setup.

The same code works for local MongoDB and MongoDB Atlas; only MONGODB_URI changes.
"""

from pymongo import ASCENDING, AsyncMongoClient, IndexModel
from pymongo.asynchronous.database import AsyncDatabase

from app.config import Settings

METRICS_TTL_SECONDS = 7 * 24 * 60 * 60

# CLAUDE.md section 6. Unique indexes are what actually stop duplicates (e.g. two records for the
# same IP); TTL indexes make MongoDB delete old metrics and expired sessions on its own.
INDEXES: dict[str, list[IndexModel]] = {
    "devices": [IndexModel([("mgmt_ip", ASCENDING)], unique=True, name="mgmt_ip_unique")],
    "ip_addresses": [IndexModel([("ip_key", ASCENDING)], unique=True, name="ip_key_unique")],
    "subnets": [IndexModel([("network", ASCENDING)], unique=True, name="network_unique")],
    "alerts": [IndexModel([("key", ASCENDING)], unique=True, name="key_unique")],
    "users": [IndexModel([("username", ASCENDING)], unique=True, name="username_unique")],
    "metrics": [
        IndexModel([("ts", ASCENDING)], expireAfterSeconds=METRICS_TTL_SECONDS, name="ts_ttl"),
    ],
    "sessions": [
        # expireAfterSeconds=0: each document is deleted once its own expires_at time has passed.
        IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0, name="expires_at_ttl"),
        IndexModel([("token_hash", ASCENDING)], unique=True, name="token_hash_unique"),
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
