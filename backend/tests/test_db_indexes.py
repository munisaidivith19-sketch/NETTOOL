import pytest
from fastapi.testclient import TestClient
from pymongo.errors import DuplicateKeyError

from app.db import METRICS_TTL_SECONDS
from app.main import create_app
from tests.conftest import make_settings


@pytest.mark.parametrize(
    ("collection", "field"),
    [
        ("devices", "mgmt_ip"),
        ("ip_addresses", "ip_key"),
        ("subnets", "network"),
        ("alerts", "key"),
        ("users", "username"),
        ("sessions", "token_hash"),
    ],
)
def test_unique_indexes_exist(client, sync_db, collection, field):
    indexes = sync_db[collection].index_information()
    matching = [i for i in indexes.values() if i["key"] == [(field, 1)]]
    assert matching, f"no index on {collection}.{field}"
    assert matching[0].get("unique") is True


def test_ttl_indexes_exist(client, sync_db):
    metrics = sync_db["metrics"].index_information()["ts_ttl"]
    assert metrics["expireAfterSeconds"] == METRICS_TTL_SECONDS == 7 * 24 * 3600
    sessions = sync_db["sessions"].index_information()["expires_at_ttl"]
    assert sessions["expireAfterSeconds"] == 0


def test_unique_index_blocks_duplicate_ip(client, sync_db):
    key = "4:" + format(0xC0A8010A, "032x")  # 192.168.1.10 in the ip_key format
    sync_db["ip_addresses"].insert_one({"ip_key": key})
    with pytest.raises(DuplicateKeyError):
        sync_db["ip_addresses"].insert_one({"ip_key": key})


def test_startup_is_idempotent(sync_db):
    """Restarting the app must not fail because the indexes already exist."""
    for _ in range(2):
        with TestClient(create_app(make_settings())) as c:
            assert c.get("/health").status_code == 200
