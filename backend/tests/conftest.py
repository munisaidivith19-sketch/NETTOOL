"""Shared test fixtures. Tests use the separate `netmap_test` database, never `netmap`."""

import hashlib
import hmac
import json
import os
import secrets
import time
from collections.abc import Iterator

import bcrypt
import pytest
from bson import ObjectId
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.config import Settings
from app.main import create_app
from app.security.sessions import utcnow

TEST_URI = os.environ.get("NETMAP_TEST_MONGODB_URI", "mongodb://127.0.0.1:27017")
TEST_DB = "netmap_test"

# A fixed Fernet key used only by the test suite.
TEST_VAULT_KEY = "dGVzdC1vbmx5LWtleS1kby1ub3QtdXNlLWFueXdoZXI="
# Passes the password policy; used for every test account.
PASSWORD = "Granite-Lantern-58-Orbit"
# https:// so the client sends the Secure session cookie back, exactly like a browser would.
BASE_URL = "https://testserver"


def make_settings(**overrides) -> Settings:
    values = {
        "env": "test",
        "mongodb_uri": TEST_URI,
        "mongodb_db": TEST_DB,
        "agent_key_encryption_key": TEST_VAULT_KEY,
        # Low cost only so the suite runs fast; Settings refuses this outside ENV=test.
        "bcrypt_rounds": 4,
    }
    values.update(overrides)
    if values["env"] != "test" and "bcrypt_rounds" not in overrides:
        values["bcrypt_rounds"] = 12
    # _env_file=None: a developer's local .env must never leak into tests.
    return Settings(_env_file=None, **values)


@pytest.fixture
def sync_db() -> Iterator:
    """A plain synchronous client for inspecting the test database. Drops it before each test."""
    client = MongoClient(TEST_URI, serverSelectionTimeoutMS=3000, tz_aware=True)
    client.drop_database(TEST_DB)
    try:
        yield client[TEST_DB]
    finally:
        client.close()


@pytest.fixture
def client(sync_db) -> Iterator[TestClient]:
    # `with` runs the app's lifespan: connect to MongoDB and create indexes.
    with TestClient(create_app(make_settings()), base_url=BASE_URL) as c:
        yield c


def add_user(sync_db, username: str, role: str = "viewer", *, password: str = PASSWORD,
             must_change: bool = False, disabled: bool = False) -> ObjectId:
    result = sync_db.users.insert_one({
        "username": username,
        "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt(4)).decode(),
        "role": role,
        "disabled": disabled,
        "must_change_password": must_change,
        "failed_logins": 0,
        "locked_until": None,
        "created_at": utcnow(),
        "created_by": "tests",
        "last_login_at": None,
    })
    return result.inserted_id


def login(client: TestClient, username: str, password: str = PASSWORD) -> str:
    """Log in (replacing any current session cookie) and return the CSRF token."""
    client.cookies.clear()
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def csrf(token: str) -> dict:
    return {"X-CSRF-Token": token}


@pytest.fixture
def admin(client, sync_db) -> str:
    """Logged-in admin; returns the CSRF token."""
    add_user(sync_db, "admin1", "admin")
    return login(client, "admin1")


def signed_headers(agent_id: str, key: str, method: str, path: str, body: bytes = b"", *,
                   timestamp: int | None = None, nonce: str | None = None) -> dict:
    """Builds agent signing headers. Written separately from app/security/agent_auth.py on
    purpose, so the tests check the server against the documented scheme, not against itself."""
    ts = str(int(time.time()) if timestamp is None else timestamp)
    nonce = nonce or secrets.token_urlsafe(18)
    message = "\n".join([method, path, ts, nonce, hashlib.sha256(body).hexdigest()]).encode()
    return {
        "X-Agent-Id": agent_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Signature": hmac.new(key.encode(), message, hashlib.sha256).hexdigest(),
        "Content-Type": "application/json",
    }


def json_bytes(data: dict) -> bytes:
    return json.dumps(data).encode()
