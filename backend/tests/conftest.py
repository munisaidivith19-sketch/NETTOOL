"""Shared test fixtures. Tests use the separate `netmap_test` database, never `netmap`."""

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.config import Settings
from app.main import create_app

TEST_URI = os.environ.get("NETMAP_TEST_MONGODB_URI", "mongodb://127.0.0.1:27017")
TEST_DB = "netmap_test"


def make_settings(**overrides) -> Settings:
    values = {"env": "test", "mongodb_uri": TEST_URI, "mongodb_db": TEST_DB}
    values.update(overrides)
    # _env_file=None: a developer's local .env must never leak into tests.
    return Settings(_env_file=None, **values)


@pytest.fixture
def sync_db() -> Iterator:
    """A plain synchronous client for inspecting the test database. Drops it before each test."""
    client = MongoClient(TEST_URI, serverSelectionTimeoutMS=3000)
    client.drop_database(TEST_DB)
    try:
        yield client[TEST_DB]
    finally:
        client.close()


@pytest.fixture
def client(sync_db) -> Iterator[TestClient]:
    # `with` runs the app's lifespan: connect to MongoDB and create indexes.
    with TestClient(create_app(make_settings())) as c:
        yield c
