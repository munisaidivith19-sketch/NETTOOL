from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import BASE_URL, add_user, make_settings

ADMIN_PASSWORD = "Silver-Compass-46-Thunder"


def _start(**settings):
    with TestClient(create_app(make_settings(**settings)), base_url=BASE_URL) as c:
        c.get("/health")


def test_first_admin_created_when_no_users(sync_db):
    _start(admin_username="root.admin", admin_password=ADMIN_PASSWORD)
    user = sync_db.users.find_one({"username": "root.admin"})
    assert user["role"] == "admin"
    assert user["must_change_password"] is True
    assert ADMIN_PASSWORD not in str(user)


def test_env_admin_ignored_when_users_exist(sync_db):
    add_user(sync_db, "existing", "viewer")
    _start(admin_username="root.admin", admin_password=ADMIN_PASSWORD)
    assert sync_db.users.find_one({"username": "root.admin"}) is None


def test_weak_env_password_refused(sync_db):
    _start(admin_username="root.admin", admin_password="admin123")
    assert sync_db.users.count_documents({}) == 0


def test_restart_does_not_duplicate_admin(sync_db):
    for _ in range(2):
        _start(admin_username="root.admin", admin_password=ADMIN_PASSWORD)
    assert sync_db.users.count_documents({}) == 1


def test_app_refuses_to_start_without_agent_encryption_key(sync_db):
    import pytest

    with pytest.raises(RuntimeError, match="AGENT_KEY_ENCRYPTION_KEY"):
        _start(agent_key_encryption_key=None)
