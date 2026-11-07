import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import BASE_URL, add_user, make_settings


def test_security_headers_on_every_response(client):
    for path in ("/health", "/api/auth/me", "/does-not-exist"):
        headers = client.get(path).headers
        assert "default-src 'self'" in headers["content-security-policy"]
        assert "frame-ancestors 'none'" in headers["content-security-policy"]
        assert "unsafe-inline" not in headers["content-security-policy"]
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert headers["referrer-policy"] == "no-referrer"
        assert "camera=()" in headers["permissions-policy"]
        assert len(headers["x-request-id"]) == 32


def test_api_responses_not_cached(client):
    assert client.get("/api/auth/me").headers["cache-control"] == "no-store"


def test_hsts_only_in_production(client, sync_db):
    assert "strict-transport-security" not in client.get("/health").headers
    with TestClient(create_app(make_settings(env="production")), base_url=BASE_URL) as prod:
        assert "max-age=" in prod.get("/health").headers["strict-transport-security"]


def test_request_id_is_never_taken_from_client(client):
    response = client.get("/health", headers={"X-Request-ID": "attacker-chosen"})
    assert response.headers["x-request-id"] != "attacker-chosen"


def test_unhandled_error_hides_details(sync_db, caplog):
    app = create_app(make_settings())
    boom = APIRouter()

    @boom.get("/boom")
    async def explode() -> None:
        raise RuntimeError("secret internal detail: mongodb://user:pass@host")

    app.include_router(boom)
    with TestClient(app, base_url=BASE_URL) as c:
        response = c.get("/boom")
    assert response.status_code == 500
    body = response.json()
    assert body["detail"] == "Internal server error"
    assert body["request_id"] == response.headers["x-request-id"]
    assert "secret" not in response.text
    assert response.headers["x-frame-options"] == "DENY"
    # The details are kept for the server log, tagged with the same request id.
    assert body["request_id"] in caplog.text


def test_validation_error_does_not_echo_password(client, sync_db):
    add_user(sync_db, "alice")
    response = client.post("/api/auth/login",
                           json={"username": "alice", "password": "S3cret-" + "x" * 300})
    assert response.status_code == 422
    assert "S3cret" not in response.text


@pytest.mark.parametrize(
    "payload",
    [
        {"username": {"$ne": None}, "password": "x"},
        {"username": "alice", "password": {"$gt": ""}},
        {"username": {"$regex": ".*"}, "password": "Granite-Lantern-58-Orbit"},
        {"username": "alice", "password": "x", "$where": "1==1"},
    ],
)
def test_nosql_injection_payloads_rejected(client, sync_db, payload):
    add_user(sync_db, "alice")
    response = client.post("/api/auth/login", json=payload)
    assert response.status_code == 422
    assert "set-cookie" not in response.headers


def test_body_too_large_rejected(client):
    big = b'{"username":"' + b"a" * (2 * 1024 * 1024) + b'","password":"x"}'
    response = client.post("/api/auth/login", content=big,
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    assert response.headers["x-frame-options"] == "DENY"


def test_chunked_body_too_large_rejected(client):
    def chunks():
        for _ in range(3):
            yield b"a" * (1024 * 1024)

    response = client.post("/api/auth/login", content=chunks(),
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_docs_csp_relaxed_only_outside_production(client):
    assert "cdn.jsdelivr.net" in client.get("/docs").headers["content-security-policy"]
