from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import make_settings


def test_health_ok_with_database(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


def test_health_reports_unavailable_database_without_details():
    # Port 1 has nothing listening, so the database is unreachable.
    settings = make_settings(mongodb_uri="mongodb://127.0.0.1:1", mongodb_timeout_ms=300)
    with TestClient(create_app(settings)) as c:
        response = c.get("/health")
    assert response.status_code == 503
    # Exactly these two fields: no exception text, host, port or driver message leaks out.
    assert response.json() == {"status": "degraded", "database": "unavailable"}
    assert "127.0.0.1" not in response.text


def test_docs_available_outside_production(client):
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_docs_disabled_in_production(sync_db):
    with TestClient(create_app(make_settings(env="production"))) as c:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert c.get(path).status_code == 404, path


def test_docs_stay_404_when_the_dashboard_is_served(sync_db, tmp_path):
    # The dashboard's catch-all route must not answer these with index.html (a 200).
    (tmp_path / "index.html").write_text("<!doctype html><title>NetMap</title>")
    with TestClient(create_app(make_settings(env="production", frontend_dist=tmp_path))) as c:
        assert c.get("/").status_code == 200
        assert c.get("/subnets/abc").status_code == 200
        for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
            assert c.get(path).status_code == 404, path
