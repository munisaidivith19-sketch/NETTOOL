import re

import pytest
from fastapi.routing import APIRoute

from app.main import API_ROUTERS, create_app
from app.security.rbac import ACCESS_MARKER
from tests.conftest import add_user, csrf, login, make_settings

PUBLIC_ROUTES = {("POST", "/api/auth/login")}


def _api_routes():
    for router in API_ROUTERS:
        for route in router.routes:
            if isinstance(route, APIRoute):
                for method in route.methods:
                    yield method, route


def _access_labels(dependant) -> set[str]:
    labels = set()
    for dep in dependant.dependencies:
        label = getattr(dep.call, ACCESS_MARKER, None)
        if label:
            labels.add(label)
        labels |= _access_labels(dep)
    return labels


def _concrete(path: str) -> str:
    sample = {"user_id": "0" * 24, "agent_id": "agt_" + "0" * 16, "subnet_id": "0" * 24,
              "ip": "10.0.0.1"}
    return re.sub(r"\{(\w+)\}", lambda m: sample.get(m.group(1), "x"), path)


ROUTES = sorted({(m, r.path) for m, r in _api_routes()})


def test_routes_exist():
    assert len(ROUTES) >= 10


def test_route_list_covers_the_whole_app():
    """The checks below use API_ROUTERS. This makes sure the running app has no /api route that
    isn't in that list (for example a router added to main.py some other way)."""
    schema = create_app(make_settings()).openapi()
    in_app = {
        (method.upper(), path)
        for path, operations in schema["paths"].items()
        if path.startswith("/api/")
        for method in operations
    }
    assert in_app == set(ROUTES)


def test_every_api_route_declares_its_access_rule():
    """Deny by default: a route added without an access dependency makes this test fail."""
    missing = [
        f"{method} {route.path}"
        for method, route in _api_routes()
        if not _access_labels(route.dependant)
    ]
    assert missing == []


def test_only_login_is_public():
    public = {
        (method, route.path)
        for method, route in _api_routes()
        if "public" in _access_labels(route.dependant)
    }
    assert public == PUBLIC_ROUTES


@pytest.mark.parametrize(("method", "path"), [r for r in ROUTES if r not in PUBLIC_ROUTES])
def test_unauthenticated_request_rejected(client, method, path):
    response = client.request(method, _concrete(path), json={})
    assert response.status_code == 401, f"{method} {path} -> {response.status_code}"


ADMIN_ONLY = [
    ("GET", "/api/users"),
    ("POST", "/api/users"),
    ("PATCH", "/api/users/" + "0" * 24),
    ("POST", "/api/users/" + "0" * 24 + "/reset-password"),
    ("GET", "/api/agents"),
    ("POST", "/api/agents"),
    ("POST", "/api/agents/agt_" + "0" * 16 + "/revoke"),
    ("GET", "/api/audit"),
]


@pytest.mark.parametrize("role", ["viewer", "engineer"])
@pytest.mark.parametrize(("method", "path"), ADMIN_ONLY)
def test_non_admins_get_403_on_admin_routes(client, sync_db, role, method, path):
    add_user(sync_db, "someone", role)
    token = login(client, "someone")
    response = client.request(method, path, json={}, headers=csrf(token))
    assert response.status_code == 403


def test_admin_can_use_admin_routes(client, admin):
    for path in ("/api/users", "/api/agents", "/api/audit"):
        assert client.get(path).status_code == 200, path


def test_user_session_cannot_call_agent_routes(client, admin):
    response = client.post("/api/agent/heartbeat", json={}, headers=csrf(admin))
    assert response.status_code == 401


def test_detector_catches_an_unprotected_route():
    """Proves the deny-by-default check above isn't passing vacuously."""
    from fastapi import APIRouter

    router = APIRouter(prefix="/api/forgotten")

    @router.get("/x")
    async def forgotten() -> dict:
        return {}

    route = next(r for r in router.routes if isinstance(r, APIRoute))
    assert _access_labels(route.dependant) == set()
