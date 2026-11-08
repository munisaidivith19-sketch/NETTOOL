"""Every input to every route is bounded and strict (CLAUDE.md 7.4), checked by walking the app.

Per-route tests check the important fields one by one. These tests make sure nothing slips
through when a route is added later:
- every request body model forbids unknown fields, so `{"$where": ...}` or `{"a.b": ...}`
  can't ride along into a query;
- every string has a max length or a pattern, every list a max length, every dict
  constrained keys and a size limit, and there is no `Any`;
- every string query parameter has a max length or a pattern;
- sending `$`-keys and dotted keys to every write route gives 422.
"""

import types
import typing
from datetime import date, datetime

import pytest
from annotated_types import MaxLen
from fastapi.routing import APIRoute
from pydantic import BaseModel, IPvAnyAddress, IPvAnyInterface, IPvAnyNetwork
from pydantic.fields import FieldInfo

from app.main import API_ROUTERS
from tests.conftest import csrf, json_bytes, signed_headers
from tests.test_rbac import _concrete

# Fixed-size types, and pydantic's IP types, which parse with `ipaddress` (CLAUDE.md 7.4).
SIMPLE = (int, float, bool, datetime, date, type(None), IPvAnyAddress, IPvAnyNetwork,
          IPvAnyInterface)


def _routes():
    for router in API_ROUTERS:
        for route in router.routes:
            if isinstance(route, APIRoute):
                yield route


def _bounded(metadata) -> bool:
    for item in metadata:
        if isinstance(item, FieldInfo):  # Query(max_length=...) / Field(...) inside Annotated
            if _bounded(item.metadata):
                return True
            continue
        if isinstance(item, MaxLen):
            return True
        if getattr(item, "max_length", None) is not None or getattr(item, "pattern", None):
            return True
    return False


def _problems(annotation, where: str, metadata=(), seen=None) -> list[str]:
    """Why this type is not bounded (empty list = fine)."""
    seen = seen if seen is not None else set()
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin is typing.Annotated:
        return _problems(args[0], where, [*metadata, *args[1:]], seen)
    if origin in (typing.Union, types.UnionType):
        return [p for a in args for p in _problems(a, where, metadata, seen)]
    if origin is typing.Literal or annotation in SIMPLE:
        return []
    if annotation is typing.Any:
        return [f"{where}: Any"]
    if annotation is str:
        return [] if _bounded(metadata) else [f"{where}: str without max_length/pattern"]
    if origin in (list, set, tuple):
        own = [] if _bounded(metadata) else [f"{where}: {origin.__name__} without max_length"]
        return own + [p for a in args if a is not Ellipsis
                      for p in _problems(a, f"{where}[]", (), seen)]
    if origin is dict:
        own = [] if _bounded(metadata) else [f"{where}: dict without max_length"]
        return own + _problems(args[0], f"{where}{{key}}", (), seen) + \
            _problems(args[1], f"{where}{{value}}", (), seen)
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return _model_problems(annotation, seen)
    if isinstance(annotation, type) and issubclass(annotation, (str, int)):  # enums
        return []
    return [f"{where}: unchecked type {annotation!r}"]


def _model_problems(model: type[BaseModel], seen: set) -> list[str]:
    if model in seen:
        return []
    seen.add(model)
    problems = []
    if model.model_config.get("extra") != "forbid":
        problems.append(f"{model.__name__}: extra fields not forbidden")
    for name, field in model.model_fields.items():
        problems += _problems(field.annotation, f"{model.__name__}.{name}", field.metadata, seen)
    return problems


BODY_ROUTES = sorted(
    {(m, r.path) for r in _routes() for m in r.methods if r.dependant.body_params})


def _route(method, path):
    return next(r for r in _routes() if r.path == path and method in r.methods)


@pytest.mark.parametrize(("method", "path"), BODY_ROUTES)
def test_body_models_are_strict_and_bounded(method, path):
    problems = []
    for param in _route(method, path).dependant.body_params:
        problems += _problems(param.field_info.annotation, param.name)
    assert problems == []


def test_query_parameters_are_bounded():
    problems = []
    for route in _routes():
        for param in route.dependant.query_params:
            info: FieldInfo = param.field_info
            problems += _problems(info.annotation, f"{route.path}?{param.name}", info.metadata)
    assert problems == []


def test_detector_catches_a_loose_model():
    class Loose(BaseModel):
        name: str
        tags: list[str]

    assert len(_model_problems(Loose, set())) == 4  # extra allowed, str, list, list item


INJECTIONS = [{"$where": "sleep(1000)"}, {"username": {"$ne": None}, "a.b": 1},
              {"$set": {"role": "admin"}}]


@pytest.fixture
def agent(client, admin):
    agent = client.post("/api/agents", headers=csrf(admin), json={"name": "sweep"}).json()
    return agent


@pytest.mark.parametrize("payload", INJECTIONS)
def test_operator_keys_rejected_on_every_write_route(client, admin, agent, payload):
    """Signed in as admin (or signed as the agent), every body route answers 422."""
    results = {}
    for method, path in BODY_ROUTES:
        url = _concrete(path)
        if path.startswith("/api/agent/"):
            body = json_bytes(payload)
            headers = signed_headers(agent["id"], agent["key"], method, url, body)
            response = client.request(method, url, content=body, headers=headers)
        elif path == "/api/auth/mfa/verify":
            continue  # needs a challenge cookie first: covered in test_mfa.py
        else:
            response = client.request(method, url, json=payload, headers=csrf(admin))
        results[f"{method} {path}"] = response.status_code
    assert {k: v for k, v in results.items() if v != 422} == {}
