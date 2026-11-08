import pytest
from pydantic import ValidationError

from app.config import Settings
from tests.conftest import make_settings


def test_mongodb_uri_is_hidden_in_repr():
    settings = make_settings(mongodb_uri="mongodb+srv://netmap_app:S3cret-pass@x.mongodb.net/")
    assert "S3cret-pass" not in repr(settings)
    assert "S3cret-pass" not in str(settings.model_dump())


def test_production_flag():
    assert make_settings(env="production").is_production
    assert not make_settings(env="development").is_production


@pytest.mark.parametrize("bad_name", ["", "net map", "netmap$", "a.b", "x" * 64])
def test_invalid_database_name_rejected(bad_name):
    with pytest.raises(ValidationError):
        make_settings(mongodb_db=bad_name)


def test_unknown_env_rejected():
    with pytest.raises(ValidationError):
        make_settings(env="staging")


# ---- Phase 9: production settings ----------------------------------------------------------

ATLAS = "mongodb+srv://netmap_app:pw@cluster0.abcde.mongodb.net/?retryWrites=true"


def _production(**overrides):
    return make_settings(env="production", **overrides)


def test_production_needs_mongodb_uri_set():
    values = {"env": "production", "agent_key_encryption_key": "x", "mfa_encryption_key": "y"}
    with pytest.raises(ValidationError, match="MONGODB_URI must be set"):
        Settings(_env_file=None, **values)


def test_production_mongodb_uri_from_environment_counts_as_set(monkeypatch):
    monkeypatch.setenv("MONGODB_URI", ATLAS)
    settings = Settings(_env_file=None, env="production")
    assert settings.mongodb_uri.get_secret_value() == ATLAS


@pytest.mark.parametrize("uri", [
    "mongodb://netmap_app:pw@db.example.com:27017/netmap",
    "mongodb://a.example.com,b.example.com/?replicaSet=rs0",
    "mongodb+srv://u:p@cluster0.x.mongodb.net/?tls=false",
])
def test_production_refuses_unencrypted_database(uri):
    with pytest.raises(ValidationError, match="must use TLS"):
        _production(mongodb_uri=uri)


def test_production_refuses_unencrypted_ai_database():
    with pytest.raises(ValidationError, match="AI_MONGODB_URI must use TLS"):
        _production(mongodb_uri=ATLAS, ai_mongodb_uri="mongodb://ro:pw@db.example.com/")


@pytest.mark.parametrize("uri", [
    ATLAS,
    "mongodb://u:p@db.example.com:27017/?tls=true",
    "mongodb://a.example.com,b.example.com/?replicaSet=rs0&ssl=true",
    "mongodb://127.0.0.1:27017/?replicaSet=rs0",
    "mongodb://[::1]:27017",
])
def test_production_accepts_encrypted_or_local_database(uri):
    assert _production(mongodb_uri=uri).is_production


def test_production_refuses_missing_frontend_build(tmp_path):
    with pytest.raises(ValidationError, match="No frontend build"):
        _production(frontend_dist=tmp_path)
    (tmp_path / "index.html").write_text("<!doctype html>")
    assert _production(frontend_dist=tmp_path).frontend_dist == tmp_path


def test_development_has_none_of_these_checks(tmp_path):
    assert not make_settings(env="development", frontend_dist=tmp_path,
                             mongodb_uri="mongodb://db.example.com/").is_production
