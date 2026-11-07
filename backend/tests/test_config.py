import pytest
from pydantic import ValidationError

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
