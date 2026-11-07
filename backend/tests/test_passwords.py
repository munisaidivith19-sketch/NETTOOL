import pytest
from pydantic import ValidationError

from app.security.passwords import hash_password, policy_problems, verify_password
from tests.conftest import make_settings


def test_good_password_accepted():
    assert policy_problems("Granite-Lantern-58-Orbit", "alice") == []


@pytest.mark.parametrize(
    "password",
    [
        "Short-1",  # under 12 characters
        "a" * 65,  # over 64 characters
        "é" * 40,  # 40 characters but 80 bytes: over bcrypt's 72-byte limit
        "abababababababab",  # too few distinct characters
        "qwerty123456",  # on the common-passwords list
        "1q2w3e4r5t6y",  # on the common-passwords list
        "Welcome-alice-2026",  # contains the username
    ],
)
def test_bad_passwords_rejected(password):
    assert policy_problems(password, "alice")


def test_hash_is_bcrypt_and_verifies():
    hashed = hash_password("Granite-Lantern-58-Orbit", rounds=4)
    assert hashed.startswith("$2b$04$")
    assert "Granite" not in hashed
    assert verify_password("Granite-Lantern-58-Orbit", hashed)
    assert not verify_password("Granite-Lantern-58-Orbix", hashed)


def test_verify_never_crashes_on_bad_input():
    assert not verify_password("x" * 500, hash_password("Granite-Lantern-58-Orbit", rounds=4))
    assert not verify_password("anything", "not-a-hash")


def test_default_bcrypt_cost_is_12():
    assert make_settings(env="development").bcrypt_rounds == 12


@pytest.mark.parametrize("env", ["development", "production"])
def test_low_bcrypt_cost_refused_outside_tests(env):
    with pytest.raises(ValidationError):
        make_settings(env=env, bcrypt_rounds=10)
