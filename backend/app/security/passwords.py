"""Password hashing (bcrypt) and the password policy (CLAUDE.md 7.1)."""

import secrets
from functools import lru_cache
from pathlib import Path

import bcrypt

MIN_LENGTH = 12
MAX_LENGTH = 64
# bcrypt only uses the first 72 bytes and bcrypt 5 raises an error beyond that, so longer
# passwords are refused instead of being silently cut short.
MAX_BYTES = 72
MIN_DISTINCT_CHARS = 5

_COMMON_FILE = Path(__file__).with_name("common_passwords.txt")


@lru_cache
def _common_passwords() -> frozenset[str]:
    with _COMMON_FILE.open(encoding="utf-8") as handle:
        return frozenset(
            line.strip() for line in handle if line.strip() and not line.startswith("#")
        )


def policy_problems(password: str, username: str | None = None) -> list[str]:
    """Return every reason the password is not acceptable (empty list = acceptable)."""
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"Use at least {MIN_LENGTH} characters.")
    if len(password) > MAX_LENGTH or len(password.encode("utf-8")) > MAX_BYTES:
        problems.append(f"Use at most {MAX_LENGTH} characters.")
    if len(set(password)) < MIN_DISTINCT_CHARS:
        problems.append("Use more varied characters; this one repeats too much.")
    if password.lower() in _common_passwords():
        problems.append("This password is on a list of commonly used passwords. Choose another.")
    if username and len(username) >= 3 and username.lower() in password.lower():
        problems.append("Don't include your username in the password.")
    return problems


def hash_password(password: str, rounds: int) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except ValueError:
        # Over-long input or a malformed stored hash: treat as a failed check, never crash.
        return False


@lru_cache
def dummy_hash(rounds: int) -> str:
    """A real hash of a random value, checked when the username doesn't exist.

    Without it, "unknown user" answers instantly while "wrong password" takes ~250 ms of bcrypt,
    and an attacker could use that timing difference to find valid usernames.
    """
    return hash_password(secrets.token_urlsafe(16), rounds)
