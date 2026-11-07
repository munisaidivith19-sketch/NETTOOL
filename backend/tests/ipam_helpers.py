"""Shared setup for the IPAM tests: an agent report, then users of each role."""

from tests.conftest import add_user, csrf, login
from tests.test_ingest import _new_agent, core_switch, report, send


def seed_report(client, sync_db, *devices, ping=None) -> dict:
    """Create an agent (as a temporary admin) and ingest one report. Leaves no session."""
    if sync_db.users.find_one({"username": "seedadmin"}) is None:
        add_user(sync_db, "seedadmin", "admin")
    token = login(client, "seedadmin")
    agent = _new_agent(client, token, "Seed agent")
    response = send(client, agent, report(*devices, ping=ping))
    assert response.status_code == 200, response.text
    return agent


def as_role(client, sync_db, role: str) -> dict:
    """Log in as a user with `role` and return headers carrying the CSRF token."""
    username = f"{role}1"
    if sync_db.users.find_one({"username": username}) is None:
        add_user(sync_db, username, role)
    return csrf(login(client, username))


__all__ = ["as_role", "core_switch", "report", "seed_report", "send"]
