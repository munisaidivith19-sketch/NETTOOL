"""Phase 9: the real client IP behind Render's proxy can't be chosen by the client."""

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.security.client_ip import resolve
from tests.conftest import BASE_URL, add_user, login, make_settings

RENDER_PROXY = "10.21.157.68"
CLOUDFLARE = "104.22.17.40"
ME = "99.61.165.29"


def test_no_proxy_configured_ignores_the_header():
    assert resolve("127.0.0.1", ["6.6.6.6"], 0) == ("127.0.0.1", "peer")


def test_render_chain_picks_the_entry_cloudflare_added():
    assert resolve(RENDER_PROXY, [f"{ME}, {CLOUDFLARE}"], 2) == (ME, "forwarded")


def test_forged_leftmost_entries_are_ignored():
    # The client sent "X-Forwarded-For: 1.2.3.4"; the proxies appended the real addresses.
    assert resolve(RENDER_PROXY, [f"1.2.3.4, 5.6.7.8, {ME}, {CLOUDFLARE}"], 2)[0] == ME


def test_several_header_lines_are_joined_in_order():
    assert resolve(RENDER_PROXY, ["1.2.3.4", f"{ME}, {CLOUDFLARE}"], 2)[0] == ME


def test_public_peer_did_not_come_through_the_proxy():
    assert resolve("8.8.8.8", [f"{ME}, {CLOUDFLARE}"], 2) == ("8.8.8.8",
                                                          "peer_not_a_proxy")


@pytest.mark.parametrize("chain", [[], [CLOUDFLARE], [""], [" , "]])
def test_short_chain_falls_back_to_the_peer(chain):
    assert resolve(RENDER_PROXY, chain, 2) == (RENDER_PROXY, "chain_too_short")


@pytest.mark.parametrize("entry", ["not-an-ip", "1.2.3.4:5678", "999.1.1.1", "<script>"])
def test_invalid_entry_falls_back_to_the_peer(entry):
    assert resolve(RENDER_PROXY, [f"{entry}, {CLOUDFLARE}"], 2) == (RENDER_PROXY,
                                                                    "invalid_entry")


def test_ipv6_entries():
    assert resolve("fd00::1", ["2001:db8::7, 2606:4700::1"], 2)[0] == "2001:db8::7"
    assert resolve(RENDER_PROXY, ["2001:DB8:0:0::7, 104.22.17.40"], 2)[0] == "2001:db8::7"


def test_huge_forged_header_does_not_matter():
    forged = ", ".join(["9.9.9.9"] * 5000)
    assert resolve(RENDER_PROXY, [forged + f", {ME}, {CLOUDFLARE}"], 2)[0] == ME


def test_garbage_peer_is_not_trusted():
    assert resolve("testclient", [f"{ME}, {CLOUDFLARE}"], 2)[1] == "peer_not_a_proxy"


@pytest.fixture
def proxied(sync_db):
    """The app as it runs on Render: two trusted hops, requests arriving from Render's proxy."""
    app = create_app(make_settings(trusted_proxy_hops=2))
    with TestClient(app, base_url=BASE_URL, client=(RENDER_PROXY, 40000)) as c:
        yield c


def _bad_login(client, forged: str):
    return client.post("/api/auth/login", json={"username": "nobody", "password": "wrong-pass-x"},
                       headers={"X-Forwarded-For": f"{forged}, {ME}, {CLOUDFLARE}"})


def test_rotating_forged_ips_still_hit_the_per_ip_limit(proxied, sync_db):
    statuses = [_bad_login(proxied, f"198.51.100.{i}").status_code for i in range(12)]
    assert statuses[:10] == [401] * 10
    assert statuses[10:] == [429, 429]
    ips = {e["ip"] for e in sync_db.audit_log.find({"action": "auth.login"})}
    assert ips == {ME}


def test_request_info_shows_what_was_chosen(proxied, sync_db):
    add_user(sync_db, "root", role="admin")
    login(proxied, "root")
    body = proxied.get("/api/admin/request-info",
                       headers={"X-Forwarded-For": f"1.2.3.4, {ME}, {CLOUDFLARE}"}).json()
    assert body == {"peer": RENDER_PROXY, "forwarded_for": ["1.2.3.4", ME, CLOUDFLARE],
                    "trusted_proxy_hops": 2, "client_ip": ME, "chosen_by": "forwarded"}


def test_request_info_is_admin_only(proxied, sync_db):
    add_user(sync_db, "vic", role="viewer")
    login(proxied, "vic")
    assert proxied.get("/api/admin/request-info").status_code == 403
