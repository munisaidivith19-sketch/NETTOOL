"""Phase 8 review: device logins never reach logs, error codes or uploads (CLAUDE.md 7.6)."""

import logging

import httpx
import pytest
from netmiko.exceptions import NetmikoAuthenticationException

import netmap_agent.ai_training.oui as oui
from netmap_agent.config_mgmt import connection
from netmap_agent.config_mgmt.connection import SessionError, open_session
from netmap_agent.credential_store import Profile

PASSWORD = "Dev1ce-Passw0rd-Do-Not-Log"
SECRET = "En4ble-Secret-Do-Not-Log"


def _profile() -> Profile:
    return Profile(name="lab", match="192.0.2.0/24", device_type="cisco_ios", username="netmap",
                   password=PASSWORD, secret=SECRET)


@pytest.mark.parametrize("error", [
    NetmikoAuthenticationException(f"Authentication to device failed for {PASSWORD}"),
    OSError(f"socket closed while sending {PASSWORD} / {SECRET}"),
    RuntimeError(f"unexpected prompt after enable secret {SECRET}"),
])
def test_ssh_failures_carry_no_secret(monkeypatch, caplog, error):
    """Even when the library's own error text contains the password, NetMap's error code
    and message (what gets logged and uploaded) don't."""
    caplog.set_level(logging.DEBUG)

    def fail(**kwargs):
        raise error

    import netmiko
    monkeypatch.setattr(netmiko, "ConnectHandler", fail)
    with pytest.raises(SessionError) as caught:
        with open_session("192.0.2.10", _profile()):
            pass
    shown = f"{caught.value.code} {caught.value}"
    assert PASSWORD not in shown and SECRET not in shown
    logging.getLogger("netmap_agent.config").warning("Backup failed: %s", caught.value.code)
    assert PASSWORD not in caplog.text and SECRET not in caplog.text


def test_netmiko_and_paramiko_logs_kept_quiet():
    # Their DEBUG output includes what is typed into the SSH channel, passwords included.
    # Importing NetMap's connection module is what sets them to WARNING.
    assert connection.CONNECT_TIMEOUT > 0
    for name in ("netmiko", "paramiko"):
        assert logging.getLogger(name).getEffectiveLevel() >= logging.WARNING


def test_profile_repr_hides_secrets():
    text = repr(_profile()) + str(_profile())
    assert PASSWORD not in text and SECRET not in text


def test_oui_download_refuses_http_redirect(monkeypatch, tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            return httpx.Response(302, headers={"Location": "http://mirror.example/oui.csv"})
        return httpx.Response(200, text="Registry,Assignment,Organization Name\n")

    def stream(method, url, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return httpx.Client(**{k: kwargs.pop(k) for k in ("transport", "follow_redirects")
                               if k in kwargs}).stream(method, url, **kwargs)

    monkeypatch.setattr(httpx, "stream", stream)
    target = tmp_path / "oui.csv"
    with pytest.raises(ValueError, match="non-HTTPS"):
        oui.update(target)
    assert not target.exists()
