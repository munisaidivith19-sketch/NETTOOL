import logging

import pytest
from pydantic import ValidationError

from netmap_agent.config import AgentSettings


def make(**values) -> AgentSettings:
    return AgentSettings(_env_file=None, **values)


def test_https_is_the_default_and_accepted():
    assert make().api_url.startswith("https://")
    assert make(api_url="https://netmap.example.org/").api_url == "https://netmap.example.org"


@pytest.mark.parametrize(
    "values",
    [
        {"api_url": "http://netmap.example.org"},  # remote http, even with the flag
        {"api_url": "http://netmap.example.org", "allow_insecure_local": True},
        {"api_url": "http://127.0.0.1:8000"},  # local, but the flag is off
        {"api_url": "http://10.0.0.5:8000", "allow_insecure_local": True},  # LAN is not local
        {"api_url": "ftp://127.0.0.1"},
        {"api_url": "https://"},
    ],
)
def test_plain_http_refused(values):
    with pytest.raises(ValidationError):
        make(**values)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "[::1]"])
def test_http_allowed_for_localhost_with_flag(host):
    assert make(api_url=f"http://{host}:8000", allow_insecure_local=True)


def test_targets_parsed_including_ipv6():
    settings = make(snmp_targets="127.0.0.11:1161,[2001:db8::1]:1161,10.0.0.1")
    assert settings.targets == [("127.0.0.11", 1161), ("2001:db8::1", 1161), ("10.0.0.1", 161)]


@pytest.mark.parametrize("bad", ["switch.example.com", "10.0.0.1:99999", "10.0.0.1;whoami"])
def test_bad_targets_rejected(bad):
    with pytest.raises(ValidationError):
        make(snmp_targets=bad)


def test_oversized_range_rejected():
    with pytest.raises(ValidationError, match="maximum"):
        make(scan_ranges="10.0.0.0/16")


def test_total_scan_size_capped():
    assert make(scan_ranges="10.0.0.0/22,10.0.4.0/22,10.0.8.0/22,10.0.12.0/22")
    with pytest.raises(ValidationError, match="in total"):
        make(scan_ranges="10.0.0.0/22,10.0.4.0/22,10.0.8.0/22,10.0.12.0/22,10.0.16.0/30")


@pytest.mark.parametrize("agent_id", ["agt_123", "AGT_0123456789abcdef", "agt_0123456789abcdeg"])
def test_agent_id_format(agent_id):
    with pytest.raises(ValidationError):
        make(agent_id=agent_id)


def test_v2c_warns(caplog):
    with caplog.at_level(logging.WARNING, logger="netmap_agent"):
        make(snmp_version="v2c", snmp_v2c_community="lab-community").warn_if_weak()
    assert "clear text" in caplog.text
    assert "lab-community" not in caplog.text


def test_v3_does_not_warn(caplog):
    with caplog.at_level(logging.WARNING, logger="netmap_agent"):
        make().warn_if_weak()
    assert caplog.text == ""
