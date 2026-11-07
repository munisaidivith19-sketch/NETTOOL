import pytest
from pydantic import ValidationError

import netmap_agent
from netmap_agent.config import AgentSettings


def make(**values) -> AgentSettings:
    return AgentSettings(_env_file=None, **values)


def test_package_imports():
    assert netmap_agent.__version__ == "0.1.0"


def test_comma_separated_lists_from_env(monkeypatch):
    monkeypatch.setenv("SCAN_RANGES", "10.0.10.0/24, 2001:db8:10::/120")
    monkeypatch.setenv("SNMP_TARGETS", "127.0.0.11:1161,127.0.0.12")
    settings = make()
    assert settings.scan_ranges == ["10.0.10.0/24", "2001:db8:10::/120"]
    assert settings.snmp_targets == ["127.0.0.11:1161", "127.0.0.12"]


@pytest.mark.parametrize("bad", ["10.0.0.0/33", "not-a-network", "10.0.0.0/24; calc.exe"])
def test_invalid_scan_range_rejected(bad):
    with pytest.raises(ValidationError):
        make(scan_ranges=[bad])


def test_secrets_hidden_in_repr():
    settings = make(agent_key="agent-key-value", snmp_v3_auth_key="auth-key-value")
    assert "agent-key-value" not in repr(settings)
    assert "auth-key-value" not in repr(settings)
