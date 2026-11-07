import subprocess

import pytest

from netmap_agent.discovery import ping

# Captured from real Windows 11 and Linux (iputils) ping runs.
WIN_REPLY = ("Pinging 10.0.0.1 with 32 bytes of data:\r\n"
             "Reply from 10.0.0.1: bytes=32 time<1ms TTL=128\r\n")
WIN_REPLY_V6 = "Pinging ::1 with 32 bytes of data:\r\nReply from ::1: time<1ms \r\n"
WIN_UNREACHABLE = ("Pinging 10.0.0.9 with 32 bytes of data:\r\n"
                   "Reply from 10.0.0.254: Destination host unreachable.\r\n")
WIN_TIMEOUT = "Pinging 10.0.0.9 with 32 bytes of data:\r\nRequest timed out.\r\n"
WIN_V6_UNREACHABLE = ("Pinging 2001:db8::9 with 32 bytes of data:\r\n"
                      "Destination host unreachable.\r\n")


def test_windows_command():
    assert ping.build_command("C:/Windows/System32/PING.EXE", "10.0.0.1", 800, "win32") == [
        "C:/Windows/System32/PING.EXE", "-4", "-n", "1", "-w", "800", "10.0.0.1"]
    assert ping.build_command("ping", "2001:db8::1", 1000, "win32")[1] == "-6"


def test_linux_command():
    assert ping.build_command("/usr/bin/ping", "10.0.0.1", 1500, "linux") == [
        "/usr/bin/ping", "-4", "-c", "1", "-W", "2", "10.0.0.1"]
    assert ping.build_command("/usr/bin/ping", "10.0.0.1", 100, "linux")[5] == "1"


@pytest.mark.parametrize(
    "target", ["example.com", "10.0.0.1 && calc", "-t", "10.0.0.1/24", "", "10.0.0.256"])
def test_command_refuses_non_ips(target):
    with pytest.raises(ValueError):
        ping.build_command("ping", target, 1000, "win32")


@pytest.mark.parametrize(
    ("returncode", "output", "version", "platform", "up"),
    [
        (0, WIN_REPLY, 4, "win32", True),
        (0, WIN_REPLY_V6, 6, "win32", True),
        (0, WIN_UNREACHABLE, 4, "win32", False),  # exit code 0, but nobody answered
        (1, WIN_TIMEOUT, 4, "win32", False),
        (0, WIN_TIMEOUT, 4, "win32", False),
        (0, WIN_V6_UNREACHABLE, 6, "win32", False),
        (0, "64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.3 ms", 4, "linux", True),
        (1, "1 packets transmitted, 0 received, 100% packet loss", 4, "linux", False),
    ],
)
def test_is_reply(returncode, output, version, platform, up):
    assert ping.is_reply(returncode, output, version, platform) is up


def test_ping_one_uses_argument_list_without_shell(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=WIN_REPLY, stderr="")

    monkeypatch.setattr(ping.subprocess, "run", fake_run)
    monkeypatch.setattr(ping.sys, "platform", "win32")
    assert ping.ping_one("ping", "10.0.0.1", 500) is True
    command, kwargs = calls[0]
    assert isinstance(command, list) and command[-1] == "10.0.0.1"
    assert kwargs.get("shell", False) is False


def test_ping_one_timeout_is_down(monkeypatch):
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 1)

    monkeypatch.setattr(ping.subprocess, "run", fake_run)
    assert ping.ping_one("ping", "10.0.0.1", 500) is False


def test_sweep_dedupes_and_orders(monkeypatch):
    seen = []
    monkeypatch.setattr(ping, "ping_binary", lambda: "ping")
    monkeypatch.setattr(ping, "ping_one", lambda _b, ip, _t: seen.append(ip) or ip.endswith(".2"))
    result = ping.sweep(["10.0.0.10", "10.0.0.2", "10.0.0.2", "::1"], 100)
    assert list(result) == ["10.0.0.2", "10.0.0.10", "::1"]
    assert result == {"10.0.0.2": True, "10.0.0.10": False, "::1": False}
    assert sorted(seen) == ["10.0.0.10", "10.0.0.2", "::1"]


def test_sweep_rejects_garbage_before_pinging(monkeypatch):
    monkeypatch.setattr(ping, "ping_binary", lambda: pytest.fail("must not get this far"))
    with pytest.raises(ValueError):
        ping.sweep(["10.0.0.1", "10.0.0.1 | whoami"])


def test_real_ping_of_localhost():
    if ping.shutil.which("ping") is None:
        pytest.skip("no ping command on this machine")
    assert ping.sweep(["127.0.0.1"], 1000) == {"127.0.0.1": True}
