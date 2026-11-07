"""Masking, compliance facts and the command denylist (CLAUDE.md 7.5 / 7.6 required tests)."""

import pytest

from netmap_agent.config_mgmt.denylist import check_commands, same_interface
from netmap_agent.config_mgmt.facts import config_facts
from netmap_agent.config_mgmt.masking import MASK, mask_config

IOS_SECRETS = """\
enable secret 9 $9$enableHASH
enable secret level 15 5 $1$levelHASH
username admin privilege 15 secret 9 $9$userHASH
username old password 0 PlainPass1
snmp-server community campusRW RW
snmp-server host 10.0.0.5 version 2c TrapComm1
snmp-server user u1 g1 v3 auth sha AuthKey123 priv aes 128 PrivKey123
tacacs-server key 7 0822455D0A16
crypto isakmp key IsakmpPsk1 address 1.2.3.4
key chain KC
 key 1
  key-string 7 KeyStr1ng
interface Gi0/1
 ip ospf message-digest-key 1 md5 OspfKey1
ntp authentication-key 1 md5 NtpKey1 7
line vty 0 4
 password 7 060506324F41
dot11 ssid STAFF
 wpa-psk ascii 0 WifiPass1
"""
SECRET_VALUES = ["enableHASH", "levelHASH", "userHASH", "PlainPass1", "campusRW", "TrapComm1",
                 "AuthKey123", "PrivKey123", "0822455D0A16", "IsakmpPsk1", "KeyStr1ng",
                 "OspfKey1", "NtpKey1", "060506324F41", "WifiPass1"]


def test_every_ios_secret_is_masked() -> None:
    masked = mask_config(IOS_SECRETS, "cisco_ios")
    for value in SECRET_VALUES:
        assert value not in masked, value
    assert "enable secret 9 <masked>" in masked  # the type number survives for compliance
    assert "snmp-server community <masked> RW" in masked
    assert " ip ospf message-digest-key 1 md5 <masked>" in masked  # indentation kept


def test_masking_keeps_non_secret_lines_and_is_idempotent() -> None:
    text = "hostname R1\ncrypto key generate rsa modulus 2048\nservice password-encryption\n"
    assert mask_config(text, "cisco_ios") == text
    once = mask_config(IOS_SECRETS, "cisco_ios")
    assert mask_config(once, "cisco_ios") == once


def test_routeros_secrets_are_masked() -> None:
    text = ('/user add name=bob password="two words" group=full\n'
            "/snmp community\nset [ find default=yes ] name=SecretComm\n"
            "/interface wireless security-profiles\n"
            "add name=p wpa2-pre-shared-key=WifiKey1 authentication-types=wpa2-psk\n"
            "/ppp secret add name=x secret=PppSecret\n")
    masked = mask_config(text, "mikrotik_routeros")
    for value in ("two words", "SecretComm", "WifiKey1", "PppSecret"):
        assert value not in masked
    assert "name=bob" in masked and f"password={MASK}" in masked


@pytest.mark.parametrize(("config", "vendor", "weak"), [
    ("snmp-server community public RO\n", "cisco_ios", True),
    ("snmp-server community PRIVATE RW\n", "cisco_ios", True),
    ("snmp-server community s3cret RO\n", "cisco_ios", False),
    ("/snmp\nset enabled=yes\n", "mikrotik_routeros", True),  # the built-in "public" is active
    ("/snmp\nset enabled=yes\n/snmp community\nset [ find default=yes ] name=campus\n",
     "mikrotik_routeros", False),
    ("/snmp community\nadd name=public\n", "mikrotik_routeros", True),
])
def test_default_community_fact(config: str, vendor: str, weak: bool) -> None:
    assert config_facts(config, vendor) == {"snmp_default_community": weak}


# ------------------------------------------------------------------ denylist

PROTECTED = ["GigabitEthernet0/1", "Vlan99"]


@pytest.mark.parametrize("command", [
    "erase startup-config", "write erase", "wr er", "reload", "rel", "reload in 5",
    "do reload", "delete flash:config.text", "format flash:", "crypto key zeroize rsa",
    "cry k z", "no username admin", "no user admin", "copy tftp: running-config",
    "configure replace flash:old", "boot system flash:x.bin", "config-register 0x2142",
    "no archive", "alias exec x reload", "event manager applet X",
])
def test_denylisted_ios_commands_are_blocked(command: str) -> None:
    violations = check_commands(command, "cisco_ios", PROTECTED)
    assert violations and violations[0].reason.startswith("Blocked")


@pytest.mark.parametrize("commands", [
    "interface GigabitEthernet0/1\n shutdown",
    "interface Gi0/1\n shut",
    "int g0/1\n no ip address",
    "interface Vlan99\n ip address 10.9.9.9 255.255.255.0",
    "interface range Gi0/1 - 4\n shutdown",
    "interface Gi0/9\n interface Gi0/1\n  shutdown",  # nested: lands on Gi0/1 on a device
    "no interface Vlan99",
    "default interface Gi0/1",
    "no vlan 99",
])
def test_protected_interfaces_cannot_be_cut(commands: str) -> None:
    assert check_commands(commands, "cisco_ios", PROTECTED)


@pytest.mark.parametrize("commands", [
    "hostname ACCESS-SW-3",
    "interface Gi0/2\n shutdown",
    "interface range Gi0/2 - 8\n switchport mode access\n switchport port-security",
    "interface Gi0/1\n description Uplink to core\n no shutdown",
    "interface Gi0/1\n switchport trunk allowed vlan add 30",
    "crypto key generate rsa modulus 2048",
    "line vty 0 4\n transport input ssh\n exec-timeout 10 0",
    "archive\n path flash:archive\n maximum 5",
    "username netops privilege 15 secret S0me-L0ng-Secret",
])
def test_normal_changes_pass(commands: str) -> None:
    assert check_commands(commands, "cisco_ios", PROTECTED) == []


@pytest.mark.parametrize("commands", [
    "shutdown",  # not indented: would hit whichever interface the CLI is in
    "a\tb",
    "hostname X\r",
    "hostname \x1b[2J",
    "",
    "\n".join(["hostname X"] * 501),
    "interface range something-odd\n description x",
])
def test_ambiguous_or_malformed_input_is_blocked(commands: str) -> None:
    assert check_commands(commands, "cisco_ios", PROTECTED)


@pytest.mark.parametrize(("commands", "blocked"), [
    ("/system reset-configuration", True),
    ("/sys reb", True),
    ("/system/reboot", True),
    ("/file remove flash/x", True),
    ("/user remove admin", True),
    ("/import file=x.rsc", True),
    ("/interface disable ether1", True),
    ("/interface ethernet\nset ether1 disabled=yes", True),
    ("/interface ethernet set [ find default-name=ether1 ] disabled=yes", True),
    (":foreach i in=[/interface find] do={/interface disable $i}", True),
    ("/ip service set ssh port=2200", True),
    ("/interface disable ether7", False),
    ("/system identity set name=ACCESS-SW-2", False),
    ("/ip service set telnet disabled=yes", False),
    ("/interface vlan add name=vlan30 vlan-id=30 interface=bridge", False),
])
def test_routeros_denylist(commands: str, blocked: bool) -> None:
    assert bool(check_commands(commands, "mikrotik_routeros", ["ether1"])) is blocked


def test_unknown_vendor_is_refused() -> None:
    assert check_commands("hostname X", "junos", [])


@pytest.mark.parametrize(("a", "b", "same"), [
    ("Gi0/1", "GigabitEthernet0/1", True), ("vl99", "Vlan99", True),
    ("Po1", "Port-channel1", True), ("Gi0/1", "Gi0/10", False),
    ("Gi0/1", "Te0/1", False), ("ether1", "ether1", True),
])
def test_interface_names_match_abbreviations(a: str, b: str, same: bool) -> None:
    assert same_interface(a, b) is same
