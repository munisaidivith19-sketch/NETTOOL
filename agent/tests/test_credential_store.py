import sys

import pytest
from cryptography.fernet import Fernet

from netmap_agent.credential_store import CredentialError, CredentialStore, Profile, main


def profile(name: str = "core", match: str = "10.10.0.0/24", **extra) -> Profile:
    values = {"device_type": "cisco_ios", "username": "netmap", "password": "Sup3r-Secret-Pw",
              "secret": "En4ble-Secret"} | extra
    return Profile(name=name, match=match, **values)


@pytest.fixture
def store(tmp_path) -> CredentialStore:
    return CredentialStore(tmp_path / "credentials.enc", Fernet.generate_key().decode())


def test_round_trip_and_file_holds_no_plaintext(store: CredentialStore) -> None:
    store.add(profile())
    raw = store.path.read_bytes()
    assert b"Sup3r-Secret-Pw" not in raw and b"En4ble" not in raw and b"netmap" not in raw
    loaded = store.load()
    assert loaded[0].password == "Sup3r-Secret-Pw" and loaded[0].secret == "En4ble-Secret"


def test_wrong_key_cannot_read(store: CredentialStore, tmp_path) -> None:
    store.add(profile())
    other = CredentialStore(store.path, Fernet.generate_key().decode())
    with pytest.raises(CredentialError, match="can't be decrypted"):
        other.load()
    with pytest.raises(CredentialError, match="valid Fernet key"):
        CredentialStore(store.path, "not-a-key").load()


def test_most_specific_profile_wins(store: CredentialStore) -> None:
    store.add(profile("campus", "10.10.0.0/16"))
    store.add(profile("core", "10.10.99.1/32", username="coreadmin"))
    store.add(profile("v6", "2001:db8::/32"))
    assert store.for_ip("10.10.99.1").name == "core"
    assert store.for_ip("10.10.20.5").name == "campus"
    assert store.for_ip("2001:db8::1").name == "v6"
    assert store.for_ip("192.168.1.1") is None
    assert store.for_ip("not-an-ip") is None


def test_add_replaces_and_remove(store: CredentialStore) -> None:
    store.add(profile())
    store.add(profile(username="other"))
    assert [p.username for p in store.load()] == ["other"]
    assert store.remove("core") is True and store.load() == []
    assert store.remove("core") is False


def test_secrets_never_in_repr_or_public_view() -> None:
    item = profile()
    assert "Sup3r" not in repr(item) and "En4ble" not in repr(item)
    assert "Sup3r" not in str(item.public()) and item.public()["has_enable_secret"] is True


@pytest.mark.parametrize("bad", [
    {"match": "10.10.0.0/33"}, {"match": "core-switch"}, {"device_type": "junos"},
    {"username": "a b"}, {"password": ""}, {"ssh_port": 0}, {"ssh_host": "a;rm -rf"},
    {"name": "../etc"},
])
def test_invalid_profiles_are_rejected(bad: dict) -> None:
    with pytest.raises(CredentialError):
        profile(**bad)


def test_cli_list_never_prints_passwords(store: CredentialStore, monkeypatch, capsys) -> None:
    store.add(profile())
    monkeypatch.setattr("netmap_agent.credential_store._store_from_env", lambda: store)
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "core" in out and "Sup3r" not in out and "En4ble" not in out


def test_cli_add_reads_passwords_from_stdin(store: CredentialStore, monkeypatch) -> None:
    import io

    monkeypatch.setattr("netmap_agent.credential_store._store_from_env", lambda: store)
    monkeypatch.setattr(sys, "stdin", io.StringIO("Lab-Pass-123\nLab-Enable-123\n"))
    assert main(["add", "--name", "lab", "--match", "127.0.0.11/32", "--device-type",
                 "cisco_ios", "--username", "netmap", "--ssh-port", "2222",
                 "--password-stdin"]) == 0
    saved = store.for_ip("127.0.0.11")
    assert saved.password == "Lab-Pass-123" and saved.secret == "Lab-Enable-123"
    assert saved.ssh_port == 2222


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_dpapi_protected_key_file(tmp_path) -> None:
    store = CredentialStore(tmp_path / "credentials.enc")
    store.init()
    store.add(profile())
    key_file = store.key_path.read_bytes()
    assert len(key_file) > 44  # the DPAPI blob, not the bare 44-byte Fernet key
    assert CredentialStore(tmp_path / "credentials.enc").load()[0].name == "core"
