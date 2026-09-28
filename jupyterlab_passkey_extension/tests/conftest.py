"""Shared fixtures for the server + CLI unit tests.

The relay now has two backends (keyctl and shm) chosen once per process and cached
in a module global. A test process would otherwise inherit whichever backend the
first test resolved, so every test resets that cache here and pins a backend: shm by
default - the existing suite asserts file behaviour - and keyctl only for the tests
marked `@pytest.mark.keyctl`, which exercise the kernel-keyring path directly.
"""

import pytest

from jupyterlab_passkey_extension import cli, relay


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "keyctl: run this test against the keyctl backend, not shm"
    )


@pytest.fixture(autouse=True)
def _relay_backend(request, monkeypatch):
    # Reset the per-process cache so each test's backend choice is honoured rather
    # than the first test's, and so the fallback warning fires afresh where tested.
    monkeypatch.setattr(relay, "_backend_cache", None)
    monkeypatch.setattr(relay, "_warned", False)
    # And the found server, which the CLI keeps for the rest of its process.
    monkeypatch.setattr(cli, "_found", None)
    if request.node.get_closest_marker("keyctl"):
        monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "keyctl")
    else:
        monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "shm")
    yield


@pytest.fixture
def vault_env(tmp_path, monkeypatch):
    """A throwaway vault: its own file, state and relay dirs, the process memory holder
    (never the host's real keyring or agent), a fresh server-side service, and a cheap
    Scrypt so a test does not spend a quarter second per passphrase."""
    from jupyterlab_passkey_extension.vault import handlers, holders, store

    monkeypatch.setenv("JLAB_PASSKEY_VAULT", str(tmp_path / "vault" / "vault.json"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(tmp_path / "relay"))
    monkeypatch.setenv(holders.ENV, "memory")
    monkeypatch.setattr(holders, "_selected", None)
    monkeypatch.setattr(holders, "_skipped", {})
    monkeypatch.setattr(holders, "_notice", None)
    monkeypatch.setattr(store, "SCRYPT", {"n": 2**10, "r": 8, "p": 1})
    monkeypatch.setattr(handlers, "_service", handlers.VaultService())
    yield tmp_path
    # Wipe the key and stop its timer, so the holder - and its locked page - is freed
    # rather than kept alive for its 240-minute timer; with a 64 KiB memlock limit the
    # leftover pages starve the mlock tests that run later.
    held = holders._selected
    if isinstance(held, holders.MemoryHolder) and held._vault_id is not None:
        held.clear(held._vault_id)
