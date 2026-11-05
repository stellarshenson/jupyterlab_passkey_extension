"""The vault key lifecycle lines: one INFO record per event, under one stable prefix.

The Jupyter server's own logging carries these records to the container log; the tests
read the logger `jupyterlab_passkey_extension.vault` at INFO. Every case asserts exactly
one line for its event, and no line holds a secret.
"""

import base64
import json
import logging
import time

import pytest

from jupyterlab_passkey_extension.vault import handlers, holders, service, store, totp

from .test_vault_routes import _version_one_vault_held_by_its_root
from .test_vault_webauthn import add_pair, unlock_pair

PASS = "correct horse battery staple"
SECRET = "s3cret-MUST-NOT-LEAK"
APP = bytes(range(40, 60))
APP_KEY = base64.b32encode(APP).decode()
UNLOCK = "an everyday password"
PRF = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
LOGGER = "jupyterlab_passkey_extension.vault"


@pytest.fixture(autouse=True)
def _info(caplog):
    caplog.set_level(logging.INFO, logger=LOGGER)


def _lines(caplog, event):
    """The vault key INFO lines for `event`: the stable prefix and the event name."""
    return [r.getMessage() for r in caplog.records
            if r.name.startswith(LOGGER) and r.levelno == logging.INFO
            and r.getMessage().startswith(f"{holders.KEY_LOG}: {event}")]


def _one(caplog, event):
    assert _lines(caplog, event) == [f"{holders.KEY_LOG}: {event}"]


def _write_doc(doc):
    with open(store.vault_path(), "w") as f:
        json.dump(doc, f)


def test_vault_created(vault_env, caplog):
    handlers._service.init(PASS)
    _one(caplog, "vault created")


def test_unlocked_with_a_passkey(vault_env, caplog):
    svc = handlers._service
    svc.init(PASS)
    svc.add_passkey("cred-1", "lab.example", "c2FsdA", PRF, None, {"current": PASS})
    svc.lock()
    caplog.clear()
    svc.unlock_passkey("cred-1", PRF)
    _one(caplog, "unlocked method=passkey")


def test_unlocked_with_the_recovery_passphrase(vault_env, caplog):
    svc = handlers._service
    svc.init(PASS)
    svc.lock()
    caplog.clear()
    svc.unlock_recovery(PASS)
    _one(caplog, "unlocked method=recovery")


def test_unlocked_with_the_password_and_a_code(vault_env, caplog):
    svc = handlers._service
    svc.init(PASS)
    svc.add("github/api", {"password": SECRET})
    step = int(time.time()) // totp.STEP
    svc.add_mfa(UNLOCK, APP_KEY, totp.code(APP, step), {"current": PASS})
    svc.lock()
    caplog.clear()
    svc.unlock_password(UNLOCK, totp.code(APP, step + 1))
    _one(caplog, "unlocked method=password")
    assert SECRET not in caplog.text
    assert PASS not in caplog.text


def test_unlocked_with_password_and_passkey(vault_env, caplog):
    svc = handlers._service
    svc.init(PASS)
    authenticator = add_pair(svc)
    svc.lock()
    caplog.clear()
    unlock_pair(svc, authenticator)
    _one(caplog, "unlocked method=pair")


def test_locked(vault_env, caplog):
    svc = handlers._service
    svc.init(PASS)
    caplog.clear()
    svc.lock()
    _one(caplog, "locked")


def test_lock_twice_reports_one_line(vault_env, caplog):
    svc = handlers._service
    svc.init(PASS)
    caplog.clear()
    svc.lock()
    # Nothing is held after the first lock: the second clears no key.
    svc.lock()
    _one(caplog, "locked")


def test_lock_after_a_restart_with_no_key_held_reports_nothing(vault_env, caplog):
    handlers._service.init(PASS)
    handlers._service.lock()
    restarted = service.VaultService()
    caplog.clear()
    restarted.lock()
    assert _lines(caplog, "locked") == []


def test_key_expired_is_reported_once(vault_env, caplog):
    svc = handlers._service
    svc.init(PASS)
    holders._selected._expiry = time.monotonic() - 1
    caplog.clear()
    assert svc.status()["unlocked"] is False
    assert svc.status()["unlocked"] is False
    with pytest.raises(service.Locked):
        svc.read("absent")
    _one(caplog, "key expired")


def test_key_expired_after_a_server_restart_is_reported_once(vault_env, caplog):
    handlers._service.init(PASS)
    # A fresh service is a restarted server: the holder kept the key, and the service
    # has no memory of putting it there.
    restarted = service.VaultService()
    assert restarted.status()["unlocked"] is True
    holders._selected._expiry = time.monotonic() - 1
    caplog.clear()
    assert restarted.status()["unlocked"] is False
    assert restarted.status()["unlocked"] is False
    _one(caplog, "key expired")


def test_key_expired_after_a_restart_read_is_reported_once(vault_env, caplog):
    svc = handlers._service
    svc.init(PASS)
    svc.add("github/api", {"password": SECRET})
    restarted = service.VaultService()
    assert restarted.read("github/api") == SECRET
    holders._selected._expiry = time.monotonic() - 1
    caplog.clear()
    with pytest.raises(service.Locked):
        restarted.read("github/api")
    assert restarted.status()["unlocked"] is False
    _one(caplog, "key expired")


def test_holder_chosen(vault_env, caplog):
    holders.select()
    _one(caplog, "holder chosen name=memory")


def test_holder_chosen_automatically(vault_env, caplog, monkeypatch):
    # The production default: no holder named, so the first usable one in the order is
    # chosen - here process memory, since neither keyctl nor gpg-agent works.
    monkeypatch.delenv(holders.ENV)
    monkeypatch.setattr(holders.KeyctlHolder, "unusable_reason",
                        classmethod(lambda c: "no keyring in this test"))
    monkeypatch.setattr(holders.GpgAgentHolder, "unusable_reason",
                        classmethod(lambda c: "no agent in this test"))
    holders.select()
    _one(caplog, "holder chosen name=memory")


def test_data_key_created(vault_env, caplog):
    _version_one_vault_held_by_its_root(vault_env)
    caplog.clear()
    handlers._service.unlock_recovery(PASS)
    _one(caplog, "data key created")


def test_data_key_created_when_a_version_one_vault_gains_a_password(vault_env, caplog):
    _version_one_vault_held_by_its_root(vault_env)
    step = int(time.time()) // totp.STEP
    caplog.clear()
    handlers._service.add_mfa(UNLOCK, APP_KEY, totp.code(APP, step), {"current": PASS})
    _one(caplog, "data key created")


def test_data_key_rotated(vault_env, caplog):
    svc = handlers._service
    svc.init(PASS)
    config = vault_env / "state" / "jupyterlab-passkey" / "vault-config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({"rotate_days": 1}))
    doc = store.load(store.vault_path())
    doc["data_key"]["created"] = "2020-01-01T00:00:00Z"
    _write_doc(doc)
    svc.lock()
    caplog.clear()
    svc.unlock_recovery(PASS)
    _one(caplog, "data key rotated")


def test_a_manual_rotation_is_reported(vault_env, caplog):
    svc = handlers._service
    svc.init(PASS)
    caplog.clear()
    svc.rotate({"current": PASS})
    _one(caplog, "data key rotated")
