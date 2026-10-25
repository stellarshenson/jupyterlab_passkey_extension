"""The vault REST API, end to end through a real Jupyter server."""

import base64
import json
import logging
import os
import shutil
import string
import time

import pytest
import tornado.httpclient
from jupyter_server.utils import url_path_join

from jupyterlab_passkey_extension.vault import handlers, service as vault_service, store, totp

PASS = "correct horse battery staple"
PRF = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
SECRET = "pw-MUST-NOT-LEAK-7f3a"
NEEDS_PROOF = "this needs a proof: a passkey, a code of the authenticator app or the recovery passphrase"
# An authenticator app: its secret, and the setup key the app is given.
APP = bytes(range(40, 60))
APP_KEY = base64.b32encode(APP).decode()
# The unlock password that is added with the app.
UNLOCK = "an everyday password"


async def call(jp_fetch, action, body=None, method="POST", **params):
    kw = {"method": method}
    if method != "GET":
        kw["body"] = json.dumps(body if body is not None else {})
    if params:
        kw["params"] = params
    r = await jp_fetch("jupyterlab-passkey-extension", "vault", action, **kw)
    return json.loads(r.body) if r.body else None


async def fails(jp_fetch, action, body=None, method="POST", **params):
    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await call(jp_fetch, action, body, method, **params)
    body = exc.value.response.body
    return exc.value.code, (json.loads(body).get("error") if body else None)


async def init(jp_fetch):
    await call(jp_fetch, "init", {"recovery": PASS})


async def add(jp_fetch, name="github/api", password=SECRET, **fields):
    await call(jp_fetch, "entries", {"name": name, "fields": {"password": password, **fields}})


@pytest.fixture
def clock(monkeypatch):
    """The clock the codes are checked against, stopped: a test moves it by whole steps."""
    class Clock:
        now = 1_700_000_010.0

        def time(self):
            return self.now

        def code(self, steps=0, secret=APP):
            """The app's code `steps` time steps from now."""
            return totp.code(secret, int(self.now) // totp.STEP + steps)

        def advance(self, steps):
            self.now += steps * totp.STEP

    stopped = Clock()
    monkeypatch.setattr(totp, "time", stopped)
    return stopped


async def add_mfa(jp_fetch, clock):
    """Add the unlock password and the authenticator app, then move to the next code."""
    await call(jp_fetch, "mfa", {"password": UNLOCK, "secret": APP_KEY, "code": clock.code(),
                                 "proof": {"current": PASS}})
    clock.advance(1)


@pytest.fixture
def entry_clock(monkeypatch):
    """The clock entry dates are written from, stopped: a test sets the stamp."""
    class Clock:
        stamp = "2026-01-02T03:04:05Z"

        def __call__(self):
            return self.stamp

    stopped = Clock()
    monkeypatch.setattr(store, "_now", stopped)
    return stopped


def edit_vault_file(vault_env, change):
    path = vault_env / "vault" / "vault.json"
    doc = json.loads(path.read_text())
    change(doc)
    path.write_text(json.dumps(doc))


def vault_file(vault_env):
    return (vault_env / "vault" / "vault.json").read_text()


def downgrade_slot(kind, secret):
    """Rewrite the vault's `kind` slot with scrypt, as an older build wrote it."""
    path = store.vault_path()
    doc = store.load(path)
    root = store.unwrap_recovery(doc, PASS)
    old = [s for s in doc["slots"] if s.get("type") == kind][0]
    slot = {"type": kind, "kdf": "scrypt", **store.SCRYPT, "salt": store._b64e(os.urandom(16))}
    if "created" in old:
        slot["created"] = old["created"]
    slot["wrapped"] = store._seal(store._scrypt_kek(slot, secret), root, store._slot_aad(slot))
    doc["slots"][doc["slots"].index(old)] = slot
    with open(path, "w") as f:
        json.dump(doc, f)
    return old


def write_config(vault_env, values):
    """Write the vault policy file the server reads, under its state directory."""
    path = vault_env / "state" / "jupyterlab-passkey" / "vault-config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(values))


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #


async def test_status_before_init(jp_fetch, vault_env):
    s = await call(jp_fetch, "status", method="GET")
    assert s["initialized"] is False and s["unlocked"] is False
    assert s["settings"] == {"unlock_minutes": 30, "password_min_length": 12,
                             "reveal_seconds": 60, "rotate_days": 365}
    assert s["holder"]["name"].startswith("memory/")
    assert set(s["holder"]["capabilities"]) == {
        "locked_memory", "no_core_dump", "holder_ttl", "locks_on_restart", "container_isolated"}


def test_status_shows_a_path_under_home_with_a_tilde(vault_env, monkeypatch):
    monkeypatch.setenv("HOME", str(vault_env))
    monkeypatch.setenv("JLAB_PASSKEY_VAULT", str(vault_env / "v" / "vault.json"))
    assert vault_service.VaultService().status()["path"] == "~/v/vault.json"
    monkeypatch.setenv("JLAB_PASSKEY_VAULT", "/srv/vault.json")
    assert vault_service.VaultService().status()["path"] == "/srv/vault.json"


async def test_init_unlocks_for_the_configured_duration(jp_fetch, vault_env):
    await init(jp_fetch)
    s = await call(jp_fetch, "status", method="GET")
    assert s["initialized"] and s["unlocked"]
    assert 30 * 60 - 5 <= s["remaining"] <= 30 * 60
    assert [slot["type"] for slot in s["slots"]] == ["recovery"]


async def test_init_needs_a_passphrase_and_refuses_a_second_vault(jp_fetch, vault_env):
    code, error = await fails(jp_fetch, "init", {"recovery": ""})
    assert code == 400 and "recovery passphrase" in error
    await init(jp_fetch)
    code, error = await fails(jp_fetch, "init", {"recovery": PASS})
    assert code == 400 and "already exists" in error


async def test_lock_then_every_call_that_needs_the_held_key_answers_423(jp_fetch, vault_env):
    await init(jp_fetch)
    await add(jp_fetch)
    await call(jp_fetch, "lock")
    assert (await call(jp_fetch, "status", method="GET"))["unlocked"] is False
    for action, body, method in [
        ("entries", None, "GET"),
        ("entries", {"name": "x", "fields": {}}, "POST"),
        ("entries", {"name": "github/api", "fields": {"url": "u"}}, "PATCH"),
        ("delete", {"name": "github/api"}, "POST"),
        ("reveal", {"name": "github/api"}, "POST"),
        ("stage", {"name": "github/api", "kind": "secret"}, "POST"),
        ("import", {"entries": []}, "POST"),
        ("passkeys-remove", {"cred_id": "c"}, "POST"),
        ("rotate", {"proof": {"current": PASS}}, "POST"),
    ]:
        code, error = await fails(jp_fetch, action, body, method)
        assert code == 423, action
        assert error == "the vault is locked"


async def test_recovery_unlock(jp_fetch, vault_env):
    await init(jp_fetch)
    await call(jp_fetch, "lock")
    code, error = await fails(jp_fetch, "unlock", {"recovery": PASS + "x"})
    assert code == 400 and error == "wrong recovery passphrase"
    assert (await call(jp_fetch, "status", method="GET"))["unlocked"] is False
    s = await call(jp_fetch, "unlock", {"recovery": PASS})
    assert s["unlocked"] is True


@pytest.mark.parametrize("change,error", [
    (lambda s: s.update(m=1), "wrong recovery passphrase"),
    (lambda s: s.update(m=-1), "the recovery slot has an unusable Argon2id cost"),
    (lambda s: s.update(m=2**32), "the recovery slot has an unusable Argon2id cost"),
    (lambda s: s.update(t=-1), "the recovery slot has an unusable Argon2id cost"),
    (lambda s: s.update(p=-1), "the recovery slot has an unusable Argon2id cost"),
])
async def test_an_argon2_parameter_argon2_rejects_answers_400(jp_fetch, vault_env, change, error):
    await init(jp_fetch)
    edit_vault_file(vault_env, lambda d: change(d["slots"][0]))
    await call(jp_fetch, "lock")
    code, message = await fails(jp_fetch, "unlock", {"recovery": PASS})
    assert code == 400 and message == error


async def test_a_fresh_init_writes_an_argon2id_recovery_slot(jp_fetch, vault_env):
    await init(jp_fetch)
    slot = json.loads(vault_file(vault_env))["slots"][0]
    assert (slot["type"], slot["kdf"]) == ("recovery", "argon2id")
    assert (slot["m"], slot["t"], slot["p"]) == (65536, 3, 1)
    assert "n" not in slot and "r" not in slot


async def test_a_recovery_unlock_upgrades_the_recovery_slot(jp_fetch, vault_env):
    await init(jp_fetch)
    await add(jp_fetch)
    downgrade_slot("recovery", PASS)
    await call(jp_fetch, "lock")
    assert (await call(jp_fetch, "unlock", {"recovery": PASS}))["unlocked"] is True
    slot = [s for s in json.loads(vault_file(vault_env))["slots"] if s["type"] == "recovery"][0]
    assert slot["kdf"] == "argon2id"
    assert (slot["m"], slot["t"], slot["p"]) == (65536, 3, 1)
    doc = json.loads(vault_file(vault_env))
    root = store.unwrap_recovery(doc, PASS)
    entries = store.read_entries(doc, store.open_data_key(doc, root))
    assert [e["name"] for e in entries] == ["github/api"]
    assert (await call(jp_fetch, "reveal", {"name": "github/api"}))["value"] == SECRET


async def test_a_password_unlock_upgrades_the_password_slot(jp_fetch, vault_env, clock):
    await init(jp_fetch)
    await add(jp_fetch)
    await add_mfa(jp_fetch, clock)
    old = downgrade_slot("password", UNLOCK)
    await call(jp_fetch, "lock")
    assert (await call(jp_fetch, "unlock", {"password": UNLOCK, "code": clock.code()}))["unlocked"] is True
    slot = [s for s in json.loads(vault_file(vault_env))["slots"] if s["type"] == "password"][0]
    assert slot["kdf"] == "argon2id" and slot["created"] == old["created"]
    doc = json.loads(vault_file(vault_env))
    root = store.unwrap_password(doc, UNLOCK)
    entries = store.read_entries(doc, store.open_data_key(doc, root))
    assert [e["name"] for e in entries] == ["github/api"]


async def test_a_passkey_unlock_leaves_the_file_unchanged(jp_fetch, vault_env):
    await init(jp_fetch)
    await call(jp_fetch, "passkeys", {
        "cred_id": "cred-1", "rp_id": "lab.example", "prf_salt": "c2FsdA", "prf": PRF,
        "proof": {"current": PASS}})
    downgrade_slot("recovery", PASS)
    before = vault_file(vault_env)
    await call(jp_fetch, "lock")
    assert (await call(jp_fetch, "unlock", {"cred_id": "cred-1", "prf": PRF}))["unlocked"] is True
    assert vault_file(vault_env) == before


def test_a_failed_slot_upgrade_does_not_fail_the_unlock(vault_env, monkeypatch, caplog):
    svc = handlers._service
    svc.init(PASS)
    svc.add("github/api", {"password": "s3cret"})
    svc.lock()

    def boom(*args, **kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr(store, "upgrade_slot", boom)
    caplog.set_level(logging.WARNING)
    svc.unlock_recovery(PASS)
    assert svc.read("github/api") == "s3cret"
    assert "Argon2id" in caplog.text and PASS not in caplog.text


@pytest.mark.parametrize("error", [
    OSError("read-only file system"),
    store.VaultError("no entry named 'github/api'"),
])
def test_a_failed_used_stamp_does_not_fail_a_read(vault_env, monkeypatch, caplog, error):
    svc = handlers._service
    svc.init(PASS)
    svc.add("github/api", {"password": SECRET})

    def boom(*args, **kwargs):
        raise error

    monkeypatch.setattr(store, "update_entries", boom)
    caplog.set_level(logging.WARNING)
    assert svc.read("github/api") == SECRET
    assert svc.reveal_proven("github/api", {"current": PASS}) == SECRET
    assert "could not record the entry's last use" in caplog.text
    assert "github/api" not in caplog.text
    assert str(error) not in caplog.text


# --------------------------------------------------------------------------- #
# data-key rotation
# --------------------------------------------------------------------------- #


async def test_rotate_with_the_recovery_proof_changes_the_data_key(jp_fetch, vault_env):
    await init(jp_fetch)
    await add(jp_fetch)
    edit_vault_file(vault_env, lambda d: d["data_key"].update(created="2025-01-01T00:00:00Z"))
    before = await call(jp_fetch, "status", method="GET")
    assert before["rotation"]["created"] == "2025-01-01T00:00:00Z"
    assert before["rotation"]["period_days"] == 365 and before["rotation"]["due"] is True
    result = await call(jp_fetch, "rotate", {"proof": {"current": PASS}})
    after = await call(jp_fetch, "status", method="GET")
    assert result["rotation"] == after["rotation"]
    assert after["rotation"]["created"] != before["rotation"]["created"]
    assert after["rotation"]["age_days"] == 0 and after["rotation"]["due"] is False
    assert (await call(jp_fetch, "reveal", {"name": "github/api"}))["value"] == SECRET


async def test_rotate_needs_an_unlocked_vault(jp_fetch, vault_env):
    await init(jp_fetch)
    await call(jp_fetch, "lock")
    assert await fails(jp_fetch, "rotate", {"proof": {"current": PASS}}) == (
        423, "the vault is locked")


async def test_rotate_needs_a_proof(jp_fetch, vault_env):
    await init(jp_fetch)
    assert await fails(jp_fetch, "rotate", {}) == (403, NEEDS_PROOF)
    assert await fails(jp_fetch, "rotate", {"proof": None}) == (403, NEEDS_PROOF)


async def test_a_code_alone_is_no_proof_for_rotation(jp_fetch, vault_env, clock):
    await init(jp_fetch)
    await add_mfa(jp_fetch, clock)
    assert await fails(jp_fetch, "rotate", {"proof": {"code": clock.code()}}) == (
        403, "a code of the authenticator app is no proof for this - use a passkey or "
             "the recovery passphrase")


async def test_an_unlock_rotates_a_data_key_past_its_period(jp_fetch, vault_env):
    await init(jp_fetch)
    await add(jp_fetch)
    edit_vault_file(vault_env, lambda d: d["data_key"].update(created="2025-01-01T00:00:00Z"))
    await call(jp_fetch, "lock")
    before = json.loads(vault_file(vault_env))["data_key"]["sealed"]
    assert (await call(jp_fetch, "unlock", {"recovery": PASS}))["rotation"]["due"] is False
    assert json.loads(vault_file(vault_env))["data_key"]["sealed"] != before
    assert (await call(jp_fetch, "reveal", {"name": "github/api"}))["value"] == SECRET


def test_a_version_one_fixture_is_migrated_on_unlock(vault_env):
    path = vault_env / "vault" / "vault.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(os.path.join(os.path.dirname(__file__), "fixtures", "vault-1.1.55.json"),
                    path)
    svc = handlers._service
    svc.unlock_recovery(PASS)
    doc = store.load(path)
    assert doc["version"] == 2
    root = store.unwrap_recovery(doc, PASS)
    held = svc.holder().get(svc._vault_id())
    assert held[:32] == root and store.open_data_key(doc, root) == held[32:]
    assert [e["name"] for e in store.read_entries(doc, held[32:])] == ["fixture-entry"]
    assert [e["name"] for e in svc.list_entries()] == ["fixture-entry"]
    with pytest.raises(store.VaultError, match="do not decrypt"):
        store.read_entries(doc, root)


def test_adding_mfa_to_an_unlocked_version_one_vault_rekeys_the_holder(vault_env, clock):
    path = vault_env / "vault" / "vault.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(os.path.join(os.path.dirname(__file__), "fixtures", "vault-1.1.55.json"),
                    path)
    doc = store.load(path)
    root = store.unwrap_recovery(doc, PASS)
    svc = handlers._service
    svc.holder().put(doc["id"], root, 600)
    svc.add_mfa(UNLOCK, APP_KEY, clock.code(), {"current": PASS})
    after = store.load(path)
    assert after["version"] == 2
    held = svc.holder().get(after["id"])
    assert len(held) == 64 and held[:32] == root and held[32:] == store.open_data_key(after, root)
    assert [e["name"] for e in svc.list_entries()] == ["fixture-entry"]
    assert svc.read("fixture-entry") == "fixture-password"


def test_an_adopt_that_cannot_be_written_keeps_a_version_one_file_readable(
        vault_env, monkeypatch, caplog):
    # A read-only vault: the unlock must still serve the file with the root key, and a
    # later write must seal with the version-1 AAD, leaving the version at 1.
    path = vault_env / "vault" / "vault.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(os.path.join(os.path.dirname(__file__), "fixtures", "vault-1.1.55.json"),
                    path)
    svc = handlers._service

    def boom(*args, **kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr(store, "adopt_data_key", boom)
    caplog.set_level(logging.WARNING)
    svc.unlock_recovery(PASS)
    assert "could not give the vault a data key" in caplog.text
    assert PASS not in caplog.text
    svc.add("github/api", {"password": "s3cret"})
    assert store.load(path)["version"] == 1
    assert svc.read("github/api") == "s3cret"


async def test_passkey_register_and_unlock(jp_fetch, vault_env):
    await init(jp_fetch)
    await call(jp_fetch, "passkeys", {
        "cred_id": "cred-1", "rp_id": "lab.example", "prf_salt": "c2FsdA", "prf": PRF, "label": "laptop",
        "proof": {"current": PASS}})
    await call(jp_fetch, "lock")
    code, error = await fails(jp_fetch, "unlock", {"cred_id": "cred-1", "prf": "AAAA"})
    assert code == 400
    assert (await call(jp_fetch, "status", method="GET"))["unlocked"] is False
    s = await call(jp_fetch, "unlock", {"cred_id": "cred-1", "prf": PRF})
    assert s["unlocked"] is True
    held = vault_service.DEFAULT_UNLOCK_MINUTES * 60
    assert held - 5 <= s["remaining"] <= held
    slot = [x for x in s["slots"] if x["type"] == "passkey"][0]
    assert slot["cred_id"] == "cred-1" and slot["rp_id"] == "lab.example" and slot["label"] == "laptop"
    assert slot["prf_salt"] == "c2FsdA"


async def test_a_passkey_reveal_answers_the_password_only_for_a_prf_that_opens_a_slot(
        jp_fetch, vault_env, caplog):
    caplog.set_level(logging.DEBUG)
    await init(jp_fetch)
    await add(jp_fetch)
    await call(jp_fetch, "passkeys", {"cred_id": "c1", "rp_id": "h", "prf_salt": "s", "prf": PRF,
                                       "proof": {"current": PASS}})
    body = {"name": "github/api", "cred_id": "c1", "prf": PRF}
    assert (await call(jp_fetch, "reveal", body))["value"] == SECRET
    wrong = base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode()
    for bad in ({"prf": wrong}, {"cred_id": "c2"}, {"prf": "!"}, {"prf": None}):
        code, error = await fails(jp_fetch, "reveal", {**body, **bad})
        assert code == 403 and error == "the passkey did not open the vault"
    # A locked vault shows nothing, whatever the proof: the passkey unlocks it first.
    await call(jp_fetch, "lock")
    assert await fails(jp_fetch, "reveal", body) == (423, "the vault is locked")
    for secret in (SECRET, PRF, wrong):
        assert secret not in caplog.text


async def test_a_reveal_takes_the_recovery_passphrase_as_its_proof(jp_fetch, vault_env, caplog):
    # A hostname with no passkey, or a user with no authenticator at all, still reads
    # a password in the panel: the passphrase unwraps the key as a passkey's PRF does.
    caplog.set_level(logging.DEBUG)
    await init(jp_fetch)
    await add(jp_fetch)
    body = {"name": "github/api", "current": PASS}
    assert (await call(jp_fetch, "reveal", body))["value"] == SECRET
    for bad in (PASS + "x", "", None):
        assert await fails(jp_fetch, "reveal", {**body, "current": bad}) == (403, "wrong recovery passphrase")
    # A locked vault shows nothing, whatever the proof: the passphrase unlocks it first.
    await call(jp_fetch, "lock")
    assert await fails(jp_fetch, "reveal", body) == (423, "the vault is locked")
    assert (await call(jp_fetch, "status", method="GET"))["unlocked"] is False
    for secret in (SECRET, PASS):
        assert secret not in caplog.text


async def test_a_passkey_is_registered_only_with_a_proof(jp_fetch, vault_env):
    # A passkey opens the vault and proves a recovery change, so an unlocked vault is
    # not enough to add one over the API: the proof comes with the request.
    await init(jp_fetch)
    slot = {"cred_id": "c1", "rp_id": "h", "prf_salt": "s", "prf": PRF}
    for proof, error in [(None, NEEDS_PROOF),
                         ({"current": PASS + "x"}, "wrong recovery passphrase")]:
        code, message = await fails(jp_fetch, "passkeys", {**slot, "proof": proof})
        assert (code, message) == (403, error)
    s = await call(jp_fetch, "status", method="GET")
    assert [x["type"] for x in s["slots"]] == ["recovery"]
    # The proof, not an unlock: a locked vault takes the recovery passphrase ...
    await call(jp_fetch, "lock")
    await call(jp_fetch, "passkeys", {**slot, "proof": {"current": PASS}})
    # ... and an existing passkey, but only one whose PRF opens its slot.
    second = {"cred_id": "c2", "rp_id": "h", "prf_salt": "s", "prf": PRF}
    code, message = await fails(jp_fetch, "passkeys", {**second, "proof": {"cred_id": "c1", "prf": "AAAA"}})
    assert (code, message) == (403, "the passkey did not open the vault")
    await call(jp_fetch, "passkeys", {**second, "proof": {"cred_id": "c1", "prf": PRF}})
    s = await call(jp_fetch, "status", method="GET")
    assert s["unlocked"] is False
    assert [x["cred_id"] for x in s["slots"] if x["type"] == "passkey"] == ["c1", "c2"]


# --------------------------------------------------------------------------- #
# password and authenticator app
# --------------------------------------------------------------------------- #

NO_PROOF = (403, "the unlock password is no proof for this - use a passkey, a code of the "
                 "authenticator app or the recovery passphrase")
TOO_MANY = (403, "too many wrong codes - codes are refused until the vault is unlocked with a "
                 "passkey or the recovery passphrase")


def test_codes_match_the_rfc_6238_test_vectors():
    # The RFC's SHA-1 vectors have eight digits; a six-digit code is their last six.
    secret = b"12345678901234567890"
    for at, eight in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                      (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]:
        assert totp.code(secret, at // totp.STEP) == eight[-6:]
        assert totp.matching_step(secret, eight[-6:], now=at) == at // totp.STEP
        # With the space an app shows in the middle, as the panel's code field takes it.
        assert totp.matching_step(secret, f"{eight[2:5]} {eight[5:]}", now=at) == at // totp.STEP
    # A setup key as an app shows it: lower case, in groups.
    assert totp.decode_secret("gezd gnbv gy3t qojq gezd gnbv gy3t qojq") == secret
    for bad in ("", "MZXW6===", "not base32!", None, base64.b32encode(bytes(65)).decode()):
        assert totp.decode_secret(bad) is None
    for bad in ("", "12345", "1234567", "12345a", "１２３４５６", None, 123456):
        assert totp.matching_step(secret, bad, now=59) is None


def store_secret(vault_env):
    from jupyterlab_passkey_extension.vault import store

    svc = handlers._service
    held = svc.holder().get(svc._vault_id())
    return store.authenticator_secret(store.load(store.vault_path()), held[32:])


async def test_the_password_and_the_app_are_added_together_with_a_right_code_and_a_proof(
        jp_fetch, vault_env, clock, caplog):
    caplog.set_level(logging.DEBUG)
    await init(jp_fetch)
    before = vault_file(vault_env)
    right = {"password": UNLOCK, "secret": APP_KEY, "code": clock.code(), "proof": {"current": PASS}}
    short = (400, "an unlock password is at least 12 characters")
    no_secret = (400, "an authenticator app's secret is base32 of 16 to 64 bytes")
    for bad, refusal in [({"code": clock.code(5)}, (403, "wrong code")),
                         ({"code": None}, (403, "wrong code")),
                         ({"proof": None}, (403, NEEDS_PROOF)),
                         ({"proof": {"current": PASS + "x"}}, (403, "wrong recovery passphrase")),
                         ({"proof": {"code": clock.code()}}, (403, "the vault has no authenticator app")),
                         ({"proof": {"password": UNLOCK}}, NO_PROOF),
                         ({"password": "eleven char"}, short),
                         ({"password": None}, short),
                         ({"secret": APP_KEY[:16]}, no_secret),
                         ({"secret": None}, no_secret)]:
        assert await fails(jp_fetch, "mfa", {**right, **bad}) == refusal
        assert vault_file(vault_env) == before
    assert (await call(jp_fetch, "status", method="GET"))["authenticator"] is None
    assert await fails(jp_fetch, "unlock", {"password": UNLOCK, "code": clock.code()}) == (
        400, "the vault has no unlock password")
    await call(jp_fetch, "mfa", right)
    # One write adds both. The password slot is built as the recovery slot is.
    doc = json.loads(vault_file(vault_env))
    assert [x["type"] for x in doc["slots"]] == ["recovery", "password"]
    recovery, slot = doc["slots"]
    assert (slot["kdf"], slot["m"], slot["t"], slot["p"]) == tuple(recovery[k] for k in ("kdf", "m", "t", "p"))
    # The file tells that an app was added and since when; its secret is sealed.
    app = doc["authenticator"]
    assert set(app) == {"created", "secret"}
    for clear in (UNLOCK, APP_KEY, base64.b64encode(APP).decode(), APP.hex()):
        assert clear not in vault_file(vault_env)
    assert store_secret(vault_env) == APP
    # Status shows both without a key.
    s = await call(jp_fetch, "status", method="GET")
    assert [x for x in s["slots"] if x["type"] == "password"] == [
        {k: slot[k] for k in ("type", "kdf", "m", "t", "p", "created")}]
    assert s["authenticator"] == {"created": app["created"]}
    # One pair at a time.
    clock.advance(1)
    assert await fails(jp_fetch, "mfa", {**right, "code": clock.code()}) == (
        409, "the vault already has a password and authenticator app - remove them first")
    # Locked, status still says only that the app is there.
    await call(jp_fetch, "lock")
    assert (await call(jp_fetch, "status", method="GET"))["authenticator"] == {"created": app["created"]}
    for secret in (UNLOCK, "eleven char", APP_KEY):
        assert secret not in caplog.text


async def test_the_unlock_password_opens_the_vault_only_with_a_code(jp_fetch, vault_env, clock):
    await init(jp_fetch)
    await add_mfa(jp_fetch, clock)
    await call(jp_fetch, "lock")

    async def locked():
        return (await call(jp_fetch, "status", method="GET"))["unlocked"] is False

    # The password alone, a code alone, and a wrong half of the pair open nothing.
    assert await fails(jp_fetch, "unlock", {"password": UNLOCK}) == (
        403, "a password unlock needs a code of the authenticator app")
    code, _ = await fails(jp_fetch, "unlock", {"code": clock.code()})
    assert code == 400
    for wrong in (UNLOCK + "x", PASS, "", None):
        code, _ = await fails(jp_fetch, "unlock", {"password": wrong, "code": clock.code()})
        assert code == 400
    assert await fails(jp_fetch, "unlock", {"password": UNLOCK, "code": "000000"}) == (403, "wrong code")
    assert await locked()
    # Both open it. A wrong password did not use up the code.
    assert (await call(jp_fetch, "unlock", {"password": UNLOCK, "code": clock.code()}))["unlocked"] is True
    # A code opens it once.
    await call(jp_fetch, "lock")
    assert await fails(jp_fetch, "unlock", {"password": UNLOCK, "code": clock.code()}) == (
        403, "that code was already used - wait for the next one")
    clock.advance(1)
    # Five wrong codes in a row stop the pair, the right code included.
    for _ in range(5):
        assert await fails(jp_fetch, "unlock", {"password": UNLOCK, "code": "000000"}) == (403, "wrong code")
    assert await fails(jp_fetch, "unlock", {"password": UNLOCK, "code": clock.code()}) == TOO_MANY
    assert await locked()
    # The recovery passphrase still opens it, and the pair works again after that.
    await call(jp_fetch, "unlock", {"recovery": PASS})
    await call(jp_fetch, "lock")
    assert (await call(jp_fetch, "unlock", {"password": UNLOCK, "code": clock.code()}))["unlocked"] is True


async def test_a_code_proves_on_an_unlocked_vault_and_the_password_alone_only_a_reveal(
        jp_fetch, vault_env, clock):
    await init(jp_fetch)
    await add(jp_fetch)
    await add_mfa(jp_fetch, clock)
    slot = {"cred_id": "c1", "rp_id": "h", "prf_salt": "s", "prf": PRF}
    reveal = {"name": "github/api"}
    # The password alone shows a password. It adds no way in and replaces no secret.
    assert (await call(jp_fetch, "reveal", {**reveal, "password": UNLOCK}))["value"] == SECRET
    for wrong in (UNLOCK + "x", "", None):
        assert await fails(jp_fetch, "reveal", {**reveal, "password": wrong}) == (403, "wrong unlock password")
    before = vault_file(vault_env)
    for action, body in [("passkeys", slot), ("recovery", {"recovery": "a new passphrase"})]:
        assert await fails(jp_fetch, action, {**body, "proof": {"password": UNLOCK}}) == NO_PROOF
        assert vault_file(vault_env) == before
    # A code proves a reveal, a new passkey and a recovery replacement on an unlocked
    # vault: it checks the code, then hands the held root to the slot writer. It holds
    # no key of its own, so a rotation still refuses it
    # (test_a_code_alone_is_no_proof_for_rotation).
    assert (await call(jp_fetch, "reveal", {**reveal, "code": clock.code()}))["value"] == SECRET
    clock.advance(1)
    await call(jp_fetch, "passkeys", {**slot, "proof": {"code": clock.code()}})
    clock.advance(1)
    await call(jp_fetch, "recovery", {"recovery": "second passphrase", "proof": {"code": clock.code()}})
    s = await call(jp_fetch, "status", method="GET")
    assert [x["cred_id"] for x in s["slots"] if x["type"] == "passkey"] == ["c1"]
    # Locked, neither half proves anything alone: only the pair opens the vault.
    await call(jp_fetch, "lock")
    locked = (423, "the vault is locked")
    assert await fails(jp_fetch, "reveal", {**reveal, "password": UNLOCK}) == locked
    assert await fails(jp_fetch, "reveal", {**reveal, "code": clock.code()}) == locked
    assert await fails(jp_fetch, "passkeys", {**slot, "cred_id": "c2", "proof": {"code": clock.code()}}) == locked
    assert await fails(jp_fetch, "recovery", {"recovery": "third", "proof": {"code": clock.code()}}) == locked
    assert (await call(jp_fetch, "status", method="GET"))["unlocked"] is False
    assert (await call(jp_fetch, "unlock", {"recovery": "second passphrase"}))["unlocked"]


async def test_the_shortest_unlock_password_comes_from_the_server_config(
        jp_fetch, vault_env, clock):
    await init(jp_fetch)
    write_config(vault_env, {"password_min_length": 16})
    pair = {"secret": APP_KEY, "code": clock.code(), "proof": {"current": PASS}}
    assert await fails(jp_fetch, "mfa", {**pair, "password": "x" * 15}) == (
        400, "an unlock password is at least 16 characters")
    await call(jp_fetch, "mfa", {**pair, "password": "x" * 16})
    assert (await call(jp_fetch, "status", method="GET"))["settings"]["password_min_length"] == 16


async def test_a_code_is_accepted_one_step_either_side_once_and_five_wrong_ones_stop_codes(
        jp_fetch, vault_env, clock):
    await init(jp_fetch)
    await add(jp_fetch)
    await add_mfa(jp_fetch, clock)

    async def reveal(code):
        return await call(jp_fetch, "reveal", {"name": "github/api", "code": code})

    async def refused(code):
        return await fails(jp_fetch, "reveal", {"name": "github/api", "code": code})

    clock.advance(3)
    # The step before the current one, then the step after it.
    assert (await reveal(clock.code(-1)))["value"] == SECRET
    assert (await reveal(clock.code(1)))["value"] == SECRET
    # Once: the same code again, and a code of an earlier step than the last one used.
    used = (403, "that code was already used - wait for the next one")
    assert await refused(clock.code(1)) == used
    assert await refused(clock.code()) == used
    # Two steps away, either side.
    clock.advance(10)
    assert await refused(clock.code(-2)) == (403, "wrong code")
    assert await refused(clock.code(2)) == (403, "wrong code")
    # A right code clears the count; five wrong ones in a row stop every code.
    assert (await reveal(clock.code()))["value"] == SECRET
    clock.advance(1)
    for _ in range(5):
        assert await refused("000000") == (403, "wrong code")
    assert await refused(clock.code()) == TOO_MANY
    # The other proofs still work, and an unlock with one of them starts the count again.
    assert (await call(jp_fetch, "reveal", {"name": "github/api", "current": PASS}))["value"] == SECRET
    await call(jp_fetch, "lock")
    await call(jp_fetch, "unlock", {"recovery": PASS})
    assert (await reveal(clock.code()))["value"] == SECRET


async def test_the_password_and_the_app_are_removed_together(jp_fetch, vault_env, clock):
    await init(jp_fetch)
    await add(jp_fetch)
    assert await fails(jp_fetch, "mfa-remove") == (400, "the vault has no password and authenticator app")
    await add_mfa(jp_fetch, clock)
    await call(jp_fetch, "lock")
    assert await fails(jp_fetch, "mfa-remove") == (423, "the vault is locked")
    await call(jp_fetch, "unlock", {"recovery": PASS})
    await call(jp_fetch, "mfa-remove")
    doc = json.loads(vault_file(vault_env))
    assert "authenticator" not in doc and [x["type"] for x in doc["slots"]] == ["recovery"]
    assert await fails(jp_fetch, "reveal", {"name": "github/api", "code": clock.code()}) == (
        403, "the vault has no authenticator app")
    await call(jp_fetch, "lock")
    assert await fails(jp_fetch, "unlock", {"password": UNLOCK, "code": clock.code()}) == (
        400, "the vault has no unlock password")
    await call(jp_fetch, "unlock", {"recovery": PASS})
    await add_mfa(jp_fetch, clock)
    assert (await call(jp_fetch, "status", method="GET"))["authenticator"] is not None


async def test_a_vault_of_an_earlier_build_holds_one_without_the_other(jp_fetch, vault_env, clock):
    # 1.1.28 to 1.1.31 added the password and the app apart from each other.
    await init(jp_fetch)
    await add_mfa(jp_fetch, clock)
    conflict = (409, "the vault already has a password and authenticator app - remove them first")
    pair = {"password": UNLOCK, "secret": APP_KEY, "proof": {"current": PASS}}
    # A password and no app: the password opens the vault alone, and no pair is added over it.
    edit_vault_file(vault_env, lambda doc: doc.pop("authenticator"))
    await call(jp_fetch, "lock")
    assert (await call(jp_fetch, "unlock", {"password": UNLOCK}))["unlocked"] is True
    assert await fails(jp_fetch, "mfa", {**pair, "code": clock.code()}) == conflict
    await call(jp_fetch, "mfa-remove")
    assert [x["type"] for x in json.loads(vault_file(vault_env))["slots"]] == ["recovery"]
    # An app and no password: the same, and Remove removes the app.
    await add_mfa(jp_fetch, clock)
    edit_vault_file(vault_env, lambda doc: doc["slots"].pop())
    assert await fails(jp_fetch, "mfa", {**pair, "code": clock.code()}) == conflict
    await call(jp_fetch, "mfa-remove")
    assert "authenticator" not in json.loads(vault_file(vault_env))


async def test_passkey_removal(jp_fetch, vault_env):
    await init(jp_fetch)
    await call(jp_fetch, "passkeys", {"cred_id": "c1", "rp_id": "h", "prf_salt": "s", "prf": PRF,
                                       "proof": {"current": PASS}})
    await call(jp_fetch, "passkeys-remove", {"cred_id": "c1"})
    s = await call(jp_fetch, "status", method="GET")
    assert [x["type"] for x in s["slots"]] == ["recovery"]
    code, _ = await fails(jp_fetch, "passkeys-remove", {"cred_id": "c1"})
    assert code == 400


async def test_recovery_replacement_needs_a_proof_in_the_same_request(jp_fetch, vault_env):
    await init(jp_fetch)
    await call(jp_fetch, "passkeys", {"cred_id": "c1", "rp_id": "h", "prf_salt": "s", "prf": PRF,
                                       "proof": {"current": PASS}})
    # Unlocked is not enough; a wrong proof changes nothing.
    for proof, error in [(None, NEEDS_PROOF),
                         ({}, NEEDS_PROOF),
                         ({"current": PASS + "x"}, "wrong recovery passphrase"),
                         ({"cred_id": "c1", "prf": "AAAA"}, "the passkey did not open the vault"),
                         ({"cred_id": "c2", "prf": PRF}, "the passkey did not open the vault")]:
        code, message = await fails(jp_fetch, "recovery", {"recovery": "never set", "proof": proof})
        assert (code, message) == (403, error)
    await call(jp_fetch, "recovery", {"recovery": "brand new passphrase", "proof": {"current": PASS}})
    await call(jp_fetch, "lock")
    code, _ = await fails(jp_fetch, "unlock", {"recovery": PASS})
    assert code == 400
    # A passkey proves it too, on a locked vault as well.
    await call(jp_fetch, "recovery", {"recovery": "third passphrase",
                                      "proof": {"cred_id": "c1", "prf": PRF}})
    assert (await call(jp_fetch, "unlock", {"recovery": "third passphrase"}))["unlocked"]


async def test_the_vault_locks_itself_at_expiry(jp_fetch, vault_env, monkeypatch):
    svc = handlers._service
    monkeypatch.setattr(svc, "_hold",
                        lambda root, dek: svc.holder().put(svc._vault_id(), root + dek, 1))
    await init(jp_fetch)
    assert (await call(jp_fetch, "status", method="GET"))["unlocked"]
    time.sleep(1.5)
    assert (await call(jp_fetch, "status", method="GET"))["unlocked"] is False
    code, _ = await fails(jp_fetch, "entries", method="GET")
    assert code == 423


# --------------------------------------------------------------------------- #
# settings
# --------------------------------------------------------------------------- #


async def test_the_unlock_duration_setting_reaches_the_holder(jp_fetch, vault_env):
    write_config(vault_env, {"unlock_minutes": 1})
    await init(jp_fetch)
    s = await call(jp_fetch, "status", method="GET")
    assert s["settings"] == {"unlock_minutes": 1, "password_min_length": 12,
                             "reveal_seconds": 60, "rotate_days": 365}
    assert 55 <= s["remaining"] <= 60


async def test_the_config_file_values_reach_status(jp_fetch, vault_env):
    write_config(vault_env, {"unlock_minutes": 45, "reveal_seconds": 120,
                             "password_min_length": 20, "rotate_days": 30})
    assert (await call(jp_fetch, "status", method="GET"))["settings"] == {
        "unlock_minutes": 45, "password_min_length": 20, "reveal_seconds": 120,
        "rotate_days": 30}


async def test_an_absent_or_invalid_config_key_uses_its_default(jp_fetch, vault_env):
    defaults = {"unlock_minutes": 30, "password_min_length": 12,
                "reveal_seconds": 60, "rotate_days": 365}
    assert (await call(jp_fetch, "status", method="GET"))["settings"] == defaults
    write_config(vault_env, {"unlock_minutes": 0, "password_min_length": "20",
                             "reveal_seconds": 3601, "rotate_days": True})
    assert (await call(jp_fetch, "status", method="GET"))["settings"] == defaults


async def test_the_reveal_window_comes_from_the_server_config(jp_fetch, vault_env):
    assert (await call(jp_fetch, "status", method="GET"))["settings"]["reveal_seconds"] == 60
    write_config(vault_env, {"reveal_seconds": 300})
    assert (await call(jp_fetch, "status", method="GET"))["settings"]["reveal_seconds"] == 300
    write_config(vault_env, {"reveal_seconds": 0})
    assert (await call(jp_fetch, "status", method="GET"))["settings"]["reveal_seconds"] == 0


async def test_the_config_action_is_gone(jp_fetch, vault_env):
    code, _ = await fails(jp_fetch, "config", {"unlock_minutes": 30})
    assert code == 404


# --------------------------------------------------------------------------- #
# entries
# --------------------------------------------------------------------------- #


async def test_every_field_round_trips(jp_fetch, vault_env):
    await init(jp_fetch)
    await add(jp_fetch, username="me", url="https://github.com", category="infrastructure",
              notes='{"scope": "repo"}')
    [entry] = (await call(jp_fetch, "entries", method="GET"))["entries"]
    assert entry["name"] == "github/api" and entry["username"] == "me"
    assert entry["url"] == "https://github.com" and entry["category"] == "infrastructure"
    assert entry["notes"] == '{"scope": "repo"}' and entry["created"] and entry["updated"]
    assert (await call(jp_fetch, "reveal", {"name": "github/api"}))["value"] == SECRET
    assert (await call(jp_fetch, "reveal", {"name": "github/api", "field": "username"}))["value"] == "me"


async def test_the_list_never_carries_a_password(jp_fetch, vault_env):
    await init(jp_fetch)
    await add(jp_fetch)
    r = await jp_fetch("jupyterlab-passkey-extension", "vault", "entries", method="GET")
    assert SECRET not in r.body.decode()
    assert "password" not in json.loads(r.body)["entries"][0]


async def test_add_refuses_a_duplicate_and_edit_changes_only_given_fields(jp_fetch, vault_env):
    await init(jp_fetch)
    await add(jp_fetch)
    code, error = await fails(jp_fetch, "entries", {"name": "github/api", "fields": {}})
    assert code == 409 and "already exists" in error
    before = (await call(jp_fetch, "entries", method="GET"))["entries"][0]
    time.sleep(1.1)
    await call(jp_fetch, "entries", {"name": "github/api", "fields": {"url": "https://x"}}, method="PATCH")
    after = (await call(jp_fetch, "entries", method="GET"))["entries"][0]
    assert after["url"] == "https://x" and after["updated"] > before["updated"]
    assert (await call(jp_fetch, "reveal", {"name": "github/api"}))["value"] == SECRET


async def test_a_new_entry_has_no_used_stamp(jp_fetch, vault_env, entry_clock):
    await init(jp_fetch)
    await add(jp_fetch)
    [entry] = (await call(jp_fetch, "entries", method="GET"))["entries"]
    assert entry["used"] == ""


async def test_a_reveal_stamps_used_and_leaves_created_and_updated(jp_fetch, vault_env, entry_clock):
    await init(jp_fetch)
    await add(jp_fetch)
    [entry] = (await call(jp_fetch, "entries", method="GET"))["entries"]
    created, updated = entry["created"], entry["updated"]
    entry_clock.stamp = "2026-01-02T03:05:06Z"
    assert (await call(jp_fetch, "reveal", {"name": "github/api", "current": PASS}))["value"] == SECRET
    [entry] = (await call(jp_fetch, "entries", method="GET"))["entries"]
    assert entry["used"] == "2026-01-02T03:05:06Z"
    assert entry["created"] == created and entry["updated"] == updated
    entry_clock.stamp = "2026-01-02T03:06:07Z"
    assert (await call(jp_fetch, "reveal", {"name": "github/api"}))["value"] == SECRET
    [entry] = (await call(jp_fetch, "entries", method="GET"))["entries"]
    assert entry["used"] == "2026-01-02T03:06:07Z"
    assert entry["created"] == created and entry["updated"] == updated


async def test_an_edit_stamps_used_and_updated(jp_fetch, vault_env, entry_clock):
    await init(jp_fetch)
    await add(jp_fetch)
    entry_clock.stamp = "2026-01-02T03:05:06Z"
    await call(jp_fetch, "entries", {"name": "github/api", "fields": {"url": "https://x"}}, method="PATCH")
    [entry] = (await call(jp_fetch, "entries", method="GET"))["entries"]
    assert entry["updated"] == "2026-01-02T03:05:06Z" and entry["used"] == "2026-01-02T03:05:06Z"


async def test_the_used_stamp_survives_a_lock_and_unlock(jp_fetch, vault_env, entry_clock):
    await init(jp_fetch)
    await add(jp_fetch)
    entry_clock.stamp = "2026-01-02T03:05:06Z"
    await call(jp_fetch, "reveal", {"name": "github/api"})
    await call(jp_fetch, "lock")
    await call(jp_fetch, "unlock", {"recovery": PASS})
    [entry] = (await call(jp_fetch, "entries", method="GET"))["entries"]
    assert entry["used"] == "2026-01-02T03:05:06Z"


async def test_the_used_stamp_is_sealed_in_the_vault_file(jp_fetch, vault_env, entry_clock):
    await init(jp_fetch)
    await add(jp_fetch, name="github/raw-check")
    entry_clock.stamp = "2026-01-02T03:05:06Z"
    await call(jp_fetch, "reveal", {"name": "github/raw-check"})
    text = vault_file(vault_env)
    assert "github/raw-check" not in text and "2026-01-02T03:05:06Z" not in text


async def test_delete_and_missing_names(jp_fetch, vault_env):
    await init(jp_fetch)
    await add(jp_fetch)
    await call(jp_fetch, "delete", {"name": "github/api"})
    assert (await call(jp_fetch, "entries", method="GET"))["entries"] == []
    for action, body, method in [
        ("delete", {"name": "github/api"}, "POST"),
        ("reveal", {"name": "github/api"}, "POST"),
        ("entries", {"name": "github/api", "fields": {}}, "PATCH"),
    ]:
        code, error = await fails(jp_fetch, action, body, method)
        assert code == 404 and "no entry named" in error


@pytest.mark.parametrize("name", ["", "   ", "a\nb", "x" * 201, None, 5])
async def test_bad_names_are_refused(jp_fetch, vault_env, name):
    await init(jp_fetch)
    code, _ = await fails(jp_fetch, "entries", {"name": name, "fields": {}})
    assert code == 400


async def test_generate(jp_fetch, vault_env):
    value = (await call(jp_fetch, "generate", method="GET", length="30"))["value"]
    assert len(value) == 30
    plain = (await call(jp_fetch, "generate", method="GET", symbols="0"))["value"]
    assert len(plain) == 24 and all(c in string.ascii_letters + string.digits for c in plain)
    code, _ = await fails(jp_fetch, "generate", method="GET", length="5")
    assert code == 400


def test_generated_passwords_leave_out_characters_that_look_alike():
    # Read off the Show image or typed on a phone, l/I/1/| and O/0 get confused.
    for _ in range(200):
        assert not set(vault_service.generate()) & set("lI1|O0")


def test_generated_passwords_hold_every_character_class():
    for _ in range(200):
        value = vault_service.generate()
        assert len(value) == 24
        assert any(c.islower() for c in value) and any(c.isupper() for c in value)
        assert any(c.isdigit() for c in value) and any(c in vault_service.SYMBOLS for c in value)
        assert not set(value) & set("'\"\\` ")


async def test_import_adds_new_names_and_reports_skipped(jp_fetch, vault_env):
    await init(jp_fetch)
    await add(jp_fetch)
    result = await call(jp_fetch, "import", {"entries": [
        {"service": "github/api", "password": "other"},
        {"service": "nas/ugos", "username": "konrad", "password": "p", "notes": {"ip": "192.168.1.2"}},
    ]})
    assert result == {"added": 1, "skipped": ["github/api"]}
    assert (await call(jp_fetch, "reveal", {"name": "github/api"}))["value"] == SECRET
    entries = {e["name"]: e for e in (await call(jp_fetch, "entries", method="GET"))["entries"]}
    assert json.loads(entries["nas/ugos"]["notes"]) == {"ip": "192.168.1.2"}


async def test_stage_hands_the_value_to_the_relay_for_copy(jp_fetch, vault_env):
    await init(jp_fetch)
    await add(jp_fetch)
    nonce = (await call(jp_fetch, "stage", {"name": "github/api", "kind": "secret"}))["nonce"]
    assert (vault_env / "relay" / f"{nonce}.secret").read_text() == SECRET
    code, _ = await fails(jp_fetch, "stage", {"name": "github/api", "kind": "pass"})
    assert code == 400


async def test_stage_refuses_a_code_too_long_to_show(jp_fetch, vault_env):
    await init(jp_fetch)
    await add(jp_fetch, password="x" * 300)
    code, error = await fails(jp_fetch, "stage", {"name": "github/api", "kind": "code"})
    assert code == 400 and "too long" in error


# --------------------------------------------------------------------------- #
# the REST surface
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("action,method", [
    ("status", "GET"), ("entries", "GET"), ("generate", "GET"), ("init", "POST"),
    ("unlock", "POST"), ("lock", "POST"), ("rotate", "POST"), ("reveal", "POST"),
    ("passkeys", "POST"), ("entries", "PATCH"), ("mfa", "POST"), ("mfa-remove", "POST"),
])
async def test_every_action_needs_the_token(http_server_client, jp_base_url, vault_env, action, method):
    path = url_path_join(jp_base_url, "jupyterlab-passkey-extension", "vault", action)
    kw = {"method": method}
    if method != "GET":
        # A matching XSRF cookie and header pass the XSRF check, which runs first,
        # so the 403 can only come from the missing token.
        kw["body"] = json.dumps({"recovery": PASS})
        kw["headers"] = {"Cookie": "_xsrf=x", "X-XSRFToken": "x"}
    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await http_server_client.fetch(path, **kw)
    assert exc.value.code == 403
    assert not (vault_env / "vault" / "vault.json").exists()


async def test_no_secret_is_logged(jp_fetch, vault_env, caplog, clock):
    caplog.set_level(logging.DEBUG)
    await init(jp_fetch)
    await add(jp_fetch)
    # The unlock password and the authenticator app: the password, the setup key, a
    # right code and a wrong one.
    codes = [clock.code(), clock.code(1), "135790"]
    await add_mfa(jp_fetch, clock)
    await call(jp_fetch, "reveal", {"name": "github/api", "code": codes[1]})
    errors = [await fails(jp_fetch, "reveal", {"name": "github/api", "code": codes[2]}),
              await fails(jp_fetch, "mfa", {"password": UNLOCK, "secret": APP_KEY, "code": codes[2],
                                            "proof": {"current": PASS}}),
              await fails(jp_fetch, "unlock", {"password": UNLOCK, "code": codes[2]})]
    await call(jp_fetch, "mfa-remove")
    for told in [UNLOCK, APP_KEY, *(f'"{c}"' for c in codes)]:
        assert told not in caplog.text
    assert not any(c in str(errors) or APP_KEY in str(errors) for c in codes)
    await call(jp_fetch, "passkeys", {"cred_id": "c1", "rp_id": "h", "prf_salt": "s", "prf": PRF,
                                       "proof": {"current": PASS}})
    await call(jp_fetch, "reveal", {"name": "github/api"})
    await call(jp_fetch, "reveal", {"name": "github/api", "cred_id": "c1", "prf": PRF})
    generated = (await call(jp_fetch, "generate", method="GET"))["value"]
    await call(jp_fetch, "lock")
    await fails(jp_fetch, "unlock", {"recovery": PASS + "-wrong"})
    await call(jp_fetch, "unlock", {"recovery": PASS})
    await call(jp_fetch, "unlock", {"cred_id": "c1", "prf": PRF})
    svc = handlers._service
    dek = svc.holder().get(svc._vault_id())
    edited, imported, new_pass = "edited-MUST-NOT-LEAK", "imported-MUST-NOT-LEAK", "new-pass-MUST-NOT-LEAK"
    await call(jp_fetch, "entries", {"name": "github/api", "fields": {"password": edited}}, method="PATCH")
    await call(jp_fetch, "import", {"entries": [{"service": "db/prod", "password": imported}]})
    await call(jp_fetch, "stage", {"name": "github/api", "kind": "secret"})
    await call(jp_fetch, "recovery", {"recovery": new_pass, "proof": {"current": PASS}})
    # A malformed body carrying a secret must not be echoed into the log either.
    with pytest.raises(tornado.httpclient.HTTPClientError):
        await jp_fetch("jupyterlab-passkey-extension", "vault", "unlock", method="POST",
                       body='{"recovery": "' + SECRET)
    for secret in (PASS, SECRET, PRF, generated, edited, imported, new_pass, dek.hex(), str(dek)):
        assert secret not in caplog.text


async def test_status_carries_no_secret(jp_fetch, vault_env):
    await init(jp_fetch)
    await add(jp_fetch)
    await call(jp_fetch, "passkeys", {"cred_id": "c1", "rp_id": "h", "prf_salt": "s", "prf": PRF,
                                       "proof": {"current": PASS}})
    r = await jp_fetch("jupyterlab-passkey-extension", "vault", "status", method="GET")
    text = r.body.decode()
    for secret in (PASS, SECRET, PRF, "wrapped", "hkdf_salt"):
        assert secret not in text


async def test_a_holder_failure_is_a_clean_500(jp_fetch, vault_env, monkeypatch):
    svc = handlers._service

    def broken(vault_id, dek, ttl):
        raise OSError("keyctl padd failed: quota exceeded")

    monkeypatch.setattr(svc.holder(), "put", broken)
    code, error = await fails(jp_fetch, "init", {"recovery": PASS})
    assert code == 500 and "quota exceeded" in error


def test_two_vaults_under_one_user_never_share_the_unlocked_key(vault_env, monkeypatch):
    # One uid, two vault files (two labs, or JLAB_PASSKEY_VAULT): unlocking B once made
    # A decrypt with B's key and report "wrong key or a damaged file".
    svc = handlers._service
    a, b = vault_env / "a" / "vault.json", vault_env / "b" / "vault.json"
    monkeypatch.setenv("JLAB_PASSKEY_VAULT", str(a))
    svc.init(PASS)
    svc.add("github/api", {"password": "from-a"})
    monkeypatch.setenv("JLAB_PASSKEY_VAULT", str(b))
    svc.init(PASS)
    monkeypatch.setenv("JLAB_PASSKEY_VAULT", str(a))
    # vault_env pins the memory holder, which keeps one key at a time: A is locked,
    # never opened with B's key. keyctl keeping both is test_keyctl_keeps_one_key_per_vault.
    with pytest.raises(vault_service.Locked):
        svc.read("github/api")


def test_lock_clears_the_key_even_when_the_file_has_moved(vault_env):
    # lock reads the vault id from the file; with the file moved or damaged it must
    # still clear the key this server put in the holder.
    svc = handlers._service
    svc.init(PASS)
    path = vault_env / "vault" / "vault.json"
    moved = vault_env / "moved.json"
    path.rename(moved)
    svc.lock()
    moved.rename(path)
    with pytest.raises(vault_service.Locked):
        svc.read("anything")


def test_lock_on_a_damaged_file_still_clears_the_held_key(vault_env):
    svc = handlers._service
    svc.init(PASS)
    held = svc._vault_id()
    (vault_env / "vault" / "vault.json").write_text("not json")
    svc.lock()  # no error: the key this server held is cleared
    assert svc.holder().get(held) is None
    # Nothing held any more: a second lock cannot read the id, and says what that means.
    with pytest.raises(vault_service.VaultError, match="on keyctl or gpg-agent a key unlocked before a server restart can stay held"):
        svc.lock()


def test_lock_after_a_restart_clears_the_key_of_the_file_it_points_at(vault_env):
    # A restarted server holds nothing of its own, and the holder can still hold the
    # key (keyctl, gpg-agent): lock clears it by the id in the file.
    handlers._service.init(PASS)
    held = handlers._service._vault_id()
    restarted = vault_service.VaultService()
    restarted.lock()
    assert restarted.holder().get(held) is None


def test_status_revision_changes_with_the_entries(vault_env):
    # An open panel re-reads the entries when this changes - from any client.
    svc = handlers._service
    svc.init(PASS)
    before = svc.status()["revision"]
    svc.add("github/api", {"password": "x"})
    assert svc.status()["revision"] != before


def test_lock_with_no_vault_says_so(vault_env):
    with pytest.raises(vault_service.VaultError, match="no vault at .* until its unlock duration ends"):
        handlers._service.lock()


async def test_an_unknown_action_is_404(jp_fetch, vault_env):
    code, _ = await fails(jp_fetch, "nonsense", {})
    assert code == 404


async def test_a_body_that_is_not_an_object_is_400(jp_fetch, vault_env):
    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch("jupyterlab-passkey-extension", "vault", "init", method="POST", body="[1]")
    assert exc.value.code == 400


def test_the_settings_schema_declares_only_the_sidebar():
    import pathlib

    schema = json.loads(
        (pathlib.Path(__file__).parents[2] / "schema" / "vault.json").read_text()
    )
    # The vault's policy lives in the server's configuration file, not the page.
    assert set(schema["properties"]) == {"sidebar"}
    sidebar = schema["properties"]["sidebar"]
    assert sidebar["type"] == "string" and sidebar["default"] == "right"
    assert [(option["const"], option["title"]) for option in sidebar["oneOf"]] == [
        ("right", "Right"),
        ("left", "Left"),
    ]
