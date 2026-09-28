"""The vault REST API, end to end through a real Jupyter server."""

import base64
import json
import logging
import string
import time

import pytest
import tornado.httpclient
from jupyter_server.utils import url_path_join

from jupyterlab_passkey_extension.vault import handlers, service as vault_service

PASS = "correct horse battery staple"
PRF = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
SECRET = "pw-MUST-NOT-LEAK-7f3a"


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


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #


async def test_status_before_init(jp_fetch, vault_env):
    s = await call(jp_fetch, "status", method="GET")
    assert s["initialized"] is False and s["unlocked"] is False
    assert s["settings"] == {"unlock_minutes": 240}
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
    assert 240 * 60 - 5 <= s["remaining"] <= 240 * 60
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
    # Locked, it still answers: the PRF unwraps its own key, not the held one.
    await call(jp_fetch, "lock")
    assert (await call(jp_fetch, "reveal", body))["value"] == SECRET
    for secret in (SECRET, PRF, wrong):
        assert secret not in caplog.text


async def test_a_passkey_is_registered_only_with_a_proof(jp_fetch, vault_env):
    # A passkey opens the vault and proves a recovery change, so an unlocked vault is
    # not enough to add one over the API: the proof comes with the request.
    await init(jp_fetch)
    slot = {"cred_id": "c1", "rp_id": "h", "prf_salt": "s", "prf": PRF}
    for proof, error in [(None, "this needs a proof: a passkey or the recovery passphrase"),
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
    for proof, error in [(None, "this needs a proof: a passkey or the recovery passphrase"),
                         ({}, "this needs a proof: a passkey or the recovery passphrase"),
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
    monkeypatch.setattr(svc, "_hold", lambda dek: svc.holder().put(svc._vault_id(), dek, 1))
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
    await call(jp_fetch, "config", {"unlock_minutes": 1})
    await init(jp_fetch)
    s = await call(jp_fetch, "status", method="GET")
    assert s["settings"] == {"unlock_minutes": 1}
    assert 55 <= s["remaining"] <= 60


@pytest.mark.parametrize("bad", [0, 1441, "30", True, None, 2.5])
async def test_the_unlock_duration_must_be_1_to_1440(jp_fetch, vault_env, bad):
    code, error = await fails(jp_fetch, "config", {"unlock_minutes": bad})
    assert code == 400 and "1 to 1440" in error


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
    ("unlock", "POST"), ("lock", "POST"), ("reveal", "POST"), ("config", "POST"),
    ("passkeys", "POST"), ("entries", "PATCH"),
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


async def test_no_secret_is_logged(jp_fetch, vault_env, caplog):
    caplog.set_level(logging.DEBUG)
    await init(jp_fetch)
    await add(jp_fetch)
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


def test_the_settings_schema_declares_the_unlock_duration_and_sidebar():
    import pathlib

    schema = json.loads(
        (pathlib.Path(__file__).parents[2] / "schema" / "vault.json").read_text()
    )
    minutes = schema["properties"]["unlockMinutes"]
    assert (minutes["type"], minutes["default"], minutes["minimum"], minutes["maximum"]) == (
        "integer", 240, 1, vault_service.MAX_UNLOCK_MINUTES)
    assert minutes["default"] == vault_service.DEFAULT_UNLOCK_MINUTES
    sidebar = schema["properties"]["sidebar"]
    assert sidebar["enum"] == ["right", "left"] and sidebar["default"] == "right"
