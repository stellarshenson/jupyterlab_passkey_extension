"""The vault file: keyslots, tamper detection, atomic and serialised writes."""

import base64
import json
import os
import shutil
import stat
import subprocess
import sys

import pytest

from jupyterlab_passkey_extension.vault import store
from jupyterlab_passkey_extension.vault.store import VaultError

PASS = "correct horse battery staple"
PRF = bytes(range(32))
PRF_B64URL = base64.urlsafe_b64encode(PRF).rstrip(b"=").decode()
FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "vault-1.1.55.json")


@pytest.fixture
def path(vault_env):
    return store.vault_path()


def _from_fixture(path):
    """Put the 1.1.55 vault fixture at `path`; return its unwrapped key and document."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    shutil.copyfile(FIXTURE, path)
    doc = store.load(path)
    return store.unwrap_recovery(doc, PASS), doc


def _root(path, passphrase=PASS):
    """The root key of a vault, as its recovery passphrase unwraps it."""
    return store.unwrap_recovery(store.load(path), passphrase)


def _add(path, dek, name, password="s3cret"):
    store.update_entries(path, dek, lambda es: es.append({"name": name, "password": password}))


def _downgrade(path, root, kind, secret):
    """Rewrite the `kind` slot with scrypt, as an older build wrote it."""
    doc = store.load(path)
    old = [s for s in doc["slots"] if s.get("type") == kind][0]
    slot = {"type": kind, "kdf": "scrypt", **store.SCRYPT, "salt": store._b64e(os.urandom(16))}
    if "created" in old:
        slot["created"] = old["created"]
    slot["wrapped"] = store._seal(store._scrypt_kek(slot, secret), root, store._slot_aad(slot))
    doc["slots"][doc["slots"].index(old)] = slot
    with open(path, "w") as f:
        json.dump(doc, f)
    return old


def test_create_writes_one_private_file_with_names_hidden(path):
    dek = store.create(path, PASS)
    _add(path, dek, "github/api", "tok-123")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    raw = open(path, "rb").read()
    assert b"github/api" not in raw and b"tok-123" not in raw
    doc = store.load(path)
    assert doc["format"] == store.FORMAT and doc["version"] == store.VERSION
    assert [s["type"] for s in doc["slots"]] == ["recovery"]


def test_the_default_path_follows_xdg_data_home(monkeypatch, tmp_path):
    monkeypatch.delenv("JLAB_PASSKEY_VAULT", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert store.vault_path() == str(tmp_path / "jupyterlab-passkey" / "vault.json")


def test_a_set_path_expands_the_home_directory_and_is_absolute(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("JLAB_PASSKEY_VAULT", "~/vaults/v.json")
    assert store.vault_path() == str(tmp_path / "home" / "vaults" / "v.json")
    monkeypatch.setenv("JLAB_PASSKEY_VAULT", "v.json")
    assert store.vault_path() == str(tmp_path / "v.json")


@pytest.mark.parametrize("passphrase", ["", None])
def test_create_needs_a_recovery_passphrase(path, passphrase):
    with pytest.raises(VaultError, match="recovery passphrase is required"):
        store.create(path, passphrase)
    assert not os.path.exists(path)


def test_create_refuses_an_existing_vault(path):
    store.create(path, PASS)
    with pytest.raises(VaultError, match="already exists"):
        store.create(path, PASS)


def test_create_writes_version_two_with_a_sealed_data_key(path):
    dek = store.create(path, PASS)
    doc = store.load(path)
    assert doc["version"] == 2
    assert set(doc["data_key"]) == {"created", "sealed"}
    root = _root(path)
    assert root != dek
    assert store.open_data_key(doc, root) == dek
    with pytest.raises(VaultError, match="do not decrypt"):
        store.read_entries(doc, root)


def test_any_slot_opens_the_same_vault(path):
    dek = store.create(path, PASS)
    _add(path, dek, "a")
    root = _root(path)
    store.add_passkey(path, root, "cred-1", "lab.example", "salt", PRF, "laptop")
    doc = store.load(path)
    assert store.unwrap_recovery(doc, PASS) == root
    assert store.unwrap_passkey(doc, "cred-1", PRF) == root
    assert [e["name"] for e in store.read_entries(doc, dek)] == ["a"]


def test_a_wrong_passphrase_or_prf_is_refused(path):
    store.create(path, PASS)
    root = _root(path)
    store.add_passkey(path, root, "cred-1", "lab.example", "salt", PRF, "laptop")
    doc = store.load(path)
    with pytest.raises(VaultError, match="wrong recovery passphrase"):
        store.unwrap_recovery(doc, PASS + "x")
    with pytest.raises(VaultError, match="did not open"):
        store.unwrap_passkey(doc, "cred-1", bytes(32))
    with pytest.raises(VaultError, match="does not have that passkey"):
        store.unwrap_passkey(doc, "cred-2", PRF)


def test_a_passkey_cannot_be_registered_twice(path):
    store.create(path, PASS)
    root = _root(path)
    store.add_passkey(path, root, "cred-1", "lab.example", "salt", PRF, "laptop")
    with pytest.raises(VaultError, match="already has that passkey"):
        store.add_passkey(path, root, "cred-1", "lab.example", "salt", PRF, "laptop")


def test_the_recovery_slot_is_replaced_never_removed(path):
    dek = store.create(path, PASS)
    root = _root(path)
    store.add_passkey(path, root, "cred-1", "lab.example", "salt", PRF, "laptop")
    store.replace_recovery(path, root, "new passphrase")
    doc = store.load(path)
    assert [s["type"] for s in doc["slots"]] == ["recovery", "passkey"]
    assert store.unwrap_recovery(doc, "new passphrase") == root
    assert store.open_data_key(doc, root) == dek
    with pytest.raises(VaultError):
        store.unwrap_recovery(doc, PASS)
    # remove_passkey only ever removes passkey slots - no call reaches the recovery slot.
    with pytest.raises(VaultError, match="does not have that passkey"):
        store.remove_passkey(path, None)
    store.remove_passkey(path, "cred-1")
    assert [s["type"] for s in store.load(path)["slots"]] == ["recovery"]


def test_a_write_under_the_wrong_key_is_refused(path):
    store.create(path, PASS)
    with pytest.raises(VaultError):
        store.add_passkey(path, bytes(32), "cred-1", "lab.example", "salt", PRF, "x")
    with pytest.raises(VaultError):
        store.replace_recovery(path, bytes(32), "other")


def _tamper(path, mutate):
    doc = json.load(open(path))
    mutate(doc)
    with open(path, "w") as f:
        json.dump(doc, f)


def _flip(b64):
    raw = bytearray(base64.b64decode(b64))
    raw[-1] ^= 1
    return base64.b64encode(bytes(raw)).decode()


def test_changed_entries_fail_to_decrypt(path):
    dek = store.create(path, PASS)
    _tamper(path, lambda d: d.update(entries=_flip(d["entries"])))
    with pytest.raises(VaultError, match="do not decrypt"):
        store.read_entries(store.load(path), dek)


@pytest.mark.parametrize("change", [
    lambda s: s.update(n=2**11),
    lambda s: s.update(salt=base64.b64encode(os.urandom(16)).decode()),
    lambda s: s.update(wrapped=_flip(s["wrapped"])),
])
def test_a_changed_recovery_slot_fails_to_open(path, change):
    store.create(path, PASS)
    _tamper(path, lambda d: change(d["slots"][0]))
    with pytest.raises(VaultError):
        store.unwrap_recovery(store.load(path), PASS)


def test_a_changed_argon2_parameter_fails_to_open(path):
    store.create(path, PASS)
    _tamper(path, lambda d: d["slots"][0].update(m=2**12))
    with pytest.raises(VaultError, match="wrong recovery passphrase"):
        store.unwrap_recovery(store.load(path), PASS)


@pytest.mark.parametrize("change,match", [
    (lambda s: s.update(m=1), "wrong recovery passphrase"),
    (lambda s: s.update(m=-1), "the recovery slot has an unusable Argon2id cost"),
    (lambda s: s.update(m=2**32), "the recovery slot has an unusable Argon2id cost"),
    (lambda s: s.update(t=-1), "the recovery slot has an unusable Argon2id cost"),
    (lambda s: s.update(t=9), "the recovery slot has an unusable Argon2id cost"),
    (lambda s: s.update(p=-1), "the recovery slot has an unusable Argon2id cost"),
])
def test_an_argon2_parameter_argon2_rejects_raises_vault_error(path, change, match):
    store.create(path, PASS)
    _tamper(path, lambda d: change(d["slots"][0]))
    with pytest.raises(VaultError, match=match):
        store.unwrap_recovery(store.load(path), PASS)


def test_a_slot_with_an_unknown_kdf_is_refused(path):
    store.create(path, PASS)
    _tamper(path, lambda d: d["slots"][0].update(kdf="bcrypt"))
    with pytest.raises(VaultError, match="unknown KDF 'bcrypt'"):
        store.unwrap_recovery(store.load(path), PASS)


@pytest.mark.parametrize("change", [
    lambda s: s.update(rp_id="evil.example"),
    lambda s: s.update(prf_salt="other"),
    lambda s: s.update(created="2000-01-01T00:00:00Z"),
    lambda s: s.update(wrapped=_flip(s["wrapped"])),
])
def test_a_changed_passkey_slot_fails_to_open(path, change):
    store.create(path, PASS)
    store.add_passkey(path, _root(path), "cred-1", "lab.example", "salt", PRF, "laptop")
    _tamper(path, lambda d: change(d["slots"][1]))
    with pytest.raises(VaultError):
        store.unwrap_passkey(store.load(path), "cred-1", PRF)


def test_a_failed_write_leaves_the_previous_vault(path, monkeypatch):
    dek = store.create(path, PASS)
    _add(path, dek, "kept")

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(store.os, "replace", boom)
    with pytest.raises(OSError):
        _add(path, dek, "lost")
    monkeypatch.undo()
    names = [e["name"] for e in store.read_entries(store.load(path), dek)]
    assert names == ["kept"]
    leftovers = [f for f in os.listdir(os.path.dirname(path)) if f.endswith(".tmp")]
    assert leftovers == []


_WRITER = """
import sys
from jupyterlab_passkey_extension.vault import store
dek = bytes.fromhex(sys.argv[2])
for i in range(20):
    store.update_entries(sys.argv[1], dek, lambda es, i=i: es.append({"name": f"{sys.argv[3]}-{i}"}))
"""


def test_two_concurrent_writers_lose_nothing(path):
    dek = store.create(path, PASS)
    procs = [
        subprocess.Popen([sys.executable, "-c", _WRITER, path, dek.hex(), tag])
        for tag in ("a", "b")
    ]
    assert [p.wait(timeout=60) for p in procs] == [0, 0]
    entries = store.read_entries(store.load(path), dek)
    assert len(entries) == 40


def test_each_slot_keeps_its_own_kdf_parameters(path, monkeypatch):
    dek, _ = _from_fixture(path)  # its recovery slot was written at n=2**17
    monkeypatch.setattr(store, "SCRYPT", {"n": 2**12, "r": 8, "p": 1})
    assert store.unwrap_recovery(store.load(path), PASS) == dek


def test_an_argon2id_slot_round_trips(path):
    dek = store.create(path, PASS)
    slot = store.load(path)["slots"][0]
    assert slot["type"] == "recovery" and slot["kdf"] == "argon2id"
    assert (slot["m"], slot["t"], slot["p"]) == (65536, 3, 1)
    root = store.unwrap_recovery(store.load(path), PASS)
    assert store.open_data_key(store.load(path), root) == dek


def test_an_old_scrypt_slot_still_opens(path):
    key, doc = _from_fixture(path)
    assert doc["slots"][0]["kdf"] == "scrypt"
    assert store.unwrap_recovery(store.load(path), PASS) == key
    assert [e["name"] for e in store.read_entries(doc, key)] == ["fixture-entry"]


def test_adopt_data_key_migrates_the_1_1_55_fixture(path):
    key, doc = _from_fixture(path)
    old_wrapped = doc["slots"][0]["wrapped"]
    entries = store.read_entries(doc, key)
    dek, changed = store.adopt_data_key(path, key)
    assert changed is True and dek != key
    after = store.load(path)
    assert after["version"] == 2
    assert after["slots"][0]["wrapped"] == old_wrapped
    assert after["data_key"]["created"] == store.data_key_created(after)
    assert store.open_data_key(after, key) == dek
    assert store.read_entries(after, dek) == entries
    # The old single key is no longer the data key.
    with pytest.raises(VaultError, match="do not decrypt"):
        store.read_entries(after, key)
    # A second call opens the file's data key and writes nothing.
    assert store.adopt_data_key(path, key) == (dek, False)


def test_rotate_data_key_replaces_the_key_and_keeps_every_slot(path):
    dek = store.create(path, PASS)
    root = _root(path)
    _add(path, dek, "a")
    store.add_passkey(path, root, "cred-1", "lab.example", "salt", PRF, "laptop")
    store.set_mfa(path, root, dek, "unlock password", b"app secret")
    entries = store.read_entries(store.load(path), dek)
    first = store.rotate_data_key(path, root)
    assert first != dek
    doc = store.load(path)
    assert store.read_entries(doc, first) == entries
    assert store.authenticator_secret(doc, first) == b"app secret"
    with pytest.raises(VaultError, match="do not decrypt"):
        store.read_entries(doc, dek)
    # The slots still wrap the root, so every unlock method still opens the vault.
    assert store.unwrap_recovery(doc, PASS) == root
    assert store.unwrap_password(doc, "unlock password") == root
    assert store.unwrap_passkey(doc, "cred-1", PRF) == root
    second = store.rotate_data_key(path, root)
    assert second not in (dek, first)
    doc = store.load(path)
    assert store.read_entries(doc, second) == entries
    assert store.authenticator_secret(doc, second) == b"app secret"
    with pytest.raises(VaultError, match="do not decrypt"):
        store.read_entries(doc, first)
    assert store.unwrap_recovery(doc, PASS) == root


def test_a_tampered_data_key_block_fails_to_open(path):
    store.create(path, PASS)
    root = _root(path)
    _tamper(path, lambda d: d["data_key"].update(sealed=_flip(d["data_key"]["sealed"])))
    with pytest.raises(VaultError, match="data key does not decrypt"):
        store.open_data_key(store.load(path), root)


@pytest.mark.parametrize("change", [
    lambda d: d.pop("data_key"),
    lambda d: d.update(data_key=[]),
    lambda d: d["data_key"].pop("created"),
    lambda d: d["data_key"].update(created=None),
    lambda d: d["data_key"].update(sealed=5),
])
def test_a_version_two_file_without_a_usable_data_key_is_damaged(path, change):
    store.create(path, PASS)
    _tamper(path, change)
    with pytest.raises(VaultError, match="damaged: data_key missing"):
        store.load(path)


def test_a_scrypt_cost_beyond_what_1_1_55_wrote_is_refused(path):
    _from_fixture(path)
    _tamper(path, lambda d: d["slots"][0].update(n=2**18))
    with pytest.raises(VaultError, match="the recovery slot has an unusable scrypt cost"):
        store.unwrap_recovery(store.load(path), PASS)


def test_upgrade_slot_rewrites_the_used_recovery_slot_once(path):
    root, doc = _from_fixture(path)
    old = doc["slots"][0]
    store.add_passkey(path, root, "cred-1", "lab.example", "salt", PRF, "laptop")
    before = store.load(path)
    others = [s for s in before["slots"] if s["type"] != "recovery"]
    entries = store.read_entries(before, root)
    assert store.upgrade_slot(path, root, "recovery", PASS) is True
    after = store.load(path)
    slot = [s for s in after["slots"] if s["type"] == "recovery"][0]
    assert slot["type"] == "recovery" and slot["kdf"] == "argon2id"
    assert (slot["m"], slot["t"], slot["p"]) == (65536, 3, 1)
    assert slot["salt"] != old["salt"]
    assert [s for s in after["slots"] if s["type"] != "recovery"] == others
    assert store.read_entries(after, root) == entries
    assert store.unwrap_recovery(after, PASS) == root
    text = open(path).read()
    assert store.upgrade_slot(path, root, "recovery", PASS) is False
    assert open(path).read() == text


def test_upgrade_slot_keeps_the_password_slot_created_stamp(path):
    dek = store.create(path, PASS)
    root = _root(path)
    store.set_mfa(path, root, dek, "unlock password", b"app secret")
    old = _downgrade(path, root, "password", "unlock password")
    assert store.upgrade_slot(path, root, "password", "unlock password") is True
    slot = [s for s in store.load(path)["slots"] if s["type"] == "password"][0]
    assert slot["type"] == "password" and slot["created"] == old["created"]
    assert slot["kdf"] == "argon2id"
    assert store.unwrap_password(store.load(path), "unlock password") == root


def test_slot_metadata_carries_no_key_material(path):
    store.create(path, PASS)
    store.add_passkey(path, _root(path), "cred-1", "lab.example", "salt", PRF, "laptop")
    meta = store.slot_metadata(store.load(path))
    for slot in meta:
        assert not {"wrapped", "salt", "hkdf_salt"} & set(slot)
    assert meta[1]["label"] == "laptop" and meta[1]["rp_id"] == "lab.example"


def test_load_explains_a_missing_or_foreign_file(path):
    with pytest.raises(VaultError, match="vault init"):
        store.load(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump({"format": "other"}, f)
    with pytest.raises(VaultError, match="not a jupyterlab-passkey vault"):
        store.load(path)
    with open(path, "w") as f:
        json.dump({"format": store.FORMAT, "version": 99}, f)
    with pytest.raises(VaultError, match="version 99"):
        store.load(path)


def test_load_refuses_a_slot_that_is_not_an_object(path):
    store.create(path, "pw")
    doc = store.load(path)
    doc["slots"].append("not a slot")
    with open(path, "w") as f:
        json.dump(doc, f)
    with pytest.raises(VaultError, match="damaged"):
        store.load(path)


def test_load_refuses_a_missing_or_malformed_id(path):
    # The id goes into keyring and agent names; nothing but 16 hex characters passes.
    store.create(path, "pw")
    good = store.load(path)
    for bad in (None, "", "abc", "0123456789abcdeg", "0123456789abcdef --x"):
        doc = {**good, "id": bad}
        with open(path, "w") as f:
            json.dump(doc, f)
        with pytest.raises(VaultError, match="id missing"):
            store.load(path)


def test_each_new_vault_gets_its_own_id(tmp_path, vault_env):
    a, b = str(tmp_path / "a" / "v.json"), str(tmp_path / "b" / "v.json")
    store.create(a, "pw")
    store.create(b, "pw")
    assert store.load(a)["id"] != store.load(b)["id"]


def test_b64url_decode_accepts_unpadded_values():
    assert store.b64url_decode(PRF_B64URL) == PRF
