"""The vault file: one JSON document whose entries are sealed under a data key.

    {
      "format": "jupyterlab-passkey-vault", "version": 2, "id": hex16,
      "slots": [
        {"type": "recovery", "kdf": "argon2id", "m": 65536, "t": 3, "p": 1,
         "salt": b64, "wrapped": b64},
        {"type": "passkey", "cred_id": b64url, "rp_id": host, "prf_salt": b64url,
         "hkdf_salt": b64, "label": text, "created": iso, "wrapped": b64},
        {"type": "password", "kdf": "argon2id", "m": 65536, "t": 3, "p": 1,
         "salt": b64, "created": iso, "wrapped": b64}
      ],
      "entries": b64(nonce | AES-256-GCM(data key, JSON list of entries)),
      "data_key": {"created": iso, "sealed": b64(nonce | AES-256-GCM(root key, data key))},
      "authenticator": {"created": iso, "secret": b64(nonce | AES-256-GCM(data key, secret))}
    }

Two keys. The root key (32 random bytes) is what the slots wrap under their own
key-encryption key - `Argon2id(passphrase)` for the recovery slot, `HKDF(PRF)` for a
passkey slot, `Argon2id(password)` for the one unlock password slot a vault can have; a
slot written by an earlier build keeps its scrypt parameters and is rewritten under
Argon2id on its next unlock - so any one slot opens the root, and adding or removing a
slot never re-encrypts the entries. Every slot parameter except the
wrapped key itself and its label is bound into the wrap as associated data, so a changed
salt, KDF cost, credential or hostname fails to open rather than opening wrongly.

The data key (32 random bytes) encrypts every entry, names included, as one blob, and is
itself sealed under the root key. Rotating the data key re-seals the entries and the
authenticator secret and leaves every slot as it is, so the slots keep opening the root
and a copy of an old data key stops reading the vault. A version-1 file, which had one
key for both jobs, gains a data key on its first unlock (`adopt_data_key`); its slots
stay as they are and now wrap the root, which for that file is the old single key.

`authenticator` is there only while the vault has an authenticator app. Its secret is
sealed under the data key, so a locked vault tells that an app exists and nothing more.
The unlock password slot and the app are added and removed together (`set_mfa`,
`remove_mfa`): the service opens the vault with the password only for a right code.

`id` is random per vault. It names the unlocked key in its holder, so two vaults under
one user (two labs, or a second `JLAB_PASSKEY_VAULT`) never read each other's key.

Every change is a read-modify-write under an exclusive lock on `<vault>.lock`, written to
a temp file in the same directory, fsynced and renamed over the vault.
"""

import base64
import contextlib
import fcntl
import json
import os
import re
import tempfile
from datetime import datetime, timezone

from argon2.exceptions import HashingError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT = "jupyterlab-passkey-vault"
VERSION = 2
# Argon2id cost for new recovery and password slots: 64 MiB, three passes, one lane.
# Each slot stores its own cost, so raising these later leaves existing slots readable.
# SCRYPT is the cost older builds wrote, opened from each slot's stored n, r and p, and
# it is what the tests that fabricate old slots use.
ARGON2 = {"m": 65536, "t": 3, "p": 1}
SCRYPT = {"n": 2**17, "r": 8, "p": 1}
_ARGON2_BOUNDS = {"m": 2**18, "t": 8, "p": 8}
# The scrypt cost 1.1.55 and earlier wrote, as a fixed literal. It must not follow SCRYPT
# at call time: the tests cheapen SCRYPT to n=2**10, while the 1.1.55 fixture's n=2**17
# slot must still open.
_SCRYPT_BOUNDS = {"n": 2**17, "r": 8, "p": 1}
# The version-1 strings stay as that build wrote them: a version-1 file is read with
# them, never written. Everything this build writes carries the version-2 strings.
_ENTRIES_AAD = f"{FORMAT}/v1/entries".encode()
_AUTHENTICATOR_AAD = f"{FORMAT}/v1/authenticator".encode()
_ENTRIES_AAD_V2 = f"{FORMAT}/v2/entries".encode()
_AUTHENTICATOR_AAD_V2 = f"{FORMAT}/v2/authenticator".encode()
_DATA_KEY_AAD = f"{FORMAT}/v2/data_key".encode()
_HKDF_INFO = f"{FORMAT}/passkey".encode()


class VaultError(Exception):
    """A refusal the caller reports as one line: wrong secret, no vault, a clash."""


def vault_path():
    explicit = os.environ.get("JLAB_PASSKEY_VAULT")
    if explicit:
        # JupyterHub, compose and systemd pass the value with no shell to expand a ~;
        # absolute, it is the file status reports.
        return os.path.abspath(os.path.expanduser(explicit))
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share"
    )
    return os.path.join(base, "jupyterlab-passkey", "vault.json")


def _b64e(b):
    return base64.b64encode(b).decode("ascii")


def _b64d(s):
    return base64.b64decode(s, validate=True)


def b64url_decode(s):
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _stamp(when):
    """A date as the vault writes it: UTC, to the second."""
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now():
    return _stamp(datetime.now(timezone.utc))


# --------------------------------------------------------------------------- #
# sealing
# --------------------------------------------------------------------------- #


def _seal(key, plaintext, aad):
    nonce = os.urandom(12)
    return _b64e(nonce + AESGCM(key).encrypt(nonce, plaintext, aad))


def _open(key, sealed, aad):
    blob = _b64d(sealed)
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


def _entries_aad(doc):
    """The associated data the entries of this document were sealed with."""
    return _ENTRIES_AAD if doc.get("version") == 1 else _ENTRIES_AAD_V2


def _authenticator_aad(doc):
    """The associated data the authenticator secret of this document was sealed with."""
    return _AUTHENTICATOR_AAD if doc.get("version") == 1 else _AUTHENTICATOR_AAD_V2


def _slot_aad(slot):
    bound = {k: v for k, v in slot.items() if k not in ("wrapped", "label")}
    return (f"{FORMAT}/slot/" + json.dumps(bound, sort_keys=True)).encode()


def _scrypt_kek(slot, secret):
    """The key of an older recovery or unlock password slot, from the secret typed."""
    for name, bound in _SCRYPT_BOUNDS.items():
        value = slot.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= bound:
            raise VaultError(f"the {slot.get('type')} slot has an unusable scrypt cost")
    return Scrypt(
        salt=_b64d(slot["salt"]), length=32, n=slot["n"], r=slot["r"], p=slot["p"]
    ).derive(secret.encode("utf-8"))


def _argon2_kek(slot, secret):
    """The key of a recovery or an unlock password slot, from the secret typed."""
    for name, bound in _ARGON2_BOUNDS.items():
        value = slot.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= bound:
            raise VaultError(f"the {slot.get('type')} slot has an unusable Argon2id cost")
    return hash_secret_raw(
        secret=secret.encode("utf-8"), salt=_b64d(slot["salt"]),
        time_cost=slot["t"], memory_cost=slot["m"], parallelism=slot["p"],
        hash_len=32, type=Type.ID,
    )


def _kek(slot, secret):
    """The key-encryption key of a typed-secret slot, by the KDF the slot names."""
    kdf = slot.get("kdf")
    if kdf == "scrypt":
        return _scrypt_kek(slot, secret)
    if kdf == "argon2id":
        return _argon2_kek(slot, secret)
    raise VaultError(f"unknown KDF {kdf!r} in the {slot.get('type')} slot")


def _passkey_kek(slot, prf):
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=_b64d(slot["hkdf_salt"]), info=_HKDF_INFO
    ).derive(prf)


def _recovery_slot(root, passphrase):
    if not isinstance(passphrase, str) or passphrase == "":
        raise VaultError("a recovery passphrase is required")
    slot = {"type": "recovery", "kdf": "argon2id", **ARGON2, "salt": _b64e(os.urandom(16))}
    slot["wrapped"] = _seal(_kek(slot, passphrase), root, _slot_aad(slot))
    return slot


def _password_slot(root, password):
    slot = {"type": "password", "kdf": "argon2id", **ARGON2, "salt": _b64e(os.urandom(16)),
            "created": _now()}
    slot["wrapped"] = _seal(_kek(slot, password), root, _slot_aad(slot))
    return slot


def _passkey_slot(root, cred_id, rp_id, prf_salt, prf, label):
    slot = {
        "type": "passkey", "cred_id": cred_id, "rp_id": rp_id, "prf_salt": prf_salt,
        "hkdf_salt": _b64e(os.urandom(16)), "created": _now(),
    }
    slot["wrapped"] = _seal(_passkey_kek(slot, prf), root, _slot_aad(slot))
    slot["label"] = label
    return slot


# --------------------------------------------------------------------------- #
# the file
# --------------------------------------------------------------------------- #


@contextlib.contextmanager
def _locked(path):
    """Hold an exclusive lock covering one read-modify-write of `path`."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _write(path, doc):
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".vault-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def exists(path):
    return os.path.exists(path)


def load(path):
    """The vault document, checked for shape. VaultError when absent or unreadable."""
    try:
        with open(path) as f:
            doc = json.load(f)
    except FileNotFoundError:
        raise VaultError(f"no vault at {path} - run `jupyterlab-passkey vault init`")
    except (OSError, ValueError) as e:
        raise VaultError(f"cannot read the vault at {path}: {e}")
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise VaultError(f"{path} is not a jupyterlab-passkey vault")
    if doc.get("version") not in (1, VERSION):
        raise VaultError(f"{path} is vault format version {doc.get('version')}; this code reads 1 or {VERSION}")
    if (not isinstance(doc.get("slots"), list) or not all(isinstance(x, dict) for x in doc["slots"])
            or not isinstance(doc.get("entries"), str)):
        raise VaultError(f"{path} is damaged: slots or entries missing")
    # The id goes into keyring and agent names, so only its own shape is accepted.
    if not isinstance(doc.get("id"), str) or not re.fullmatch(r"[0-9a-f]{16}", doc["id"]):
        raise VaultError(f"{path} is damaged: id missing")
    if doc["version"] == VERSION:
        data_key = doc.get("data_key")
        if (not isinstance(data_key, dict) or not isinstance(data_key.get("created"), str)
                or not isinstance(data_key.get("sealed"), str)):
            raise VaultError(f"{path} is damaged: data_key missing")
    return doc


def create(path, passphrase):
    """Write a new, empty vault with a recovery slot. Returns the data key."""
    root = os.urandom(32)
    dek = os.urandom(32)
    slot = _recovery_slot(root, passphrase)
    with _locked(path):
        if exists(path):
            raise VaultError(f"a vault already exists at {path}")
        _write(path, {
            "format": FORMAT, "version": VERSION, "id": os.urandom(8).hex(), "slots": [slot],
            "entries": _seal(dek, b"[]", _ENTRIES_AAD_V2),
            "data_key": {"created": _now(), "sealed": _seal(root, dek, _DATA_KEY_AAD)},
        })
    return dek


def _unwrap_typed(doc, kind, secret, wrong, missing):
    """The root key from the slot of type `kind`, which a typed secret opens."""
    for slot in doc["slots"]:
        if slot.get("type") == kind:
            try:
                return _open(_kek(slot, secret), slot["wrapped"], _slot_aad(slot))
            except (InvalidTag, ValueError, KeyError, TypeError, OverflowError, HashingError):
                raise VaultError(wrong)
    raise VaultError(missing)


def unwrap_recovery(doc, passphrase):
    return _unwrap_typed(doc, "recovery", passphrase, "wrong recovery passphrase",
                         "the vault has no recovery slot")


def unwrap_password(doc, password):
    return _unwrap_typed(doc, "password", password, "wrong unlock password",
                         "the vault has no unlock password")


def unwrap_passkey(doc, cred_id, prf):
    for slot in doc["slots"]:
        if slot.get("type") == "passkey" and slot.get("cred_id") == cred_id:
            try:
                return _open(_passkey_kek(slot, prf), slot["wrapped"], _slot_aad(slot))
            except (InvalidTag, ValueError, KeyError, TypeError):
                raise VaultError("the passkey did not open the vault")
    raise VaultError("this vault does not have that passkey")


def open_data_key(doc, root):
    """The data key of `doc`, opened with `root`: for a version-1 file the root itself,
    where the two jobs had one key."""
    if doc.get("version") == 1:
        return root
    try:
        return _open(root, doc["data_key"]["sealed"], _DATA_KEY_AAD)
    except (InvalidTag, ValueError, KeyError, TypeError):
        raise VaultError("the vault data key does not decrypt - a damaged file")


def _adopt_locked(doc, root):
    """Migrate `doc` in memory from version 1 to version 2. Returns (data key, changed).

    The slots already wrap `root`; only the entries and the authenticator secret are
    re-sealed under a new data key, which is then sealed under the root. The caller
    holds the file's lock and writes `doc` when `changed`."""
    if doc["version"] != 1:
        return open_data_key(doc, root), False
    entries = read_entries(doc, root)
    secret = authenticator_secret(doc, root)
    dek = os.urandom(32)
    doc["entries"] = _seal(dek, json.dumps(entries).encode(), _ENTRIES_AAD_V2)
    if secret is not None:
        doc["authenticator"]["secret"] = _seal(dek, secret, _AUTHENTICATOR_AAD_V2)
    doc["version"] = VERSION
    doc["data_key"] = {"created": _now(), "sealed": _seal(root, dek, _DATA_KEY_AAD)}
    return dek, True


def adopt_data_key(path, root):
    """Give a version-1 file a data key, under the file's lock. Returns (data key,
    whether the file was rewritten). No slot is touched: the slots already wrap `root`."""
    with _locked(path):
        doc = load(path)
        dek, changed = _adopt_locked(doc, root)
        if changed:
            _write(path, doc)
    return dek, changed


def rotate_data_key(path, root):
    """Re-seal the entries and the authenticator secret under a new random data key,
    under the file's lock, and return that key. A version-1 file is adopted first; no
    slot is touched, so every slot still opens the same root."""
    with _locked(path):
        doc = load(path)
        current, _ = _adopt_locked(doc, root)
        entries = read_entries(doc, current)
        secret = authenticator_secret(doc, current)
        dek = os.urandom(32)
        doc["entries"] = _seal(dek, json.dumps(entries).encode(), _ENTRIES_AAD_V2)
        if secret is not None:
            doc["authenticator"]["secret"] = _seal(dek, secret, _AUTHENTICATOR_AAD_V2)
        doc["data_key"] = {"created": _now(), "sealed": _seal(root, dek, _DATA_KEY_AAD)}
        _write(path, doc)
    return dek


def data_key_created(doc):
    """When the data key was made; None for a version-1 file, which has no data key."""
    if doc.get("version") == 1:
        return None
    return doc["data_key"]["created"]


def read_entries(doc, dek):
    try:
        entries = json.loads(_open(dek, doc["entries"], _entries_aad(doc)))
    except (InvalidTag, ValueError):
        raise VaultError("the vault entries do not decrypt - wrong key or a damaged file")
    if not isinstance(entries, list):
        raise VaultError("the vault entries are damaged")
    return entries


def _check_dek(doc, dek):
    # Any write re-seals under `dek`; a wrong key must never overwrite good data.
    read_entries(doc, dek)


def _check_root(doc, root):
    # A slot this build adds wraps `root`, so the root must be the one the file uses.
    read_entries(doc, open_data_key(doc, root))


def update_entries(path, dek, change):
    """Apply `change(entries) -> result` to the entries and write them back. A
    version-1 file stays version 1: its entries are sealed with its own AAD."""
    with _locked(path):
        doc = load(path)
        entries = read_entries(doc, dek)
        result = change(entries)
        doc["entries"] = _seal(dek, json.dumps(entries).encode(), _entries_aad(doc))
        _write(path, doc)
    return result


def add_passkey(path, root, cred_id, rp_id, prf_salt, prf, label):
    slot = _passkey_slot(root, cred_id, rp_id, prf_salt, prf, label)
    with _locked(path):
        doc = load(path)
        _check_root(doc, root)
        if any(s.get("cred_id") == cred_id for s in doc["slots"]):
            raise VaultError("this vault already has that passkey")
        doc["slots"].append(slot)
        _write(path, doc)


def remove_passkey(path, cred_id):
    with _locked(path):
        doc = load(path)
        kept = [s for s in doc["slots"] if not (s.get("type") == "passkey" and s.get("cred_id") == cred_id)]
        if len(kept) == len(doc["slots"]):
            raise VaultError("this vault does not have that passkey")
        doc["slots"] = kept
        _write(path, doc)


def replace_recovery(path, root, passphrase):
    slot = _recovery_slot(root, passphrase)
    with _locked(path):
        doc = load(path)
        _check_root(doc, root)
        doc["slots"] = [slot] + [s for s in doc["slots"] if s.get("type") != "recovery"]
        _write(path, doc)


def upgrade_slot(path, root, kind, secret):
    """Rewrite the `kind` slot under Argon2id, if an older KDF wrote it, wrapping the
    root key as every slot does. The unlock just proved `secret`, so no further proof
    is asked. Returns whether it changed."""
    if kind not in ("recovery", "password"):
        raise VaultError(f"the {kind} slot is not upgraded")
    with _locked(path):
        doc = load(path)
        for index, old in enumerate(doc["slots"]):
            if old.get("type") == kind:
                break
        else:
            return False
        if old.get("kdf") == "argon2id":
            return False
        slot = {k: v for k, v in old.items()
                if k not in ("kdf", "wrapped", "n", "r", "p", "salt")}
        slot.update({"kdf": "argon2id", **ARGON2, "salt": _b64e(os.urandom(16))})
        slot["wrapped"] = _seal(_kek(slot, secret), root, _slot_aad(slot))
        # A wrong key must never overwrite good data.
        read_entries(doc, open_data_key(doc, root))
        doc["slots"][index] = slot
        _write(path, doc)
    return True


def set_mfa(path, root, dek, password, secret):
    """Add the unlock password and the authenticator app in one write: the two unlock the
    vault only together, so the file is never left with one of them. The password slot
    wraps the root; the app's secret is sealed with the data key, as the entries are."""
    slot = _password_slot(root, password)
    with _locked(path):
        doc = load(path)
        _check_root(doc, root)
        _check_dek(doc, dek)
        if "authenticator" in doc or any(s.get("type") == "password" for s in doc["slots"]):
            raise VaultError("the vault already has a password and authenticator app - remove them first")
        doc["slots"] = doc["slots"] + [slot]
        doc["authenticator"] = {"created": _now(), "secret": _seal(dek, secret, _authenticator_aad(doc))}
        _write(path, doc)


def remove_mfa(path):
    """Remove the unlock password and the authenticator app. A vault written by 1.1.28
    to 1.1.31 can hold one without the other: what is there is removed."""
    with _locked(path):
        doc = load(path)
        kept = [s for s in doc["slots"] if s.get("type") != "password"]
        if len(kept) == len(doc["slots"]) and "authenticator" not in doc:
            raise VaultError("the vault has no password and authenticator app")
        doc["slots"] = kept
        doc.pop("authenticator", None)
        _write(path, doc)


def authenticator_secret(doc, dek):
    """The secret of the authenticator app, or None when there is none."""
    if "authenticator" not in doc:
        return None
    try:
        return _open(dek, doc["authenticator"]["secret"], _authenticator_aad(doc))
    except (InvalidTag, ValueError, KeyError, TypeError):
        raise VaultError("the authenticator app's secret does not decrypt - a damaged file")


def authenticator_metadata(doc):
    """When the authenticator app was added, or None - what status shows."""
    app = doc.get("authenticator")
    return {"created": app.get("created")} if isinstance(app, dict) else None


def slot_metadata(doc):
    """The slots without their wrapped keys - what status shows."""
    return [{k: v for k, v in s.items() if k not in ("wrapped", "salt", "hkdf_salt")} for s in doc["slots"]]
