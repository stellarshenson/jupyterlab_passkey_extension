"""The vault file: one JSON document whose entries are sealed under a data key.

    {
      "format": "jupyterlab-passkey-vault", "version": 1, "id": hex16,
      "slots": [
        {"type": "recovery", "kdf": "scrypt", "n": 131072, "r": 8, "p": 1,
         "salt": b64, "wrapped": b64},
        {"type": "passkey", "cred_id": b64url, "rp_id": host, "prf_salt": b64url,
         "hkdf_salt": b64, "label": text, "created": iso, "wrapped": b64},
        {"type": "password", "kdf": "scrypt", "n": 131072, "r": 8, "p": 1,
         "salt": b64, "created": iso, "wrapped": b64}
      ],
      "entries": b64(nonce | AES-256-GCM(data key, JSON list of entries)),
      "authenticator": {"created": iso, "secret": b64(nonce | AES-256-GCM(data key, secret))}
    }

The data key (32 random bytes) encrypts every entry, names included, as one blob. Each
slot wraps that same key under its own key-encryption key - `Scrypt(passphrase)` for
the recovery slot, `HKDF(PRF)` for a passkey slot, `Scrypt(password)` for the one
unlock password slot a vault can have - so any one slot opens the vault and
adding or removing a slot never re-encrypts the entries. Every slot parameter except the
wrapped key itself and its label is bound into the wrap as associated data, so a changed
salt, KDF cost, credential or hostname fails to open rather than opening wrongly.

`authenticator` is there only while the vault has an authenticator app. Its secret is
sealed under the data key, so a locked vault tells that an app exists and nothing more.

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

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT = "jupyterlab-passkey-vault"
VERSION = 1
# Scrypt cost for new recovery slots (~128 MiB, a fraction of a second per guess). Each
# slot stores its own, so raising these later leaves existing slots readable.
SCRYPT = {"n": 2**17, "r": 8, "p": 1}
_ENTRIES_AAD = f"{FORMAT}/v{VERSION}/entries".encode()
_AUTHENTICATOR_AAD = f"{FORMAT}/v{VERSION}/authenticator".encode()
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


def _slot_aad(slot):
    bound = {k: v for k, v in slot.items() if k not in ("wrapped", "label")}
    return (f"{FORMAT}/slot/" + json.dumps(bound, sort_keys=True)).encode()


def _scrypt_kek(slot, secret):
    """The key of a recovery or an unlock password slot, from the secret typed."""
    if slot.get("kdf") != "scrypt":
        raise VaultError(f"unknown KDF {slot.get('kdf')!r} in the {slot.get('type')} slot")
    return Scrypt(
        salt=_b64d(slot["salt"]), length=32, n=slot["n"], r=slot["r"], p=slot["p"]
    ).derive(secret.encode("utf-8"))


def _passkey_kek(slot, prf):
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=_b64d(slot["hkdf_salt"]), info=_HKDF_INFO
    ).derive(prf)


def _recovery_slot(dek, passphrase):
    if not isinstance(passphrase, str) or passphrase == "":
        raise VaultError("a recovery passphrase is required")
    slot = {"type": "recovery", "kdf": "scrypt", **SCRYPT, "salt": _b64e(os.urandom(16))}
    slot["wrapped"] = _seal(_scrypt_kek(slot, passphrase), dek, _slot_aad(slot))
    return slot


def _password_slot(dek, password):
    slot = {"type": "password", "kdf": "scrypt", **SCRYPT, "salt": _b64e(os.urandom(16)),
            "created": _now()}
    slot["wrapped"] = _seal(_scrypt_kek(slot, password), dek, _slot_aad(slot))
    return slot


def _passkey_slot(dek, cred_id, rp_id, prf_salt, prf, label):
    slot = {
        "type": "passkey", "cred_id": cred_id, "rp_id": rp_id, "prf_salt": prf_salt,
        "hkdf_salt": _b64e(os.urandom(16)), "created": _now(),
    }
    slot["wrapped"] = _seal(_passkey_kek(slot, prf), dek, _slot_aad(slot))
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
    if doc.get("version") != VERSION:
        raise VaultError(f"{path} is vault format version {doc.get('version')}; this code reads {VERSION}")
    if (not isinstance(doc.get("slots"), list) or not all(isinstance(x, dict) for x in doc["slots"])
            or not isinstance(doc.get("entries"), str)):
        raise VaultError(f"{path} is damaged: slots or entries missing")
    # The id goes into keyring and agent names, so only its own shape is accepted.
    if not isinstance(doc.get("id"), str) or not re.fullmatch(r"[0-9a-f]{16}", doc["id"]):
        raise VaultError(f"{path} is damaged: id missing")
    return doc


def create(path, passphrase):
    """Write a new, empty vault with a recovery slot. Returns the data key."""
    dek = os.urandom(32)
    slot = _recovery_slot(dek, passphrase)
    with _locked(path):
        if exists(path):
            raise VaultError(f"a vault already exists at {path}")
        _write(path, {
            "format": FORMAT, "version": VERSION, "id": os.urandom(8).hex(), "slots": [slot],
            "entries": _seal(dek, b"[]", _ENTRIES_AAD),
        })
    return dek


def _unwrap_typed(doc, kind, secret, wrong, missing):
    """The data key from the slot of type `kind`, which a typed secret opens."""
    for slot in doc["slots"]:
        if slot.get("type") == kind:
            try:
                return _open(_scrypt_kek(slot, secret), slot["wrapped"], _slot_aad(slot))
            except (InvalidTag, ValueError, KeyError, TypeError):
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


def read_entries(doc, dek):
    try:
        entries = json.loads(_open(dek, doc["entries"], _ENTRIES_AAD))
    except (InvalidTag, ValueError):
        raise VaultError("the vault entries do not decrypt - wrong key or a damaged file")
    if not isinstance(entries, list):
        raise VaultError("the vault entries are damaged")
    return entries


def _check_dek(doc, dek):
    # Any write re-seals under `dek`; a wrong key must never overwrite good data.
    read_entries(doc, dek)


def update_entries(path, dek, change):
    """Apply `change(entries) -> result` to the entries and write them back."""
    with _locked(path):
        doc = load(path)
        entries = read_entries(doc, dek)
        result = change(entries)
        doc["entries"] = _seal(dek, json.dumps(entries).encode(), _ENTRIES_AAD)
        _write(path, doc)
    return result


def add_passkey(path, dek, cred_id, rp_id, prf_salt, prf, label):
    slot = _passkey_slot(dek, cred_id, rp_id, prf_salt, prf, label)
    with _locked(path):
        doc = load(path)
        _check_dek(doc, dek)
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


def replace_recovery(path, dek, passphrase):
    slot = _recovery_slot(dek, passphrase)
    with _locked(path):
        doc = load(path)
        _check_dek(doc, dek)
        doc["slots"] = [slot] + [s for s in doc["slots"] if s.get("type") != "recovery"]
        _write(path, doc)


def set_password(path, dek, password):
    """Set the unlock password, in place of the one there was."""
    slot = _password_slot(dek, password)
    with _locked(path):
        doc = load(path)
        _check_dek(doc, dek)
        doc["slots"] = [s for s in doc["slots"] if s.get("type") != "password"] + [slot]
        _write(path, doc)


def remove_password(path):
    with _locked(path):
        doc = load(path)
        kept = [s for s in doc["slots"] if s.get("type") != "password"]
        if len(kept) == len(doc["slots"]):
            raise VaultError("no unlock password is set")
        doc["slots"] = kept
        _write(path, doc)


def set_authenticator(path, dek, secret):
    with _locked(path):
        doc = load(path)
        _check_dek(doc, dek)
        if "authenticator" in doc:
            raise VaultError("the vault already has an authenticator app - remove it first")
        doc["authenticator"] = {"created": _now(), "secret": _seal(dek, secret, _AUTHENTICATOR_AAD)}
        _write(path, doc)


def remove_authenticator(path):
    with _locked(path):
        doc = load(path)
        if "authenticator" not in doc:
            raise VaultError("the vault has no authenticator app")
        del doc["authenticator"]
        _write(path, doc)


def authenticator_secret(doc, dek):
    """The secret of the authenticator app, or None when there is none."""
    if "authenticator" not in doc:
        return None
    try:
        return _open(dek, doc["authenticator"]["secret"], _AUTHENTICATOR_AAD)
    except (InvalidTag, ValueError, KeyError, TypeError):
        raise VaultError("the authenticator app's secret does not decrypt - a damaged file")


def authenticator_metadata(doc):
    """When the authenticator app was added, or None - what status shows."""
    app = doc.get("authenticator")
    return {"created": app.get("created")} if isinstance(app, dict) else None


def slot_metadata(doc):
    """The slots without their wrapped keys - what status shows."""
    return [{k: v for k, v in s.items() if k not in ("wrapped", "salt", "hkdf_salt")} for s in doc["slots"]]
