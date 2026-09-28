"""The vault agent inside the Jupyter server.

Only this process opens the vault. It unwraps the data key at unlock, keeps it in the
key holder for the configured duration, and does every read and write on behalf of the
REST handlers - which the CLI, the Python API and the panel all call. No secret is ever
put in an exception message, so a refusal can be reported and logged as it is.
"""

import hashlib
import json
import os
import secrets
import string

from .. import relay
from . import holders, store
from .store import VaultError

DEFAULT_UNLOCK_MINUTES = 240
# What a lock cannot reach, said when it finds no vault file, or a damaged one.
_RESTART_CLAUSE = (
    "on keyctl or gpg-agent a key unlocked before a server restart can stay held until its "
    "unlock duration ends"
)
MAX_UNLOCK_MINUTES = holders.MAX_TTL // 60
GENERATE_LENGTH = 24
FIELDS = ("username", "password", "url", "category", "notes")
READABLE = ("password", "username", "url", "category", "notes", "name")
MAX_NAME = 200
MAX_FIELD = 65536
# A generated password is read off the Show image or typed on a phone, so characters
# that look alike there are left out: l I 1 | O 0. So are quotes, backslash, backtick
# and space.
LOWER = string.ascii_lowercase.replace("l", "")
UPPER = string.ascii_uppercase.replace("I", "").replace("O", "")
DIGITS = "23456789"
SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{}~"


class Locked(VaultError):
    pass


class NotFound(VaultError):
    pass


class Conflict(VaultError):
    pass


class Denied(VaultError):
    pass


def _config_path():
    return os.path.join(holders._state_dir(), "vault-config.json")


def _shown(path):
    """The path as a user reads it: ~ for the home directory."""
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


def _check_name(name):
    if not isinstance(name, str) or not name.strip():
        raise VaultError("an entry needs a name")
    if len(name) > MAX_NAME or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise VaultError(f"an entry name is at most {MAX_NAME} printable characters")
    return name.strip()


def _check_fields(fields):
    clean = {}
    for key in FIELDS:
        if key in fields:
            value = fields[key]
            if value is None:
                value = ""
            if isinstance(value, (dict, list)) and key == "notes":
                value = json.dumps(value)
            if not isinstance(value, str) or len(value) > MAX_FIELD:
                raise VaultError(f"`{key}` must be text of at most {MAX_FIELD} characters")
            clean[key] = value
    return clean


def generate(length=GENERATE_LENGTH, symbols=True):
    """A random password with at least one of each character class in use."""
    if not isinstance(length, int) or not 8 <= length <= 256:
        raise VaultError("a generated password is 8 to 256 characters")
    classes = [LOWER, UPPER, DIGITS]
    if symbols:
        classes.append(SYMBOLS)
    alphabet = "".join(classes)
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in cls for c in value) for cls in classes):
            return value


class VaultService:
    def __init__(self):
        # The id of the vault whose key this server last put in the holder, so `lock`
        # can clear it even when the file has since moved or been damaged.
        self._held = None

    # -- configuration -----------------------------------------------------

    def unlock_minutes(self):
        try:
            with open(_config_path()) as f:
                minutes = json.load(f).get("unlock_minutes")
        except (OSError, ValueError, AttributeError):
            return DEFAULT_UNLOCK_MINUTES
        if isinstance(minutes, int) and 1 <= minutes <= MAX_UNLOCK_MINUTES:
            return minutes
        return DEFAULT_UNLOCK_MINUTES

    def set_config(self, unlock_minutes):
        if (not isinstance(unlock_minutes, int) or isinstance(unlock_minutes, bool)
                or not 1 <= unlock_minutes <= MAX_UNLOCK_MINUTES):
            raise VaultError(f"unlock_minutes must be a whole number from 1 to {MAX_UNLOCK_MINUTES}")
        path = _config_path()
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"unlock_minutes": unlock_minutes}, f)

    # -- holder and data key -------------------------------------------------

    def holder(self):
        return holders.select()

    def _vault_id(self):
        return store.load(store.vault_path())["id"]

    def _dek(self):
        dek = self.holder().get(self._vault_id())
        if dek is None:
            raise Locked("the vault is locked")
        return dek

    def _hold(self, dek):
        vault_id = self._vault_id()
        self.holder().put(vault_id, dek, self.unlock_minutes() * 60)
        self._held = vault_id

    # -- state ---------------------------------------------------------------

    def status(self):
        path = store.vault_path()
        holder = self.holder()
        result = {
            "initialized": store.exists(path),
            "unlocked": False,
            "remaining": None,
            "holder": {**holders.describe(holder), "debug": holders.debug_report()},
            "slots": [],
            "settings": {"unlock_minutes": self.unlock_minutes()},
            "path": _shown(path),
        }
        if result["initialized"]:
            doc = store.load(path)
            result["slots"] = store.slot_metadata(doc)
            # Changes whenever an entry does, from any client, so an open panel knows to
            # read the entries again. A hash of the ciphertext tells nothing about them.
            result["revision"] = hashlib.sha256(doc["entries"].encode()).hexdigest()[:16]
            remaining = holder.remaining(doc["id"])
            result["unlocked"] = remaining is not None
            result["remaining"] = remaining
        return result

    def init(self, recovery):
        dek = store.create(store.vault_path(), recovery)
        self._hold(dek)

    def unlock_passkey(self, cred_id, prf):
        if not isinstance(cred_id, str) or not isinstance(prf, str):
            raise VaultError("a passkey unlock needs cred_id and prf")
        try:
            prf_bytes = store.b64url_decode(prf)
        except ValueError:
            raise VaultError("the prf is not base64url")
        self._hold(store.unwrap_passkey(store.load(store.vault_path()), cred_id, prf_bytes))

    def unlock_recovery(self, passphrase):
        if not isinstance(passphrase, str) or not passphrase:
            raise VaultError("a recovery unlock needs the passphrase")
        self._hold(store.unwrap_recovery(store.load(store.vault_path()), passphrase))

    def lock(self):
        """Clear the key of the vault last unlocked here and of the one the file is now."""
        path = store.vault_path()
        held, self._held = self._held, None
        if held is None and not store.exists(path):
            raise VaultError(f"no vault at {path}; {_RESTART_CLAUSE}")
        if held is not None:
            self.holder().clear(held)
        if store.exists(path):
            try:
                self.holder().clear(self._vault_id())
            except VaultError as e:
                # A damaged file: the key this server held is cleared, which is the lock.
                if held is None:
                    raise VaultError(f"{e}; {_RESTART_CLAUSE}")

    # -- entries -------------------------------------------------------------

    def _entries(self):
        path = store.vault_path()
        return store.read_entries(store.load(path), self._dek())

    def list_entries(self):
        return [
            {k: e.get(k, "") for k in ("name", "username", "url", "category", "notes", "created", "updated")}
            for e in sorted(self._entries(), key=lambda e: e["name"].lower())
        ]

    def _find(self, entries, name):
        for e in entries:
            if e["name"] == name:
                return e
        raise NotFound(f"no entry named {name!r}")

    def add(self, name, fields):
        name, fields = _check_name(name), _check_fields(fields)

        def change(entries):
            if any(e["name"] == name for e in entries):
                raise Conflict(f"an entry named {name!r} already exists")
            now = store._now()
            entries.append({"name": name, **{k: fields.get(k, "") for k in FIELDS},
                            "created": now, "updated": now})

        store.update_entries(store.vault_path(), self._dek(), change)

    def edit(self, name, fields):
        name, fields = _check_name(name), _check_fields(fields)

        def change(entries):
            entry = self._find(entries, name)
            entry.update(fields)
            entry["updated"] = store._now()

        store.update_entries(store.vault_path(), self._dek(), change)

    def delete(self, name):
        name = _check_name(name)

        def change(entries):
            entries.remove(self._find(entries, name))

        store.update_entries(store.vault_path(), self._dek(), change)

    def read(self, name, field="password"):
        if field not in READABLE:
            raise VaultError(f"field must be one of {', '.join(READABLE)}")
        return self._find(self._entries(), _check_name(name)).get(field, "")

    def _proven_dek(self, doc, proof):
        """The data key from a proof sent with this request - {"current": the recovery
        passphrase} or {"cred_id", "prf": a passkey's PRF} - never from the holder: an
        unlocked vault alone proves nothing about who is asking now."""
        if not isinstance(proof, dict) or not ("current" in proof or "prf" in proof):
            raise Denied("this needs a proof: a passkey or the recovery passphrase")
        try:
            if "current" in proof:
                return store.unwrap_recovery(doc, proof["current"])
            return store.unwrap_passkey(doc, proof.get("cred_id"), store.b64url_decode(proof["prf"]))
        except (VaultError, ValueError, AttributeError):
            raise Denied("wrong recovery passphrase" if "current" in proof
                         else "the passkey did not open the vault")

    def reveal_with_passkey(self, name, cred_id, prf):
        """The panel's reveal: the password, read with the key this passkey unwraps.
        `read` stays for the CLI and the Python API."""
        doc = store.load(store.vault_path())
        dek = self._proven_dek(doc, {"cred_id": cred_id, "prf": prf})
        return self._find(store.read_entries(doc, dek), _check_name(name)).get("password", "")

    def stage(self, name, field, kind):
        """Put a value in a one-shot relay for the existing copy or show flow."""
        if kind not in ("secret", "code"):
            raise VaultError("kind must be secret or code")
        value = self.read(name, field)
        if not value:
            raise VaultError(f"{name!r} has no {field}")
        if kind == "code" and len(value) > relay.MAX_CODE_CHARS:
            raise VaultError(f"the {field} is too long to show as an image")
        nonce = secrets.token_urlsafe(24)
        relay.stage(nonce, kind, value)
        return nonce

    def import_entries(self, items):
        if not isinstance(items, list):
            raise VaultError("import takes a JSON list of entries")
        clean = []
        for item in items:
            if not isinstance(item, dict):
                raise VaultError("each imported entry must be a JSON object")
            name = item.get("name", item.get("service"))
            clean.append((_check_name(name), _check_fields(item)))

        def change(entries):
            names = {e["name"] for e in entries}
            added, skipped = 0, []
            for name, fields in clean:
                if name in names:
                    skipped.append(name)
                    continue
                now = store._now()
                entries.append({"name": name, **{k: fields.get(k, "") for k in FIELDS},
                                "created": now, "updated": now})
                names.add(name)
                added += 1
            return {"added": added, "skipped": skipped}

        return store.update_entries(store.vault_path(), self._dek(), change)

    # -- slots ---------------------------------------------------------------

    def add_passkey(self, cred_id, rp_id, prf_salt, prf, label, proof):
        """A new passkey slot, allowed only with a proof (`_proven_dek`): a passkey opens
        the vault and proves a recovery change, so an unlocked vault is not enough to
        add one."""
        for key, value in (("cred_id", cred_id), ("rp_id", rp_id), ("prf_salt", prf_salt), ("prf", prf)):
            if not isinstance(value, str) or not value:
                raise VaultError(f"registering a passkey needs {key}")
        if label is not None and (not isinstance(label, str) or len(label) > MAX_NAME):
            raise VaultError(f"a passkey label is at most {MAX_NAME} characters")
        try:
            prf_bytes = store.b64url_decode(prf)
        except ValueError:
            raise VaultError("the prf is not base64url")
        path = store.vault_path()
        store.add_passkey(path, self._proven_dek(store.load(path), proof), cred_id, rp_id, prf_salt,
                          prf_bytes, label or rp_id)

    def remove_passkey(self, cred_id):
        self._dek()  # removing a passkey needs an unlocked vault
        store.remove_passkey(store.vault_path(), cred_id)

    def replace_recovery(self, passphrase, proof):
        """A new recovery passphrase, allowed only with a proof: see `_proven_dek`."""
        path = store.vault_path()
        store.replace_recovery(path, self._proven_dek(store.load(path), proof), passphrase)
