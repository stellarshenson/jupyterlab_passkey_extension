"""The vault agent inside the Jupyter server.

Only this process opens the vault. It unwraps the root key at unlock, opens the data
key with it, keeps both in the key holder for the configured duration, and does every
read and write on behalf of the REST handlers - which the CLI, the Python API and the
panel all call. No secret is ever put in an exception message, so a refusal can be
reported and logged as it is.
"""

import hashlib
import json
import logging
import os
import re
import secrets
import string
import time
from datetime import datetime, timezone

from .. import relay
from . import holders, store, totp, webauthn
from .store import VaultError

log = logging.getLogger(__name__)

DEFAULT_UNLOCK_MINUTES = 30
# The shortest unlock password the vault accepts: the setting, and what it may be set
# to. A copied vault file can be attacked through this slot, so short is not offered.
DEFAULT_PASSWORD_MIN_LENGTH = 12
PASSWORD_MIN_LENGTH_RANGE = (8, 128)
# How long an unlock or an accepted proof in a tab shows a password without another
# proof, and what the setting may be. 0 asks a proof at every reveal.
DEFAULT_REVEAL_SECONDS = 60
REVEAL_SECONDS_RANGE = (0, 3600)
# How long a data key may serve before an unlock rotates it, in days, and what the
# setting may be. 0 turns automatic rotation off.
DEFAULT_ROTATE_DAYS = 365
ROTATE_DAYS_RANGE = (0, 3650)
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
# Wrong codes in a row before codes are refused until an unlock with a passkey or the
# recovery passphrase: a code has six digits, so nothing else stands between a script
# and a guess.
MAX_WRONG_CODES = 5
MAX_FIELD = 65536
# How long a passkey challenge is accepted, in seconds: as long as a registration may
# take, since it signs before the offer and the new password are answered.
CHALLENGE_SECONDS = 600
# The one answer to every refused passkey check: it tells a forger nothing.
CHECK_FAILED = "the passkey check failed or expired - try again"
# The kinds of proof, by the key that carries the secret, with the name a refusal gives
# them. The unlock password alone proves the panel's reveal and nothing else: it opens
# the vault only with a code, so alone it must not add an unlock method or replace the
# recovery passphrase. A passkey with no PRF (`assertion`) proves as a code does.
PROOFS = {
    "prf": "a passkey",
    "code": "a code of the authenticator app",
    "assertion": "a passkey with no PRF",
    "current": "the recovery passphrase",
    "password": "the unlock password",
}
REVEAL_ONLY = "password"
_full = [name for key, name in PROOFS.items() if key != REVEAL_ONLY]
FULL_PROOFS = f"{', '.join(_full[:-1])} or {_full[-1]}"
# What an imported entry can give besides its name. A field outside these is refused:
# dropped without a word, an import would report an entry as added and lose part of it.
IMPORT_DATES = ("created", "updated")
IMPORT_FIELDS = ("name", *FIELDS, *IMPORT_DATES)
# ISO 8601 as other password managers export it: fractional seconds of any length
# (pass-cli writes nine digits), and a zone as Z, an offset, or none (taken as UTC).
_IMPORT_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?")
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


def _age_days(stamp):
    """Whole days from a vault date to now; 0 for today, and 0 for a clock behind."""
    then = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - then).days)


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


def _check_date(n, key, value):
    """The date `key` of imported entry `n`, as the vault writes dates."""
    match = _IMPORT_DATE.fullmatch(value) if isinstance(value, str) else None
    if match:
        day, time, zone = match.groups()
        try:
            return store._stamp(datetime.fromisoformat(f"{day}T{time}{'+00:00' if zone in (None, 'Z') else zone}"))
        except ValueError:
            pass
    raise VaultError(f"imported entry {n}: `{key}` must be a date and time such as 2026-03-23T20:37:13Z; "
                     "nothing was imported")


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
        # Of the authenticator app: wrong codes in a row, and the time step of the last
        # code accepted, since a code is accepted once.
        self._wrong_codes = 0
        self._last_step = None
        # The one live passkey challenge and when it expires (`time.monotonic`), or None.
        # A new one replaces it; a request that names one uses it up.
        self._challenge = None

    # -- configuration -----------------------------------------------------

    def _setting(self, key, low, high, default):
        """The stored setting `key` when it is a whole number in its range, else its default."""
        try:
            with open(_config_path()) as f:
                value = json.load(f).get(key)
        except (OSError, ValueError, AttributeError):
            return default
        whole = isinstance(value, int) and not isinstance(value, bool)
        return value if whole and low <= value <= high else default

    def unlock_minutes(self):
        return self._setting("unlock_minutes", 1, MAX_UNLOCK_MINUTES, DEFAULT_UNLOCK_MINUTES)

    def password_min_length(self):
        return self._setting("password_min_length", *PASSWORD_MIN_LENGTH_RANGE,
                             DEFAULT_PASSWORD_MIN_LENGTH)

    def reveal_seconds(self):
        return self._setting("reveal_seconds", *REVEAL_SECONDS_RANGE, DEFAULT_REVEAL_SECONDS)

    def rotate_days(self):
        return self._setting("rotate_days", *ROTATE_DAYS_RANGE, DEFAULT_ROTATE_DAYS)

    # -- holder and data key -------------------------------------------------

    def holder(self):
        return holders.select()

    def _vault_id(self):
        return store.load(store.vault_path())["id"]

    def _held_key(self):
        key = self.holder().get(self._vault_id())
        if key is None:
            raise Locked("the vault is locked")
        return key

    def _dek(self):
        """The data half of the held pair. A 32-byte hold is a version-1 file's one key,
        which serves both jobs."""
        key = self._held_key()
        return key[32:] if len(key) == 64 else key

    def _root(self):
        """The root half of the held pair. A 32-byte hold is a version-1 file's one key,
        which serves both jobs."""
        key = self._held_key()
        return key[:32] if len(key) == 64 else key

    def _hold(self, root, dek):
        vault_id = self._vault_id()
        self.holder().put(vault_id, root + dek, self.unlock_minutes() * 60)
        self._held = vault_id
        self._wrong_codes = 0
        relay.end_unlock_wait()

    def _drop_old_key(self, doc):
        """The file has just taken a new data key, so the held key no longer reads it.
        It goes now, not at the next hold: a hold that fails must leave a locked vault,
        never an open one whose entries do not decrypt."""
        self.holder().clear(doc["id"])

    def _upgrade_slot(self, path, root, kind, secret):
        """Argon2id for the slot this unlock used. Best effort: an unlock that already
        succeeded must not fail because the migration could not be written."""
        try:
            store.upgrade_slot(path, root, kind, secret)
        except Exception as e:
            log.warning("could not upgrade the %s slot to Argon2id: %s", kind, e)

    def _finish_unlock(self, path, doc, root, kind, secret):
        """The root and data key for an unlock that has just opened `root`: a version-1
        file is given a data key, the slot this unlock used is upgraded, and a data key
        past its period is rotated. A migration or rotation that cannot be written is a
        warning, not a failed unlock; the key this unlock came with serves it."""
        if doc["version"] == 1:
            try:
                dek, _ = store.adopt_data_key(path, root)
            except Exception as e:
                log.warning("could not give the vault a data key: %s", e)
                dek = root
            else:
                doc = store.load(path)
                self._drop_old_key(doc)
        else:
            dek = store.open_data_key(doc, root)
        if kind is not None:
            self._upgrade_slot(path, root, kind, secret)
        period = self.rotate_days()
        created = store.data_key_created(doc)
        if period > 0 and created is not None and _age_days(created) >= period:
            try:
                dek = store.rotate_data_key(path, root)
            except Exception as e:
                log.warning("could not rotate the vault's data key: %s", e)
            else:
                self._drop_old_key(doc)
        return root, dek

    def _rotation(self, doc):
        """The data key's creation date, age, period and due state, for status."""
        created = store.data_key_created(doc)
        period = self.rotate_days()
        if created is None:
            return {"created": None, "age_days": None, "period_days": period, "due": False}
        age = _age_days(created)
        return {"created": created, "age_days": age, "period_days": period,
                "due": period > 0 and age >= period}

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
            "settings": {"unlock_minutes": self.unlock_minutes(),
                         "password_min_length": self.password_min_length(),
                         "reveal_seconds": self.reveal_seconds(),
                         "rotate_days": self.rotate_days()},
            "path": _shown(path),
        }
        if result["initialized"]:
            doc = store.load(path)
            result["slots"] = store.slot_metadata(doc)
            result["authenticator"] = store.authenticator_metadata(doc)
            result["rotation"] = self._rotation(doc)
            # Changes whenever an entry does, from any client, so an open panel knows to
            # read the entries again. A hash of the ciphertext tells nothing about them.
            result["revision"] = hashlib.sha256(doc["entries"].encode()).hexdigest()[:16]
            remaining = holder.remaining(doc["id"])
            result["unlocked"] = remaining is not None
            result["remaining"] = remaining
        return result

    def init(self, recovery):
        path = store.vault_path()
        dek = store.create(path, recovery)
        # The holder keeps the root and the data key together, so the slots can still
        # be written while the vault is open.
        self._hold(store.unwrap_recovery(store.load(path), recovery), dek)

    def unlock_passkey(self, cred_id, prf):
        if not isinstance(cred_id, str) or not isinstance(prf, str):
            raise VaultError("a passkey unlock needs cred_id and prf")
        try:
            prf_bytes = store.b64url_decode(prf)
        except ValueError:
            raise VaultError("the prf is not base64url")
        path = store.vault_path()
        doc = store.load(path)
        root = store.unwrap_passkey(doc, cred_id, prf_bytes)
        self._hold(*self._finish_unlock(path, doc, root, None, None))

    def unlock_recovery(self, passphrase):
        if not isinstance(passphrase, str) or not passphrase:
            raise VaultError("a recovery unlock needs the passphrase")
        path = store.vault_path()
        doc = store.load(path)
        root = store.unwrap_recovery(doc, passphrase)
        self._hold(*self._finish_unlock(path, doc, root, "recovery", passphrase))

    def unlock_password(self, password, code=None):
        """Unlock with the unlock password and a code of the authenticator app: the two
        are one unlock method. The password decrypts the root key and the data key is
        opened with it; the key is put in the holder only for a right code. A vault
        written by 1.1.28 to 1.1.31 can hold a password and no app; that password opens
        it alone."""
        if not isinstance(password, str) or not password:
            raise VaultError("a password unlock needs the unlock password")
        path = store.vault_path()
        doc = store.load(path)
        root = store.unwrap_password(doc, password)
        if store.authenticator_metadata(doc) is not None:
            if code is None:
                raise Denied("a password unlock needs a code of the authenticator app")
            self._check_code(doc, store.open_data_key(doc, root), code)
        self._hold(*self._finish_unlock(path, doc, root, "password", password))

    def unlock_pair(self, password, assertion):
        """Unlock with Password and passkey: the password decrypts the root key, and
        the key is put in the holder only for a verified signature of the passkey over
        the live challenge. The challenge is used up first, so a request with none
        reaches no Argon2id."""
        if not isinstance(password, str) or not password:
            raise VaultError("a password unlock needs the unlock password")
        challenge = self._take_challenge()
        path = store.vault_path()
        doc = store.load(path)
        root = store.unwrap_pair(doc, password)
        self._check_assertion(doc, store.open_data_key(doc, root), assertion, challenge)
        self._hold(*self._finish_unlock(path, doc, root, None, None))

    def challenge(self):
        """A new passkey challenge, which replaces the last one."""
        value = secrets.token_urlsafe(32)
        self._challenge = (value, time.monotonic() + CHALLENGE_SECONDS)
        return {"challenge": value}

    def _take_challenge(self):
        """The live challenge, used up whether or not the request it serves succeeds."""
        held, self._challenge = self._challenge, None
        if held is None or time.monotonic() >= held[1]:
            raise Denied(CHECK_FAILED)
        return held[0]

    def _check_assertion(self, doc, dek, assertion, challenge):
        """Refuse unless `assertion` is a signature of the passkey of Password and
        passkey over `challenge`. `dek` opens the passkey's public key. A refused check
        is not counted: a signature cannot be guessed and a challenge serves once."""
        slot, key = store.pair_key(doc, dek)
        try:
            count = webauthn.verify(assertion, key, slot["cred_id"], slot["rp_id"],
                                    slot["origin"], challenge, slot.get("sign_count", 0))
        except webauthn.Refused:
            raise Denied(CHECK_FAILED)
        if count:
            self._save_sign_count(count)

    def _save_sign_count(self, count):
        """Record the passkey's sign count. Best effort: a check that succeeded must
        not fail because the count could not be written."""
        try:
            store.set_sign_count(store.vault_path(), count)
        except Exception as e:
            log.warning("could not record the passkey's sign count: %s", type(e).__name__)

    def rotate(self, proof):
        """Rotate the data key now: the entries, the authenticator secret and the
        public key of Password and passkey are re-sealed under a new key, no slot's
        wrapped key changes, and an old copy of the data key stops reading the vault.
        Needs an unlocked vault and a recovery or PRF passkey proof; a code alone and a
        passkey with no PRF alone hold no key and are no proof here."""
        self._dek()
        path = store.vault_path()
        doc = store.load(path)
        if isinstance(proof, dict) and "code" in proof:
            raise Denied(f"{PROOFS['code']} is no proof for this - use a passkey or "
                         "the recovery passphrase")
        if isinstance(proof, dict) and "assertion" in proof:
            raise Denied(f"{PROOFS['assertion']} is no proof for this - use a passkey with PRF "
                         "or the recovery passphrase")
        root = self._proven_root(doc, proof)
        dek = store.rotate_data_key(path, root)
        self._drop_old_key(doc)
        self._hold(root, dek)
        return {"rotation": self._rotation(store.load(path))}

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
            {k: e.get(k, "") for k in ("name", "username", "url", "category", "notes", "created", "updated", "used")}
            for e in sorted(self._entries(), key=lambda e: e["name"].lower())
        ]

    def _find(self, entries, name):
        for e in entries:
            if e["name"] == name:
                return e
        raise NotFound(f"no entry named {name!r}")

    def _mark_used(self, name):
        """Record the entry's last use. The stamp is auxiliary: it must not fail a read."""
        def change(entries):
            self._find(entries, name)["used"] = store._now()

        try:
            store.update_entries(store.vault_path(), self._dek(), change)
        except Exception as e:
            log.warning("could not record the entry's last use: %s", type(e).__name__)

    def add(self, name, fields):
        name, fields = _check_name(name), _check_fields(fields)

        def change(entries):
            if any(e["name"] == name for e in entries):
                raise Conflict(f"an entry named {name!r} already exists")
            now = store._now()
            entries.append({"name": name, **{k: fields.get(k, "") for k in FIELDS},
                            "created": now, "updated": now, "used": now})

        store.update_entries(store.vault_path(), self._dek(), change)

    def edit(self, name, fields):
        name, fields = _check_name(name), _check_fields(fields)

        def change(entries):
            entry = self._find(entries, name)
            entry.update(fields)
            now = store._now()
            entry["updated"] = now
            entry["used"] = now

        store.update_entries(store.vault_path(), self._dek(), change)

    def delete(self, name):
        name = _check_name(name)

        def change(entries):
            entries.remove(self._find(entries, name))

        store.update_entries(store.vault_path(), self._dek(), change)

    def read(self, name, field="password"):
        if field not in READABLE:
            raise VaultError(f"field must be one of {', '.join(READABLE)}")
        name = _check_name(name)
        value = self._find(self._entries(), name).get(field, "")
        self._mark_used(name)
        return value

    def _proven_root(self, doc, proof, reveal=False):
        """The root key, given only for a proof sent with this request: an unlocked vault
        alone proves nothing about who is asking now. `PROOFS` names the kinds.
        {"current": the recovery passphrase} and {"cred_id", "prf": a passkey's PRF}
        unwrap the root themselves. {"password": the unlock password} unwraps the root
        too, but proves only a `reveal`: alone it opens no vault and changes nothing.
        {"code": a code of the authenticator app} holds no key of its own; on an
        unlocked vault it checks the code and returns the held root, so it proves a new
        slot, a new unlock method and a recovery change - not a rotation.
        {"assertion": a signature of the passkey of Password and passkey} proves as a
        code does, over the live challenge."""
        if not isinstance(proof, dict) or not any(k in proof for k in PROOFS):
            raise Denied(f"this needs a proof: {FULL_PROOFS}")
        if "code" in proof:
            # The code's own refusal first: no app, a wrong code, a used one.
            self._code_dek(doc, proof["code"])
            return self._root()
        if "assertion" in proof:
            # The held key first: a locked vault answers 423 and keeps the challenge.
            dek, root = self._dek(), self._root()
            self._check_assertion(doc, dek, proof["assertion"], self._take_challenge())
            return root
        if REVEAL_ONLY in proof:
            if not reveal:
                raise Denied(f"{PROOFS[REVEAL_ONLY]} is no proof for this - use {FULL_PROOFS}")
            try:
                return store.unwrap_password(doc, proof["password"])
            except (VaultError, AttributeError) as e:
                raise Denied(str(e) if isinstance(e, VaultError) else "wrong unlock password")
        try:
            if "current" in proof:
                return store.unwrap_recovery(doc, proof["current"])
            return store.unwrap_passkey(doc, proof.get("cred_id"), store.b64url_decode(proof["prf"]))
        except (VaultError, ValueError, AttributeError):
            raise Denied("wrong recovery passphrase" if "current" in proof
                         else "the passkey did not open the vault")

    def check_recovery(self, passphrase):
        """Refuse a wrong recovery passphrase, with no other effect: the page asks this
        before the steps a proof guards, and the request that acts checks its proof
        again. The proof is built here, so a code cannot come this way: `_check_code`
        would use it up."""
        self._proven_root(store.load(store.vault_path()), {"current": passphrase})

    def _code_dek(self, doc, typed):
        """The held data key, for a right code of the authenticator app."""
        dek = self._dek()
        self._check_code(doc, dek, typed)
        return dek

    def _check_code(self, doc, dek, typed):
        """Refuse unless `typed` is a right code of the vault's authenticator app that
        was not used before. `dek` opens the app's secret."""
        secret = store.authenticator_secret(doc, dek)
        if secret is None:
            raise Denied("the vault has no authenticator app")
        if self._wrong_codes >= MAX_WRONG_CODES:
            raise Denied("too many wrong codes - codes are refused until the vault is unlocked "
                         "with a passkey or the recovery passphrase")
        step = totp.matching_step(secret, typed)
        if step is None:
            self._wrong_codes += 1
            raise Denied("wrong code")
        if self._last_step is not None and step <= self._last_step:
            raise Denied("that code was already used - wait for the next one")
        self._wrong_codes, self._last_step = 0, step

    def reveal_proven(self, name, proof):
        """The panel's reveal: the password, read with the data key the proof gives. A
        code proves on an unlocked vault through the held data key; a root-bearing
        proof opens the file's data key itself. `read` stays for the CLI, the Python
        API and the panel in the `reveal_seconds` window that an unlock or an accepted
        proof in its tab starts. A locked vault shows nothing, whatever the proof: a
        secret that opens it must unlock it first, and the unlock password opens it
        only with a code."""
        self._dek()
        name = _check_name(name)
        doc = store.load(store.vault_path())
        if isinstance(proof, dict) and "code" in proof:
            dek = self._code_dek(doc, proof["code"])
        else:
            dek = store.open_data_key(doc, self._proven_root(doc, proof, reveal=True))
        value = self._find(store.read_entries(doc, dek), name).get("password", "")
        self._mark_used(name)
        return value

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
        for n, item in enumerate(items, 1):
            if not isinstance(item, dict):
                raise VaultError("each imported entry must be a JSON object")
            unknown = sorted(set(item) - {"service", *IMPORT_FIELDS})
            if unknown:
                raise VaultError(f"imported entry {n}: `{unknown[0]}` is not a field - the fields are "
                                 f"{', '.join(IMPORT_FIELDS)}; nothing was imported")
            name = item.get("name", item.get("service"))
            # An empty date is an absent one, as other managers write a date they do not have.
            dates = {key: _check_date(n, key, item[key]) for key in IMPORT_DATES if item.get(key)}
            clean.append((_check_name(name), _check_fields(item), dates))

        def change(entries):
            names = {e["name"] for e in entries}
            added, skipped = 0, []
            for name, fields, dates in clean:
                if name in names:
                    skipped.append(name)
                    continue
                now = store._now()
                entries.append({"name": name, **{k: fields.get(k, "") for k in FIELDS},
                                "created": dates.get("created", now), "updated": dates.get("updated", now),
                                "used": now})
                names.add(name)
                added += 1
            return {"added": added, "skipped": skipped}

        return store.update_entries(store.vault_path(), self._dek(), change)

    # -- slots ---------------------------------------------------------------

    def add_passkey(self, cred_id, rp_id, prf_salt, prf, label, proof):
        """A new passkey slot, allowed only with a proof (`_proven_root`): a passkey opens
        the vault and proves a recovery change, so an unlocked vault is not enough to
        add one."""
        for key, value in (("cred_id", cred_id), ("rp_id", rp_id), ("prf_salt", prf_salt), ("prf", prf)):
            if not isinstance(value, str) or not value:
                raise VaultError(f"adding a passkey needs {key}")
        if label is not None and (not isinstance(label, str) or len(label) > MAX_NAME):
            raise VaultError(f"a passkey label is at most {MAX_NAME} characters")
        try:
            prf_bytes = store.b64url_decode(prf)
        except ValueError:
            raise VaultError("the prf is not base64url")
        path = store.vault_path()
        store.add_passkey(path, self._proven_root(store.load(path), proof), cred_id, rp_id, prf_salt,
                          prf_bytes, label or rp_id)

    def remove_passkey(self, cred_id):
        self._dek()  # removing a passkey needs an unlocked vault
        store.remove_passkey(store.vault_path(), cred_id)

    def add_mfa(self, password, setup_key, typed, proof):
        """Add the unlock password and the authenticator app whose secret is
        `setup_key`, together: the two open the vault only as a pair. Allowed only with
        a proof and for a right code of the new app - the pair opens the vault, and a
        code proves a recovery change and a new passkey, so an unlocked vault is not
        enough to add it."""
        self._check_new_password(password)
        secret = totp.decode_secret(setup_key)
        if secret is None:
            raise VaultError(f"an authenticator app's secret is base32 of {totp.MIN_SECRET} "
                             f"to {totp.MAX_SECRET} bytes")
        step = totp.matching_step(secret, typed)
        if step is None:
            raise Denied("wrong code")
        path = store.vault_path()
        doc = store.load(path)
        if store.authenticator_metadata(doc) is not None or any(
                slot.get("type") == "password" for slot in doc["slots"]):
            raise Conflict("the vault already has a password and authenticator app - remove them first")
        root = self._proven_root(doc, proof)
        held = self.holder().get(doc["id"])
        dek = self._adopted(path, doc, root)
        store.set_mfa(path, root, dek, password, secret)
        if held is not None:
            self._hold(root, dek)
        # The code that added the app is used: it proves nothing after this.
        self._wrong_codes, self._last_step = 0, step

    def _check_new_password(self, password):
        shortest = self.password_min_length()
        if not isinstance(password, str) or not shortest <= len(password) <= MAX_FIELD:
            raise VaultError(f"an unlock password is at least {shortest} characters")

    def _adopted(self, path, doc, root):
        """The data key a new secret is sealed under. A version-1 file has one key for
        both jobs; it is given a data key first, and the key held for it goes."""
        if doc["version"] == 1:
            dek, _ = store.adopt_data_key(path, root)
            self._drop_old_key(doc)
            return dek
        return store.open_data_key(doc, root)

    def add_pair(self, password, cred_id, rp_id, registration, label, assertion, proof):
        """Add Password and passkey: a new unlock password, and a passkey with no PRF.
        The `create` that made the passkey passes the WebAuthn registration steps over
        the live challenge and gives the public key the vault keeps, as COSE key bytes;
        the passkey's signature over the same challenge proves the page holds that key. Allowed only
        with a proof, as every unlock method is. The origin of the registration is
        stored, and every later check compares it exactly."""
        self._check_new_password(password)
        for key, value in (("cred_id", cred_id), ("rp_id", rp_id)):
            if not isinstance(value, str) or not value:
                raise VaultError(f"adding a password and passkey needs {key}")
        if label is not None and (not isinstance(label, str) or len(label) > MAX_NAME):
            raise VaultError(f"a passkey label is at most {MAX_NAME} characters")
        challenge = self._take_challenge()
        try:
            origin = webauthn.origin_of(registration, rp_id)
            cose = webauthn.registered_key(registration, cred_id, rp_id, origin, challenge)
            count = webauthn.verify(assertion, cose, cred_id, rp_id, origin, challenge)
        except webauthn.Refused:
            raise Denied(CHECK_FAILED)
        path = store.vault_path()
        doc = store.load(path)
        if any(slot.get("type") == store.PAIR for slot in doc["slots"]):
            raise Conflict("the vault already has a password and passkey - remove them first")
        root = self._proven_root(doc, proof)
        held = self.holder().get(doc["id"])
        dek = self._adopted(path, doc, root)
        store.add_pair(path, root, dek, password, cred_id, rp_id, origin, cose, label or rp_id,
                       count)
        if held is not None:
            self._hold(root, dek)

    def remove_mfa(self):
        self._dek()  # removing an unlock method needs an unlocked vault
        store.remove_mfa(store.vault_path())

    def replace_recovery(self, passphrase, proof):
        """A new recovery passphrase, allowed only with a proof: see `_proven_root`."""
        path = store.vault_path()
        store.replace_recovery(path, self._proven_root(store.load(path), proof), passphrase)
