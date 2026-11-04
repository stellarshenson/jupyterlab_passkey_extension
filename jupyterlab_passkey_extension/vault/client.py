"""The vault as seen from outside the server: the CLI and the Python API share this.

Everything goes through the server's authenticated REST API. The two passkey steps -
unlocking with a passkey and adding one - raise a notification
whose button runs a vault command in the JupyterLab tab; the page sends the PRF
straight to the server. Through the result relay only the error of an unlock comes back
here, and `ok` or the error of an added passkey; an unlock is read in vault status. So
the PRF never passes through this process.

Processes of one user share an unlock, and with no vault a set-up. A record in the relay
directory, with no secret in it, says one is pending: the first process raises the
notification and the others wait on vault status, so one press lets them all go on. Each
process checks vault status itself, because the unlock can come from anywhere: the panel,
another tab, a terminal. The server removes the record on every unlock, the claim names
the process that holds it, and that process removes its claim when its wait ends. A claim
that goes with its process ends no wait: a waiting process claims and raises its own.
"""

import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

from .. import cli as _cli
from .. import relay
from . import store

UNLOCK_COMMAND = "passkey:vault-unlock"
REGISTER_COMMAND = "passkey:vault-register"
SETUP_COMMAND = "passkey:vault-setup"
REQUEST_TIMEOUT = 30
LOCKED = "the vault is locked - run `jupyterlab-passkey vault unlock`"
NOT_SET_UP = "no vault yet - run `jupyterlab-passkey vault init`"
WAITING_UNLOCK = "the vault is locked - waiting for the unlock notification in your JupyterLab tab"
WAITING_SETUP = "no vault yet - waiting for the set-up notification in your JupyterLab tab"
# After a notification nobody answered, a later process fails at once for this long.
UNANSWERED_SECONDS = 600
# A failed unlock stays on record this long, so each wait reads it on a coming round.
FAILED_SECONDS = 5
WAIT_POLL = 1


def no_vault(path):
    """The refusal when there is no vault file: the path looked at, and the next step."""
    return f"no vault at {path} - run `jupyterlab-passkey vault init`"


class VaultClientError(Exception):
    """A refusal from the vault or the server, as one line."""


class VaultLocked(VaultClientError):
    pass


class NoClick(VaultClientError):
    """A browser step's wait ran out: nobody answered the notification."""


class _Opened(Exception):
    """Vault status reports unlocked, so the wait for the notification is over."""


def request(method, action, body=None, params=None):
    """Call `vault/<action>`; returns the JSON answer, or None for an empty one."""
    try:
        base, token = _cli._server()
    except SystemExit as e:
        raise VaultClientError(str(e)) from None
    url = f"{base}/jupyterlab-passkey-extension/vault/{action}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"token {token}"
    data = json.dumps(body if body is not None else {}).encode() if method != "GET" else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _cli._LOOPBACK.open(req, timeout=REQUEST_TIMEOUT) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        try:
            message = json.loads(e.read() or b"{}").get("error")
        except (ValueError, AttributeError):
            message = None
        # A refused token, not a refused proof: the vault's own 403 carries an error.
        if e.code == 401 or (e.code == 403 and not message):
            _cli._forget_server()
        if e.code == 423:
            raise VaultLocked(message or "the vault is locked")
        if e.code == 404 and not message:
            # The server runs without the vault's routes, as after an install into a
            # running server - the panel says the same (src/vault/api.ts).
            message = "the vault is not loaded on this Jupyter server - restart the server"
        raise VaultClientError(message or f"the vault answered {e.code} {e.reason}")
    except OSError as e:
        _cli._forget_server()
        reason = getattr(e, "reason", e)
        raise VaultClientError(f"cannot reach {base} ({reason}) - is JupyterLab running?")
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        # A proxy or a login page can answer 200 with HTML: a failed read, as one line.
        raise VaultClientError(f"the answer of {base} to vault/{action} is not JSON") from None


def browser_step(command, args, label, message, timeout, poll=None):
    """Raise the notification for a vault command and wait for the page to finish it.
    `poll` runs on every round of the wait and raises to end it early. Returns the
    page's answer."""
    try:
        return _cli._run({**args, "nonce": secrets.token_urlsafe(24)}, label, message, timeout,
                         command_id=command, poll=poll)
    except _cli.NoRelay as e:
        raise NoClick(str(e)) from None
    except SystemExit as e:
        raise VaultClientError(str(e)) from None


def _unusable(error):
    """A relay directory that refuses: not ours, unwritable or full. On shm the relays
    need it, so it is one line. The keyctl backend needs no directory for its relays,
    so there the process goes on with no shared record and raises its own notification."""
    try:
        keyctl = relay.backend() == "keyctl"
    except OSError:
        keyctl = False
    if not keyctl:
        raise VaultClientError(f"cannot use the relay directory: {error}") from None


def _wait_path():
    """The shared unlock's record; the relay directory must be ours, as for a relay."""
    return os.path.join(relay.ensure_relay_dir(), relay.UNLOCK_WAIT)


def _alive(pid):
    # shortcut: a pid from another pid namespace reads as gone, so a process there gets
    # its own notification; record the namespace if such processes share a relay directory.
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    return True


def _wait_record():
    """The shared unlock's record while it holds, else None. Its state is `pending`, or
    how an unlock ended with the vault locked: `failed` or `unanswered`, with `why`. A
    record that does not parse is none, and so is the claim of a process that is gone."""
    try:
        with open(_wait_path()) as f:
            record = json.load(f)
    except FileNotFoundError:
        return None
    except OSError as e:
        return _unusable(e)
    except ValueError:
        return None
    try:
        since = time.time() - record["at"]
        # Negative: the system clock was set back, and the time on record says nothing.
        live = 0 <= since < record["seconds"] and isinstance(record["why"], str)
        if live and record["state"] == "pending":
            live = record["pid"] > 0 and _alive(record["pid"])
    except (TypeError, KeyError, OverflowError):
        return None
    return record if live else None


def _put_wait(state, seconds, why=""):
    record = {"at": time.time(), "seconds": seconds, "state": state, "why": why,
              "pid": os.getpid()}
    relay.write_relay("unlock-wait", relay.UNLOCK_WAIT, json.dumps(record))


def _claim_unlock(seconds):
    """None for the process that raises the notification, else the pending unlock to
    share. The claim names its process: one that is gone holds none, and the one that
    raised the notification removes its claim when its wait ends (`_drop_claim`). A claim
    over an end on record keeps its line, for the waits that have not read it yet."""
    try:
        with store._locked(_wait_path()):
            record = _wait_record()
            if record is not None and record["state"] == "pending":
                return record
            # The trigger POST comes before the wait, and may take this long.
            _put_wait("pending", seconds + _cli.TRIGGER_TIMEOUT, (record or {}).get("why", ""))
    except OSError as e:
        _unusable(e)
    return None


def _drop_claim():
    """Remove this process's claim: its wait is over, however it ended, Ctrl-C included.
    An end on record in its place, or the claim of another process, stays."""
    try:
        with store._locked(_wait_path()):
            record = _wait_record()
            if record is not None and record["state"] == "pending" \
                    and record["pid"] == os.getpid():
                os.unlink(_wait_path())
    except (OSError, VaultClientError):
        # It runs on the way out, so it must not replace the error that ends the wait;
        # a claim left here ends at its deadline.
        pass


def _end_unlock(state, seconds, why):
    """Record how the unlock ended with the vault locked, for every other process."""
    try:
        with store._locked(_wait_path()):
            _put_wait(state, seconds, why)
    except OSError as e:
        _unusable(e)


def _refuse_after_no_answer():
    """Fail at once after a notification nobody answered, so a batch does not wait on
    nobody process by process."""
    record = _wait_record()
    if record is not None and record["state"] == "unanswered":
        raise VaultClientError(record["why"])


class Vault:
    """The vault from Python code or a notebook.

        vault = Vault()
        vault.get("github/api")                    # the password
        vault.get("github/api", field="username")
    """

    def __init__(self, timeout=_cli.CLICK_TIMEOUT):
        self.timeout = timeout

    def status(self):
        return request("GET", "status")

    def unlock(self, recovery=None, password=None, code=None):
        """Unlock with the passkey (a notification to click), with the recovery
        passphrase, or with the unlock password and a code of the authenticator app.
        With no secret given, an unlocked vault returns at once, and an unlock already
        pending for this user is shared with no notification."""
        if recovery is not None:
            return request("POST", "unlock", {"recovery": recovery})
        if password is not None:
            return request("POST", "unlock", {"password": password, "code": code})
        s = self.status()
        if not s["initialized"]:
            raise VaultClientError(no_vault(s["path"]))
        if s["unlocked"]:
            return s
        if any(slot["type"] == "passkey" for slot in s["slots"]):
            # The page falls back to its chooser when no passkey matches its hostname.
            args, message = {}, "Unlock the vault with your passkey - click to approve."
        else:
            args, message = {"method": "choose"}, "Choose how to unlock the vault - click to approve."
        self._one_notification(UNLOCK_COMMAND, args, "Unlock vault", message, self.timeout,
                               "unlocked", WAITING_UNLOCK, LOCKED)
        return self.status()

    def _stop_when(self, key):
        """The poll of a wait for the notification: end it once vault status reports
        `key`. A failed read tells nothing about the unlock, so it ends no wait."""
        try:
            reached = self.status()[key]
        except VaultClientError:
            return
        if reached:
            raise _Opened

    def _one_notification(self, command, args, label, message, seconds, key, waiting, failure):
        """Raise the one notification of this user and wait until vault status reports
        `key`, or share the one another process raised. An end that does not come ends
        every other process's wait. The page posts only a failure."""
        pending = _claim_unlock(seconds)
        if pending is not None:
            seconds = self._share_unlock(pending, seconds, key, waiting, failure)
            if seconds is None:
                return
        try:
            browser_step(command, args, label, message, seconds,
                         poll=lambda: self._stop_when(key))
        except _Opened:
            pass
        except NoClick:
            # One last look, as `_wait` takes: a press in the final round is no failure.
            if not self.status()[key]:
                why = failure.replace(" - run", f" - nobody answered within {seconds:.0f}s - run")
                _end_unlock("unanswered", UNANSWERED_SECONDS, why)
                raise VaultClientError(why) from None
        except VaultClientError as e:
            _end_unlock("failed", FAILED_SECONDS, str(e))
            raise
        finally:
            _drop_claim()

    def _share_unlock(self, pending, seconds, key, waiting, failure):
        """Wait until vault status reports `key`, for the unlock another process asked
        for; None then. An end on record ends the wait with its line, and `failure` is
        the line for a deadline with none. A claim that went with no end, because its
        process stopped, ends no wait: a claim of another process in its place is
        shared, or this process claims and gets the seconds left for its own notification."""
        _cli._say(waiting)
        deadline = time.monotonic() + seconds
        while True:
            # The record first: the server removes it only after the vault opened, so
            # no record and then status short of `key` means the claim went with no unlock.
            record = _wait_record()
            try:
                reached = self.status()[key]
            except VaultClientError:
                # A failed read tells nothing about the unlock: read again next round.
                reached = None
            if reached:
                return None
            left = deadline - time.monotonic()
            if left <= 0:
                raise VaultClientError((record or {}).get("why") or failure)
            if reached is not None and record != pending:
                if record is None:
                    record = _claim_unlock(left)
                    if record is None:
                        return left
                if record["state"] != "pending" or record["why"]:
                    raise VaultClientError(record["why"] or failure)
                pending = record
            time.sleep(WAIT_POLL)

    def _setup(self, seconds):
        """Set a vault that does not exist up from the page. One notification serves
        every process of this user, by the record an unlock uses: the page's `init` is
        an unlock, so it ends the others' wait. The process that raised the notification
        waits until vault status shows a vault, made by its page or elsewhere, such as
        the panel; the choice of a method then goes on in the tab."""
        _refuse_after_no_answer()
        self._one_notification(SETUP_COMMAND, {}, "Set up vault",
                               "create the vault - click to open the set-up steps.", seconds,
                               "initialized", WAITING_SETUP, NOT_SET_UP)

    def lock(self):
        request("POST", "lock")

    def rotate(self, proof):
        """Rotate the data key; `proof` is {"current": the recovery passphrase} or
        {"cred_id", "prf": a passkey's PRF}. The vault must be unlocked."""
        return request("POST", "rotate", {"proof": proof})

    def _unlocked(self, call):
        """Run `call`; when the vault is locked, unlock with the passkey and run it
        again. It fails at once after a notification nobody answered; `unlock` itself
        asks anew."""
        try:
            return call()
        except VaultLocked:
            _refuse_after_no_answer()
            self.unlock()
            return call()

    def list(self):
        return self._unlocked(lambda: request("GET", "entries"))["entries"]

    def get(self, name, field="password"):
        return self._unlocked(
            lambda: request("POST", "reveal", {"name": name, "field": field})
        )["value"]
