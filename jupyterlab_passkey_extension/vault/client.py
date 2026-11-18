"""The vault as seen from outside the server: the CLI and the Python API share this.

Everything goes through the server's authenticated REST API. The two passkey steps -
unlocking with a passkey and adding one - raise a notification
whose button runs a vault command in the JupyterLab tab; the page sends the PRF
straight to the server. Through the result relay only the error of an unlock comes back
here, and `ok` or the error of an added passkey; an unlock is read in vault status. So
the PRF never passes through this process.

Processes of one user share a pending unlock, and with no vault a pending set-up, within
their operation. A record in the relay directory, with no secret in it, says one is
pending and which operation raised it: the first process of that operation raises the
notification and the others wait on vault status, so one press lets them all go on, while
a process of the other operation raises its own. Each process checks vault status itself,
because the unlock can come from anywhere: the panel, another tab, a terminal. The server
removes the record on every unlock, the claim names the process that holds it, and that
process removes its claim when its wait ends. A claim that goes with its process ends no
wait: a waiting process claims and raises its own. A raised notification stays on screen
when its process stops, so its claim stays shared until its window ends, 180 s at most.
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
from .cookies import to_jar, to_netscape

UNLOCK_COMMAND = "passkey:vault-unlock"
REGISTER_COMMAND = "passkey:vault-register"
SETUP_COMMAND = "passkey:vault-setup"
REQUEST_TIMEOUT = 30
LOCKED = "the vault is locked - run `jupyterlab-passkey vault unlock`"
NOT_SET_UP = "no vault yet - run `jupyterlab-passkey vault init`"
WAITING_UNLOCK = "the vault is locked - waiting for the notification in your JupyterLab tab"
WAITING_SETUP = "no vault yet - waiting for the set-up notification in your JupyterLab tab"
# After a notification nobody answered, a later process fails at once for this long.
UNANSWERED_SECONDS = 600
# A failed unlock stays on record this long, so each wait reads it on a coming round.
FAILED_SECONDS = 5
# A raised claim whose process stopped holds this long after the raise at most, the
# longest default wait (vault init and passkey add): its notification may be closed by hand.
REGISTER_TIMEOUT = 180.0
WAIT_POLL = 1


def no_vault(path):
    """The refusal when there is no vault file: the path looked at, and the next step."""
    return f"no vault at {path} - run `jupyterlab-passkey vault init`"


class VaultClientError(Exception):
    """A refusal from the vault or the server, as one line. `code` is the server's
    stable name for the kind of refusal, or None when the answer carried none."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class VaultLocked(VaultClientError):
    pass


class NoVault(VaultClientError):
    """The server found no vault file. Its own code for that is `invalid`; this one is
    `no-vault`, the CLI's --json code."""


def _missing_vault(error):
    """The path of a vault a command found missing, or None for any other error."""
    head, sep, tail = str(error).partition(" - run `jupyterlab-passkey vault init`")
    if sep and not tail and head.startswith("no vault at "):
        return head[len("no vault at "):]
    return None


class NoClick(VaultClientError):
    """A browser step's wait ran out: nobody answered the notification."""


class _Opened(Exception):
    """Vault status reports unlocked, so the wait for the notification is over."""


def request(method, action, body=None, params=None):
    """Call `vault/<action>`; returns the JSON answer, or None for an empty one."""
    try:
        base, token = _cli._server()
    except SystemExit as e:
        raise VaultClientError(str(e), "no-server") from None
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
            answer = json.loads(e.read() or b"{}")
            message, code = answer.get("error"), answer.get("code")
        except (ValueError, AttributeError):
            message = code = None
        # A refused token, not a refused proof: the vault's own 403 carries an error.
        if e.code == 401 or (e.code == 403 and not message):
            _cli._forget_server()
        # An older server carries no code; its status still says the vault is locked.
        if code == "locked" or e.code == 423:
            raise VaultLocked(message or "the vault is locked", code or "locked")
        if e.code == 404 and not message:
            # The server runs without the vault's routes, as after an install into a
            # running server - the panel says the same (src/vault/api.ts).
            message = "the vault is not loaded - restart the Jupyter server"
        if code == "invalid" and _missing_vault(message):
            raise NoVault(message, "no-vault")
        raise VaultClientError(message or f"the vault answered {e.code} {e.reason}", code)
    except OSError as e:
        _cli._forget_server()
        reason = getattr(e, "reason", e)
        raise VaultClientError(f"cannot reach {base} ({reason}) - is JupyterLab running?", "no-server")
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        # A proxy or a login page can answer 200 with HTML: a failed read, as one line.
        raise VaultClientError(f"the answer of {base} to vault/{action} is not JSON", "server") from None


def browser_step(command, args, label, message, timeout, poll=None):
    """Raise the notification for a vault command and wait for the page to finish it.
    `poll` runs on every round of the wait and raises to end it early. Returns the
    page's answer."""
    try:
        return _cli._run({**args, "nonce": secrets.token_urlsafe(24)}, label, message, timeout,
                         command_id=command, poll=poll)
    except _cli.NoRelay as e:
        raise NoClick(str(e), "relay") from None
    except SystemExit as e:
        raise VaultClientError(str(e), getattr(e, "json_code", "usage")) from None


def _unusable(error):
    """A relay directory that refuses: not ours, unwritable or full. On shm the relays
    need it, so it is one line. The keyctl backend needs no directory for its relays,
    so there the process goes on with no shared record and raises its own notification."""
    try:
        keyctl = relay.backend() == "keyctl"
    except OSError:
        keyctl = False
    if not keyctl:
        raise VaultClientError(f"cannot use the relay directory: {error}", "relay") from None


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
    record that does not parse is none, and so is the claim of a process that is gone,
    unless it raised its notification: that one holds until its `window` ends, and
    REGISTER_TIMEOUT at most."""
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
            live = since < min(record.get("window") or 0, REGISTER_TIMEOUT) \
                or (record["pid"] > 0 and _alive(record["pid"]))
    except (TypeError, KeyError, OverflowError):
        return None
    return record if live else None


def _put_wait(state, seconds, why="", command="", claim=None, window=None):
    record = {"at": time.time(), "seconds": seconds, "state": state, "why": why,
              "pid": os.getpid(), "command": command, "claim": claim, "window": window}
    relay.write_relay("unlock-wait", relay.UNLOCK_WAIT, json.dumps(record))


def _claim_unlock(seconds, command, claim=None):
    """None for the process that raises the notification, else the pending unlock to
    share. The claim names its process: one that is gone holds none until it raised its
    notification (`_raise_claim`), and the wait that raised the notification, named by
    `claim`, removes its claim when it ends (`_drop_claim`). A claim over an end on record
    keeps its line, for the waits that have not read it yet."""
    try:
        with store._locked(_wait_path()):
            record = _wait_record()
            if record is not None and record["state"] == "pending":
                return record
            # The trigger POST comes before the wait, and may take this long.
            why = (record or {}).get("why", "") if (record or {}).get("command") == command else ""
            _put_wait("pending", seconds + _cli.TRIGGER_TIMEOUT, why, command, claim)
    except OSError as e:
        _unusable(e)
    return None


def _raise_claim(claim, seconds):
    """The notification of the wait `claim` names is on screen from now for `seconds`:
    its claim holds that long, also after this process stops (`_wait_record`)."""
    try:
        with store._locked(_wait_path()):
            record = _wait_record()
            if record is not None and record["state"] == "pending" \
                    and record.get("claim") == claim:
                # The margin the claim had: this process records its end after the window.
                _put_wait("pending", seconds + _cli.TRIGGER_TIMEOUT, record["why"],
                          record["command"], claim, seconds)
    except (OSError, VaultClientError):
        # Not marked, the claim goes with this process, as one not raised does.
        pass


def _drop_claim(claim, ended):
    """Remove the claim of the wait `claim` names: that wait is over, however it ended,
    Ctrl-C included. A wait that stops with no end (`ended` false) leaves the claim of a
    raised notification, which stays on screen, for the next caller to share. An end on
    record in its place, or any other claim, one of another wait of this process
    included, stays."""
    try:
        with store._locked(_wait_path()):
            record = _wait_record()
            if record is not None and record["state"] == "pending" \
                    and record.get("claim") == claim and (ended or not record.get("window")):
                os.unlink(_wait_path())
    except (OSError, VaultClientError):
        # It runs on the way out, so it must not replace the error that ends the wait;
        # a claim left here ends at its deadline.
        pass


def _end_unlock(state, seconds, why, command):
    """Record how the unlock ended with the vault locked, for every other process."""
    try:
        with store._locked(_wait_path()):
            _put_wait(state, seconds, why, command)
    except OSError as e:
        _unusable(e)


def _unanswered(failure, seconds, command):
    """Record that nobody answered the notification within `seconds`, for every other
    process; the error that ends this wait."""
    why = failure.replace(" - run", f" - nobody answered within {seconds:.0f}s - run")
    _end_unlock("unanswered", UNANSWERED_SECONDS, why, command)
    return VaultClientError(why, "locked")


def _refuse_after_no_answer(command):
    """Fail at once after a notification nobody answered for this operation, so a batch
    does not wait on nobody process by process. The record is one per user, so only the
    one this operation raised counts: a record with no command is from an older version
    and refuses nothing."""
    record = _wait_record()
    if record is not None and record["state"] == "unanswered" \
            and record.get("command") == command:
        raise VaultClientError(record["why"], "locked")


def _entry_fields(password, generate, length, username, url, category, notes, cookies):
    """The fields of an add or edit, as `POST` and `PATCH vault/entries` take them; a field
    left None is not sent. A generated password is made by the server's generator."""
    if generate and password is not None:
        raise VaultClientError("give password or generate, not both", "usage")
    if password == "" or cookies == "":
        raise VaultClientError("nothing entered", "usage")
    fields = {key: value for key, value in (("username", username), ("url", url),
                                            ("category", category), ("notes", notes))
              if value is not None}
    if generate:
        password = request("GET", "generate", params={} if length is None else {"length": str(length)})["value"]
    if password is not None:
        fields["password"] = password
    if cookies is not None:
        fields["cookies"] = cookies
    return fields


class Vault:
    """The vault from Python code or a notebook. Each method that needs an open vault
    unlocks a locked one first; a refusal raises VaultClientError with the CLI's code.

        vault = Vault()
        vault.get("github/api")                    # the password
        vault.get("github/api", field="username")
        vault.add("db/prod", generate=True, username="app")
        vault.add("site/app", cookies=pasted, url="https://app.example.com")
        requests.get(url, cookies=vault.cookies("site/app"), headers=vault.headers("site/app"))
        vault.rename("db/prod", "db/primary")
        vault.delete("db/primary")
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
            raise VaultClientError(no_vault(s["path"]), "no-vault")
        if s["unlocked"]:
            return s
        if any(slot["type"] == "passkey" for slot in s["slots"]):
            # The page falls back to its chooser when no passkey matches its hostname.
            args, message = {}, "Unlock the vault with your passkey"
        else:
            args, message = {"method": "choose"}, "Choose how to unlock the vault"
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
        # From before the claim is written: Ctrl-C between the claim and the notification,
        # this wait's first claim or one it takes while it shares, removes it too.
        claim, raised, ended = secrets.token_hex(8), False, False

        def poll():
            nonlocal raised
            if not raised:
                # The first round comes after the trigger POST landed: the notification
                # is on screen.
                raised = True
                _raise_claim(claim, seconds)
            self._stop_when(key)

        try:
            pending = _claim_unlock(seconds, command, claim)
            if pending is not None:
                seconds = self._share_unlock(pending, seconds, key, waiting, failure, command,
                                             claim)
                if seconds is None:
                    return
            try:
                browser_step(command, args, label, message, seconds, poll=poll)
            except _Opened:
                pass
            except NoClick:
                # One last look, as `_wait` takes: a press in the final round is no failure.
                if not self.status()[key]:
                    raise _unanswered(failure, seconds, command) from None
            except VaultClientError as e:
                _end_unlock("failed", FAILED_SECONDS, str(e), command)
                raise
            ended = True
        finally:
            _drop_claim(claim, ended)

    def _share_unlock(self, pending, seconds, key, waiting, failure, command, claim):
        """Wait until vault status reports `key`, for the notification another process
        of this operation asked for; None then. A pending notification of the other
        operation is not this one's: this process gets `seconds` and raises its own. An
        end on record ends the wait with its line, and `failure` is the line for a
        deadline with none. A claim that went with no end, because its process stopped,
        ends no wait: a claim of another process of this operation in its place is
        shared, or this process claims and gets the seconds left for its own
        notification. A raised notification is shared to its window end, its process
        stopped or not; nobody answered it then, and that end goes on record."""
        if pending.get("command") != command:
            return seconds
        _cli._say(waiting)
        deadline = time.monotonic() + seconds
        while True:
            # The record first: the server removes it only after the vault opened, so
            # no record and then status short of `key` means the claim went with no unlock.
            record = _wait_record()
            if record is not None and record.get("command") != command:
                # Another operation's notification is no record for this wait.
                record = None
            if record is not None and record.get("window") \
                    and record.get("claim") == pending.get("claim"):
                # The claim shared, its notification raised since: the same request.
                pending = record
            try:
                reached = self.status()[key]
            except VaultClientError:
                # A failed read tells nothing about the unlock: read again next round.
                reached = None
            if reached:
                return None
            left = deadline - time.monotonic()
            if left <= 0:
                raise VaultClientError((record or {}).get("why") or failure, "locked")
            if reached is not None and record != pending:
                if record is None and pending.get("window") \
                        and time.time() - pending["at"] >= pending["window"]:
                    # The window ended with no end on record: its process stopped first.
                    raise _unanswered(failure, pending["window"], command)
                if record is None:
                    record = _claim_unlock(left, command, claim)
                    if record is None or record.get("command") != command:
                        return left
                if record["state"] != "pending" or record["why"]:
                    raise VaultClientError(record["why"] or failure, "locked")
                pending = record
            time.sleep(WAIT_POLL)

    def _setup(self, seconds):
        """Set a vault that does not exist up from the page. One notification serves
        every process of this user that sets up, by the record an unlock uses: the page's
        `init` is an unlock, so it ends the others' wait. The process that raised the
        notification waits until vault status shows a vault, made by its page or
        elsewhere, such as the panel; the choice of a method then goes on in the tab."""
        _refuse_after_no_answer(SETUP_COMMAND)
        self._one_notification(SETUP_COMMAND, {}, "Set up vault",
                               "Create the vault", seconds,
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
            _refuse_after_no_answer(UNLOCK_COMMAND)
            self.unlock()
            return call()

    def list(self):
        return self._unlocked(lambda: request("GET", "entries"))["entries"]

    def _read(self, name, field=None):
        """A field as the server answers it: text, or the unexpired cookies of a cookie
        entry as a list. With no field, a cookie entry's cookies, a login entry's password."""
        return self._unlocked(
            lambda: request("POST", "reveal", {"name": name, "field": field})
        )["value"]

    def get(self, name, field=None):
        """A field's value; with no field, a login entry's password or a cookie entry's
        unexpired cookies as a cookies.txt."""
        if field == "headers":
            raise VaultClientError(
                f"get does not read the headers - use `Vault().headers({name!r})`", "invalid")
        value = self._read(name, field)
        return to_netscape(value) if isinstance(value, list) else value

    def cookies(self, name):
        """A cookie entry's unexpired cookies as an http.cookiejar.CookieJar, for
        `requests.get(url, cookies=jar)` or urllib's HTTPCookieProcessor. urllib keeps a
        host-only cookie to its own host; requests copies the cookies into its own jar
        and also sends a host-only cookie to subdomains."""
        return to_jar(self._read(name, "cookies"))

    def headers(self, name):
        """The request headers a cookie entry keeps, name to value, for
        `requests.get(url, headers=...)`; a name kept twice has its last value. The
        Cookie header is not among them: `cookies` gives the cookies."""
        return dict(self._read(name, "headers"))

    def add(self, name, *, password=None, generate=False, length=None, username=None,
            url=None, category=None, notes=None, cookies=None):
        """Add a login entry with `password`, or `generate=True` for a generated one that
        is not returned; or a cookie entry from pasted `cookies` text in any form the
        vault reads."""
        if password is None and not generate and cookies is None:
            raise VaultClientError("nothing entered", "usage")
        fields = _entry_fields(password, generate, length, username, url, category, notes, cookies)
        if cookies is not None:
            fields["type"] = "cookies"
        self._unlocked(lambda: request("POST", "entries", {"name": name, "fields": fields}))

    def edit(self, name, *, password=None, generate=False, length=None, username=None,
             url=None, category=None, notes=None, cookies=None):
        """Change the fields given; a field left None keeps its value. `password`,
        `generate=True` or `cookies` replaces the secret: a password on a login entry,
        the cookies and the headers on a cookie entry."""
        fields = _entry_fields(password, generate, length, username, url, category, notes, cookies)
        if not fields:
            raise VaultClientError("nothing to change - give at least one field", "usage")
        self._unlocked(lambda: request("PATCH", "entries", {"name": name, "fields": fields}))

    def rename(self, name, new_name):
        self._unlocked(lambda: request("POST", "rename", {"name": name, "new_name": new_name}))

    def delete(self, name):
        self._unlocked(lambda: request("POST", "delete", {"name": name}))

    def import_entries(self, items):
        """Add entries from a list of objects, as `vault import` reads them; returns
        {"added": count, "skipped": [names that exist]}."""
        return self._unlocked(lambda: request("POST", "import", {"entries": items}))

    def generate(self, length=None, symbols=True):
        """A random password, not stored; `length` None is the server's default."""
        params = {"symbols": "1" if symbols else "0"}
        if length is not None:
            params["length"] = str(length)
        return request("GET", "generate", params=params)["value"]

    def _stage(self, name, field, kind, command, label, message):
        nonce = self._unlocked(
            lambda: request("POST", "stage", {"name": name, "field": field, "kind": kind}))["nonce"]
        try:
            _cli._trigger(command, {"nonce": nonce, "label": name}, label, message)
        except BaseException:
            # No button was raised, so nothing can ever collect this relay.
            relay.unstage(nonce, kind)
            raise

    def copy(self, name, field=None):
        """Raise a notification whose click puts the value on the browser clipboard: a
        cookie entry's cookies.txt with no field. The value never enters this process."""
        self._stage(name, field, "secret", _cli.COPY_COMMAND, "Copy to clipboard", f"Copy **{name}**")

    def show(self, name, field=None):
        """Raise a notification whose click shows the value as a distorted image."""
        self._stage(name, field, "code", _cli.SHOW_COMMAND, "Show", f"Show **{name}**")
