"""`jupyterlab-passkey vault ...` - the vault from a terminal.

Every command calls the vault agent in the Jupyter server. A secret is never taken
from a command-line option: a new one is typed at a hidden prompt (twice), piped on
stdin, typed in the browser with --in-browser, or generated. `copy` and `show` have
the server stage the value for the existing clipboard and image flows, so it never
enters this process at all.
"""

import argparse
import collections
import datetime
import getpass
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import urllib.parse

from .. import cli as _cli
from .. import relay
from . import gitcred, store
from .client import (
    LOCKED,
    REGISTER_COMMAND,
    Vault,
    VaultClientError,
    VaultLocked,
    browser_step,
    no_vault,
    request,
)
from .service import GENERATE_LENGTH, READABLE, _check_name

REGISTER_TIMEOUT = 600.0


def _duration(seconds):
    hours, rest = divmod(int(seconds), 3600)
    return f"{hours}h {rest // 60}m" if hours else f"{rest // 60}m {rest % 60}s"


def _minutes(minutes):
    """An unlock duration in hours and minutes, a zero part left out: 4h, 1h 30m, 45m."""
    hours, rest = divmod(minutes, 60)
    return " ".join(part for part in (f"{hours}h" if hours else "", f"{rest}m" if rest else "") if part)


def _read_secret(a, prompt, twice, blind_twice=False):
    """A secret from the browser dialog, a hidden prompt, or stdin - never argv.

    `twice` is the vault's rule for this kind of secret: two matching fields in the
    dialog and two entries at a blind prompt. `blind_twice` asks twice at the blind
    prompt alone, where a typing mistake cannot be seen."""
    if a.in_browser:
        nonce = secrets.token_urlsafe(24)
        args = {"nonce": nonce, "prompt": prompt, "twice": twice}
        _cli._trigger(_cli.PASSPHRASE_COMMAND, args, "Enter secret",
                      f"Enter {prompt[0].lower()}{prompt[1:]}")
        try:
            _cli._wait(nonce, "pass", a.timeout, "the button was never clicked, or the dialog "
                       "was left open", watch_cancel=True)
            value = relay.collect(nonce, "pass")
        finally:
            relay.unstage(nonce, "pass")
        if not value:
            raise SystemExit("the dialog relayed nothing")
        return value
    if sys.stdin.isatty():
        value = getpass.getpass(f"{prompt}: ")
        if (twice or blind_twice) and getpass.getpass("again: ") != value:
            raise SystemExit("the two entries differ")
    else:
        value = _cli._read_stdin_or_file("-", "secret", "nothing entered", "stdin is not text")
    if not value:
        raise SystemExit("nothing entered")
    return value


def _length(a):
    """The --length query parameter, or none so the server's default applies."""
    return {} if a.length is None else {"length": str(a.length)}


def _new_password(a):
    if a.generate:
        return request("GET", "generate", params=_length(a))["value"]
    return _read_secret(a, "Password", twice=False, blind_twice=True)


def _fields(a):
    fields = {}
    for key in ("username", "url", "category", "notes"):
        value = getattr(a, key)
        if value is not None:
            fields[key] = value
    return fields


def _say_mfa(s):
    """The unlock password and authenticator app, as status prints the pair."""
    password = next((x for x in s["slots"] if x["type"] == "password"), None)
    app = s.get("authenticator")
    if password and app:
        return f"added {app['created']}"
    # A vault written by 1.1.28 to 1.1.31 can hold one without the other.
    if password:
        return f"password only, added {password['created']}"
    return f"app only, added {app['created']}" if app else "none"


def _say_pair(s):
    """Password and passkey, as status prints it."""
    pair = next((x for x in s["slots"] if x["type"] == store.PAIR), None)
    return f"added {pair['created']} at {pair['origin']}" if pair else "none"


def _say_status(s):
    if not s["initialized"]:
        return no_vault(s["path"])
    if s["unlocked"]:
        return f"unlocked, {_duration(s['remaining'])} left"
    return "locked"


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #


def cmd_init(a, vault):
    s = vault.status()
    if s["initialized"]:
        raise SystemExit(f"a vault already exists at {s['path']}")
    recovery = _read_secret(a, "Recovery passphrase", twice=True)
    request("POST", "init", {"recovery": recovery})
    _cli._say(
        f"vault created at {s['path']} - store the recovery passphrase offline; "
        "it opens the vault when no other method can"
    )
    if not a.no_passkey:
        hint = ("the vault has no passkey - run `jupyterlab-passkey vault passkey add`, "
                "or add a method with the cog")
        try:
            _add_passkey(a, vault)
        except VaultClientError as e:
            raise SystemExit(f"{e}\n{hint}")
        except KeyboardInterrupt:
            raise SystemExit(f"\n{hint}")
    _cli._emit(a, "vault init", {"path": s["path"]})
    return 0


def _unlock_method(a, vault, s):
    """The unlock the options name: the recovery passphrase, or the unlock password and
    a code of the authenticator app. A vault whose only unlock password goes with a
    passkey raises the notification, as unlock with no option does."""
    if a.recovery:
        return vault.unlock(recovery=_read_secret(a, "Recovery passphrase", twice=False))
    if a.password and not any(x["type"] == "password" for x in s["slots"]) and any(
            x["type"] == store.PAIR for x in s["slots"]):
        # Password and passkey: the unlock with no option; its password is typed in the tab.
        return vault.unlock()
    if a.password:
        needs_code = bool(s.get("authenticator"))
        if needs_code and not a.in_browser and not sys.stdin.isatty():
            # A pipe carries one secret; this needs two.
            raise SystemExit("--password needs the unlock password and an app code - "
                             "run at a terminal or with --in-browser")
        password = _read_secret(a, "Unlock password", twice=False)
        # The code last: it stays right for less than a minute.
        code = _read_secret(a, "Code of the authenticator app", twice=False) if needs_code else None
        return vault.unlock(password=password, code=code)
    return vault.unlock()


def _unlock_before_read(a, vault):
    """A read command with --recovery or --password unlocks a locked vault by that
    method before its read; an unlocked vault ignores the flags and asks nothing."""
    if not (a.recovery or a.password):
        return
    s = vault.status()
    if s["initialized"] and not s["unlocked"]:
        _unlock_method(a, vault, s)


def cmd_unlock(a, vault):
    s = vault.status()
    if not s["initialized"]:
        # Before `--recovery` asks for a passphrase there is nothing to open with.
        raise _cli.Fail(no_vault(s["path"]), "no-vault")
    s = _unlock_method(a, vault, s)
    _cli._say(f"vault {_say_status(s)}")
    _cli._emit(a, "vault unlock", s)
    return 0


def cmd_lock(a, vault):
    vault.lock()
    _cli._say("vault locked")
    _cli._emit(a, "vault lock", {"locked": True})
    return 0


def cmd_status(a, vault):
    s = vault.status()
    _cli._emit(a, "vault status", s)
    if _cli._json(a):
        return 0
    h = s["holder"]
    passkeys = [x for x in s["slots"] if x["type"] == "passkey"]
    print(f"vault: {s['path']}")
    print(f"state: {_say_status(s)}")
    print(f"holder: {h['name']} - {h['about']}")
    if h.get("notice"):
        print(f"notice: {h['notice']}")
    print(f"protection: {h['summary']} - {h['protection']}")
    for d in h["details"]:
        print(f"  {d['label']}: {'yes' if h['capabilities'][d['key']] else 'no'} - {d['text']}")
    print(f"passkeys: {len(passkeys)}" + "".join(f"\n  {p['label']} @ {p['rp_id']}" for p in passkeys))
    print(f"password and authenticator app: {_say_mfa(s)}")
    print(f"password and passkey: {_say_pair(s)}")
    print(f"unlock duration: {_minutes(s['settings']['unlock_minutes'])}")
    return 0


def cmd_list(a, vault):
    _unlock_before_read(a, vault)
    entries = vault.list()
    if a.category:
        entries = [e for e in entries if e["category"] == a.category]
    _cli._emit(a, "vault list", {"entries": entries})
    if not _cli._json(a):
        for e in entries:
            print("\t".join((e["name"], e["username"], e["category"], e["url"])))
    return 0


def cmd_get(a, vault):
    _unlock_before_read(a, vault)
    value = vault.get(a.name, a.field)
    _cli._emit(a, "vault get", {"name": a.name, "field": a.field, "value": value})
    if not _cli._json(a):
        print(value)
    return 0


def cmd_add(a, vault):
    # The set-up offer runs before the secret is asked, so it is typed once.
    s = vault.status()
    if not s["initialized"]:
        raise VaultClientError(no_vault(s["path"]), "no-vault")
    password = _new_password(a)
    vault._unlocked(lambda: request("POST", "entries", {"name": a.name, "fields": {**_fields(a), "password": password}}))
    _cli._say(f"added {a.name}")
    _cli._emit(a, "vault add", {"added": a.name})
    return 0


def cmd_edit(a, vault):
    # The set-up offer runs before the secret is asked, so it is typed once.
    s = vault.status()
    if not s["initialized"]:
        raise VaultClientError(no_vault(s["path"]), "no-vault")
    fields = _fields(a)
    if a.password or a.generate:
        fields["password"] = _new_password(a)
    if not fields:
        raise SystemExit("nothing to change - give at least one field")
    vault._unlocked(lambda: request("PATCH", "entries", {"name": a.name, "fields": fields}))
    _cli._say(f"updated {a.name}")
    _cli._emit(a, "vault edit", {"updated": a.name})
    return 0


def cmd_rm(a, vault):
    vault._unlocked(lambda: request("POST", "delete", {"name": a.name}))
    _cli._say(f"removed {a.name}")
    _cli._emit(a, "vault rm", {"removed": a.name})
    return 0


def cmd_generate(a, vault):
    params = {**_length(a), "symbols": "0" if a.no_symbols else "1"}
    value = request("GET", "generate", params=params)["value"]
    _cli._emit(a, "vault generate", {"value": value})
    if not _cli._json(a):
        print(value)
    return 0


def _stage_and_trigger(a, vault, kind, command, label, message, done):
    _unlock_before_read(a, vault)
    body = {"name": a.name, "field": a.field, "kind": kind}
    nonce = vault._unlocked(lambda: request("POST", "stage", body))["nonce"]
    try:
        _cli._trigger(command, {"nonce": nonce, "label": a.name}, label, message)
    except BaseException:
        # No button was raised, so nothing can ever collect this relay.
        relay.unstage(nonce, kind)
        raise
    _cli._say(f"nothing is reported back here - the click is what {done} it")
    return 0


def cmd_copy(a, vault):
    _stage_and_trigger(a, vault, "secret", _cli.COPY_COMMAND, "Copy to clipboard",
                       f"Copy **{a.name}**", "copies")
    _cli._emit(a, "vault copy", {"posted": True, "name": a.name})
    return 0


def cmd_show(a, vault):
    _stage_and_trigger(a, vault, "code", _cli.SHOW_COMMAND, "Show",
                       f"Show **{a.name}**", "shows")
    _cli._emit(a, "vault show", {"posted": True, "name": a.name})
    return 0


def _env_spec(spec):
    var, sep, ref = spec.partition("=")
    if not sep or not var or not ref:
        raise SystemExit(f"--env takes VAR=NAME[:FIELD], got {spec!r}")
    name, _, field = ref.rpartition(":")
    if name and field in READABLE:
        return var, name, field
    return var, ref, "password"


def cmd_exec(a, vault):
    command = a.command[1:] if a.command[:1] == ["--"] else a.command
    if not command:
        raise SystemExit("exec needs a command after --")
    _unlock_before_read(a, vault)
    env = dict(os.environ)
    for spec in a.env:
        var, name, field = _env_spec(spec)
        env[var] = vault.get(name, field)
    if _cli._json(a):
        # The caller reads the object; the child's streams become fields of it.
        try:
            done = subprocess.run(command, env=env, capture_output=True)
        except OSError as e:
            raise SystemExit(f"cannot run {command[0]}: {e}")
        _cli._emit(a, "vault exec", {"exit": done.returncode,
                                     "stdout": done.stdout.decode(errors="replace"),
                                     "stderr": done.stderr.decode(errors="replace")})
        return done.returncode
    # This process becomes the command, so Ctrl+C, signals and the exit status are the
    # command's own. An ignored signal survives exec: main() ignores SIGHUP, so the
    # command gets the SIGHUP this process started with (still ignored under nohup);
    # Python ignores SIGPIPE and SIGXFSZ, so the command gets their defaults back.
    signal.signal(signal.SIGHUP, _cli.STARTED_HANGUP)
    for sig in (signal.SIGPIPE, signal.SIGXFSZ):
        signal.signal(sig, signal.SIG_DFL)
    # None when started with `2>&-` or after _say dropped a failing stderr; a closed
    # stream cannot be flushed.
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and not stream.closed:
            stream.flush()
    try:
        os.execvpe(command[0], command, env)
    except OSError as e:
        raise SystemExit(f"cannot run {command[0]}: {e}")


def _pass_cli(master, *args):
    """The stdout of `pass-cli ARGS`. pass-cli reads its master password from stdin when
    stdin is not a terminal, and prints its prompt on stderr."""
    try:
        done = subprocess.run(["pass-cli", *args], input=master + "\n", capture_output=True, text=True)
    except FileNotFoundError:
        raise SystemExit("pass-cli is not on PATH")
    if done.returncode:
        # Its own reason, never its stdout: that is where a password is printed.
        errors = [line[len("Error:"):].strip() for line in done.stderr.splitlines() if line.startswith("Error:")]
        raise SystemExit(f"pass-cli {args[0]} failed: {errors[-1] if errors else f'exit {done.returncode}'}")
    return done.stdout


def _pass_cli_items(a):
    """The entries of the pass-cli vault as import takes them, and the names left out
    because pass-cli holds a TOTP secret for them, which the vault has no field for."""
    master = _read_secret(a, "pass-cli master password", twice=False)
    try:
        listing = json.loads(_pass_cli(master, "list", "--format", "json"))
    except ValueError as e:
        raise SystemExit(f"pass-cli list printed no JSON: {e}")
    _cli._say(f"reading {len(listing)} entries from pass-cli, about a second each")
    items, with_totp = [], []
    for e in listing:
        if e.get("HasTOTP"):
            with_totp.append(e["Service"])
            continue
        password = _pass_cli(master, "get", "--field", "password", "--quiet", "--no-clipboard", "--", e["Service"])
        items.append({"name": e["Service"], "password": password.removesuffix("\n"),
                      "username": e.get("Username"), "url": e.get("URL"), "category": e.get("Category"),
                      "notes": e.get("Notes"), "created": e.get("CreatedAt"), "updated": e.get("UpdatedAt")})
    return items, with_totp


def cmd_import(a, vault):
    with_totp = []
    if a.pass_cli:
        if a.file != "-":
            raise SystemExit("--pass-cli reads the pass-cli vault and takes no FILE")
        # The vault answers before pass-cli is asked: a missing vault and the unlock of
        # a locked one come before the master password and a read of a second an entry.
        s = vault.status()
        if not s["initialized"]:
            raise _cli.Fail(no_vault(s["path"]), "no-vault")
        vault._unlocked(lambda: request("GET", "entries"))
        items, with_totp = _pass_cli_items(a)
    else:
        if a.file == "-" and sys.stdin.isatty():
            raise SystemExit("refusing to read secrets from a terminal - pipe or pass a FILE")
        raw = _cli._read_stdin_or_file(a.file, "JSON file", "nothing to import", "{source} is not text")
        try:
            items = json.loads(raw)
        except ValueError as e:
            raise SystemExit(f"not JSON: {e}")
    result = vault._unlocked(lambda: request("POST", "import", {"entries": items}))
    skipped = result["skipped"]
    _cli._say(f"added {result['added']}, skipped {len(skipped)}" + (f": {', '.join(skipped)}" if skipped else ""))
    if with_totp:
        _cli._say(f"not imported, pass-cli holds a TOTP secret for them: {', '.join(with_totp)}")
    _cli._emit(a, "vault import", {"added": result["added"], "skipped": skipped, "totp": with_totp})
    return 0


def _add_passkey(a, vault):
    """Add a passkey in the tab; returns the method the page stored."""
    s = vault.status()
    if not s["initialized"]:
        raise _cli.Fail(no_vault(s["path"]), "no-vault")
    # The page gets the proof the server asks for a new slot - an existing passkey, a
    # code of the authenticator app or the recovery passphrase - so no secret has to
    # reach it through a relay.
    answer = browser_step(REGISTER_COMMAND, {"label": a.label or ""}, "Add passkey",
                          "Add a passkey to the vault",
                          a.timeout)
    # The page names the method it stored: a passkey with no PRF is Password and passkey.
    return "password and passkey" if answer.get("method") == store.PAIR else "passkey"


def cmd_passkey_add(a, vault):
    added = _add_passkey(a, vault)
    _cli._say(f"{added} added")
    _cli._emit(a, "vault passkey add", {"added": added})
    return 0


def cmd_passkey_list(a, vault):
    slots = [slot for slot in vault.status()["slots"] if slot["type"] in ("passkey", store.PAIR)]
    _cli._emit(a, "vault passkey list", {"passkeys": slots})
    if not _cli._json(a):
        for slot in slots:
            print("\t".join((slot["cred_id"], slot["label"], slot["rp_id"], slot["created"])))
    return 0


def cmd_passkey_rm(a, vault):
    request("POST", "passkeys-remove", {"cred_id": a.cred_id})
    _cli._say("passkey removed")
    _cli._emit(a, "vault passkey rm", {"removed": a.cred_id})
    return 0


def cmd_recovery(a, vault):
    if not a.in_browser and not sys.stdin.isatty():
        # A pipe carries one secret; this needs two.
        raise SystemExit("vault recovery needs two passphrases - "
                         "run at a terminal or with --in-browser")
    s = vault.status()
    if not s["initialized"]:
        raise _cli.Fail(no_vault(s["path"]), "no-vault")
    # The server replaces it only with a proof: here, the current passphrase.
    current = _read_secret(a, "Current recovery passphrase", twice=False)
    passphrase = _read_secret(a, "New recovery passphrase", twice=True)
    request("POST", "recovery", {"recovery": passphrase, "proof": {"current": current}})
    _cli._say("recovery passphrase replaced; store the new one offline")
    _cli._emit(a, "vault recovery", {"replaced": "recovery passphrase"})
    return 0


def _say_rotation(rotation):
    """The data key's creation date, age, period and due state, as one line."""
    period = f"{rotation['period_days']} days" if rotation["period_days"] else "off"
    due = "due" if rotation["due"] else "not due"
    return (f"data key: {rotation['age_days']} days old, period {period}, {due}")


def cmd_rotate(a, vault):
    s = vault.status()
    if not s["initialized"]:
        raise _cli.Fail(no_vault(s["path"]), "no-vault")
    if not s["unlocked"]:
        raise _cli.Fail(LOCKED, "locked")
    # The proof is the current recovery passphrase, as `vault recovery` asks it.
    proof = {"current": _read_secret(a, "Recovery passphrase", twice=False)}
    rotation = vault.rotate(proof)["rotation"]
    _cli._say(_say_rotation(rotation))
    _cli._emit(a, "vault rotate", {"rotation": rotation})
    return 0


# --------------------------------------------------------------------------- #
# git's credential helper
# --------------------------------------------------------------------------- #

GIT_HELPER = "jupyterlab-passkey"
HELPER_KEY = "credential.helper"
NAMED_NO_MORE = "no helper names it - `git migrate` cannot read it"
Helper = collections.namedtuple("Helper", "scope file key value store_files")


def _git(*args):
    try:
        # surrogateescape: a config value may hold any byte, and goes back to git unchanged.
        return subprocess.run(["git", *args], capture_output=True, text=True,
                              errors="surrogateescape")
    except FileNotFoundError:
        raise SystemExit("git is not on PATH")


def _git_failed(done):
    return f"git config failed: {done.stderr.strip() or f'exit {done.returncode}'}"


def _listing(*flags):
    done = _git("config", *flags, "--show-scope", "--show-origin", "-z", "--get-regexp",
                r"^credential\.(.*\.)?helper$")
    if done.returncode not in (0, 1):
        raise SystemExit(_git_failed(done))
    fields = done.stdout.split("\0")
    helpers = []
    for scope, origin, pair in zip(fields[::3], fields[1::3], fields[2::3]):
        file = origin.partition(":")[2]
        key, _, value = pair.partition("\n")
        helpers.append(Helper(scope, file, key, value, tuple(_store_files(value, file))))
    return helpers


def _helpers(local=False):
    """Every credential.helper value git reads, URL-scoped ones included, in the order
    git reads them. `--global` reads one file although git runs two, so the scope and
    the file come from git's own listing of all of them. `--local` reads no file the
    repository's config includes, so the local scope adds `--includes`; git names a
    relative include from the top of the work tree, or from the git directory when the
    command runs with no work tree, so its path is made absolute."""
    if not local:
        return _listing()
    helpers = _listing("--local", "--includes")
    own = {helper.file for helper in _listing("--local")}
    if any(helper.file not in own for helper in helpers):
        top = (_git("rev-parse", "--show-toplevel").stdout.strip()
               or _git("rev-parse", "--absolute-git-dir").stdout.strip())
        helpers = [helper if helper.file in own else
                   helper._replace(file=os.path.normpath(os.path.join(top, helper.file)))
                   for helper in helpers]
    return helpers


def _in_scope(local):
    scope = "local" if local else "global"
    return [helper for helper in _helpers(local) if helper.scope == scope]


def _target(local, file):
    """The git config flags that write this file; git names a repository's own config
    relative to the top of the work tree, not to this directory."""
    if local and not os.path.isabs(file or ""):
        return ["--local"]
    return ["--file", file] if file else ["--global"]


def _set_helpers(target, values, key=HELPER_KEY):
    """Make the key hold exactly these values in order; unset it when empty."""
    if not values:
        done = _git("config", *target, "--unset-all", key)
        if done.returncode == 5:
            return
    else:
        done = _git("config", *target, "--replace-all", key, values[0])
        for value in values[1:]:
            if done.returncode:
                break
            done = _git("config", *target, "--add", key, value)
    if done.returncode:
        raise SystemExit(_git_failed(done))


def _restore(local, helper):
    """The git config command that puts this value back into the file that held it."""
    return shlex.join(["git", "config", *_target(local, helper.file), "--add", helper.key,
                       helper.value])


def _say_restore(local, removed):
    """After a git config write failed, each store value already removed, with the command
    that restores it: no helper of ours took its place."""
    for helper in dict.fromkeys(removed):
        if helper.store_files:
            _cli._say(f"{helper.key} = {helper.value}: to restore it, run "
                      f"`{_restore(local, helper)}`")


def _remove_helpers(local, removed):
    """Delete these values, each from the file that holds it, and say so."""
    helpers = _in_scope(local)
    done = []
    try:
        for file, key in dict.fromkeys((helper.file, helper.key) for helper in removed):
            kept = [helper.value for helper in helpers
                    if (helper.file, helper.key) == (file, key) and helper not in removed]
            _set_helpers(_target(local, file), kept, key)
            done += [helper for helper in removed if (helper.file, helper.key) == (file, key)]
    except SystemExit:
        _say_restore(local, done)
        raise
    for helper in dict.fromkeys(removed):
        _cli._say(f"removed {helper.key} = {helper.value} from {helper.file}")


def _ours(helpers):
    return [helper for helper in helpers
            if (helper.key, helper.value) == (HELPER_KEY, GIT_HELPER)]


def _install_helper(local):
    """Put ours first in the scope and remove the store values there, which would write
    every credential git accepts back in plaintext. Returns the store values removed."""
    helpers = _in_scope(local)
    stores = [helper for helper in helpers if helper.store_files]
    ours = _ours(helpers)
    others = [helper for helper in helpers if helper.key == HELPER_KEY
              and helper not in stores and helper not in ours]
    # An empty value resets git's helper list, discarding every helper before it: ours
    # goes after the last reset, else git would never run it.
    after = max((index + 1 for index, helper in enumerate(others) if not helper.value), default=0)
    # Two files can hold values: ours joins the file of the value it must run before.
    anchor = others[min(after, len(others) - 1)] if others else next(iter(ours), None)
    file = anchor.file if anchor else None
    _remove_helpers(local, stores + [helper for helper in ours if helper.file != file])
    values = [helper.value for helper in others if helper.file == file]
    before = sum(helper.file == file for helper in others[:after])
    try:
        _set_helpers(_target(local, file), [*values[:before], GIT_HELPER, *values[before:]])
    except SystemExit:
        _say_restore(local, stores)
        raise
    where = _ours(_in_scope(local))[0].file
    _cli._say(f"set {HELPER_KEY} = {GIT_HELPER} first in {where}")
    return stores


def _say_way_back(local, removed, deleted=(), blocked=()):
    """Each removed store value as written, with the git config command that restores it:
    every --file value, because a spelling only a shell can read looks like a missing file
    here, and a bare one with a file that exists and that nothing reads now. A bare one
    with no such file would only write tokens in plaintext again. Deleted files have no
    way back. `blocked` names the entries a migrate skipped, which must change first."""
    readable = set(_store_paths())
    first = f"change or remove {', '.join(blocked)} in the vault, then " if blocked else ""
    for helper in removed:
        files = set(helper.store_files) - set(deleted)
        if files and ("--file" in helper.value or any(
                os.path.exists(path) and path not in readable for path in files)):
            _cli._say(f"{helper.key} = {helper.value}: to read it again, run "
                      f"`{_restore(local, helper)}`, then {first}`jupyterlab-passkey vault "
                      "git migrate --remove-source` (a plain path, `~` or a set variable only)")


def cmd_git_install(a, vault):
    removed = _install_helper(a.local)
    left = [path for helper in removed for path in helper.store_files if os.path.exists(path)]
    readable = _store_paths()
    for path in dict.fromkeys(left):
        _cli._say(f"git's plaintext store stays at {path}: " + (
            "`git migrate --remove-source` imports and removes it"
            if path in readable else NAMED_NO_MORE))
    _say_way_back(a.local, removed)
    _cli._emit(a, "vault git install", {"lines": _lines()})
    return 0


def cmd_git_uninstall(a, vault):
    ours = _ours(_in_scope(a.local))
    if not ours:
        where = "repository" if a.local else "global"
        _cli._say(f"{HELPER_KEY} = {GIT_HELPER} is not set in the {where} git config")
    _remove_helpers(a.local, ours)
    _cli._emit(a, "vault git uninstall", {"lines": _lines()})
    return 0


_VARIABLE = re.compile(r"\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})")
_TILDE = re.compile(r"~[\w.-]*(?=/|\s|$)")


def _shell_words(value):
    """The words git's shell makes of a helper value: quotes and backslashes taken off, a
    `~` that starts a word and a set variable outside single quotes expanded. Any other
    expansion, such as `$(...)` or an unset variable, stays as written. ValueError, as
    shlex.split gives, for an unclosed quote or a backslash at the end."""
    # shortcut: an unquoted variable's value is not split at its spaces, as a shell splits it
    words, word, quote, index = [], None, None, 0
    while index < len(value):
        char = value[index]
        index += 1
        if quote == "'" and char != "'":
            word += char
        elif char in "'\"" and quote in (None, char):
            quote = None if quote else char
            word = word or ""
        elif char == "\\":
            if index == len(value):
                raise ValueError("No escaped character")
            char = value[index]
            index += 1
            # In double quotes a backslash escapes only these; a newline after one is dropped.
            kept = "\\" if quote and char not in '$`"\\\n' else ""
            word = (word or "") + kept + ("" if char == "\n" else char)
        elif char.isspace() and not quote:
            if word is not None:
                words.append(word)
            word = None
        elif char == "$" and (match := _VARIABLE.match(value, index - 1)) and (
                match[1] or match[2]) in os.environ:
            word = (word or "") + os.environ[match[1] or match[2]]
            index = match.end()
        elif char == "~" and not quote and word is None and (
                match := _TILDE.match(value, index - 1)):
            word = os.path.expanduser(match[0])
            index = match.end()
        else:
            word = (word or "") + char
    if quote:
        raise ValueError("No closing quotation")
    return words if word is None else [*words, word]


def _store_args(value, split):
    """The arguments of a value that runs git's `store` helper, else None: `store`, a full
    path to git-credential-store, or a `!` shell snippet that runs it."""
    snippet = value.startswith("!")
    words = split(value[1:] if snippet else value)
    if snippet and words[:2] == ["git", "credential-store"]:
        return words[2:]
    if not snippet and words[:1] == ["store"]:
        return words[1:]
    if words and os.path.basename(words[0]) == "git-credential-store" and (
            snippet or os.path.isabs(words[0])):
        return words[1:]
    return None


def _store_files(value, origin=""):
    """The files one credential.helper value makes git's `store` helper read: its last
    --file, as git-credential-store takes it, or the home and XDG stores a bare `store`
    reads."""
    try:
        args = _store_args(value, _shell_words)
    except ValueError as e:
        # Only a store value is ours to read; another helper's quoting is git's to judge.
        if _store_args(value, str.split) is not None:
            raise SystemExit(f"{origin}: {HELPER_KEY} = {value}: {e}")
        return []
    if args is None:
        return []
    path = None
    words = iter(args)
    for word in words:
        if word == "--file":
            path = next(words, path)
        elif word.startswith("--file="):
            path = word.partition("=")[2]
    if path is not None:
        return [path]
    # git reads XDG_CONFIG_HOME as it is, with no shell to expand a `~` in it.
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return [os.path.expanduser("~/.git-credentials"), os.path.join(xdg, "git", "credentials")]


def _store_paths():
    """The files git's `store` helper reads, in the order git reads them. The home and
    XDG stores count unless a store value for every URL names others."""
    helpers = _helpers()
    paths = [path for helper in helpers for path in helper.store_files]
    if not any(helper.store_files and helper.key == HELPER_KEY for helper in helpers):
        paths += _store_files("store")
    return list(dict.fromkeys(paths))


def _drop_store_helpers(paths):
    """Delete from the global git config every store value that reads one of these
    files, URL-scoped ones included, say so and return them; a value in another scope is
    left for the caller to check."""
    helpers = [helper for helper in _in_scope(False) if set(helper.store_files) & set(paths)]
    _remove_helpers(False, helpers)
    return helpers


def _store_entry(line):
    """One store line as a vault entry; ValueError for a bad line. git writes the host
    and the path percent-encoded, except the path's `?` and `#`. The url holds the decoded
    host, so its port is literal, and the path with all of it encoded, which
    `gitcred._parts` decodes once."""
    split = urllib.parse.urlsplit(line)
    userinfo, _, netloc = split.netloc.rpartition("@")
    # A host that is no UTF-8 text names no server: a replaced byte would name another.
    netloc = urllib.parse.unquote(netloc, errors="strict")
    host = urllib.parse.urlsplit("//" + netloc)
    # A decoded `/` or `@` would put the credential on another host of the url.
    # git writes `user:password@`, with an empty user for an entry with none.
    if (not split.scheme or not host.hostname or host.netloc != netloc or "@" in netloc
            or ":" not in userinfo):
        raise ValueError
    host.port  # raises for a port that is no number
    username, _, password = userinfo.partition(":")
    # The vault holds text: a replaced byte would be a wrong password in place of the true one.
    username = urllib.parse.unquote(username, errors="strict")
    # urlsplit ends the path at a `?` or `#`, so the path comes from the line itself.
    encoded = line[line.index(split.netloc, len(split.scheme)) + len(split.netloc):]
    path = urllib.parse.unquote(encoded)
    encoded = encoded.replace("?", "%3F").replace("#", "%23")
    # A name holds printable characters only; the url keeps the path that matches.
    shown = path if path.isprintable() else encoded
    return {
        "name": _check_name(f"git/{username}@{netloc.lower()}{shown}" if username
                            else f"git/{netloc.lower()}{shown}"),
        "url": urllib.parse.urlunsplit((split.scheme, netloc, encoded, "", "")),
        "username": username,
        "password": urllib.parse.unquote(password, errors="strict"),
        "category": "git",
    }


def _store_entries(path):
    """The store's lines as vault entries, and the numbers of the lines that hold a
    client certificate's passphrase, which no vault entry can answer: git asks for it
    with no host. A bad line names its number, never its text, which carries a password."""
    items, certs = [], []
    try:
        with open(path, "rb") as stream:
            for number, raw in enumerate(stream, 1):
                try:
                    line = raw.decode().strip()
                    if line.startswith("cert://"):
                        certs.append(number)
                    elif line:
                        items.append(_store_entry(line))
                except ValueError:
                    raise SystemExit(f"{path}, line {number}: expected "
                                     "scheme://user:password@host[/path] (UTF-8)") from None
                except store.VaultError as e:
                    raise SystemExit(f"{path}, line {number}: {e}") from None
    except OSError as e:
        raise SystemExit(f"{path}: {e.strerror}")
    return items, certs


def _same_account(known, item):
    """The entries that hold this store line's account: of the entries with its username,
    what the helper would match for a request from that line. The username comes first,
    because the longest path of another account would hide this one. Failing that, the
    entry with its name and username, whatever url it holds: the import overwrites no
    name, and a name that another username holds is a skipped line."""
    scheme, host, path = gitcred._parts(item)
    attrs = {"protocol": scheme, "host": host}
    if path.strip("/"):
        attrs["path"] = path
    return (gitcred.select([entry for entry in known
                            if entry.get("username", "") == item["username"]
                            and gitcred._parts(entry) is not None], attrs)
            or [entry for entry in known if entry["name"] == item["name"]
                and entry.get("username", "") == item["username"]])


def _sort_lines(entries, items, read):
    """The store's lines against the vault: the lines to add, the count it holds with
    the same value, and the names that hold another value. `read` gives an entry's
    value. A line in two store files meets its own copy, so a line added counts too."""
    known = list(entries)
    fresh, held, differ = [], 0, []
    for item in items:
        same = _same_account(known, item)
        values = [entry["password"] if "password" in entry else read(entry["name"])
                  for entry in same]
        if item["password"] in values:
            held += 1
        elif same:
            differ += [entry["name"] for entry in same if entry["name"] not in differ]
        else:
            fresh.append(item)
            known.append(item)
    return fresh, held, differ


def _say_several(entries):
    """One line for each host with several entries: what a request with no username gets."""
    hosts = {}
    for entry in entries:
        parts = gitcred._parts(entry)
        if parts is not None and parts[1]:
            hosts.setdefault(parts[1], {})[entry["name"]] = None
    for host, names in hosts.items():
        if len(names) > 1:
            _cli._say(f"{host} has {len(names)} vault entries: {', '.join(names)} - "
                      "newest changed answers a request with no username")


def _open_entries(vault):
    """The entries of an unlocked vault, else none: a dry run needs no vault, asks for no
    unlock and reads no value, because a read stamps the entry used."""
    try:
        return vault.list() if vault.status()["unlocked"] else []
    except VaultClientError:
        return []


def cmd_git_migrate(a, vault):
    paths = _store_paths()
    found = [path for path in paths if os.path.exists(path)]
    if not found:
        raise SystemExit(f"no git credential store at {', '.join(paths)}")
    items, certs = [], []
    for path in found:
        lines, numbers = _store_entries(path)
        items += lines
        certs += [f"{path}, line {number}" for number in numbers]
    for path in found:
        _cli._say(f"read {path}")
    for line in certs:
        _cli._say(f"{line}: a client certificate passphrase, not imported")
    if a.dry_run:
        for item in items:
            _say_out(a, f"{item['name']}\t{urllib.parse.urlsplit(item['url']).hostname or ''}")
        entries = _open_entries(vault)
        _say_several(entries + _sort_lines(entries, items, lambda name: None)[0])
        _cli._emit(a, "vault git migrate", {"lines": _lines()})
        return 0
    fresh, held, differ = _sort_lines(vault.list(), items, vault.get)
    # `store` answers its first line, and the helper the newest changed entry: the dates
    # step back one second a line, so a host answers as it did.
    now = datetime.datetime.now(datetime.UTC)
    for index, item in enumerate(fresh):
        item["created"] = item["updated"] = store._stamp(now - datetime.timedelta(seconds=index))
    result = vault._unlocked(lambda: request("POST", "import", {"entries": fresh}))
    added, skipped = result["added"], result["skipped"]
    sources = ", ".join(found)
    _cli._say(f"added {added} " + ("entry" if added == 1 else "entries") + f" from {sources}"
              + (f"; {held} already held with the same value" if held else "")
              + (f"; skipped {len(differ)} with another value in the vault: {', '.join(differ)}"
                 if differ else "")
              + (f"; skipped {len(skipped)} that exist: {', '.join(skipped)}" if skipped else ""))
    _say_several(vault.list())
    blocked = differ + skipped
    removed = False
    readers = []
    gone = []
    if a.remove_source and blocked:
        _cli._say(f"kept git's plaintext store at {sources} - "
                  "the skipped lines already have a vault entry")
    elif a.remove_source and certs:
        _cli._say(f"kept git's plaintext store at {sources} - "
                  "it holds a client certificate passphrase")
    elif a.remove_source and _terminal():
        answer = _ask(f"Remove git's plaintext store at {sources}? [y/N] ")
        if answer.strip().lower() in ("y", "yes"):
            # A store helper still configured would write the files back in plaintext.
            gone = _drop_store_helpers(paths)
            readers = [f"{helper.key} = {helper.value}" for helper in _helpers()
                       if set(helper.store_files) & set(found)]
            if readers:
                _cli._say(f"kept git's plaintext store at {sources}: "
                          + ", ".join(readers) + " in another git config still reads it")
            else:
                try:
                    for path in found:
                        os.remove(path)
                except OSError as e:
                    _say_way_back(False, gone, [path for path in found
                                                if not os.path.exists(path)])
                    raise SystemExit(f"cannot remove {e.filename}: {e.strerror}")
                _cli._say(f"removed git's plaintext store at {sources}")
                removed = True
        else:
            _cli._say(f"kept git's plaintext store at {sources}")
    elif a.remove_source:
        _cli._say(f"no terminal to ask - left git's plaintext store at {sources}")
    if not removed and not blocked and not certs and not readers:
        _cli._say("remove git's plaintext store with: rm "
                  + " ".join(shlex.quote(path) for path in found))
    if not a.no_install:
        try:
            gone += _install_helper(False)
        except SystemExit:
            # The values this run dropped stay out too; their deleted files need none.
            _say_restore(False, [] if removed else gone)
            raise
    if not removed:
        readable = _store_paths()
        for path in found:
            if path not in readable:
                _cli._say(f"git's plaintext store stays at {path}: {NAMED_NO_MORE}")
    _say_way_back(False, gone, found if removed else (), blocked)
    _cli._emit(a, "vault git migrate", {"lines": _lines()})
    return 0


# --------------------------------------------------------------------------- #
# the AWS CLI's credential process
# --------------------------------------------------------------------------- #

AWS_HELPER = "aws-credential-jupyterlab-passkey"


def _aws_config():
    """The AWS config file, as the AWS CLI finds it."""
    return os.environ.get("AWS_CONFIG_FILE") or os.path.expanduser("~/.aws/config")


def _aws_profile(profile):
    """A profile name the AWS CLI and the credential_process line can carry."""
    if not profile or any(char.isspace() for char in profile):
        raise SystemExit("the profile needs a name without whitespace")
    return profile


def cmd_aws_install(a, vault):
    profile = _aws_profile(a.profile)
    helper = shutil.which(AWS_HELPER)
    if not helper:
        raise SystemExit(f"{AWS_HELPER} is not on PATH - reinstall the package (make install)")
    # The line runs the absolute path, so AWS needs no PATH of ours at its time.
    helper = os.path.abspath(helper)
    aws = shutil.which("aws")
    if not aws:
        raise SystemExit("no aws on PATH - set credential_process = "
                         f"{helper} {profile} in {_aws_config()}")
    done = subprocess.run([aws, "configure", "set", "credential_process",
                           f"{helper} {profile}", "--profile", profile],
                          capture_output=True, text=True)
    if done.returncode:
        raise SystemExit(f"aws configure failed: {done.stderr.strip() or f'exit {done.returncode}'}")
    _cli._say(f"set credential_process for profile {profile} to run {helper}")
    _cli._say(f"add vault entry aws/{profile} - username: access key id, "
              "password: secret access key")
    _cli._emit(a, "vault aws install", {"lines": _lines()})
    return 0


def _credential_process(line):
    """The value of a credential_process line, or None for any other line."""
    key, sep, value = line.partition("=")
    if sep and key.strip().lower() == "credential_process":
        return value.strip()
    return None


def _our_credential_process(value):
    """Whether the value runs our helper: the basename of its first word is exactly
    AWS_HELPER. A value that does not parse, or whose first word differs, is another
    helper's, even when it holds our name as part of a longer one."""
    try:
        words = shlex.split(value)
    except ValueError:
        return False
    return bool(words) and os.path.basename(words[0]) == AWS_HELPER


def _replace_lines(path, lines):
    """Write `lines` over `path` through a temporary file in its directory and keep its
    mode, so a failure leaves the original whole."""
    fd, temp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".aws-config-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape",
                       newline="") as stream:
            stream.writelines(lines)
        os.chmod(temp, stat.S_IMODE(os.stat(path).st_mode))
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def cmd_aws_uninstall(a, vault):
    profile = _aws_profile(a.profile)
    path = _aws_config()
    try:
        with open(path, encoding="utf-8", errors="surrogateescape", newline="") as stream:
            lines = stream.readlines()
    except FileNotFoundError:
        _cli._say(f"no AWS config at {path}")
        _cli._emit(a, "vault aws uninstall", {"lines": _lines()})
        return 0
    except OSError as e:
        raise SystemExit(f"{path}: {e.strerror}")
    section = None
    kept, removed, foreign = [], [], []
    for line in lines:
        header = line.strip()
        if header.startswith("[") and header.endswith("]"):
            section = header[1:-1].strip()
        value = _credential_process(line)
        ours = section in (profile, f"profile {profile}")
        if ours and value is not None and _our_credential_process(value):
            removed.append(line)
            continue
        kept.append(line)
        if ours and value is not None:
            foreign.append(value)
    if removed:
        # A symlink usually means a dotfiles manager owns the link: write the file it
        # names, so the link survives and only the line goes.
        _replace_lines(os.path.realpath(path) if os.path.islink(path) else path, kept)
        _cli._say(f"removed credential_process from profile {profile} in {path}")
    if foreign:
        raise SystemExit(f"profile {profile} names another helper - left it: {foreign[0]}")
    if not removed:
        _cli._say(f"no credential_process of ours in profile {profile} in {path}")
    _cli._emit(a, "vault aws uninstall", {"lines": _lines()})
    return 0


def _missing_vault(error):
    """The path of a vault a command found missing, or None for any other error."""
    head, sep, tail = str(error).partition(" - run `jupyterlab-passkey vault init`")
    if sep and not tail and head.startswith("no vault at "):
        return head[len("no vault at "):]
    return None


def _terminal():
    """A question can be asked and answered. With --json stdout carries the object, so
    the prompt goes to stderr instead of needing a terminal there."""
    if sys.stdin is None or not sys.stdin.isatty():
        return False
    return relay.SAY_LINES is not None or (sys.stdout is not None and sys.stdout.isatty())


def ensure_vault(vault, call):
    """Run `call`; a missing vault is offered for set-up at a terminal, then call runs
    again. Declining, or no terminal, raises the original refusal."""
    try:
        return call()
    except VaultClientError as e:
        path = _missing_vault(e)
        if path is None or not _terminal():
            raise
        answer = _ask(f"No vault at {path}. Create it now? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            raise
        # `init` with the defaults its flags give, its wait included, for the helpers it shares.
        cmd_init(argparse.Namespace(in_browser=False, no_passkey=False, label=None,
                                    timeout=REGISTER_TIMEOUT), vault)
        return call()


def setup_in_browser(vault):
    """Set a vault that does not exist up from the browser: one notification whose page
    asks the recovery passphrase, then offers Passkey, Password and authenticator app,
    or Later. A cancelled or failed recovery step arrives as one line naming it."""
    # The wait is the one init takes; it ends once the vault exists, made in the tab or the panel.
    vault._setup(REGISTER_TIMEOUT)


def _fail(message, code):
    """The one-line failure: the message, then the server's stable code in brackets when
    the answer carried one, so a caller can branch on it."""
    return f"{message} [{code}]" if code else message


def _lines():
    """The lines _say collected for a --json result."""
    return list(relay.SAY_LINES or [])


def _say_out(a, line):
    """A result line for stdout: printed in text mode, collected for the object with --json."""
    if _cli._json(a):
        if relay.SAY_LINES is not None:
            relay.SAY_LINES.extend(str(line).splitlines())
    else:
        print(line)


def _ask(prompt):
    """A yes/no question; with --json its prompt goes to stderr, so stdout stays one object."""
    if relay.SAY_LINES is None:
        return input(prompt)
    if sys.stderr is not None:
        try:
            sys.stderr.write(prompt)
            sys.stderr.flush()
        except (OSError, ValueError):
            pass
    return input()


def run(a):
    vault = Vault(timeout=a.timeout)
    try:
        if a.debug:
            _cli._say(vault.status()["holder"]["debug"])
        return ensure_vault(vault, lambda: a.vault_func(a, vault))
    except VaultLocked as e:
        code = e.code or "locked"
        raise _cli.Fail(LOCKED, code, _fail(LOCKED, code))
    except VaultClientError as e:
        code = e.code or "server"
        # The server calls a missing vault an invalid request; --json has a local name
        # for it. Text mode keeps the server's word, as it always has.
        json_code = "no-vault" if code == "invalid" and _missing_vault(e) else code
        raise _cli.Fail(str(e), json_code, _fail(str(e), code))


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #


def add_vault_parser(sub, common, debugp):
    v = sub.add_parser(
        "vault", help="the password vault kept by the Jupyter server",
        description=__doc__.strip("\n"),
        epilog="""
examples:
  jupyterlab-passkey vault init                      # recovery passphrase, then a passkey
  jupyterlab-passkey vault add github/api -u me --url https://github.com
  jupyterlab-passkey vault get github/api            # the password, on stdout
  jupyterlab-passkey vault copy github/api           # to the browser clipboard
  jupyterlab-passkey vault exec --env GITHUB_TOKEN=github/api -- gh repo list
  jupyterlab-passkey vault status

server side - the Jupyter server reads these, not this CLI; set them where it starts:
  JLAB_PASSKEY_VAULT         the vault file (default $XDG_DATA_HOME/jupyterlab-passkey/vault.json)
  JLAB_PASSKEY_VAULT_HOLDER  auto (default), keyctl, gpg-agent or memory: where the unlocked key is kept
""".strip("\n"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # The subcommands that never wait for the browser take no --timeout; run() still
    # reads one.
    v.set_defaults(func=run, timeout=_cli.CLICK_TIMEOUT, command="vault")
    vs = v.add_subparsers(required=True)
    both = [common, debugp]
    instant = [debugp]
    slow = argparse.ArgumentParser(add_help=False)
    slow.add_argument(
        "--timeout", type=float, default=REGISTER_TIMEOUT, metavar="SECONDS",
        help=f"how long to wait for each step in the browser before giving up and exiting 1 "
             f"(default {REGISTER_TIMEOUT:.0f}: a new passkey takes a proof - a passkey, a code of "
             f"the authenticator app, or a recovery passphrase kept offline - two more passkey "
             f"prompts and a name)")
    registering = [slow, debugp]

    def add(name, help_, fn, parents=both, description=None, examples=()):
        # The description says what the command does, what it prints and whether it
        # waits for the browser; an agent reads this help instead of a manual.
        epilog = "examples:\n" + "\n".join(f"  {line}" for line in examples) if examples else None
        p = vs.add_parser(name, help=help_, description=(description or help_).strip("\n"),
                          epilog=epilog, parents=parents,
                          formatter_class=argparse.RawDescriptionHelpFormatter)
        p.set_defaults(vault_func=fn, command=f"vault {name}")
        return p

    def in_browser(p):
        p.add_argument("--in-browser", action="store_true",
                       help="type the secret in a JupyterLab dialog instead of this terminal")

    def read_methods(p):
        # The method a read command unlocks a locked vault with, in the same call.
        typed = p.add_mutually_exclusive_group()
        typed.add_argument("--recovery", action="store_true",
                           help="unlock a locked vault with the recovery passphrase")
        typed.add_argument("--password", action="store_true",
                           help="unlock a locked vault with the unlock password and a code of "
                                "the authenticator app")
        in_browser(p)

    unlocks_first = ("A locked vault is unlocked as part of the command: a notification to click, then the passkey, or\n"
                     "the chooser of the passkey, the unlock password and a code, the unlock password and\n"
                     "a passkey with no PRF, and the recovery passphrase when no passkey can open it.")

    read_unlocks = ("--recovery or --password unlocks a locked vault in the same call, asking the secret at\n"
                    "the terminal or in a dialog with --in-browser; an unlocked vault asks nothing.")

    p = add("init", "create the vault: a recovery passphrase, then a passkey", cmd_init, registering,
            description="""
create the vault: a recovery passphrase, typed twice, then a passkey added in the
JupyterLab tab, which asks for the passphrase once more as its proof. Store the recovery
passphrase offline: it opens the vault when no other unlock method can. Each browser step
raises a notification and waits for the click (--timeout, default 600 s). With no passkey,
add Password and authenticator app under Vault settings and security (the cog).
""",
            examples=('jupyterlab-passkey vault init --in-browser --label "Work laptop"',
                      "jupyterlab-passkey vault init --no-passkey        # recovery passphrase only"))
    in_browser(p)
    p.add_argument("--label", help="name for the passkey (default: the hostname)")
    p.add_argument("--no-passkey", action="store_true", help="skip adding a passkey")

    p = add("unlock", "unlock with the passkey, the unlock password and a code, or the recovery passphrase",
            cmd_unlock,
            description="""
unlock the vault for the unlock_minutes setting of the server's configuration file
(default 30 minutes), for every client:
this CLI, the Python Vault class and the panel. With a passkey: a notification to click,
then the passkey prompt in the tab. A passkey works only in a tab opened at the hostname it
was added at, or a subdomain of it. In a tab with no such passkey, or at an IP address, the
same notification opens a chooser: the passkey when it can be used, the unlock password and
a code, the unlock password and a passkey with no PRF, or the recovery passphrase.
--password asks the unlock password, then a code of the authenticator app: the two are one
unlock method, added together in the panel's cog view; status says whether the vault has
it. Both are typed, so --password runs at a terminal or with --in-browser, not from a
pipe. On a vault whose only unlock password goes with a passkey (Password and passkey),
--password raises the notification, as unlock with no option does: a tab that can use
another passkey of the vault asks for that passkey first and opens the chooser on a cancel,
and any other tab opens the chooser at once. The chooser offers Password and passkey in a
tab at the address where it was added.
""",
            examples=("jupyterlab-passkey vault unlock",
                      "jupyterlab-passkey vault unlock --password --in-browser",
                      "jupyterlab-passkey vault unlock --recovery --in-browser"))
    typed = p.add_mutually_exclusive_group()
    typed.add_argument("--recovery", action="store_true", help="use the recovery passphrase")
    typed.add_argument("--password", action="store_true",
                       help="use the unlock password and a code of the authenticator app; when"
                            " the only unlock password is that of Password and passkey, raise"
                            " the notification as unlock with no option does")
    in_browser(p)

    add("lock", "lock the vault now", cmd_lock, instant,
        description="""
remove the unlocked key from its key holder now. A value that copy or show staged and
nobody clicked stays until its relay expires; lock does not remove it.
""",
        examples=("jupyterlab-passkey vault lock",))
    add("status", "state, time left, key holder and its capabilities", cmd_status, instant,
        description="""
print the vault path, locked or unlocked with the time left, the key holder and what it
protects on this host, the passkeys, whether the vault has a password and authenticator
app and a password and passkey, and the unlock duration. Never waits.
""",
        examples=("jupyterlab-passkey vault status",))

    p = add("list", "entry names and metadata, never passwords", cmd_list,
            description=f"""
print one line per entry, tab-separated: name, username, category, url. Never passwords.
{unlocks_first}
{read_unlocks}
""",
            examples=("jupyterlab-passkey vault list",
                      "jupyterlab-passkey vault list --recovery --in-browser",
                      "jupyterlab-passkey vault list --category infrastructure --json"))
    p.add_argument("--category", help="only this category")
    read_methods(p)

    p = add("get", "print one value to stdout (unlocks if needed)", cmd_get,
            description=f"""
print one field of an entry and a newline to stdout. Whatever reads stdout receives the
value: send it to a pipe or a file, not to a screen or a log. To give a value to a
command, use exec; to give it to the user, use copy or show.
{unlocks_first}
{read_unlocks}
""",
            examples=("jupyterlab-passkey vault get github/api | gh auth login --with-token",
                      "jupyterlab-passkey vault get github/api --field username",
                      "jupyterlab-passkey vault get github/api --recovery --in-browser"))
    p.add_argument("name", help="entry name, such as github/api")
    p.add_argument("--field", default="password", choices=READABLE, help="the field (default password)")
    read_methods(p)

    new_password = f"""
The password comes from a hidden prompt typed twice, from stdin, from a JupyterLab dialog
with --in-browser (one field; Cancel exits 1), or from --generate; never from an option.
--generate makes {GENERATE_LENGTH} characters by default, without l I 1 | O 0, quotes, backslash,
backtick and space.
{unlocks_first}
"""
    for name, help_, fn, description, examples in (
            ("add", "add an entry; the password is prompted, piped or generated", cmd_add,
             "add an entry." + new_password,
             ('jupyterlab-passkey vault add github/api -u me -c infrastructure --url https://github.com --in-browser',
              "jupyterlab-passkey vault add db/prod -u app --generate --length 32",
              "<producer> | jupyterlab-passkey vault add gitlab/api -u me    # the password on stdin")),
            ("edit", "change fields of an entry", cmd_edit,
             "change fields of an entry; a field not given keeps its value. --password or\n"
             "--generate also sets a new password." + new_password,
             ("jupyterlab-passkey vault edit github/api --password --in-browser",
              'jupyterlab-passkey vault edit github/api --notes "rotated 2026-09"'))):
        p = add(name, help_, fn, description=description, examples=examples)
        p.add_argument("name", help="entry name, such as github/api")
        p.add_argument("-u", "--username", help="the account name")
        p.add_argument("--url", help="where the entry is used")
        p.add_argument("-c", "--category", help="a group name that list --category filters on")
        p.add_argument("--notes", help="free text")
        p.add_argument("--generate", action="store_true", help="generate the password")
        p.add_argument("--length", type=int, help=f"generated password length (default {GENERATE_LENGTH})")
        in_browser(p)
        if name == "edit":
            p.add_argument("--password", action="store_true",
                           help="also set a new password (prompted, piped or --in-browser)")

    p = add("rm", "remove an entry", cmd_rm,
            description=f"""
remove an entry. It cannot be restored.
{unlocks_first}
""",
            examples=("jupyterlab-passkey vault rm old/entry",))
    p.add_argument("name", help="entry name, such as github/api")

    p = add("generate", "print a random password", cmd_generate, instant,
            description=f"""
print a random password to stdout without storing it: {GENERATE_LENGTH} characters by default, 8 to
256, without l I 1 | O 0, quotes, backslash, backtick and space. Never waits.
""",
            examples=("jupyterlab-passkey vault generate --length 32 --no-symbols",))
    p.add_argument("--length", type=int, help=f"password length (default {GENERATE_LENGTH})")
    p.add_argument("--no-symbols", action="store_true", help="letters and digits only")

    staged = f"""
The server stages the value and raises a notification; the value never enters this
process. Exit 0 means the notification was raised, not that it was clicked: nothing is
reported back. An unclicked value stays staged for 900 s on the kernel keyring, or until
reboot in /dev/shm; lock does not remove it.
{unlocks_first}
{read_unlocks}
"""
    for name, help_, fn, description, examples in (
            ("copy", "put a value on the browser clipboard", cmd_copy,
             "put a value on the browser clipboard: the click copies it." + staged,
             ("jupyterlab-passkey vault copy github/api",
              "jupyterlab-passkey vault copy github/api --field username",
              "jupyterlab-passkey vault copy github/api --recovery --in-browser")),
            ("show", "show a value in the browser as a distorted image", cmd_show,
             f"show a value in the browser as a distorted image, to type elsewhere; at most\n"
             f"{relay.MAX_CODE_CHARS} characters." + staged,
             ("jupyterlab-passkey vault show wifi/guest",
              "jupyterlab-passkey vault show wifi/guest --password --in-browser"))):
        p = add(name, help_, fn, description=description, examples=examples)
        p.add_argument("name", help="entry name, such as github/api")
        p.add_argument("--field", default="password", choices=READABLE, help="the field (default password)")
        read_methods(p)

    p = add("exec", "run a command with vault values in its environment", cmd_exec,
            description=f"""
run COMMAND with vault values in its environment only. This process becomes the command,
so the exit status, the signals and the output are the command's own: do not run a
command that prints the values it was given. Fields: {", ".join(READABLE)}.
{unlocks_first}
{read_unlocks}
""",
            examples=("jupyterlab-passkey vault exec --env GITHUB_TOKEN=github/api -- gh repo list",
                      "jupyterlab-passkey vault exec --recovery --in-browser --env GITHUB_TOKEN=github/api -- gh repo list",
                      "jupyterlab-passkey vault exec --env DB_USER=db/prod:username --env DB_PASS=db/prod -- ./migrate.sh"))
    p.add_argument("--env", action="append", default=[], metavar="VAR=NAME[:FIELD]",
                   help="set VAR to the entry's field (password by default); repeatable")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]")
    read_methods(p)

    p = add("import", "add entries from a JSON list, or from a pass-cli vault", cmd_import,
            description=f"""
add entries from a JSON list in FILE or on stdin: objects with name (or service),
username, password, url, category, notes, created and updated. created and updated are
dates such as 2026-03-23T20:37:13Z; without them the entry gets the time of the import.
Any other field is refused by name and nothing is imported. Names that already exist are
skipped and listed. Refuses a terminal on stdin. A file of entries holds plaintext
passwords: pipe them in instead of writing one.

--pass-cli reads the entries from this user's pass-cli vault instead: it runs
`pass-cli list` and one `pass-cli get` per entry, about a second each, and changes
nothing in that vault but its usage counters. The pass-cli master password comes from
a hidden prompt, from stdin, or from a JupyterLab dialog with --in-browser. An entry
with a TOTP secret is named and not imported: the vault has no field for it.
{unlocks_first}
""",
            examples=("<producer> | jupyterlab-passkey vault import",
                      "jupyterlab-passkey vault import --pass-cli --in-browser"))
    p.add_argument("file", nargs="?", default="-", metavar="FILE", help="JSON file (default: stdin)")
    p.add_argument("--pass-cli", action="store_true", help="import every entry of the pass-cli vault")
    in_browser(p)

    g = vs.add_parser(
        "git", help="make the vault git's credential helper",
        description="""
give git its credentials from the vault. `install` points the global git config's
credential.helper at git-credential-jupyterlab-passkey and removes a store helper there,
`uninstall` removes that line, and `migrate` copies git's plaintext credential store into
the vault, one entry per account, then installs the helper unless --no-install. The
helper follows gitcredentials(7): git asks by protocol, host, path and username. An
entry with that username answers, or else an entry with no username, which gives the
password only. With no username in the request, the newest changed entry answers. git
never writes to the vault. A locked vault is unlocked first from the same notification
and passkey click as the other commands.
""",
        epilog="""
examples:
  jupyterlab-passkey vault git install
  jupyterlab-passkey vault git migrate --dry-run
  jupyterlab-passkey vault git migrate --no-install
  jupyterlab-passkey vault git uninstall
""".strip("\n"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    gs = g.add_subparsers(required=True)

    waiting = argparse.ArgumentParser(add_help=False)
    waiting.add_argument(
        "--timeout", type=float, default=_cli.CLICK_TIMEOUT, metavar="SECONDS",
        help=f"how long to wait for the unlock in the browser before giving up and exiting 1 "
             f"(default {_cli.CLICK_TIMEOUT:.0f})")

    def add_git(name, help_, fn, parents, description, examples):
        p = gs.add_parser(name, help=help_, description=description.strip("\n"),
                          epilog="examples:\n" + "\n".join(f"  {line}" for line in examples),
                          parents=parents, formatter_class=argparse.RawDescriptionHelpFormatter)
        p.set_defaults(vault_func=fn, command=f"vault git {name}")
        return p

    p = add_git(
        "install", "point git's credential.helper at this helper", cmd_git_install, instant,
        """
put credential.helper = jupyterlab-passkey first in the global git config, so git runs
git-credential-jupyterlab-passkey for every credential request; the other helper values
stay behind it in their order. A store helper there - store, a full path to
git-credential-store or !git credential-store - a credential.<url>.helper one
included, is removed and named, because git would write every credential it accepts back
in plaintext; its file stays until `vault git migrate --remove-source`. A store --file
file that no helper names now is out of that command's reach, so install prints the value
as written and the git config command that restores it, and the path of a file it read
that stays. Running it again leaves one of ours. The global config is ~/.gitconfig and the XDG file, and the command says which file it wrote.
--local writes the repository's config, and the files it includes, instead. A git config
write that fails after a removal prints the command that restores each removed value.
credential.<url>.helper stays available for per-host scoping. Never waits.
""",
        ("jupyterlab-passkey vault git install",
         "jupyterlab-passkey vault git install --local"))
    p.add_argument("--local", action="store_true",
                   help="write the repository config, not the global one")

    p = add_git(
        "uninstall", "remove that line from the global git config", cmd_git_uninstall, instant,
        """
remove every credential.helper = jupyterlab-passkey from the global git config, in
~/.gitconfig and in the XDG file, and keep the other helper values in their order. When
the line is not there the command succeeds and says so. --local acts on the repository
config instead. Never waits.
""",
        ("jupyterlab-passkey vault git uninstall",
         "jupyterlab-passkey vault git uninstall --local"))
    p.add_argument("--local", action="store_true",
                   help="write the repository config, not the global one")

    p = add_git(
        "migrate", "copy git's plaintext credential store into the vault", cmd_git_migrate,
        [waiting, debugp],
        f"""
read the files git's store helper reads - credential.helper or credential.<url>.helper
"store --file <path>" or "store --file=<path>", the last one, with a ~ that starts the
word and a set variable outside single quotes expanded as git's shell expands them, else
~/.git-credentials and $XDG_CONFIG_HOME/git/credentials (default
$HOME/.config/git/credentials), both of them -
and add one vault entry per account, named git/<username>@<host>[:<port>][/<path>]
(git/<host>... when the line has no username) with url, username, password and category
git. Each line is checked first: the same host, username and value adds nothing and
counts as held; the same host and username with another value adds nothing and is named,
and the files stay; another username gets its own entry. Every file read is reported.
An entry with the line's name and username counts the same way, whatever url it holds.
An entry of that name with another username is never overwritten: the line is skipped
and the files stay. One line names each host left with several entries. Then install the
helper unless --no-install. --dry-run prints the names and hosts and writes nothing; it
reads the entries of an unlocked vault, and with a locked vault or none it counts the
store's lines alone. Never prints a password. Prints
the source files; --remove-source asks first, at a terminal, removes the files only when
nothing was skipped, and leaves them when there is no terminal. Once no helper names a
store --file file, migrate cannot find it: install and every run that removes such a
value print it as written with the git config command that restores it, whether or not
a line was left out, unless the run removed the file, and the path of a file it read
that stays; a run that left no line out also prints an rm line for it. Migrate reads
only a plain path, ~ and a set variable, and any other spelling gets that line. A line
with a client certificate's passphrase is named, not imported, and keeps the files. A
line the vault cannot hold stops the run with its file and line number: a host, username
or password that is not UTF-8 text, or a name it refuses.
{unlocks_first}
""",
        ("jupyterlab-passkey vault git migrate --dry-run",
         "jupyterlab-passkey vault git migrate --remove-source"))
    p.add_argument("--dry-run", action="store_true", help="print the entries without writing")
    p.add_argument("--no-install", action="store_true", help="do not install the helper")
    p.add_argument("--remove-source", action="store_true",
                   help="remove the plaintext store, once every line is imported, after "
                        "a yes typed at a terminal; also remove the global store helpers, "
                        "credential.<url>.helper ones included, that would rewrite it")

    aw = vs.add_parser(
        "aws", help="give the AWS CLI its static access keys from the vault",
        description="""
give the AWS CLI its static access keys from the vault. `install` writes a
credential_process line for a profile through `aws configure set`, naming the
aws-credential-jupyterlab-passkey helper; `uninstall` removes that line. The helper
reads vault entry aws/<profile>: username is the access key id, password the secret
access key. Static keys only: SSO and session profiles get nothing from it.
""",
        epilog="""
examples:
  jupyterlab-passkey vault aws install work
  jupyterlab-passkey vault aws uninstall work
""".strip("\n"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    aws = aw.add_subparsers(required=True)

    def add_aws(name, help_, fn, description, examples):
        p = aws.add_parser(name, help=help_, description=description.strip("\n"),
                           epilog="examples:\n" + "\n".join(f"  {line}" for line in examples),
                           parents=instant, formatter_class=argparse.RawDescriptionHelpFormatter)
        p.set_defaults(vault_func=fn, command=f"vault aws {name}")
        return p

    p = add_aws(
        "install", "write credential_process for an AWS profile", cmd_aws_install,
        """
write credential_process = "<absolute helper path> <profile>" into the profile through
`aws configure set`, so the AWS CLI runs the helper for that profile's credentials. The
absolute path makes the line independent of PATH at AWS time. Add the key pair as vault
entry aws/<profile>: username the access key id, password the secret access key. The
helper prints the credential-process JSON; a locked vault raises the unlock notification
and the aws command waits. Static keys only: an SSO or session profile bypasses the
helper. Never waits here. Needs aws on PATH; without it, the line to add by hand is
printed.
""",
        ("jupyterlab-passkey vault aws install work",))
    p.add_argument("profile", metavar="PROFILE", help="the AWS profile name, without whitespace")

    p = add_aws(
        "uninstall", "remove that line from the AWS config", cmd_aws_uninstall,
        """
remove the credential_process lines of this profile that name
aws-credential-jupyterlab-passkey, from its section ([<profile>] or [profile <profile>])
in the AWS config ($AWS_CONFIG_FILE, else ~/.aws/config), and keep every other line as
it is. An empty section stays. A line naming another helper stays and the command exits
1 naming its value. With no such line the command succeeds and says so; with no config
file it says there is none. Never waits, and prints no key.
""",
        ("jupyterlab-passkey vault aws uninstall work",))
    p.add_argument("profile", metavar="PROFILE", help="the AWS profile name")

    pk = vs.add_parser("passkey", help="add, list or remove passkeys",
                       description="add, list or remove the vault's passkeys")
    pks = pk.add_subparsers(required=True)

    def add_passkey_command(name, help_, fn, parents, description, examples):
        p = pks.add_parser(name, help=help_, description=description.strip("\n"),
                           epilog="examples:\n" + "\n".join(f"  {line}" for line in examples),
                           parents=parents, formatter_class=argparse.RawDescriptionHelpFormatter)
        p.set_defaults(vault_func=fn, command=f"vault passkey {name}")
        return p

    p = add_passkey_command(
        "add", "add a passkey (a notification to click; the browser asks for a proof: an "
               "existing passkey, a code of the authenticator app, or the recovery passphrase)",
        cmd_passkey_add, registering,
        """
add a passkey in the JupyterLab tab: a notification to click, then the browser asks
for a proof - a passkey already added for this hostname, else a code of the
authenticator app when the vault has one and is unlocked, else the recovery
passphrase - and creates the new passkey. It opens the vault only from the tab's hostname or a
subdomain of it; a tab at an IP address cannot add one. Waits for each step
(--timeout, default 600 s).
""",
        ('jupyterlab-passkey vault passkey add --label "Work laptop"',))
    p.add_argument("--label", help="name for the passkey (default: the hostname)")
    add_passkey_command(
        "list", "cred_id, label, hostname and date of each passkey", cmd_passkey_list, instant,
        """
print one line per passkey, tab-separated: cred_id, label, hostname, creation time; the
passkey of Password and passkey too. Never waits.
""",
        ("jupyterlab-passkey vault passkey list",))
    p = add_passkey_command(
        "rm", "remove a passkey", cmd_passkey_rm, instant,
        """
remove a passkey; the vault must be unlocked. The cred_id comes from passkey list. The
cred_id of Password and passkey removes that unlock method, its password with it.
""",
        ("jupyterlab-passkey vault passkey rm --cred-id <cred_id>",))
    p.add_argument("--cred-id", required=True, metavar="B64URL", help="the passkey's cred_id, as passkey list prints it")

    p = add("recovery", "replace the recovery passphrase: the current one, then the new one",
            cmd_recovery,
            description="""
replace the recovery passphrase: the current one, then the new one - typed twice at a
terminal, in two fields that must match in the browser. Needs a terminal or --in-browser,
because it reads two secrets. Store the new one offline.
""",
            examples=("jupyterlab-passkey vault recovery --in-browser",))
    in_browser(p)

    p = add("rotate", "rotate the data key: the recovery passphrase is the proof", cmd_rotate,
            description="""
re-seal every entry and the authenticator secret under a new random data key. No slot
changes, and a copy of the old data key stops reading the vault. The vault must be
unlocked; the proof is the current recovery passphrase. Prints the data key's creation
date, age, period and whether rotation is due. An unlock rotates automatically once the
period (default 365 days) has passed; 0 turns automatic rotation off.
""",
            examples=("jupyterlab-passkey vault rotate",
                      "jupyterlab-passkey vault rotate --in-browser"))
    in_browser(p)
