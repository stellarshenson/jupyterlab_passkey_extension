"""`jupyterlab-passkey vault ...` - the vault from a terminal.

Every command calls the vault agent in the Jupyter server. A secret is never taken
from a command-line option: a new one is typed at a hidden prompt (twice), piped on
stdin, typed in the browser with --in-browser, or generated. `copy` and `show` have
the server stage the value for the existing clipboard and image flows, so it never
enters this process at all.
"""

import argparse
import getpass
import json
import os
import secrets
import signal
import sys

from .. import cli as _cli
from .. import relay
from .client import (
    REGISTER_COMMAND,
    Vault,
    VaultClientError,
    VaultLocked,
    browser_step,
    no_vault,
    request,
)
from .service import GENERATE_LENGTH, READABLE

REGISTER_TIMEOUT = 600.0


def _duration(seconds):
    hours, rest = divmod(int(seconds), 3600)
    return f"{hours}h {rest // 60}m" if hours else f"{rest // 60}m {rest % 60}s"


def _minutes(minutes):
    """An unlock duration in hours and minutes, a zero part left out: 4h, 1h 30m, 45m."""
    hours, rest = divmod(minutes, 60)
    return " ".join(part for part in (f"{hours}h" if hours else "", f"{rest}m" if rest else "") if part)


def _read_secret(a, prompt, twice):
    """A secret from the browser dialog, a hidden prompt, or stdin - never argv."""
    if a.in_browser:
        nonce = secrets.token_urlsafe(24)
        args = {"nonce": nonce, "prompt": prompt}
        if not twice:
            args["once"] = True
        _cli._trigger(_cli.PASSPHRASE_COMMAND, args, "Enter secret", f"{prompt} - click to open the dialog.")
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
        if twice and getpass.getpass("again: ") != value:
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
    return _read_secret(a, "Password", twice=True)


def _fields(a):
    fields = {}
    for key in ("username", "url", "category", "notes"):
        value = getattr(a, key)
        if value is not None:
            fields[key] = value
    return fields


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
    _cli._say(f"vault created at {s['path']}; store the recovery passphrase offline - it is the only way in without a passkey")
    if not a.no_passkey:
        hint = "the vault exists without a passkey - run `jupyterlab-passkey vault passkey add`"
        try:
            cmd_passkey_add(a, vault)
        except VaultClientError as e:
            raise SystemExit(f"{e}\n{hint}")
        except KeyboardInterrupt:
            raise SystemExit(f"\n{hint}")
    return 0


def cmd_unlock(a, vault):
    s = vault.status()
    if not s["initialized"]:
        # Before `--recovery` asks for a passphrase there is nothing to open with.
        raise SystemExit(_say_status(s))
    if a.recovery:
        s = vault.unlock(recovery=_read_secret(a, "Recovery passphrase", twice=False))
    else:
        s = vault.unlock()
    _cli._say(f"vault {_say_status(s)}")
    return 0


def cmd_lock(a, vault):
    vault.lock()
    _cli._say("vault locked")
    return 0


def cmd_status(a, vault):
    s = vault.status()
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
    print(f"unlock duration: {_minutes(s['settings']['unlock_minutes'])}")
    return 0


def cmd_list(a, vault):
    entries = vault.list()
    if a.category:
        entries = [e for e in entries if e["category"] == a.category]
    if a.json:
        print(json.dumps(entries, indent=1))
    else:
        for e in entries:
            print("\t".join((e["name"], e["username"], e["category"], e["url"])))
    return 0


def cmd_get(a, vault):
    print(vault.get(a.name, a.field))
    return 0


def cmd_add(a, vault):
    password = _new_password(a)
    vault._unlocked(lambda: request("POST", "entries", {"name": a.name, "fields": {**_fields(a), "password": password}}))
    _cli._say(f"added {a.name}")
    return 0


def cmd_edit(a, vault):
    fields = _fields(a)
    if a.password or a.generate:
        fields["password"] = _new_password(a)
    if not fields:
        raise SystemExit("nothing to change - give at least one field")
    vault._unlocked(lambda: request("PATCH", "entries", {"name": a.name, "fields": fields}))
    _cli._say(f"updated {a.name}")
    return 0


def cmd_rm(a, vault):
    vault._unlocked(lambda: request("POST", "delete", {"name": a.name}))
    _cli._say(f"removed {a.name}")
    return 0


def cmd_generate(a, vault):
    params = {**_length(a), "symbols": "0" if a.no_symbols else "1"}
    print(request("GET", "generate", params=params)["value"])
    return 0


def _stage_and_trigger(a, vault, kind, command, label, message, done):
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
    return _stage_and_trigger(a, vault, "secret", _cli.COPY_COMMAND, "Copy to clipboard",
                              f"Copy {a.name} - click to copy it to the clipboard.", "copies")


def cmd_show(a, vault):
    return _stage_and_trigger(a, vault, "code", _cli.SHOW_COMMAND, "Show",
                              f"Show {a.name} - click to show it.", "shows")


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
    env = dict(os.environ)
    for spec in a.env:
        var, name, field = _env_spec(spec)
        env[var] = vault.get(name, field)
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


def cmd_import(a, vault):
    if a.file == "-" and sys.stdin.isatty():
        raise SystemExit("refusing to read secrets from a terminal - pipe the JSON in or pass a FILE")
    raw = _cli._read_stdin_or_file(a.file, "JSON file", "nothing to import", "{source} is not text")
    try:
        items = json.loads(raw)
    except ValueError as e:
        raise SystemExit(f"not JSON: {e}")
    result = vault._unlocked(lambda: request("POST", "import", {"entries": items}))
    skipped = result["skipped"]
    _cli._say(f"added {result['added']}, skipped {len(skipped)}" + (f": {', '.join(skipped)}" if skipped else ""))
    return 0


def cmd_passkey_add(a, vault):
    s = vault.status()
    if not s["initialized"]:
        raise SystemExit(_say_status(s))
    # The page gets the proof the server asks for a new slot - an existing passkey, or
    # the recovery passphrase - so no secret has to reach it through a relay.
    browser_step(REGISTER_COMMAND, {"label": a.label or ""}, "Register passkey",
                 "Register a passkey for the vault - click; a passkey you already have, or the "
                 "recovery passphrase, is asked first.", a.timeout)
    _cli._say("passkey registered")
    return 0


def cmd_passkey_list(a, vault):
    for slot in vault.status()["slots"]:
        if slot["type"] == "passkey":
            print("\t".join((slot["cred_id"], slot["label"], slot["rp_id"], slot["created"])))
    return 0


def cmd_passkey_rm(a, vault):
    request("POST", "passkeys-remove", {"cred_id": a.cred_id})
    _cli._say("passkey removed")
    return 0


def cmd_recovery(a, vault):
    if not a.in_browser and not sys.stdin.isatty():
        # A pipe carries one secret; this needs two.
        raise SystemExit("vault recovery asks for the current and the new passphrase - "
                         "run it at a terminal or with --in-browser")
    s = vault.status()
    if not s["initialized"]:
        raise SystemExit(_say_status(s))
    # The server replaces it only with a proof: here, the current passphrase.
    current = _read_secret(a, "Current recovery passphrase", twice=False)
    passphrase = _read_secret(a, "New recovery passphrase", twice=True)
    request("POST", "recovery", {"recovery": passphrase, "proof": {"current": current}})
    _cli._say("recovery passphrase replaced; store the new one offline")
    return 0


def run(a):
    vault = Vault(timeout=a.timeout)
    try:
        if a.debug:
            _cli._say(vault.status()["holder"]["debug"])
        return a.vault_func(a, vault)
    except VaultLocked:
        raise SystemExit("the vault is locked - run `jupyterlab-passkey vault unlock`")
    except VaultClientError as e:
        raise SystemExit(str(e))


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
""".strip("\n"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # The subcommands that never wait for the browser take no --timeout; run() still
    # reads one.
    v.set_defaults(func=run, timeout=_cli.CLICK_TIMEOUT)
    vs = v.add_subparsers(dest="vault_op", required=True, metavar="VAULT_COMMAND")
    both = [common, debugp]
    instant = [debugp]
    slow = argparse.ArgumentParser(add_help=False)
    slow.add_argument(
        "--timeout", type=float, default=REGISTER_TIMEOUT, metavar="SECONDS",
        help=f"how long to wait for each step in the browser before giving up and exiting 1 "
             f"(default {REGISTER_TIMEOUT:.0f}: a registration takes a proof - a passkey, or a "
             f"recovery passphrase kept offline - two more passkey prompts and a name)")
    registering = [slow, debugp]

    def add(name, help_, fn, parents=both):
        p = vs.add_parser(name, help=help_, description=help_, parents=parents)
        p.set_defaults(vault_func=fn)
        return p

    def in_browser(p):
        p.add_argument("--in-browser", action="store_true",
                       help="type the secret in a JupyterLab dialog instead of this terminal")

    p = add("init", "create the vault: a recovery passphrase, then a passkey", cmd_init, registering)
    in_browser(p)
    p.add_argument("--label", help="name for the passkey (default: the hostname)")
    p.add_argument("--no-passkey", action="store_true", help="skip registering a passkey")

    p = add("unlock", "unlock with the passkey, or the recovery passphrase", cmd_unlock)
    p.add_argument("--recovery", action="store_true", help="use the recovery passphrase")
    in_browser(p)

    add("lock", "lock the vault now", cmd_lock, instant)
    add("status", "state, time left, key holder and its capabilities", cmd_status, instant)

    p = add("list", "entry names and metadata, never passwords", cmd_list)
    p.add_argument("--category", help="only this category")
    p.add_argument("--json", action="store_true", help="print JSON")

    p = add("get", "print one value to stdout (unlocks if needed)", cmd_get)
    p.add_argument("name")
    p.add_argument("--field", default="password", choices=READABLE)

    for name, help_, fn in (("add", "add an entry; the password is prompted, piped or generated", cmd_add),
                            ("edit", "change fields of an entry", cmd_edit)):
        p = add(name, help_, fn)
        p.add_argument("name")
        p.add_argument("-u", "--username")
        p.add_argument("--url")
        p.add_argument("-c", "--category")
        p.add_argument("--notes")
        p.add_argument("--generate", action="store_true", help="generate the password")
        p.add_argument("--length", type=int, help=f"generated password length (default {GENERATE_LENGTH})")
        in_browser(p)
        if name == "edit":
            p.add_argument("--password", action="store_true",
                           help="also set a new password (prompted, piped or --in-browser)")

    p = add("rm", "remove an entry", cmd_rm)
    p.add_argument("name")

    p = add("generate", "print a random password", cmd_generate, instant)
    p.add_argument("--length", type=int, help=f"password length (default {GENERATE_LENGTH})")
    p.add_argument("--no-symbols", action="store_true")

    for name, help_, fn in (("copy", "put a value on the browser clipboard", cmd_copy),
                            ("show", "show a value in the browser as a distorted image", cmd_show)):
        p = add(name, help_, fn)
        p.add_argument("name")
        p.add_argument("--field", default="password", choices=READABLE)

    p = add("exec", "run a command with vault values in its environment", cmd_exec)
    p.add_argument("--env", action="append", default=[], metavar="VAR=NAME[:FIELD]",
                   help="set VAR to the entry's field (password by default); repeatable")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]")

    p = add("import", "add entries from a JSON list (pass-cli `service` names accepted)", cmd_import)
    p.add_argument("file", nargs="?", default="-", metavar="FILE")

    pk = vs.add_parser("passkey", help="register, list or remove passkeys")
    pks = pk.add_subparsers(dest="passkey_op", required=True, metavar="PASSKEY_COMMAND")
    p = pks.add_parser("add", help="register a passkey (a notification to click; the browser asks "
                                   "for an existing passkey, or the recovery passphrase)",
                       parents=registering)
    p.add_argument("--label", help="name for the passkey (default: the hostname)")
    p.set_defaults(vault_func=cmd_passkey_add)
    p = pks.add_parser("list", help="cred_id, label, hostname and date of each passkey", parents=instant)
    p.set_defaults(vault_func=cmd_passkey_list)
    p = pks.add_parser("rm", help="remove a passkey", parents=instant)
    p.add_argument("--cred-id", required=True, metavar="B64URL")
    p.set_defaults(vault_func=cmd_passkey_rm)

    p = add("recovery", "replace the recovery passphrase: the current one, then the new one twice",
            cmd_recovery)
    in_browser(p)
