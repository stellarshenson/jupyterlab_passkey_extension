"""`jupyterlab-passkey vault ...` and the Python `Vault` class.

The HTTP layer is covered by test_vault_routes; here `client.request` is routed
straight into a real VaultService (same dispatch tables as the handlers), and the two
browser steps are stubbed to do what the page does - register a passkey or unlock with
one - so every command runs against a real vault file.
"""

import argparse
import base64
import io
import json
import pathlib
import re
import signal
import subprocess
import sys
import time

import pytest

from jupyterlab_passkey_extension import cli, relay
from jupyterlab_passkey_extension.vault import client, handlers, holders, service, totp
from jupyterlab_passkey_extension.vault import cli as vcli
from jupyterlab_passkey_extension.vault.store import VaultError

# The fixture `server` replaces the browser step; a test of the page's answer uses this.
REAL_BROWSER_STEP = client.browser_step

PASS = "correct horse battery staple"
PRF = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
SECRET = "tok-MUST-NOT-LEAK-91"
# The unlock password, and the authenticator app added with it: its secret and setup key.
UNLOCK = "an everyday password"
APP = bytes(range(40, 60))
APP_KEY = base64.b32encode(APP).decode()


class FakeStdin:
    def __init__(self, text, tty=False):
        self.buffer = io.BytesIO(text.encode())
        self._tty = tty

    def isatty(self):
        return self._tty

    def read(self):
        return self.buffer.read().decode()


class FakeTty(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def server(vault_env, monkeypatch):
    svc = handlers._service
    calls, steps = [], []

    def request(method, action, body=None, params=None):
        table = {"GET": handlers._GET, "POST": handlers._POST, "PATCH": handlers._PATCH}[method]
        arg = (params or {}) if method == "GET" else (body or {})
        try:
            return table[action](svc, arg)
        except service.Locked as e:
            raise client.VaultLocked(str(e), "locked")
        except service.Denied as e:
            raise client.VaultClientError(str(e), "denied")
        except service.NotFound as e:
            raise client.VaultClientError(str(e), "entry-not-found")
        except service.Conflict as e:
            raise client.VaultClientError(str(e), "conflict")
        except VaultError as e:
            raise client.VaultClientError(str(e), "invalid")

    def browser_step(command, args, label, message, timeout, poll=None):
        calls.append(command)
        steps.append({"command": command, **args})
        if command == client.REGISTER_COMMAND:
            n = len(svc.status()["slots"])  # the recovery slot is one: cred-1, then cred-2
            # The page sends a proof; here the recovery passphrase.
            svc.add_passkey(f"cred-{n}", "lab.example", "c2FsdA", PRF, args.get("label") or None,
                            {"current": PASS})
            # The page's answer names the method it stored (`answerCli` in plugin.ts).
            return {"ok": True, "method": "passkey"}
        elif command == client.UNLOCK_COMMAND:
            if args.get("method") == "choose":
                # The chooser was answered with the recovery passphrase.
                svc.unlock_recovery(PASS)
            else:
                svc.unlock_passkey("cred-1", PRF)

    for module in (client, vcli):
        monkeypatch.setattr(module, "request", request)
        monkeypatch.setattr(module, "browser_step", browser_step)
    svc.calls = calls
    svc.steps = steps
    return svc


def run(monkeypatch, *argv, stdin=None):
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", *argv])
    if stdin is not None:
        monkeypatch.setattr(sys, "stdin", FakeStdin(stdin))
    return cli.main()


@pytest.fixture
def ready(server, monkeypatch, capsys):
    """An initialised vault with one passkey and one entry, unlocked."""
    assert run(monkeypatch, "vault", "init", stdin=PASS + "\n") == 0
    assert run(monkeypatch, "vault", "add", "github/api", "-u", "me", "-c", "infra",
               "--url", "https://github.com", stdin=SECRET + "\n") == 0
    capsys.readouterr()
    return server


# --------------------------------------------------------------------------- #
# init, unlock, lock, status
# --------------------------------------------------------------------------- #


def test_init_sets_the_recovery_passphrase_and_registers_a_passkey(server, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "init", stdin=PASS + "\n") == 0
    err = capsys.readouterr().err
    assert f"vault created at {server.status()['path']} -" in err
    assert "it opens the vault when no other method can" in err
    slots = server.status()["slots"]
    assert [s["type"] for s in slots] == ["recovery", "passkey"]
    assert server.calls == [client.REGISTER_COMMAND]


def test_init_without_a_passkey(server, monkeypatch):
    assert run(monkeypatch, "vault", "init", "--no-passkey", stdin=PASS) == 0
    assert [s["type"] for s in server.status()["slots"]] == ["recovery"]


def test_a_vault_without_a_passkey_chooses_a_method_and_get_returns_the_value(server, monkeypatch, capsys):
    # One call: the chooser step, then the reveal, with no separate unlock.
    run(monkeypatch, "vault", "init", "--no-passkey", stdin=PASS)
    run(monkeypatch, "vault", "add", "github/api", stdin=SECRET + "\n")
    run(monkeypatch, "vault", "lock")
    server.calls.clear()
    server.steps.clear()
    assert run(monkeypatch, "vault", "get", "github/api") == 0
    assert server.calls == [client.UNLOCK_COMMAND]
    assert [(s["command"], s.get("method")) for s in server.steps] == [
        (client.UNLOCK_COMMAND, "choose")]
    assert capsys.readouterr().out == SECRET + "\n"


def test_a_cancelled_chooser_exits_non_zero_without_a_secret(server, monkeypatch, capsys):
    run(monkeypatch, "vault", "init", "--no-passkey", stdin=PASS)
    run(monkeypatch, "vault", "add", "github/api", stdin=SECRET + "\n")
    run(monkeypatch, "vault", "lock")

    def cancelled(command, args, label, message, timeout, poll=None):
        assert args.get("method") == "choose"
        raise SystemExit("ceremony failed: the unlock was cancelled")

    monkeypatch.setattr(client, "browser_step", cancelled)
    with pytest.raises(SystemExit) as exit_:
        run(monkeypatch, "vault", "get", "github/api")
    # The one line is the exit status; no value reaches stdout or stderr.
    assert exit_.value.code != 0
    assert "the unlock was cancelled" in str(exit_.value.code)
    out, err = capsys.readouterr()
    assert SECRET not in out + err
    assert server.status()["unlocked"] is False


def test_the_python_unlock_without_a_vault_says_run_init(server):
    with pytest.raises(client.VaultClientError, match="no vault at .+/vault/vault.json - run `jupyterlab-passkey vault init`"):
        client.Vault().unlock()
    assert server.calls == []


def test_init_refuses_an_existing_vault(ready, monkeypatch):
    with pytest.raises(SystemExit, match="already exists"):
        run(monkeypatch, "vault", "init", stdin=PASS)


def test_init_at_a_terminal_asks_twice_and_refuses_a_mismatch(server, monkeypatch):
    answers = iter([PASS, PASS + "x"])
    monkeypatch.setattr(vcli.getpass, "getpass", lambda prompt: next(answers))
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    with pytest.raises(SystemExit, match="differ"):
        run(monkeypatch, "vault", "init")
    assert server.status()["initialized"] is False


def _dialogs(monkeypatch, *answers):
    """Answer browser dialogs with `answers`, then PASS, and return the arguments they got."""
    seen, left = [], iter(answers)
    monkeypatch.setattr(vcli._cli, "_trigger", lambda command, args, label, message: seen.append(args))
    monkeypatch.setattr(vcli._cli, "_wait", lambda *a, **kw: None)
    monkeypatch.setattr(vcli.relay, "collect", lambda nonce, kind: next(left, PASS))
    monkeypatch.setattr(vcli.relay, "unstage", lambda nonce, kind: None)
    return seen


def test_vault_init_in_the_browser_sends_twice(server, monkeypatch):
    # The frontend reads only `twice`, so a recovery passphrase needs it to get two fields.
    seen = _dialogs(monkeypatch)
    assert run(monkeypatch, "vault", "init", "--in-browser", "--no-passkey") == 0
    assert [(d["prompt"], d["twice"]) for d in seen] == [("Recovery passphrase", True)]
    assert "once" not in seen[0]


def test_vault_recovery_in_the_browser_sends_twice_for_the_new_passphrase_only(ready, monkeypatch):
    seen = _dialogs(monkeypatch)
    assert run(monkeypatch, "vault", "recovery", "--in-browser") == 0
    assert [(d["prompt"], d["twice"]) for d in seen] == [
        ("Current recovery passphrase", False),
        ("New recovery passphrase", True),
    ]


@pytest.mark.parametrize("argv", [["add", "github/new"], ["edit", "github/api", "--password"]])
def test_an_entry_value_in_the_browser_has_one_field(ready, monkeypatch, argv):
    # The blind prompt asks an entry value twice; the dialog of the same call has one field.
    seen = _dialogs(monkeypatch)
    assert run(monkeypatch, "vault", *argv, "--in-browser") == 0
    assert [(d["prompt"], d["twice"]) for d in seen] == [("Password", False)]


def test_an_unlock_in_the_browser_has_one_field(ready, monkeypatch):
    run(monkeypatch, "vault", "lock")
    seen = _dialogs(monkeypatch)
    assert run(monkeypatch, "vault", "unlock", "--recovery", "--in-browser") == 0
    assert [(d["prompt"], d["twice"]) for d in seen] == [("Recovery passphrase", False)]


def test_a_password_unlock_and_a_proof_in_the_browser_have_one_field(ready, monkeypatch):
    step = int(time.time()) // totp.STEP
    ready.add_mfa(UNLOCK, APP_KEY, totp.code(APP, step), {"current": PASS})
    run(monkeypatch, "vault", "lock")
    seen = _dialogs(monkeypatch, UNLOCK, totp.code(APP, step + 1))
    assert run(monkeypatch, "vault", "unlock", "--password", "--in-browser") == 0
    assert run(monkeypatch, "vault", "rotate", "--in-browser") == 0
    assert [(d["prompt"], d["twice"]) for d in seen] == [
        ("Unlock password", False),
        ("Code of the authenticator app", False),
        ("Recovery passphrase", False),
    ]


@pytest.mark.parametrize("argv", [["add", "github/new"], ["edit", "github/api", "--password"]])
def test_an_entry_value_at_a_blind_prompt_asks_twice_and_refuses_a_mismatch(ready, monkeypatch, argv):
    answers = iter([SECRET, SECRET + "x"])
    monkeypatch.setattr(vcli.getpass, "getpass", lambda prompt: next(answers))
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    with pytest.raises(SystemExit, match="differ"):
        run(monkeypatch, "vault", *argv)
    assert next(answers, None) is None


def test_lock_and_unlock_with_passkey_and_recovery(ready, monkeypatch, capsys):
    run(monkeypatch, "vault", "lock")
    assert ready.status()["unlocked"] is False
    run(monkeypatch, "vault", "unlock")
    assert ready.status()["unlocked"] is True
    run(monkeypatch, "vault", "lock")
    run(monkeypatch, "vault", "unlock", "--recovery", stdin=PASS + "\n")
    assert ready.status()["unlocked"] is True
    assert "vault unlocked" in capsys.readouterr().err


def test_unlock_with_the_unlock_password_and_a_code(ready, monkeypatch, capsys):
    run(monkeypatch, "vault", "status")
    assert "password and authenticator app: none" in capsys.readouterr().out
    step = int(time.time()) // totp.STEP
    ready.add_mfa(UNLOCK, APP_KEY, totp.code(APP, step), {"current": PASS})
    # The code that added the app is used; the next one is accepted one step early.
    code = totp.code(APP, step + 1)
    run(monkeypatch, "vault", "lock")
    # Two typed secrets: a pipe carries one, and is refused before anything is read.
    with pytest.raises(SystemExit, match="run at a terminal or with --in-browser"):
        run(monkeypatch, "vault", "unlock", "--password", stdin=UNLOCK + "\n")

    def typed(*answers):
        left, prompts = iter(answers), []
        monkeypatch.setattr(vcli.getpass, "getpass", lambda prompt: prompts.append(prompt) or next(left))
        monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
        return prompts

    for answers, refusal in [(("not the password", code), r"^wrong unlock password \[invalid\]$"),
                             ((UNLOCK, "000000"), r"^wrong code \[denied\]$")]:
        typed(*answers)
        with pytest.raises(SystemExit, match=refusal):
            run(monkeypatch, "vault", "unlock", "--password")
        assert ready.status()["unlocked"] is False
    # The password first, the code last.
    prompts = typed(UNLOCK, code)
    run(monkeypatch, "vault", "unlock", "--password")
    assert prompts == ["Unlock password: ", "Code of the authenticator app: "]
    assert ready.status()["unlocked"] is True
    out, err = capsys.readouterr()
    assert "vault unlocked" in err and UNLOCK not in out + err and code not in out + err
    run(monkeypatch, "vault", "status")
    assert "password and authenticator app: added 20" in capsys.readouterr().out
    # One typed method at a time.
    with pytest.raises(SystemExit):
        run(monkeypatch, "vault", "unlock", "--password", "--recovery", stdin="x\n")


def test_status_names_a_password_or_an_app_an_earlier_build_left_alone():
    # 1.1.28 to 1.1.31 added the two apart from each other.
    password = {"type": "password", "created": "2026-10-02T11:00:00Z"}
    app = {"created": "2026-10-02T10:00:00Z"}
    assert vcli._say_mfa({"slots": [password], "authenticator": None}) == (
        "password only, added 2026-10-02T11:00:00Z")
    assert vcli._say_mfa({"slots": [], "authenticator": app}) == "app only, added 2026-10-02T10:00:00Z"


def test_status_prints_state_holder_and_capabilities(ready, monkeypatch, capsys):
    run(monkeypatch, "vault", "status")
    out = capsys.readouterr().out
    assert "state: unlocked, 29m 59s left" in out or "state: unlocked, 30m 0s left" in out
    assert "holder: memory/" in out and "this extension's own code" in out
    assert "protection: " in out
    # The detail the panel keeps in tooltips: one line per capability, explained.
    assert "  Expires on its own: no - a timer in the Jupyter server" in out
    rows = [line for line in out.splitlines() if ": yes - " in line or ": no - " in line]
    assert len(rows) == len(holders.CAPABILITY_TEXT)
    assert "passkeys: 1" in out and "@ lab.example" in out
    assert "password and authenticator app: none" in out
    assert "unlock duration: 30m" in out


def test_the_unlock_duration_reads_in_hours_and_minutes():
    assert [vcli._minutes(m) for m in (240, 90, 45, 1440)] == ["4h", "1h 30m", "45m", "24h"]


def test_debug_prints_the_holder_decision(ready, monkeypatch, capsys):
    run(monkeypatch, "vault", "status", "--debug")
    err = capsys.readouterr().err
    assert "vault: JLAB_PASSKEY_VAULT_HOLDER=memory" in err
    assert "vault: holder=memory/" in err


# --------------------------------------------------------------------------- #
# entries
# --------------------------------------------------------------------------- #


def test_get_prints_only_the_value(ready, monkeypatch, capsys):
    run(monkeypatch, "vault", "get", "github/api")
    assert capsys.readouterr().out == SECRET + "\n"
    run(monkeypatch, "vault", "get", "github/api", "--field", "username")
    assert capsys.readouterr().out == "me\n"


def test_get_on_a_locked_vault_unlocks_first(ready, monkeypatch, capsys):
    run(monkeypatch, "vault", "lock")
    ready.calls.clear()
    ready.steps.clear()
    run(monkeypatch, "vault", "get", "github/api")
    # A passkey for the tab's hostname is the fast path: one click, no chooser.
    assert ready.calls == [client.UNLOCK_COMMAND]
    assert [(s["command"], s.get("method")) for s in ready.steps] == [
        (client.UNLOCK_COMMAND, None)]
    assert capsys.readouterr().out == SECRET + "\n"


def test_list_hides_passwords_and_filters(ready, monkeypatch, capsys):
    run(monkeypatch, "vault", "add", "nas/ugos", "-c", "home", stdin="p\n")
    capsys.readouterr()
    run(monkeypatch, "vault", "list")
    out = capsys.readouterr().out
    assert "github/api\tme\tinfra\thttps://github.com" in out and SECRET not in out
    run(monkeypatch, "vault", "list", "--category", "home", "--json")
    assert [e["name"] for e in json.loads(capsys.readouterr().out)["result"]["entries"]] == ["nas/ugos"]


def test_add_refuses_a_duplicate(ready, monkeypatch):
    with pytest.raises(SystemExit, match="already exists"):
        run(monkeypatch, "vault", "add", "github/api", stdin="x\n")


def test_add_with_a_generated_password(ready, monkeypatch):
    run(monkeypatch, "vault", "add", "gen/one", "--generate", "--length", "32")
    assert len(ready.read("gen/one")) == 32


def test_edit_changes_only_given_fields(ready, monkeypatch):
    run(monkeypatch, "vault", "edit", "github/api", "--url", "https://x")
    assert ready.read("github/api", "url") == "https://x"
    assert ready.read("github/api") == SECRET
    run(monkeypatch, "vault", "edit", "github/api", "--password", stdin="new-secret\n")
    assert ready.read("github/api") == "new-secret"
    with pytest.raises(SystemExit, match="nothing to change"):
        run(monkeypatch, "vault", "edit", "github/api")


def test_rm_and_missing_names(ready, monkeypatch):
    run(monkeypatch, "vault", "rm", "github/api")
    with pytest.raises(SystemExit, match="no entry named"):
        run(monkeypatch, "vault", "get", "github/api")


# --------------------------------------------------------------------------- #
# one call from a locked vault to a value
# --------------------------------------------------------------------------- #


class ReadVault:
    """A locked vault that records every call, in order."""

    def __init__(self, unlocked=False, authenticator=None, pair=False, fail=None):
        self.state = {
            "initialized": True,
            "unlocked": unlocked,
            "path": "/vault/vault.json",
            "slots": [{"type": store.PAIR}] if pair else [{"type": "recovery"}],
            "authenticator": authenticator,
        }
        self.calls = []
        self.fail = fail

    def status(self):
        self.calls.append(("status",))
        return dict(self.state)

    def unlock(self, recovery=None, password=None, code=None):
        self.calls.append(("unlock", recovery, password, code))
        if self.fail is not None:
            raise self.fail
        self.state["unlocked"] = True
        return dict(self.state)

    def list(self):
        self.calls.append(("list",))
        return []

    def get(self, name, field="password"):
        self.calls.append(("get", name, field))
        return "value"

    def _unlocked(self, call):
        self.calls.append(("stage",))
        return call()


def _read_ns(**values):
    base = dict(recovery=False, password=False, in_browser=False, timeout=1.0,
                category=None, json=False, name="github/api", field="password",
                env=["TOKEN=github/api"], command=["true"])
    base.update(values)
    return argparse.Namespace(**base)


READ_COMMANDS = [
    (vcli.cmd_list, ("list",)),
    (vcli.cmd_get, ("get", "github/api", "password")),
    (vcli.cmd_copy, ("stage",)),
    (vcli.cmd_show, ("stage",)),
    (vcli.cmd_exec, ("get", "github/api", "password")),
]


@pytest.mark.parametrize("command, read", READ_COMMANDS, ids=lambda value: getattr(value, "__name__", ""))
def test_a_read_command_unlocks_with_the_recovery_passphrase_first(monkeypatch, command, read):
    vault = ReadVault()
    asked = []
    monkeypatch.setattr(vcli, "_read_secret",
                        lambda a, prompt, twice, blind_twice=False: asked.append((prompt, twice)) or PASS)
    monkeypatch.setattr(vcli, "request", lambda *a, **k: {"nonce": "n" * 20})
    monkeypatch.setattr(vcli._cli, "_trigger", lambda *a, **k: None)
    monkeypatch.setattr(vcli.os, "execvpe", lambda *a: None)
    command(_read_ns(recovery=True), vault)
    assert asked == [("Recovery passphrase", False)]
    assert vault.calls == [("status",), ("unlock", PASS, None, None), read]


@pytest.mark.parametrize("command, read", READ_COMMANDS, ids=lambda value: getattr(value, "__name__", ""))
def test_an_unlocked_vault_ignores_the_method(monkeypatch, command, read):
    vault = ReadVault(unlocked=True)
    monkeypatch.setattr(vcli, "_read_secret", lambda *a, **k: pytest.fail("a secret was asked"))
    monkeypatch.setattr(vcli, "request", lambda *a, **k: {"nonce": "n" * 20})
    monkeypatch.setattr(vcli._cli, "_trigger", lambda *a, **k: None)
    monkeypatch.setattr(vcli.os, "execvpe", lambda *a: None)
    command(_read_ns(recovery=True), vault)
    assert ("unlock", PASS, None, None) not in vault.calls
    assert [call[0] for call in vault.calls] == ["status", read[0]]


def test_a_read_command_with_a_wrong_passphrase_propagates_the_code(monkeypatch):
    vault = ReadVault(fail=client.VaultClientError("wrong recovery passphrase", "denied"))
    monkeypatch.setattr(vcli, "_read_secret", lambda *a, **k: PASS + "x")
    with pytest.raises(client.VaultClientError) as caught:
        vcli.cmd_get(_read_ns(recovery=True), vault)
    assert caught.value.code == "denied"
    assert [call[0] for call in vault.calls] == ["status", "unlock"]


def test_a_password_read_from_a_pipe_is_refused_before_a_secret_is_read(monkeypatch):
    # A pipe carries one secret; the unlock password and the code are two.
    vault = ReadVault(authenticator={"created": "2026-01-02T03:04:05Z"})
    monkeypatch.setattr(sys, "stdin", FakeStdin(UNLOCK + "\n"))
    monkeypatch.setattr(vcli, "_read_secret", lambda *a, **k: pytest.fail("a secret was asked"))
    with pytest.raises(SystemExit, match="--password needs the unlock password and an app code"):
        vcli.cmd_get(_read_ns(password=True), vault)
    assert [call[0] for call in vault.calls] == ["status"]


def test_a_password_read_in_the_browser_asks_the_password_then_the_code(monkeypatch):
    vault = ReadVault(authenticator={"created": "2026-01-02T03:04:05Z"})
    asked = []

    def secret(a, prompt, twice, blind_twice=False):
        asked.append(prompt)
        return UNLOCK if len(asked) == 1 else "123456"

    monkeypatch.setattr(vcli, "_read_secret", secret)
    assert vcli.cmd_get(_read_ns(password=True, in_browser=True), vault) == 0
    assert asked == ["Unlock password", "Code of the authenticator app"]
    assert vault.calls == [("status",), ("unlock", None, UNLOCK, "123456"),
                           ("get", "github/api", "password")]


@pytest.mark.parametrize("argv", [
    ["list", "--recovery", "--in-browser"],
    ["list", "--password", "--in-browser"],
    ["get", "github/api", "--recovery", "--in-browser"],
    ["get", "github/api", "--password", "--in-browser"],
    ["copy", "github/api", "--recovery", "--in-browser"],
    ["copy", "github/api", "--password", "--in-browser"],
    ["show", "github/api", "--recovery", "--in-browser"],
    ["show", "github/api", "--password", "--in-browser"],
    ["exec", "--recovery", "--in-browser", "--", "true"],
    ["exec", "--password", "--in-browser", "--", "true"],
])
def test_every_read_command_takes_the_method_and_the_browser_flag(monkeypatch, argv):
    parsed = []
    monkeypatch.setattr(vcli, "run",
                        lambda a: parsed.append((a.recovery, a.password, a.in_browser)) or 0)
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "vault", *argv])
    assert cli.main() == 0
    assert parsed == [(bool(argv.count("--recovery")), bool(argv.count("--password")), True)]


def test_a_read_command_takes_one_method_at_a_time(monkeypatch, capsys):
    monkeypatch.setattr(vcli, "run", lambda a: 0)
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "vault", "get", "x",
                                      "--recovery", "--password"])
    with pytest.raises(SystemExit):
        cli.main()
    assert "not allowed with argument" in capsys.readouterr().err


def test_the_cli_error_line_carries_the_code(ready, monkeypatch):
    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "vault", "get", "absent/entry")
    assert str(caught.value.code) == (
        "no entry named 'absent/entry' - run `jupyterlab-passkey vault list --json` "
        "to see the names [entry-not-found]")
    run(monkeypatch, "vault", "lock")
    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "vault", "get", "github/api", "--recovery", stdin=PASS + "-wrong\n")
    assert str(caught.value.code) == "wrong recovery passphrase [denied]"


def test_the_locked_line_carries_the_code(monkeypatch):
    def refused(vault, call):
        raise client.VaultLocked("the vault is locked", "locked")

    monkeypatch.setattr(vcli, "ensure_vault", refused)
    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "vault", "status")
    assert str(caught.value.code) == vcli.LOCKED + " [locked]"


def test_no_option_takes_a_secret_as_its_value():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers()
    vcli.add_vault_parser(sub, argparse.ArgumentParser(add_help=False), argparse.ArgumentParser(add_help=False))
    vault = sub.choices["vault"]
    subparsers = [a for a in vault._actions if isinstance(a, argparse._SubParsersAction)][0]
    for name, parser in subparsers.choices.items():
        for action in parser._actions:
            if action.dest in ("password", "recovery", "secret", "passphrase"):
                assert action.nargs == 0, f"`vault {name}` takes a {action.dest} value on argv"


def test_registering_waits_longer_than_a_click_unless_told(monkeypatch):
    # 120 s gave up while the page carried on and registered the passkey.
    parsed = []
    monkeypatch.setattr(vcli, "run", lambda a: parsed.append(a.timeout) or 0)
    for argv in (["init"], ["passkey", "add"], ["passkey", "add", "--timeout", "30"], ["unlock"]):
        monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "vault", *argv])
        cli.main()
    assert parsed == [vcli.REGISTER_TIMEOUT, vcli.REGISTER_TIMEOUT, 30.0, cli.CLICK_TIMEOUT]


def test_a_subcommand_that_never_waits_takes_no_timeout(monkeypatch, capsys):
    # Accepting --timeout and ignoring it would say it waits for a click; it never does.
    monkeypatch.setattr(vcli, "run", lambda a: 0)
    for argv in (["lock"], ["status"], ["generate"], ["passkey", "list"],
                 ["passkey", "rm", "--cred-id", "AAEC"]):
        monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "vault", *argv, "--timeout", "5"])
        with pytest.raises(SystemExit):
            cli.main()
        assert "unrecognized arguments: --timeout" in capsys.readouterr().err


def test_generate(server, monkeypatch, capsys):
    run(monkeypatch, "vault", "generate", "--length", "40", "--no-symbols")
    value = capsys.readouterr().out.strip()
    assert len(value) == 40 and value.isalnum()


def test_import(ready, monkeypatch, capsys, tmp_path):
    f = tmp_path / "export.json"
    f.write_text(json.dumps([{"service": "github/api", "password": "x"},
                             {"service": "nas/ugos", "password": "y"}]))
    run(monkeypatch, "vault", "import", str(f))
    assert "added 1, skipped 1: github/api" in capsys.readouterr().err
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    with pytest.raises(SystemExit, match="refusing to read secrets from a terminal"):
        run(monkeypatch, "vault", "import")


def _names(monkeypatch, capsys):
    capsys.readouterr()
    run(monkeypatch, "vault", "list", "--json")
    return {e["name"]: e for e in json.loads(capsys.readouterr().out)["result"]["entries"]}


def test_import_refuses_a_field_it_does_not_know_and_imports_nothing(ready, monkeypatch, capsys):
    # pass-cli's own JSON spells the fields `Username`, `URL`, `Notes`: dropped without a
    # word, the entry would be counted as added with those fields empty.
    items = [{"name": "ok/one", "password": "p"},
             {"name": "bad/two", "password": "p", "Username": "u"}]
    with pytest.raises(SystemExit, match="imported entry 2: `Username` is not a field - the fields are "
                                         "name, username, password, url, category, notes, created, updated; "
                                         "nothing was imported"):
        run(monkeypatch, "vault", "import", stdin=json.dumps(items))
    assert set(_names(monkeypatch, capsys)) == {"github/api"}


def test_import_keeps_the_dates_an_entry_gives(ready, monkeypatch, capsys):
    items = [{"name": "dated/both", "password": "p",
              # as pass-cli writes them: nine fraction digits and an offset
              "created": "2026-03-23T20:37:13.736252971+01:00", "updated": "2026-05-26T15:23:19Z"},
             {"name": "dated/none", "password": "p", "created": "", "updated": None}]
    run(monkeypatch, "vault", "import", stdin=json.dumps(items))
    entries = _names(monkeypatch, capsys)
    assert (entries["dated/both"]["created"], entries["dated/both"]["updated"]) == \
        ("2026-03-23T19:37:13Z", "2026-05-26T15:23:19Z")
    # Without a date the entry gets the time of the import.
    none = entries["dated/none"]
    assert none["created"] == none["updated"] and none["created"] > "2026-05-26T15:23:19Z"
    bad = [{"name": "dated/bad", "password": "p", "created": "yesterday"}]
    with pytest.raises(SystemExit, match="imported entry 1: `created` must be a date and time"):
        run(monkeypatch, "vault", "import", stdin=json.dumps(bad))
    assert "dated/bad" not in _names(monkeypatch, capsys)


FAKE_PASS_CLI = r"""#!%s
import json, sys
print("Master password: ", file=sys.stderr)
if sys.stdin.readline() != "old-master\n":
    print("Error: failed to unlock vault: decryption failed", file=sys.stderr)
    print("Usage:\n  pass-cli", file=sys.stderr)
    sys.exit(1)
ENTRIES = [
    {"Service": "mig/one", "Username": "kj", "URL": "https://one.example", "Category": "infra",
     "Notes": "{\"k\": 1}", "CreatedAt": "2026-03-23T20:37:13.736252971+01:00",
     "UpdatedAt": "2026-05-26T15:23:19.01327459+02:00", "HasTOTP": False, "UsageCount": 81,
     "GitRepositories": None},
    {"Service": "-dash", "Username": "", "URL": "", "Category": "", "Notes": "",
     "CreatedAt": "2026-04-01T00:00:00Z", "UpdatedAt": "2026-04-01T00:00:00Z", "HasTOTP": False},
    {"Service": "totp/one", "Username": "x", "HasTOTP": True},
]
PASSWORDS = {"mig/one": "pw one with spaces ", "-dash": "pw-dash"}
if sys.argv[1:] == ["list", "--format", "json"]:
    print(json.dumps(ENTRIES, indent=2))
elif sys.argv[1:-1] == ["get", "--field", "password", "--quiet", "--no-clipboard", "--"]:
    print(PASSWORDS[sys.argv[-1]])
else:
    print("Error: unexpected arguments " + repr(sys.argv[1:]), file=sys.stderr)
    sys.exit(2)
""" % sys.executable


@pytest.fixture
def pass_cli(tmp_path, monkeypatch):
    """A `pass-cli` on PATH that answers as the real one does when stdin is a pipe."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "pass-cli"
    script.write_text(FAKE_PASS_CLI)
    script.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    return bin_dir


def test_import_from_pass_cli_moves_every_field_and_names_the_totp_entries(ready, pass_cli, monkeypatch, capsys):
    run(monkeypatch, "vault", "import", "--pass-cli", stdin="old-master\n")
    err = capsys.readouterr().err
    assert "reading 3 entries from pass-cli" in err and "added 2, skipped 0" in err
    assert "not imported, pass-cli holds a TOTP secret for them: totp/one" in err
    entries = _names(monkeypatch, capsys)
    assert set(entries) == {"github/api", "mig/one", "-dash"}
    one = entries["mig/one"]
    assert (one["username"], one["url"], one["category"], one["notes"]) == \
        ("kj", "https://one.example", "infra", '{"k": 1}')
    assert (one["created"], one["updated"]) == ("2026-03-23T19:37:13Z", "2026-05-26T13:23:19Z")
    # The password as pass-cli printed it, less the one newline it ends the line with.
    run(monkeypatch, "vault", "get", "mig/one")
    assert capsys.readouterr().out == "pw one with spaces \n"
    # A second run adds nothing: every name exists.
    run(monkeypatch, "vault", "import", "--pass-cli", stdin="old-master\n")
    assert "added 0, skipped 2: " in capsys.readouterr().err


def test_import_from_pass_cli_asks_the_vault_before_pass_cli(server, pass_cli, monkeypatch, capsys):
    read = vcli._pass_cli

    def recorded(master, *args):
        server.calls.append(f"pass-cli {args[0]}")
        return read(master, *args)

    monkeypatch.setattr(vcli, "_pass_cli", recorded)
    # No vault: said before the master password is read or pass-cli is run.
    with pytest.raises(SystemExit, match="no vault at .* vault init"):
        run(monkeypatch, "vault", "import", "--pass-cli", stdin="")
    assert server.calls == []
    # A locked vault: the unlock is asked first, as the help says.
    run(monkeypatch, "vault", "init", stdin=PASS + "\n")
    run(monkeypatch, "vault", "lock")
    server.calls.clear()
    run(monkeypatch, "vault", "import", "--pass-cli", stdin="old-master\n")
    assert server.calls == [client.UNLOCK_COMMAND, "pass-cli list", "pass-cli get", "pass-cli get"]
    assert "added 2, skipped 0" in capsys.readouterr().err


def test_import_from_pass_cli_says_why_it_stopped(ready, pass_cli, monkeypatch, capsys):
    # pass-cli's own reason, not its usage text.
    with pytest.raises(SystemExit, match=r"^pass-cli list failed: failed to unlock vault: decryption failed$"):
        run(monkeypatch, "vault", "import", "--pass-cli", stdin="wrong\n")
    with pytest.raises(SystemExit, match="--pass-cli reads the pass-cli vault and takes no FILE"):
        run(monkeypatch, "vault", "import", "--pass-cli", "export.json", stdin="old-master\n")
    (pass_cli / "pass-cli").unlink()
    with pytest.raises(SystemExit, match="pass-cli is not on PATH"):
        run(monkeypatch, "vault", "import", "--pass-cli", stdin="old-master\n")
    assert set(_names(monkeypatch, capsys)) == {"github/api"}


def test_a_pass_cli_master_password_in_the_browser_has_one_field(ready, pass_cli, monkeypatch):
    seen = _dialogs(monkeypatch, "old-master")
    assert run(monkeypatch, "vault", "import", "--pass-cli", "--in-browser") == 0
    assert [(d["prompt"], d["twice"]) for d in seen] == [("pass-cli master password", False)]


# --------------------------------------------------------------------------- #
# copy, show, exec
# --------------------------------------------------------------------------- #


def test_copy_stages_on_the_server_and_the_value_never_reaches_the_cli(ready, monkeypatch, capsys, vault_env):
    seen = []
    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: seen.append((c, a, l, m)))
    run(monkeypatch, "vault", "copy", "github/api")
    [(command, args, label, message)] = seen
    assert message == "Copy **github/api**"
    assert command == cli.COPY_COMMAND and set(args) == {"nonce", "label"}
    assert SECRET not in json.dumps(seen)
    out, err = capsys.readouterr()
    assert SECRET not in out + err
    assert (vault_env / "relay" / f"{args['nonce']}.secret").read_text() == SECRET


def test_copy_unstages_when_the_trigger_fails(ready, monkeypatch, vault_env):
    def boom(*a):
        raise SystemExit("trigger rejected (404)")

    monkeypatch.setattr(cli, "_trigger", boom)
    with pytest.raises(SystemExit):
        run(monkeypatch, "vault", "copy", "github/api")
    assert not list((vault_env / "relay").glob("*.secret"))


def test_show_stages_a_code(ready, monkeypatch, vault_env):
    seen = []
    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: seen.append((c, a)))
    run(monkeypatch, "vault", "show", "github/api")
    [(command, args)] = seen
    assert command == cli.SHOW_COMMAND
    assert (vault_env / "relay" / f"{args['nonce']}.code").read_text() == SECRET


def _fake_exec(monkeypatch):
    """Record the exec instead of replacing the test process with the command."""
    seen = []

    def execvpe(file, argv, env):
        seen.append((file, argv, env))
        raise SystemExit(0)

    monkeypatch.setattr(vcli.os, "execvpe", execvpe)
    monkeypatch.setattr(vcli.signal, "signal", lambda sig, handler: seen.append((sig, handler)))
    return seen


def test_exec_becomes_the_command_with_the_values_in_its_environment(ready, monkeypatch):
    # exec, not a child: Ctrl+C, signals and the exit status stay the command's own.
    monkeypatch.setattr(cli, "STARTED_HANGUP", vcli.signal.SIG_DFL)
    seen = _fake_exec(monkeypatch)
    with pytest.raises(SystemExit):
        run(monkeypatch, "vault", "exec", "--env", "TOKEN=github/api",
            "--env", "WHO=github/api:username", "--", "psql", "-c", "select 1")
    file, argv, env = seen[-1]
    assert (file, argv) == ("psql", ["psql", "-c", "select 1"])
    assert env["TOKEN"] == SECRET and env["WHO"] == "me"
    # An ignored signal survives exec; the command gets the defaults back.
    restored = {sig for sig, handler in seen[:-1] if handler == vcli.signal.SIG_DFL}
    assert {vcli.signal.SIGHUP, vcli.signal.SIGPIPE} <= restored


def test_exec_under_nohup_leaves_the_command_ignoring_sighup(ready, monkeypatch):
    # Only main()'s own ignore is undone: a SIGHUP ignored by nohup stays ignored.
    monkeypatch.setattr(cli, "STARTED_HANGUP", vcli.signal.SIG_IGN)
    seen = _fake_exec(monkeypatch)
    with pytest.raises(SystemExit):
        run(monkeypatch, "vault", "exec", "--", "sleep", "60")
    last = dict(seen[:-1])
    assert last[vcli.signal.SIGHUP] == vcli.signal.SIG_IGN
    assert last[vcli.signal.SIGPIPE] == vcli.signal.SIG_DFL


@pytest.mark.parametrize("started,ignored", [(signal.SIG_DFL, 0), (signal.SIG_IGN, 1)])
def test_python_m_exec_hands_the_command_the_sighup_it_started_with(started, ignored):
    # A real process, attached (SIG_DFL) or under nohup (SIG_IGN): run as `python -m`
    # the module is __main__, and the command must still get what the process began with.
    out = subprocess.run(
        [sys.executable, "-m", "jupyterlab_passkey_extension.cli", "vault", "exec", "--",
         "grep", "SigIgn", "/proc/self/status"],
        preexec_fn=lambda: signal.signal(signal.SIGHUP, started),
        cwd=pathlib.Path(cli.__file__).parents[1], capture_output=True, text=True, check=True,
    ).stdout
    assert int(out.split()[1], 16) & 1 == ignored


def test_exec_runs_the_command_with_stdout_or_stderr_closed(ready, monkeypatch, tmp_path):
    # Started with `>&-` the stream is None, as it is after _say drops a failing
    # stderr; a stream something else closed cannot be flushed.
    seen = _fake_exec(monkeypatch)
    closed = open(tmp_path / "stderr", "w")
    closed.close()
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", closed)
    with pytest.raises(SystemExit):
        run(monkeypatch, "vault", "exec", "--", "sleep", "60")
    assert seen[-1][1] == ["sleep", "60"]


def test_exec_passes_the_command_arguments_through_untouched(ready, monkeypatch):
    # The --cred-id gluing is for this CLI's own flags, never the command's.
    seen = _fake_exec(monkeypatch)
    with pytest.raises(SystemExit):
        run(monkeypatch, "vault", "exec", "--env", "T=github/api", "--", "tool", "--cred-id", "abc")
    assert seen[-1][1] == ["tool", "--cred-id", "abc"]


class _Answer(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_the_server_is_found_once_per_process(monkeypatch):
    # `jupyter server list` takes about a second; a notebook reading several secrets,
    # or a vault command that also raises a notification, must not pay it per request.
    found = []
    monkeypatch.setattr(cli, "_server_list", lambda: found.append(1) or {"port": 1, "token": "t"})
    monkeypatch.setattr(cli._LOOPBACK, "open", lambda req, timeout: _Answer(b"{}"))
    client.request("GET", "status")
    client.request("GET", "status")
    cli._trigger("passkey:copy", {"nonce": "n" * 20}, "Copy", "msg")
    assert found == [1]


def test_a_server_the_cli_cannot_tell_is_a_client_error_not_an_exit(monkeypatch):
    # The Python Vault class runs in a notebook kernel, where SystemExit is the wrong
    # answer: the refusal must arrive as the class's own error.
    def refuse():
        raise SystemExit("cannot tell which server is the lab")

    monkeypatch.setattr(cli, "_server_list", refuse)
    with pytest.raises(client.VaultClientError, match="cannot tell which server"):
        client.request("GET", "status")


@pytest.fixture
def local_server():
    """A real HTTP server on loopback that records each request's path and headers."""
    import http.server
    import threading

    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self):
            length = int(self.headers.get("Content-Length") or 0)
            seen.append((self.path, dict(self.headers), self.rfile.read(length)))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        do_GET = do_POST = _answer

        def log_message(self, *a):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1], seen
    httpd.shutdown()


def test_requests_to_the_local_server_never_go_through_a_proxy(local_server, monkeypatch):
    # urlopen follows http_proxy even for 127.0.0.1; through a proxy the token and a
    # new password would leave the host. Port 9 is closed: a proxied request fails.
    port, seen = local_server
    for var in ("http_proxy", "HTTP_PROXY"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.setattr(cli, "_server_list", lambda: {"port": port, "token": "t"})
    client.request("POST", "entries", {"name": "x", "fields": {"password": "p"}})
    cli._trigger("passkey:copy", {"nonce": "n" * 20}, "Copy", "msg")
    assert [path for path, _, _ in seen] == [
        "/jupyterlab-passkey-extension/vault/entries", f"/{cli.INGEST}"]


def test_exec_needs_a_command(ready, monkeypatch):
    with pytest.raises(SystemExit, match="needs a command"):
        run(monkeypatch, "vault", "exec", "--env", "T=github/api")


# --------------------------------------------------------------------------- #
# passkeys and recovery
# --------------------------------------------------------------------------- #


def test_passkey_list_and_remove(ready, monkeypatch, capsys):
    run(monkeypatch, "vault", "passkey", "list")
    assert capsys.readouterr().out.startswith("cred-1\tlab.example\tlab.example\t")
    run(monkeypatch, "vault", "passkey", "rm", "--cred-id", "cred-1")
    assert [s["type"] for s in ready.status()["slots"]] == ["recovery"]


def test_password_and_passkey_in_status_passkey_list_rm_and_unlock(server, monkeypatch, capsys):
    from jupyterlab_passkey_extension.tests.test_vault_webauthn import (ORIGIN, PAIR_PASSWORD,
                                                                       add_pair)
    assert run(monkeypatch, "vault", "init", "--no-passkey", stdin=PASS + "\n") == 0
    run(monkeypatch, "vault", "status")
    assert "password and passkey: none" in capsys.readouterr().out
    add_pair(server)
    slot = [s for s in server.status()["slots"] if s["type"] == "password-passkey"][0]
    run(monkeypatch, "vault", "status")
    assert f"password and passkey: added {slot['created']} at {ORIGIN}" in capsys.readouterr().out
    run(monkeypatch, "vault", "passkey", "list")
    assert capsys.readouterr().out == "\t".join(
        (slot["cred_id"], "laptop", "lab.example", slot["created"])) + "\n"
    # --password on a vault whose only unlock password goes with a passkey: the tab asks
    # for it with the passkey, so the terminal reads no secret.
    run(monkeypatch, "vault", "lock")
    monkeypatch.setattr(vcli.getpass, "getpass", lambda prompt: pytest.fail("a secret was asked"))
    monkeypatch.setattr(sys, "stdin", FakeStdin(PAIR_PASSWORD + "\n", tty=True))
    run(monkeypatch, "vault", "unlock", "--password")
    assert server.steps[-1] == {"command": client.UNLOCK_COMMAND, "method": "choose"}
    assert sys.stdin.read() == PAIR_PASSWORD + "\n"
    run(monkeypatch, "vault", "passkey", "rm", "--cred-id", slot["cred_id"])
    assert [s["type"] for s in server.status()["slots"]] == ["recovery"]


def test_passkey_remove_needs_an_unlocked_vault(ready, monkeypatch):
    run(monkeypatch, "vault", "lock")
    with pytest.raises(SystemExit, match="the vault is locked - run `jupyterlab-passkey vault unlock`"):
        run(monkeypatch, "vault", "passkey", "rm", "--cred-id", "cred-1")


def test_passkey_add_needs_no_unlock(ready, monkeypatch):
    # A proof, not an unlock: a locked vault takes a new passkey without an unlock
    # notification first, and stays locked.
    run(monkeypatch, "vault", "lock")
    ready.calls.clear()
    run(monkeypatch, "vault", "passkey", "add", "--label", "Work laptop")
    assert ready.calls == [client.REGISTER_COMMAND]
    s = ready.status()
    assert s["unlocked"] is False
    assert [x["label"] for x in s["slots"] if x["type"] == "passkey"] == ["lab.example", "Work laptop"]


@pytest.mark.parametrize("method, said", [("password-passkey", "password and passkey added"),
                                          ("passkey", "passkey added")])
def test_passkey_add_names_the_method_the_page_stored(ready, monkeypatch, capsys, method, said):
    # The page's answer through the result relay: a passkey with no PRF is stored as
    # Password and passkey, and the line names that method.
    def trigger(command_id, args_obj, label, message, seconds=None):
        nonce = args_obj["nonce"]
        relay.stage(nonce, "json", json.dumps({"nonce": nonce, "ok": True, "method": method}))

    monkeypatch.setattr(cli, "_trigger", trigger)
    monkeypatch.setattr(vcli, "browser_step", REAL_BROWSER_STEP)
    assert run(monkeypatch, "vault", "passkey", "add") == 0
    assert capsys.readouterr().err == said + "\n"


def test_passkey_add_without_a_vault_says_run_init(server, monkeypatch):
    # Not a registration notification that can only fail: there is no vault to add to.
    with pytest.raises(SystemExit, match="no vault at .+/vault/vault.json - run `jupyterlab-passkey vault init`"):
        run(monkeypatch, "vault", "passkey", "add")
    assert server.calls == []


def test_unlock_without_a_vault_says_run_init(server, monkeypatch):
    with pytest.raises(SystemExit, match="no vault at .+/vault/vault.json - run `jupyterlab-passkey vault init`"):
        run(monkeypatch, "vault", "unlock")
    assert server.calls == []


def test_a_rejected_trigger_forgets_the_server(monkeypatch):
    import urllib.error

    def refused(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(b"{}"))

    monkeypatch.setattr(cli, "_found", ("http://127.0.0.1:1", "old-token"))
    monkeypatch.setattr(cli._LOOPBACK, "open", refused)
    with pytest.raises(SystemExit, match="403"):
        cli._trigger("passkey:copy", {"nonce": "n" * 20}, "Copy", "msg")
    assert cli._found is None


def test_a_trigger_that_gets_no_answer_forgets_the_server(monkeypatch):
    import urllib.error

    def unreachable(req, timeout):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(cli, "_found", ("http://127.0.0.1:1", "t"))
    monkeypatch.setattr(cli._LOOPBACK, "open", unreachable)
    with pytest.raises(SystemExit, match="cannot reach"):
        cli._trigger("passkey:copy", {"nonce": "n" * 20}, "Copy", "msg")
    assert cli._found is None


def test_a_request_that_gets_no_answer_forgets_the_server(monkeypatch):
    def unreachable(req, timeout):
        raise OSError("connection refused")

    monkeypatch.setattr(cli, "_found", ("http://127.0.0.1:1", "t"))
    monkeypatch.setattr(cli._LOOPBACK, "open", unreachable)
    with pytest.raises(client.VaultClientError, match="cannot reach"):
        client.request("GET", "status")
    assert cli._found is None


def test_a_restarted_server_is_looked_up_again(monkeypatch):
    # A 403 (new token after a restart) or no answer forgets the found server, so a
    # long-running Python process recovers on its next call.
    import urllib.error

    def refused(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(b"{}"))

    monkeypatch.setattr(cli, "_found", ("http://127.0.0.1:1", "old-token"))
    monkeypatch.setattr(cli._LOOPBACK, "open", refused)
    with pytest.raises(client.VaultClientError):
        client.request("GET", "status")
    assert cli._found is None


def test_a_server_without_the_vault_says_to_restart_it(monkeypatch):
    # Installed into a running server: its HTML 404 carries no vault error.
    import urllib.error

    def missing(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {},
                                     io.BytesIO(b"<html>404: Not Found</html>"))

    monkeypatch.setattr(cli, "_found", ("http://127.0.0.1:1", "token"))
    monkeypatch.setattr(cli._LOOPBACK, "open", missing)
    with pytest.raises(client.VaultClientError,
                       match="the vault is not loaded - restart the Jupyter server"):
        client.request("GET", "status")


def test_an_answer_that_is_not_json_is_one_line(monkeypatch):
    # A proxy or a login page can answer 200 with HTML; a wait reads it as a failed read.
    monkeypatch.setattr(cli, "_found", ("http://127.0.0.1:1", "token"))
    monkeypatch.setattr(cli._LOOPBACK, "open", lambda req, timeout: _Answer(b"<html>login</html>"))
    with pytest.raises(client.VaultClientError, match="vault/status is not JSON"):
        client.request("GET", "status")


def test_a_refused_proof_keeps_the_found_server(monkeypatch):
    # The vault's own 403 (a wrong proof) carries an error; only a refused token -
    # a new one after a restart - makes the client look the server up again.
    import urllib.error

    def denied(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {},
                                     io.BytesIO(b'{"error": "wrong recovery passphrase"}'))

    monkeypatch.setattr(cli, "_found", ("http://127.0.0.1:1", "token"))
    monkeypatch.setattr(cli._LOOPBACK, "open", denied)
    with pytest.raises(client.VaultClientError, match="wrong recovery passphrase"):
        client.request("POST", "recovery", {})
    assert cli._found == ("http://127.0.0.1:1", "token")


@pytest.mark.parametrize("status, body, expected", [
    (423, {"error": "the vault is locked", "code": "locked"}, "locked"),
    (400, {"error": "the vault is locked", "code": "locked"}, "locked"),
    (423, {"error": "the vault is locked"}, "locked"),
], ids=["the code", "the code on another status", "the status alone"])
def test_the_client_reads_a_locked_vault_from_the_body_or_the_status(
        monkeypatch, status, body, expected):
    # The status alone is an older server, which carries no code.
    import urllib.error

    def locked(req, timeout):
        raise urllib.error.HTTPError(req.full_url, status, "Locked", {},
                                     io.BytesIO(json.dumps(body).encode()))

    monkeypatch.setattr(cli, "_found", ("http://127.0.0.1:1", "token"))
    monkeypatch.setattr(cli._LOOPBACK, "open", locked)
    with pytest.raises(client.VaultLocked, match="the vault is locked") as caught:
        client.request("GET", "entries")
    assert caught.value.code == expected


@pytest.mark.parametrize("status, body, exception", [
    (403, {"error": "wrong recovery passphrase", "code": "denied"}, client.VaultClientError),
    (404, {"error": "no entry named 'x' - run `jupyterlab-passkey vault list --json`",
           "code": "entry-not-found"}, client.VaultClientError),
    (400, {"error": "field must be one of password, username", "code": "invalid"},
     client.VaultClientError),
    (423, {"error": "the vault is locked", "code": "locked"}, client.VaultLocked),
    (500, {"error": "the vault broke"}, client.VaultClientError),
])
def test_the_client_carries_the_server_code(monkeypatch, status, body, exception):
    import urllib.error

    def answer(req, timeout):
        raise urllib.error.HTTPError(req.full_url, status, "No", {},
                                     io.BytesIO(json.dumps(body).encode()))

    monkeypatch.setattr(cli, "_found", ("http://127.0.0.1:1", "token"))
    monkeypatch.setattr(cli._LOOPBACK, "open", answer)
    with pytest.raises(exception) as caught:
        client.request("GET", "entries")
    assert caught.value.code == body.get("code")


def test_a_client_error_with_no_code_is_none():
    assert client.VaultClientError("one line").code is None


def test_recovery_needs_the_current_passphrase_not_an_unlock(ready, monkeypatch):
    run(monkeypatch, "vault", "lock")
    ready.calls.clear()
    answers = iter([PASS + "-wrong", "another passphrase", "another passphrase"])
    monkeypatch.setattr(vcli.getpass, "getpass", lambda prompt: next(answers))
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    with pytest.raises(SystemExit, match="wrong recovery passphrase"):
        run(monkeypatch, "vault", "recovery")
    assert ready.calls == []
    with pytest.raises(SystemExit, match="at a terminal or with --in-browser"):
        run(monkeypatch, "vault", "recovery", stdin="another passphrase\n")


NEXT_STEP = (r"vault has no passkey - run `jupyterlab-passkey vault passkey add`, "
             r"or add a method with the cog")


def test_init_names_the_next_step_when_the_passkey_step_fails(server, monkeypatch):
    def refused(command, args, label, message, timeout):
        raise client.VaultClientError("the passkey request was cancelled or not allowed")

    monkeypatch.setattr(vcli, "browser_step", refused)
    with pytest.raises(SystemExit, match=NEXT_STEP):
        run(monkeypatch, "vault", "init", stdin=PASS + "\n")
    assert server.status()["initialized"]


def test_init_names_the_next_step_when_the_passkey_step_is_interrupted(server, monkeypatch):
    def interrupted(command, args, label, message, timeout):
        raise KeyboardInterrupt

    monkeypatch.setattr(vcli, "browser_step", interrupted)
    with pytest.raises(SystemExit, match=NEXT_STEP):
        run(monkeypatch, "vault", "init", stdin=PASS + "\n")
    assert server.status()["initialized"]


def test_copy_says_nothing_comes_back(ready, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_trigger", lambda *a: None)
    run(monkeypatch, "vault", "copy", "github/api")
    assert "nothing is reported back here - the click is what copies it" in capsys.readouterr().err


def test_recovery_replacement(ready, monkeypatch):
    answers = iter([PASS, "another passphrase", "another passphrase"])
    monkeypatch.setattr(vcli.getpass, "getpass", lambda prompt: next(answers))
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    run(monkeypatch, "vault", "recovery")
    run(monkeypatch, "vault", "lock")
    with pytest.raises(SystemExit, match="wrong recovery passphrase"):
        run(monkeypatch, "vault", "unlock", "--recovery", stdin=PASS)
    run(monkeypatch, "vault", "unlock", "--recovery", stdin="another passphrase")
    assert ready.status()["unlocked"]


def test_rotate_replaces_the_data_key_with_the_recovery_proof(ready, monkeypatch, capsys):
    before = ready.holder().get(ready._vault_id())
    run(monkeypatch, "vault", "rotate", stdin=PASS + "\n")
    out, err = capsys.readouterr()
    assert "data key: " in err and "days old" in err and "period 365 days" in err and "not due" in err
    assert ready.holder().get(ready._vault_id()) != before
    assert ready.read("github/api") == SECRET


def test_rotate_needs_an_unlocked_vault(ready, monkeypatch):
    run(monkeypatch, "vault", "lock")
    with pytest.raises(SystemExit, match="the vault is locked - run `jupyterlab-passkey vault unlock`"):
        run(monkeypatch, "vault", "rotate", stdin=PASS + "\n")


def test_rotate_refuses_a_wrong_recovery_proof(ready, monkeypatch):
    before = ready.holder().get(ready._vault_id())
    with pytest.raises(SystemExit, match="wrong recovery passphrase"):
        run(monkeypatch, "vault", "rotate", stdin=PASS + "-wrong\n")
    assert ready.holder().get(ready._vault_id()) == before


# --------------------------------------------------------------------------- #
# errors and the Python API
# --------------------------------------------------------------------------- #


def test_a_missing_vault_is_one_line(server, monkeypatch):
    with pytest.raises(SystemExit, match="no vault at .* vault init"):
        run(monkeypatch, "vault", "list")


def test_a_missing_vault_asks_once_and_creates_it_on_yes(server, monkeypatch):
    answers = iter([PASS, PASS])  # the recovery passphrase, typed twice by init
    monkeypatch.setattr(vcli.getpass, "getpass", lambda prompt: next(answers))
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    monkeypatch.setattr(sys, "stdout", FakeTty())
    asked = []
    monkeypatch.setattr("builtins.input", lambda prompt: asked.append(prompt) or "yes")
    assert run(monkeypatch, "vault", "list") == 0
    assert asked == [f"No vault at {server.status()['path']}. Create it now? [y/N] "]
    assert server.status()["initialized"] is True
    assert server.calls == [client.REGISTER_COMMAND]


def test_the_missing_vault_offer_waits_for_the_passkey_as_init_does(server, monkeypatch):
    waits = []
    stub = vcli.browser_step

    def browser_step(command, args, label, message, timeout, poll=None):
        waits.append((command, timeout))
        return stub(command, args, label, message, timeout)

    monkeypatch.setattr(vcli, "browser_step", browser_step)
    answers = iter([PASS, PASS])
    monkeypatch.setattr(vcli.getpass, "getpass", lambda prompt: next(answers))
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    monkeypatch.setattr(sys, "stdout", FakeTty())
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    # `--timeout` is the wait for `list`'s click; the passkey step of the set-up takes a proof
    # and a name, so it waits 600 s whatever `--timeout` is.
    assert run(monkeypatch, "vault", "list", "--timeout", "30") == 0
    assert waits == [(client.REGISTER_COMMAND, vcli.REGISTER_TIMEOUT)]


# The commands that offer the set-up, as the documents name them, with a run of each;
# `git migrate` offers it too (test_vault_git). Then the ones that refuse it (ruling 13).
OFFERS = [("list", ("list",)), ("get", ("get", "x")), ("add", ("add", "x")),
          ("edit", ("edit", "x", "-u", "y")), ("rm", ("rm", "x")), ("copy", ("copy", "x")),
          ("show", ("show", "x")), ("exec", ("exec", "--env", "A=x", "--", "true")),
          ("import", ("import", "FILE")), ("passkey rm", ("passkey", "rm", "--cred-id", "x"))]
REFUSES = [("unlock", ("unlock",)), ("lock", ("lock",)),
           ("import --pass-cli", ("import", "--pass-cli")), ("passkey add", ("passkey", "add")),
           ("recovery", ("recovery",)), ("rotate", ("rotate",))]
ROOT = pathlib.Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("name, argv, offers", [(*row, True) for row in OFFERS]
                         + [(*row, False) for row in REFUSES], ids=lambda value: str(value))
def test_the_set_up_offer_comes_with_the_commands_the_documents_name(name, argv, offers, server,
                                                                     tmp_path, monkeypatch):
    entries = tmp_path / "entries.json"
    entries.write_text('[{"name": "x", "password": "y"}]')
    argv = tuple(str(entries) if word == "FILE" else word for word in argv)
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    monkeypatch.setattr(sys, "stdout", FakeTty())
    asked = []
    monkeypatch.setattr("builtins.input", lambda prompt: asked.append(prompt) or "n")
    with pytest.raises(SystemExit, match="no vault"):
        run(monkeypatch, "vault", *argv)
    assert bool(asked) is offers
    assert server.status()["initialized"] is False

    for doc in ("docs/cli-reference.md", "README.md"):
        line = next(line for line in (ROOT / doc).read_text().splitlines()
                    if line.startswith(("- **Missing vault** - ", "- **Vault on demand** - ")))
        offering, refusing = re.match(r"- \*\*[^*]+\*\* - (.+?) offer .*?[.;] (.+?) offer nothing",
                                      line).groups()
        assert f"`{name}`" in (offering if offers else refusing), doc


def test_a_missing_vault_is_left_alone_on_no(server, monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    monkeypatch.setattr(sys, "stdout", FakeTty())
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    with pytest.raises(SystemExit, match=r"^no vault at .+ - run `jupyterlab-passkey vault init` \[invalid\]$"):
        run(monkeypatch, "vault", "list")
    assert server.status()["initialized"] is False
    assert server.calls == []


def test_add_offers_the_missing_vault_before_asking_for_the_secret(server, monkeypatch):
    order = []
    answers = iter([PASS, PASS, SECRET, SECRET])  # the recovery passphrase twice, then the password

    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    monkeypatch.setattr(sys, "stdout", FakeTty())
    monkeypatch.setattr("builtins.input", lambda prompt: order.append("create") or "yes")
    monkeypatch.setattr(vcli.getpass, "getpass", lambda prompt: order.append("secret") or next(answers))
    assert run(monkeypatch, "vault", "add", "github/api", "-u", "me",
               "--url", "https://github.com") == 0
    # The set-up offer first: the secret is typed once, after the vault exists.
    assert order == ["create", "secret", "secret", "secret", "secret"]
    assert [entry["name"] for entry in server.list_entries()] == ["github/api"]


def test_edit_checks_the_vault_before_asking_for_the_secret(server, monkeypatch):
    monkeypatch.setattr(vcli, "_new_password",
                        lambda a: pytest.fail("asked for the secret before the set-up offer"))
    a = argparse.Namespace(username=None, url=None, category=None, notes=None,
                           password=True, generate=False, in_browser=False)
    with pytest.raises(client.VaultClientError, match="no vault at"):
        vcli.cmd_edit(a, client.Vault())


def test_a_missing_vault_never_asks_without_a_terminal_on_stdout(server, monkeypatch):
    # A terminal on stdin but not stdout, as `vault get x > file`: no question, no vault.
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("asked on a pipe"))
    with pytest.raises(SystemExit, match="no vault at"):
        run(monkeypatch, "vault", "list")
    assert server.status()["initialized"] is False
    assert server.calls == []


def test_no_server_is_one_line(vault_env, monkeypatch):
    monkeypatch.setattr(cli, "_server", lambda: ("http://127.0.0.1:9", None))
    with pytest.raises(SystemExit, match="cannot reach .* is JupyterLab running"):
        run(monkeypatch, "vault", "status")


def test_python_api(ready):
    vault = client.Vault()
    assert vault.get("github/api") == SECRET
    assert vault.get("github/api", field="url") == "https://github.com"
    assert [e["name"] for e in vault.list()] == ["github/api"]
    vault.lock()
    assert vault.status()["unlocked"] is False
    assert vault.unlock(recovery=PASS)["unlocked"] is True
    rotation = vault.rotate({"current": PASS})["rotation"]
    assert rotation["period_days"] == 365 and rotation["due"] is False


def test_python_api_unlocks_on_demand(ready):
    vault = client.Vault()
    vault.lock()
    ready.calls.clear()
    assert vault.get("github/api") == SECRET
    assert ready.calls == [client.UNLOCK_COMMAND]


def test_the_package_exports_vault():
    from jupyterlab_passkey_extension import vault

    assert vault.Vault is client.Vault


def _help(monkeypatch, capsys, *words):
    monkeypatch.setattr(cli, "_ignore_hangup", lambda: None)
    monkeypatch.setenv("PYTHON_COLORS", "0")
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", *words, "--help"])
    with pytest.raises(SystemExit) as exit_:
        cli.main()
    assert exit_.value.code == 0
    return capsys.readouterr().out


def test_every_vault_subcommand_help_has_a_description_and_examples(monkeypatch, capsys):
    # The agent skill sends an agent to --help first, so each subcommand's help says what
    # it does and prints, and shows it run (ACC-VAULT-186).
    listed = re.compile(r"^    ([a-z]+) ", re.M)
    commands = listed.findall(_help(monkeypatch, capsys, "vault"))
    passkey = listed.findall(_help(monkeypatch, capsys, "vault", "passkey"))
    assert "exec" in commands and "rm" in passkey
    words = [("vault", c) for c in commands if c != "passkey"]
    words += [("vault", "passkey", c) for c in passkey]
    for w in words:
        text = _help(monkeypatch, capsys, *w)
        description = text.split("\n\n")[1]
        examples = text.partition("\nexamples:\n")[2]
        assert description.strip() and "jupyterlab-passkey vault " in examples, w


def test_git_help_says_a_store_value_out_of_reach_gets_its_line(monkeypatch, capsys):
    text = " ".join(_help(monkeypatch, capsys, "vault", "git", "install").split())
    assert "install prints the value as written and the git config command that restores" in text
    text = " ".join(_help(monkeypatch, capsys, "vault", "git", "migrate").split())
    assert "print it as written with the git config command that restores it" in text
    assert "only a plain path, ~ and a set variable" in text


# --------------------------------------------------------------------------- #
# --json: one object on stdout, nothing on stderr
# --------------------------------------------------------------------------- #


def _one(capsys):
    """The one line on stdout as an object, and no stderr beside it."""
    out, err = capsys.readouterr()
    assert err == ""
    assert out.endswith("\n") and out.count("\n") == 1
    return json.loads(out)


@pytest.fixture
def git_home(tmp_path, monkeypatch):
    """A throwaway HOME and git config, so no command reads or writes the real ones."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    return home


def test_init_json_names_the_vault_path(server, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "init", "--no-passkey", "--json", stdin=PASS) == 0
    assert _one(capsys) == {"ok": True, "command": "vault init",
                            "result": {"path": server.status()["path"]}}


def test_status_json_is_the_status_object(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "status", "--json") == 0
    obj = _one(capsys)
    assert obj["ok"] is True and obj["command"] == "vault status"
    assert obj["result"]["initialized"] is True and obj["result"]["unlocked"] is True
    assert obj["result"]["path"].endswith("vault.json")


def test_lock_and_unlock_json(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "lock", "--json") == 0
    assert _one(capsys) == {"ok": True, "command": "vault lock", "result": {"locked": True}}
    assert run(monkeypatch, "vault", "unlock", "--json") == 0
    obj = _one(capsys)
    assert obj["ok"] is True and obj["command"] == "vault unlock"
    assert obj["result"]["unlocked"] is True


def test_list_json_nests_entries_under_result(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "list", "--json") == 0
    obj = _one(capsys)
    assert obj["command"] == "vault list"
    assert [e["name"] for e in obj["result"]["entries"]] == ["github/api"]


def test_get_json_names_field_and_value(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "get", "github/api", "--json") == 0
    assert _one(capsys) == {"ok": True, "command": "vault get",
                            "result": {"name": "github/api", "field": "password",
                                       "value": SECRET}}


def test_add_edit_rm_json(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "add", "nas/ugos", "--json", stdin="p\n") == 0
    assert _one(capsys) == {"ok": True, "command": "vault add",
                            "result": {"added": "nas/ugos"}}
    assert run(monkeypatch, "vault", "edit", "nas/ugos", "--notes", "n", "--json") == 0
    assert _one(capsys) == {"ok": True, "command": "vault edit",
                            "result": {"updated": "nas/ugos"}}
    assert run(monkeypatch, "vault", "rm", "nas/ugos", "--json") == 0
    assert _one(capsys) == {"ok": True, "command": "vault rm",
                            "result": {"removed": "nas/ugos"}}


def test_generate_json_prints_the_value(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "generate", "--length", "16", "--json") == 0
    obj = _one(capsys)
    assert obj["command"] == "vault generate"
    assert len(obj["result"]["value"]) == 16


def test_copy_and_show_json_report_posted(ready, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: None)
    assert run(monkeypatch, "vault", "copy", "github/api", "--json") == 0
    assert _one(capsys) == {"ok": True, "command": "vault copy",
                            "result": {"posted": True, "name": "github/api"}}
    assert run(monkeypatch, "vault", "show", "github/api", "--json") == 0
    assert _one(capsys) == {"ok": True, "command": "vault show",
                            "result": {"posted": True, "name": "github/api"}}


def test_exec_json_captures_the_command(ready, monkeypatch, capsys):
    argv = ["vault", "exec", "--json", "--env", "TOKEN=github/api", "--", sys.executable,
            "-c", "import os, sys; print(os.environ['TOKEN']); print('e', file=sys.stderr)"]
    assert run(monkeypatch, *argv) == 0
    obj = _one(capsys)
    assert obj["command"] == "vault exec"
    assert obj["result"] == {"exit": 0, "stdout": SECRET + "\n", "stderr": "e\n"}


def test_exec_json_keeps_the_childs_exit_status(ready, monkeypatch, capsys):
    argv = ["vault", "exec", "--json", "--", sys.executable, "-c", "import sys; sys.exit(3)"]
    assert run(monkeypatch, *argv) == 3
    obj = _one(capsys)
    assert obj["result"]["exit"] == 3


def test_import_json_counts_what_it_did(ready, monkeypatch, capsys):
    items = [{"name": "new/one", "password": "p"}]
    assert run(monkeypatch, "vault", "import", "--json", stdin=json.dumps(items)) == 0
    obj = _one(capsys)
    assert obj["command"] == "vault import"
    assert obj["result"] == {"added": 1, "skipped": [], "totp": []}


def test_passkey_json_commands(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "passkey", "add", "--json", "--label", "Work laptop") == 0
    assert _one(capsys) == {"ok": True, "command": "vault passkey add",
                            "result": {"added": "passkey"}}
    assert run(monkeypatch, "vault", "passkey", "list", "--json") == 0
    obj = _one(capsys)
    assert obj["command"] == "vault passkey list"
    assert [p["cred_id"] for p in obj["result"]["passkeys"]] == ["cred-1", "cred-2"]
    assert run(monkeypatch, "vault", "passkey", "rm", "--cred-id", "cred-2", "--json") == 0
    assert _one(capsys) == {"ok": True, "command": "vault passkey rm",
                            "result": {"removed": "cred-2"}}


def test_recovery_json_names_what_it_replaced(ready, monkeypatch, capsys):
    _dialogs(monkeypatch)
    assert run(monkeypatch, "vault", "recovery", "--in-browser", "--json") == 0
    assert _one(capsys) == {"ok": True, "command": "vault recovery",
                            "result": {"replaced": "recovery passphrase"}}


def test_rotate_json_returns_the_rotation(ready, monkeypatch, capsys):
    _dialogs(monkeypatch)
    assert run(monkeypatch, "vault", "rotate", "--in-browser", "--json") == 0
    obj = _one(capsys)
    assert obj["command"] == "vault rotate"
    assert obj["result"]["rotation"]["due"] is False


def test_git_uninstall_json_puts_its_lines_in_the_result(git_home, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "git", "uninstall", "--json") == 0
    obj = _one(capsys)
    assert obj["command"] == "vault git uninstall"
    assert obj["result"]["lines"] == [
        "credential.helper = jupyterlab-passkey is not set in the global git config"]


def test_git_migrate_dry_run_json_puts_its_lines_in_the_result(git_home, ready, monkeypatch, capsys):
    store = git_home / ".git-credentials"
    store.write_text("https://me:secret@github.com\n")
    assert run(monkeypatch, "vault", "git", "migrate", "--dry-run", "--json") == 0
    lines = _one(capsys)["result"]["lines"]
    assert f"read {store}" in lines
    assert "git/me@github.com\tgithub.com" in lines


def test_aws_uninstall_json_puts_its_lines_in_the_result(tmp_path, monkeypatch, capsys):
    path = tmp_path / "aws" / "config"
    monkeypatch.setenv("AWS_CONFIG_FILE", str(path))
    assert run(monkeypatch, "vault", "aws", "uninstall", "work", "--json") == 0
    obj = _one(capsys)
    assert obj["command"] == "vault aws uninstall"
    assert obj["result"]["lines"] == [f"no AWS config at {path}"]


def test_json_failure_names_the_no_vault_code(server, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "list", "--json") == 1
    obj = _one(capsys)
    assert obj["ok"] is False and obj["command"] == "vault list"
    assert obj["code"] == "no-vault" and obj["error"].startswith("no vault at ")


def test_json_failure_names_the_entry_not_found_code(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "get", "missing/entry", "--json") == 1
    obj = _one(capsys)
    assert obj["ok"] is False and obj["code"] == "entry-not-found"
    assert "missing/entry" in obj["error"]


def test_json_failure_names_the_locked_code(ready, monkeypatch, capsys):
    run(monkeypatch, "vault", "lock")
    capsys.readouterr()
    assert run(monkeypatch, "vault", "rotate", "--json") == 1
    obj = _one(capsys)
    assert obj["ok"] is False and obj["code"] == "locked"


def test_json_failure_names_the_no_server_code(monkeypatch, capsys):
    def no_server():
        raise cli.Fail("no server found - start JupyterLab", "no-server")

    monkeypatch.setattr(cli, "_server", no_server)
    assert run(monkeypatch, "vault", "status", "--json") == 1
    obj = _one(capsys)
    assert obj["ok"] is False and obj["code"] == "no-server"


def test_json_failure_names_the_usage_code(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "edit", "github/api", "--json") == 1
    obj = _one(capsys)
    assert obj["ok"] is False and obj["code"] == "usage"
    assert obj["error"].startswith("nothing to change")


def test_a_set_up_question_goes_to_stderr_with_json(server, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda: "n")
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "vault", "list", "--json"])
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    assert cli.main() == 1
    out, err = capsys.readouterr()
    assert "Create it now?" in err
    assert json.loads(out)["code"] == "no-vault"
