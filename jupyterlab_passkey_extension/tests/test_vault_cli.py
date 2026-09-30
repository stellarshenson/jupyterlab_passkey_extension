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

import pytest

from jupyterlab_passkey_extension import cli
from jupyterlab_passkey_extension.vault import client, handlers, holders, service
from jupyterlab_passkey_extension.vault import cli as vcli
from jupyterlab_passkey_extension.vault.store import VaultError

PASS = "correct horse battery staple"
PRF = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
SECRET = "tok-MUST-NOT-LEAK-91"


class FakeStdin:
    def __init__(self, text, tty=False):
        self.buffer = io.BytesIO(text.encode())
        self._tty = tty

    def isatty(self):
        return self._tty

    def read(self):
        return self.buffer.read().decode()


@pytest.fixture
def server(vault_env, monkeypatch):
    svc = handlers._service
    calls = []

    def request(method, action, body=None, params=None):
        table = {"GET": handlers._GET, "POST": handlers._POST, "PATCH": handlers._PATCH}[method]
        arg = (params or {}) if method == "GET" else (body or {})
        try:
            return table[action](svc, arg)
        except service.Locked as e:
            raise client.VaultLocked(str(e))
        except VaultError as e:
            raise client.VaultClientError(str(e))

    def browser_step(command, args, label, message, timeout):
        calls.append(command)
        if command == client.REGISTER_COMMAND:
            n = len(svc.status()["slots"])  # the recovery slot is one: cred-1, then cred-2
            # The page sends a proof; here the recovery passphrase.
            svc.add_passkey(f"cred-{n}", "lab.example", "c2FsdA", PRF, args.get("label") or None,
                            {"current": PASS})
        elif command == client.UNLOCK_COMMAND:
            svc.unlock_passkey("cred-1", PRF)

    for module in (client, vcli):
        monkeypatch.setattr(module, "request", request)
        monkeypatch.setattr(module, "browser_step", browser_step)
    svc.calls = calls
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
    assert f"vault created at {server.status()['path']};" in capsys.readouterr().err
    slots = server.status()["slots"]
    assert [s["type"] for s in slots] == ["recovery", "passkey"]
    assert server.calls == [client.REGISTER_COMMAND]


def test_init_without_a_passkey(server, monkeypatch):
    assert run(monkeypatch, "vault", "init", "--no-passkey", stdin=PASS) == 0
    assert [s["type"] for s in server.status()["slots"]] == ["recovery"]


def test_a_vault_without_a_passkey_names_the_recovery_unlock(server, monkeypatch):
    # No notification for a passkey the vault does not have: unlock and get stop at once.
    run(monkeypatch, "vault", "init", "--no-passkey", stdin=PASS)
    run(monkeypatch, "vault", "lock")
    server.calls.clear()
    for argv in (("vault", "unlock"), ("vault", "get", "github/api")):
        with pytest.raises(SystemExit, match="vault unlock --recovery"):
            run(monkeypatch, *argv)
    assert server.calls == []


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


def test_lock_and_unlock_with_passkey_and_recovery(ready, monkeypatch, capsys):
    run(monkeypatch, "vault", "lock")
    assert ready.status()["unlocked"] is False
    run(monkeypatch, "vault", "unlock")
    assert ready.status()["unlocked"] is True
    run(monkeypatch, "vault", "lock")
    run(monkeypatch, "vault", "unlock", "--recovery", stdin=PASS + "\n")
    assert ready.status()["unlocked"] is True
    assert "vault unlocked" in capsys.readouterr().err


def test_status_prints_state_holder_and_capabilities(ready, monkeypatch, capsys):
    run(monkeypatch, "vault", "status")
    out = capsys.readouterr().out
    assert "state: unlocked, 3h 59m left" in out or "state: unlocked, 4h 0m left" in out
    assert "holder: memory/" in out and "this extension's own code" in out
    assert "protection: " in out
    # The detail the panel keeps in tooltips: one line per capability, explained.
    assert "  Expires on its own: no - a timer in the Jupyter server" in out
    rows = [line for line in out.splitlines() if ": yes - " in line or ": no - " in line]
    assert len(rows) == len(holders.CAPABILITY_TEXT)
    assert "passkeys: 1" in out and "@ lab.example" in out
    assert "unlock duration: 4h" in out


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
    run(monkeypatch, "vault", "get", "github/api")
    assert ready.calls == [client.UNLOCK_COMMAND]
    assert capsys.readouterr().out == SECRET + "\n"


def test_list_hides_passwords_and_filters(ready, monkeypatch, capsys):
    run(monkeypatch, "vault", "add", "nas/ugos", "-c", "home", stdin="p\n")
    capsys.readouterr()
    run(monkeypatch, "vault", "list")
    out = capsys.readouterr().out
    assert "github/api\tme\tinfra\thttps://github.com" in out and SECRET not in out
    run(monkeypatch, "vault", "list", "--category", "home", "--json")
    assert [e["name"] for e in json.loads(capsys.readouterr().out)] == ["nas/ugos"]


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


# --------------------------------------------------------------------------- #
# copy, show, exec
# --------------------------------------------------------------------------- #


def test_copy_stages_on_the_server_and_the_value_never_reaches_the_cli(ready, monkeypatch, capsys, vault_env):
    seen = []
    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: seen.append((c, a, l, m)))
    run(monkeypatch, "vault", "copy", "github/api")
    [(command, args, label, message)] = seen
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
                       match="the vault is not loaded on this Jupyter server - restart the server"):
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


def test_init_names_the_next_step_when_the_passkey_step_fails(server, monkeypatch):
    def refused(command, args, label, message, timeout):
        raise client.VaultClientError("the passkey request was cancelled or not allowed")

    monkeypatch.setattr(vcli, "browser_step", refused)
    with pytest.raises(SystemExit, match="vault exists without a passkey - run `jupyterlab-passkey vault passkey add`"):
        run(monkeypatch, "vault", "init", stdin=PASS + "\n")
    assert server.status()["initialized"]


def test_init_names_the_next_step_when_the_passkey_step_is_interrupted(server, monkeypatch):
    def interrupted(command, args, label, message, timeout):
        raise KeyboardInterrupt

    monkeypatch.setattr(vcli, "browser_step", interrupted)
    with pytest.raises(SystemExit, match="vault exists without a passkey - run `jupyterlab-passkey vault passkey add`"):
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


# --------------------------------------------------------------------------- #
# errors and the Python API
# --------------------------------------------------------------------------- #


def test_a_missing_vault_is_one_line(server, monkeypatch):
    with pytest.raises(SystemExit, match="no vault at .* vault init"):
        run(monkeypatch, "vault", "list")


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
