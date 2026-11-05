"""The vault as git's credential helper, `vault git ...`, and git's plaintext store.

As in test_vault_cli, `client.request` is routed straight into a real VaultService and
the browser steps are stubbed to do what the page does, so the helper runs against a
real vault file. The last test runs the helper as git runs it, over a real HTTP port.
"""

import base64
import http.server
import io
import json
import os
import pathlib
import shlex
import subprocess
import sys
import threading
import time
import urllib.parse

import pytest

from jupyterlab_passkey_extension import cli
from jupyterlab_passkey_extension.vault import client, gitcred, handlers, service, totp
from jupyterlab_passkey_extension.vault import cli as vcli
from jupyterlab_passkey_extension.vault.store import VaultError

PASS = "correct horse battery staple"
PRF = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
SECRET = "s3cret-MUST-NOT-LEAK"
OLDER = "2026-01-01T10:00:00Z"
NEWER = "2026-06-01T10:00:00Z"


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

    def browser_step(command, args, label, message, timeout, poll=None):
        calls.append(command)
        if command == client.REGISTER_COMMAND:
            n = len(svc.status()["slots"])
            svc.add_passkey(f"cred-{n}", "lab.example", "c2FsdA", PRF, args.get("label") or None,
                            {"current": PASS})
            return {"ok": True, "method": "passkey"}
        elif command == client.UNLOCK_COMMAND:
            if args.get("method") == "choose":
                svc.unlock_recovery(PASS)
            else:
                svc.unlock_passkey("cred-1", PRF)

    for module in (client, vcli):
        monkeypatch.setattr(module, "request", request)
        monkeypatch.setattr(module, "browser_step", browser_step)
    svc.calls = calls
    return svc


@pytest.fixture
def git_config(tmp_path, monkeypatch):
    """A throwaway git environment: no test reads or writes a real home git file."""
    path = tmp_path / "gitconfig"
    path.write_text("")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(path))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    return path


REAL_HOME = pathlib.Path.home()
START = subprocess.Popen.__init__


def _sees_the_real_home(env):
    """git in this environment would write ~/.gitconfig or a credential store of the real
    home: its HOME is that home, or its XDG_CONFIG_HOME that home's .config."""
    return (pathlib.Path(env.get("HOME") or REAL_HOME) == REAL_HOME
            or pathlib.Path(env.get("XDG_CONFIG_HOME") or "/") == REAL_HOME / ".config")


def _start_away_from_the_real_home(self, *args, env=None, **kwargs):
    assert not _sees_the_real_home(os.environ if env is None else env), (
        "a test started a process with the real home as HOME or XDG_CONFIG_HOME")
    START(self, *args, env=env, **kwargs)


@pytest.fixture(autouse=True)
def real_home_out_of_reach(monkeypatch):
    """Every process a test starts, git and the helper it runs among them, gets a HOME and
    an XDG_CONFIG_HOME away from the real home, so none can write a real git file. The
    files themselves prove nothing: any other process of this user may write them."""
    monkeypatch.setattr(subprocess.Popen, "__init__", _start_away_from_the_real_home)


def run_vault(monkeypatch, *argv, stdin=None):
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", *argv])
    if stdin is not None:
        monkeypatch.setattr(sys, "stdin", FakeStdin(stdin))
    return cli.main()


@pytest.fixture
def ready(server, monkeypatch, capsys):
    assert run_vault(monkeypatch, "vault", "init", stdin=PASS + "\n") == 0
    capsys.readouterr()
    return server


def add(monkeypatch, capsys, name, url, username="me", password=SECRET):
    assert run_vault(monkeypatch, "vault", "add", name, "-u", username, "--url", url,
                     stdin=password + "\n") == 0
    capsys.readouterr()


def dated(svc, name, url, username, password, updated):
    """An entry with its date of last change, which `vault add` always sets to now."""
    svc.import_entries([{"name": name, "url": url, "username": username, "password": password,
                         "updated": updated}])


def fill(monkeypatch, capsys, attrs, operation="get"):
    capsys.readouterr()
    request = "".join(f"{key}={value}\n" for key, value in attrs.items()) + "\n"
    # A text stream over bytes, as git's pipe is: the helper sets how it decodes them.
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(request.encode())))
    code = gitcred.main([operation])
    out, err = capsys.readouterr()
    return code, out, err


# --------------------------------------------------------------------------- #
# the protocol
# --------------------------------------------------------------------------- #


def test_get_answers_the_entry_for_the_host(ready, git_config, monkeypatch, capsys):
    add(monkeypatch, capsys, "github/api", "https://github.com", password="pw-one")
    code, out, err = fill(monkeypatch, capsys, {"protocol": "https", "host": "GitHub.COM"})
    assert (code, out, err) == (0, "username=me\npassword=pw-one\n", "")


def test_a_bare_host_url_matches(ready, git_config, monkeypatch, capsys):
    add(monkeypatch, capsys, "github/api", "github.com", password="pw-bare")
    assert fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"}) == (
        0, "username=me\npassword=pw-bare\n", "")


def test_a_malformed_url_is_named_and_does_not_stop_the_others(ready, git_config, monkeypatch,
                                                               capsys):
    add(monkeypatch, capsys, "bad/api", "http://[::1", password=SECRET)
    add(monkeypatch, capsys, "github/api", "https://github.com", password="pw-one")
    code, out, err = fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"})
    assert (code, out) == (0, "username=me\npassword=pw-one\n")
    assert err.count("bad/api") == 1
    assert SECRET not in err


def test_a_vault_of_only_malformed_urls_exits_one_with_a_line(ready, git_config, monkeypatch,
                                                              capsys):
    add(monkeypatch, capsys, "bad/api", "http://[::1", password=SECRET)
    code, out, err = fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"})
    assert (code, out) == (1, "")
    assert "bad/api" in err
    assert "Traceback" not in err


def test_a_path_attribute_picks_the_longest_prefix(ready, git_config, monkeypatch, capsys):
    dated(ready, "git/github.com", "https://github.com", "me", "pw-root", OLDER)
    dated(ready, "git/github.com/foo", "https://github.com/foo", "me", "pw-foo", NEWER)
    dated(ready, "git/github.com/foo/bar", "https://github.com/foo/bar", "me", "pw-bar", OLDER)
    # git sends the path without its leading slash, as `git credential fill` does.
    request = {"protocol": "https", "host": "github.com", "path": "foo/bar/baz"}
    assert fill(monkeypatch, capsys, request) == (0, "username=me\npassword=pw-bar\n", "")

    # Without a path attribute git applied no useHttpPath: entry paths are ignored and
    # the three entries count as several, so the newest changed answers.
    assert fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"}) == (
        0, "username=me\npassword=pw-foo\n", "")


def test_both_path_forms_match_the_entry(ready, git_config, monkeypatch, capsys):
    add(monkeypatch, capsys, "git/github.com/org/repo.git", "https://github.com/org/repo.git",
        password="pw-repo")
    for path in ("org/repo.git", "/org/repo.git"):
        assert fill(monkeypatch, capsys,
                    {"protocol": "https", "host": "github.com", "path": path}) == (
            0, "username=me\npassword=pw-repo\n", "")


def test_a_path_scoped_entry_is_chosen_with_the_config_unset(ready, git_config, monkeypatch,
                                                             capsys):
    add(monkeypatch, capsys, "git/github.com/org", "https://github.com/org", password="pw-org")
    git_config.write_text("")
    assert fill(monkeypatch, capsys,
                {"protocol": "https", "host": "github.com", "path": "org/repo.git"}) == (
        0, "username=me\npassword=pw-org\n", "")


def test_the_port_is_part_of_the_host(ready, git_config, monkeypatch, capsys):
    add(monkeypatch, capsys, "git/example.com:8443", "https://example.com:8443",
        password="pw-8443")
    add(monkeypatch, capsys, "git/example.com", "https://example.com", password="pw-plain")
    assert fill(monkeypatch, capsys,
                {"protocol": "https", "host": "example.com:8443"}) == (
        0, "username=me\npassword=pw-8443\n", "")
    assert fill(monkeypatch, capsys, {"protocol": "https", "host": "example.com"}) == (
        0, "username=me\npassword=pw-plain\n", "")


def test_no_match_names_the_candidates(ready, git_config, monkeypatch, capsys):
    add(monkeypatch, capsys, "git/github.com/foo", "https://github.com/foo", password=SECRET)
    code, out, err = fill(monkeypatch, capsys,
                          {"protocol": "https", "host": "github.com", "path": "nope"})
    assert (code, out) == (1, "")
    assert "git/github.com/foo" in err
    assert SECRET not in err


def answered(done, username, password):
    assert done.returncode == 0, done.stderr
    assert f"username={username}\npassword={password}\n" in done.stdout


def unanswered(done, secret):
    assert done.returncode != 0
    assert "password=" not in done.stdout
    assert secret not in done.stderr


def test_a_username_with_two_paths_gets_the_line_store_answers(ready, git_config, vault_http,
                                                                tmp_path, monkeypatch, capsys):
    """With useHttpPath off both entries match the username: `store` answers its first
    line, the one written last, and the helper the newest changed entry."""
    source = tmp_path / "credentials"
    approve(source, "https://me:tok-a@git.example.test/a.git")
    approve(source, "https://me:tok-b@git.example.test/b.git")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    store = subprocess.run(["git", "credential-store", "--file", str(source), "get"], text=True,
                           input="protocol=https\nhost=git.example.test\nusername=me\n\n",
                           capture_output=True, timeout=60)
    assert store.stdout == "username=me\npassword=tok-b\n"
    only_the_helper(git_config)
    answered(_git_fill(_git_env(tmp_path, vault_http), "https://me@git.example.test"), "me",
             "tok-b")


def test_a_request_with_no_username_takes_the_newest_changed_entry(ready, git_asks):
    dated(ready, "github/a", "https://github.com", "alice", "pw-old", OLDER)
    dated(ready, "github/b", "https://github.com", "bob", "pw-new", NEWER)
    dated(ready, "github/c", "https://github.com", "carol", "pw-mid", OLDER)
    answered(git_asks("https://github.com"), "bob", "pw-new")

    # The username the request carries picks its own entry, however old.
    answered(git_asks("https://alice@github.com"), "alice", "pw-old")


def test_a_username_picks_its_entry_before_the_longest_path(ready, git_asks, monkeypatch, capsys):
    add(monkeypatch, capsys, "git/root", "https://github.com", "bob", "pw-bob")
    add(monkeypatch, capsys, "git/team", "https://github.com/team", "alice", "pw-alice")
    answered(git_asks("https://bob@github.com/team/repo.git", *HTTP_PATH), "bob", "pw-bob")


def test_a_username_no_entry_has_gets_no_answer(ready, git_asks, monkeypatch, capsys):
    add(monkeypatch, capsys, "github/api", "https://github.com", "alice", SECRET)
    done = git_asks("https://bob@github.com")
    unanswered(done, SECRET)
    assert "no vault entry matches https://github.com" in done.stderr
    assert "github/api" in done.stderr


def test_an_entry_with_no_username_answers_any_username_with_the_password_only(
        ready, git_asks, monkeypatch, capsys):
    add(monkeypatch, capsys, "github/token", "https://github.com", "", "pw-token")
    # git keeps the username it had, so the password goes out under it.
    answered(git_asks("https://oauth2@github.com"), "oauth2", "pw-token")


def test_the_entry_with_the_username_wins_over_one_with_none(ready, git_asks, monkeypatch, capsys):
    add(monkeypatch, capsys, "github/token", "https://github.com", "", "pw-token")
    add(monkeypatch, capsys, "github/alice", "https://github.com", "alice", "pw-alice")
    answered(git_asks("https://alice@github.com"), "alice", "pw-alice")


def test_no_username_on_either_side_invents_none_and_names_the_entry(ready, git_asks, monkeypatch,
                                                                     capsys):
    add(monkeypatch, capsys, "github/token", "https://github.com", "", SECRET)
    done = git_asks("https://github.com")
    unanswered(done, SECRET)
    assert "username=\n" not in done.stdout
    assert "github/token" in done.stderr and "have no username" in done.stderr


def test_store_and_erase_write_nothing(ready, git_config, monkeypatch, capsys):
    attrs = {"protocol": "https", "host": "github.com", "username": "me", "password": SECRET}
    for operation in ("store", "erase"):
        assert fill(monkeypatch, capsys, attrs, operation=operation) == (1, "", "")
    code, out, err = fill(monkeypatch, capsys, attrs, operation="lookup")
    assert (code, out) == (1, "")
    assert "usage" in err


def test_a_locked_vault_unlocks_once_and_answers(ready, git_config, monkeypatch, capsys):
    add(monkeypatch, capsys, "github/api", "https://github.com", password="pw-one")
    ready.lock()
    ready.calls.clear()
    assert fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"}) == (
        0, "username=me\npassword=pw-one\n", "")
    assert ready.calls == [client.UNLOCK_COMMAND]


def test_a_locked_vault_that_times_out_names_the_wait(ready, git_config, monkeypatch, capsys):
    add(monkeypatch, capsys, "github/api", "https://github.com", password=SECRET)
    ready.lock()

    def timeout(command, args, label, message, seconds, poll=None):
        raise client.NoClick(
            f"no relay after {seconds:.0f}s - was the button clicked and the prompt approved?")

    monkeypatch.setattr(client, "browser_step", timeout)
    code, out, err = fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"})
    assert (code, out) == (1, "")
    assert "the vault is locked" in err
    assert "120s" in err
    assert "`jupyterlab-passkey vault unlock`" in err
    assert SECRET not in err


# --------------------------------------------------------------------------- #
# the ignore variable
# --------------------------------------------------------------------------- #


def test_the_ignore_variable_answers_no_credential_and_touches_nothing(
        ready, git_config, monkeypatch, capsys):
    add(monkeypatch, capsys, "github/api", "https://github.com", password="pw-one")
    requests, steps = [], []
    monkeypatch.setattr(client, "request", lambda *args, **kwargs: requests.append(args))
    monkeypatch.setattr(client, "browser_step", lambda *args, **kwargs: steps.append(args))
    monkeypatch.setenv("JUPYTERLAB_PASSKEY_GIT_IGNORE_VAULT", "1")
    assert fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"}) == (0, "", "")
    assert (requests, steps) == ([], [])


@pytest.mark.parametrize("value", [None, "0", "", "true"])
def test_any_other_ignore_value_leaves_the_helper_unchanged(
        value, ready, git_config, monkeypatch, capsys):
    add(monkeypatch, capsys, "github/api", "https://github.com", password="pw-one")
    if value is None:
        monkeypatch.delenv("JUPYTERLAB_PASSKEY_GIT_IGNORE_VAULT", raising=False)
    else:
        monkeypatch.setenv("JUPYTERLAB_PASSKEY_GIT_IGNORE_VAULT", value)
    assert fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"}) == (
        0, "username=me\npassword=pw-one\n", "")


# --------------------------------------------------------------------------- #
# first set-up from git
# --------------------------------------------------------------------------- #


def _stub_setup(monkeypatch, server, calls):
    """What the page does for the set-up step: create the vault and its passkey, and
    add the entry this request needs so the helper has an answer to give."""
    def browser_step(command, args, label, message, timeout, poll=None):
        calls.append(command)
        assert command == client.SETUP_COMMAND
        server.init(PASS)
        server.add_passkey("cred-1", "lab.example", "c2FsdA", PRF, None, {"current": PASS})
        server.add("github/api", {"password": "pw-one", "username": "me",
                                  "url": "https://github.com"})

    monkeypatch.setattr(client, "browser_step", browser_step)


GITHUB = {"protocol": "https", "host": "github.com"}
ANSWER = (0, "username=me\npassword=pw-one\n", "")


def test_no_vault_sets_up_in_the_browser_then_answers(server, git_config, monkeypatch, capsys):
    calls = []
    _stub_setup(monkeypatch, server, calls)
    assert fill(monkeypatch, capsys, GITHUB) == ANSWER
    # One browser step, and the credential is answered after it.
    assert calls == [client.SETUP_COMMAND]


def test_later_in_the_set_up_goes_on_to_the_lookup(server, git_config, monkeypatch, capsys):
    def browser_step(command, args, label, message, timeout, poll=None):
        # Later: the page made the vault and added no method.
        server.init(PASS)
        server.add("github/api", {"password": "pw-one", "username": "me",
                                  "url": "https://github.com"})

    monkeypatch.setattr(client, "browser_step", browser_step)
    assert fill(monkeypatch, capsys, GITHUB) == ANSWER
    assert [s["type"] for s in server.status()["slots"]] == ["recovery"]


def _vault_with(monkeypatch, capsys, server, method):
    """A vault with one entry whose unlock methods are the recovery slot and `method`."""
    assert run_vault(monkeypatch, "vault", "init", "--no-passkey", stdin=PASS + "\n") == 0
    capsys.readouterr()
    if method == "pair":
        app = bytes(range(40, 60))
        step = int(time.time()) // totp.STEP
        server.add_mfa("an everyday password", base64.b32encode(app).decode(),
                       totp.code(app, step), {"current": PASS})
    elif method == "passkey":
        server.add_passkey("cred-1", "lab.example", "c2FsdA", PRF, None, {"current": PASS})
    server.add("github/api", {"password": "pw-one", "username": "me",
                              "url": "https://github.com"})


def _record_steps(monkeypatch, step=None):
    raised = []

    def browser_step(command, args, label, message, timeout, poll=None):
        raised.append((command, args))
        if step:
            step()

    monkeypatch.setattr(client, "browser_step", browser_step)
    return raised


METHODS = [("recovery", {"method": "choose"}), ("pair", {"method": "choose"}), ("passkey", {})]


@pytest.mark.parametrize("method, args", METHODS, ids=[row[0] for row in METHODS])
def test_a_locked_vault_goes_the_normal_unlock_way_with_any_method(server, git_config, monkeypatch,
                                                                   capsys, method, args):
    _vault_with(monkeypatch, capsys, server, method)
    server.lock()
    raised = _record_steps(monkeypatch, lambda: server.unlock_recovery(PASS))
    assert fill(monkeypatch, capsys, GITHUB) == ANSWER
    # The unlock chooser or the passkey, one notification, and no set-up.
    assert raised == [(client.UNLOCK_COMMAND, args)]


@pytest.mark.parametrize("method", [row[0] for row in METHODS])
def test_an_unlocked_vault_answers_with_no_notification_with_any_method(server, git_config,
                                                                        monkeypatch, capsys, method):
    _vault_with(monkeypatch, capsys, server, method)
    raised = _record_steps(monkeypatch)
    assert fill(monkeypatch, capsys, GITHUB) == ANSWER
    assert raised == []


CANCELLED = ("ceremony failed: recovery passphrase step was cancelled - rerun the command "
             "to continue")


def test_a_cancelled_set_up_names_the_step_and_prints_no_secret(server, git_config, monkeypatch,
                                                               capsys):
    def browser_step(command, args, label, message, timeout, poll=None):
        raise client.VaultClientError(CANCELLED)

    monkeypatch.setattr(client, "browser_step", browser_step)
    code, out, err = fill(monkeypatch, capsys, GITHUB)
    assert (code, out) == (1, "")
    assert err.count("\n") == 1
    assert "recovery passphrase step" in err and "cancelled" in err
    assert "rerun the command" in err
    assert SECRET not in err
    assert server.status()["initialized"] is False


def test_a_second_run_after_a_cancel_completes(server, git_config, monkeypatch, capsys):
    calls = []

    def cancelled(command, args, label, message, timeout, poll=None):
        calls.append(command)
        raise client.VaultClientError(CANCELLED)

    monkeypatch.setattr(client, "browser_step", cancelled)
    code, out, err = fill(monkeypatch, capsys, GITHUB)
    assert (code, out) == (1, "")
    assert "recovery passphrase step" in err
    _stub_setup(monkeypatch, server, calls)
    assert fill(monkeypatch, capsys, GITHUB) == ANSWER
    assert calls == [client.SETUP_COMMAND, client.SETUP_COMMAND]


def test_a_set_up_nobody_answers_names_init_and_refuses_later_runs_at_once(
        server, git_config, monkeypatch, capsys):
    raised = []

    def nobody(command, args, label, message, timeout, poll=None):
        raised.append((command, timeout))
        raise client.NoClick(f"no relay after {timeout:.0f}s")

    monkeypatch.setattr(client, "browser_step", nobody)
    for _ in range(2):
        code, out, err = fill(monkeypatch, capsys, GITHUB)
        assert (code, out) == (1, "")
        assert f"no vault yet - nobody answered within {vcli.REGISTER_TIMEOUT:.0f}s" in err
        assert "`jupyterlab-passkey vault init`" in err
    assert raised == [(client.SETUP_COMMAND, vcli.REGISTER_TIMEOUT)]


def test_a_vault_made_during_the_wait_is_no_failure(server, git_config, monkeypatch, capsys):
    def nobody_here(command, args, label, message, timeout, poll=None):
        # The notification stands unclicked: the panel made the vault meanwhile.
        server.init(PASS)
        server.add("github/api", {"password": "pw-one", "username": "me",
                                  "url": "https://github.com"})
        raise client.NoClick("no relay")

    monkeypatch.setattr(client, "browser_step", nobody_here)
    assert fill(monkeypatch, capsys, GITHUB) == ANSWER


# --------------------------------------------------------------------------- #
# vault git install, uninstall and migrate
# --------------------------------------------------------------------------- #


def test_install_and_uninstall_are_idempotent(git_config, monkeypatch, capsys):
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    assert git_config.read_text().count("helper = jupyterlab-passkey") == 1
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    assert git_config.read_text().count("helper = jupyterlab-passkey") == 1
    assert run_vault(monkeypatch, "vault", "git", "uninstall") == 0
    assert "jupyterlab-passkey" not in git_config.read_text()
    assert run_vault(monkeypatch, "vault", "git", "uninstall") == 0
    assert "not set" in capsys.readouterr().err


def _helpers(git_config):
    return [line.strip().partition("=")[2].strip() for line in git_config.read_text().splitlines()
            if line.strip().startswith("helper")]


def test_install_keeps_the_other_helpers_behind_ours(git_config, monkeypatch):
    git_config.write_text("[credential]\n\thelper = cache --timeout=60\n\thelper = manager\n")
    for _ in range(2):
        assert run_vault(monkeypatch, "vault", "git", "install") == 0
        assert _helpers(git_config) == ["jupyterlab-passkey", "cache --timeout=60", "manager"]


def test_install_goes_after_the_last_empty_helper(git_config, monkeypatch):
    # An empty value resets git's helper list: everything before it is discarded.
    git_config.write_text("[credential]\n\thelper =\n\thelper = cache\n")
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    assert _helpers(git_config) == ["", "jupyterlab-passkey", "cache"]


def test_uninstall_removes_every_one_of_ours_and_leaves_the_others(git_config, monkeypatch):
    git_config.write_text("[credential]\n\thelper = store\n\thelper = jupyterlab-passkey\n"
                          "\thelper = jupyterlab-passkey\n\thelper = cache\n")
    assert run_vault(monkeypatch, "vault", "git", "uninstall") == 0
    assert _helpers(git_config) == ["store", "cache"]


def test_uninstall_local_acts_on_the_repository_config(git_config, tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.chdir(repo)
    local = repo / ".git" / "config"
    assert run_vault(monkeypatch, "vault", "git", "install", "--local") == 0
    assert "jupyterlab-passkey" in local.read_text()
    assert "jupyterlab-passkey" not in git_config.read_text()
    assert run_vault(monkeypatch, "vault", "git", "uninstall", "--local") == 0
    assert "jupyterlab-passkey" not in local.read_text()


def _store(git_config, source):
    git_config.write_text(f"[credential]\n\thelper = store --file {source}\n")


def test_migrate_creates_entries_and_skips_existing(ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    source.write_text("https://alice:p%40ss@github.com\n"
                      "https://bob:pw-TWO@gitlab.example/team/repo.git\n")
    _store(git_config, source)

    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    err = capsys.readouterr().err
    assert str(source) in err and f"rm {source}" in err
    assert "p%40ss" not in err and "pw-TWO" not in err

    entries = {e["name"]: e for e in ready.list_entries()}
    assert set(entries) == {"git/alice@github.com", "git/bob@gitlab.example/team/repo.git"}
    assert entries["git/alice@github.com"]["url"] == "https://github.com"
    assert entries["git/alice@github.com"]["username"] == "alice"
    assert entries["git/alice@github.com"]["category"] == "git"
    assert ready.read("git/alice@github.com") == "p@ss"
    assert ready.read("git/bob@gitlab.example/team/repo.git") == "pw-TWO"

    # A second run skips every existing name and never overwrites it.
    source.write_text("https://alice:changed@github.com\n"
                      "https://bob:changed@gitlab.example/team/repo.git\n")
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert "skipped 2" in capsys.readouterr().err
    assert ready.read("git/alice@github.com") == "p@ss"
    assert ready.read("git/bob@gitlab.example/team/repo.git") == "pw-TWO"


def test_migrate_imports_two_accounts_on_one_host(ready, git_config, tmp_path, monkeypatch,
                                                  capsys):
    source = tmp_path / "credentials"
    source.write_text("https://alice:pw-A@github.com\n"
                      "https://bob:pw-B@github.com\n")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    err = capsys.readouterr().err
    assert "added 2 entries" in err and "skipped" not in err
    assert {e["name"] for e in ready.list_entries()} == {
        "git/alice@github.com", "git/bob@github.com"}
    assert ready.read("git/alice@github.com") == "pw-A"
    assert ready.read("git/bob@github.com") == "pw-B"


def test_migrate_accepts_the_equals_file_spelling(ready, git_config, tmp_path, monkeypatch,
                                                  capsys):
    source = tmp_path / "credentials"
    source.write_text("https://alice:pw-ONE@github.com\n")
    git_config.write_text(f"[credential]\n\thelper = store --file={source}\n")
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    err = capsys.readouterr().err
    assert str(source) in err
    assert {e["name"] for e in ready.list_entries()} == {"git/alice@github.com"}


def test_migrate_reads_the_home_store_then_the_xdg_store(ready, git_config, tmp_path,
                                                         monkeypatch, capsys):
    monkeypatch.delenv("XDG_CONFIG_HOME")
    home = tmp_path / ".git-credentials"
    home.write_text("https://alice:pw-ONE@github.com\n")
    xdg = tmp_path / ".config" / "git" / "credentials"
    xdg.parent.mkdir(parents=True)
    xdg.write_text("https://bob:pw-TWO@gitlab.example\n")
    git_config.write_text("[credential]\n\thelper = store\n")
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    err = capsys.readouterr().err
    assert err.index(str(home)) < err.index(str(xdg))
    assert {e["name"] for e in ready.list_entries()} == {
        "git/alice@github.com", "git/bob@gitlab.example"}
    assert ready.read("git/alice@github.com") == "pw-ONE"
    assert ready.read("git/bob@gitlab.example") == "pw-TWO"


def test_migrate_names_include_the_port(ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    approve(source, "https://alice:pw-ONE@example.com:8443/repo.git")
    approve(source, "https://bob:pw-TWO@example.com/repo.git")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert "added 2 entries" in capsys.readouterr().err
    assert {e["name"] for e in ready.list_entries()} == {
        "git/alice@example.com:8443/repo.git", "git/bob@example.com/repo.git"}


def test_migrate_dry_run_writes_nothing(ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    source.write_text("https://alice:p%40ss@github.com\n"
                      "https://bob:pw-TWO@gitlab.example/team/repo.git\n")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run") == 0
    out, err = capsys.readouterr()
    assert "git/alice@github.com\tgithub.com" in out
    assert "git/bob@gitlab.example/team/repo.git\tgitlab.example" in out
    assert "p%40ss" not in out + err and "pw-TWO" not in out + err
    assert ready.list_entries() == []


def test_migrate_remove_source_keeps_the_file_when_a_line_was_skipped(
        ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    source.write_text("https://alice:pw-ONE@github.com\n"
                      "https://bob:pw-TWO@gitlab.example\n")
    _store(git_config, source)
    add(monkeypatch, capsys, "git/alice@github.com", "https://github.com", "alice")
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    monkeypatch.setattr(sys, "stdout", FakeTty())
    # With a skipped line there is nothing to ask: no answer could delete the file.
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("asked to remove"))
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source",
                     "--no-install") == 0
    err = capsys.readouterr().err
    assert source.exists()
    assert "the skipped lines already have a vault entry" in err
    assert f"rm {source}" not in err


def test_migrate_remove_source_removes_the_file_when_nothing_was_skipped(
        ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    source.write_text("https://alice:pw-ONE@github.com\n")
    _store(git_config, source)
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    monkeypatch.setattr(sys, "stdout", FakeTty())
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source",
                     "--no-install") == 0
    err = capsys.readouterr().err
    assert not source.exists()
    assert "removed git's plaintext store" in err
    assert "rm " not in err


def test_migrate_remove_source_retires_the_store_helper_so_git_does_not_recreate_it(
        ready, git_config, vault_http, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    source.write_text("https://alice:pw-ONE@github.com\n")
    _store(git_config, source)
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    monkeypatch.setattr(sys, "stdout", FakeTty())
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source") == 0
    err = capsys.readouterr().err
    assert not source.exists()
    assert "removed credential.helper = store --file" in err
    # A store helper left behind would write the credential back in plaintext.
    done = subprocess.run(
        ["git", "credential", "approve"], env=_git_env(tmp_path, vault_http), text=True,
        timeout=60, capture_output=True,
        input="protocol=https\nhost=github.com\nusername=me\npassword=pw-approve\n\n")
    assert done.returncode == 0, done.stderr
    assert not source.exists()


def test_migrate_remove_source_keeps_the_file_a_store_in_another_scope_reads(
        ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    source.write_text("https://alice:pw-ONE@github.com\n")
    _store(git_config, source)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "--local", "credential.helper",
                    f"store --file {source}"], check=True)
    monkeypatch.chdir(repo)
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    monkeypatch.setattr(sys, "stdout", FakeTty())
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source",
                     "--no-install") == 0
    err = capsys.readouterr().err
    assert source.exists()
    assert "removed credential.helper = store --file" in err
    assert f"store --file {source}" in err
    assert "in another git config still reads it" in err
    assert f"rm {source}" not in err


def test_migrate_asks_for_a_missing_vault_once(server, git_config, tmp_path, monkeypatch):
    source = tmp_path / "credentials"
    source.write_text("https://alice:pw-ONE@github.com\n")
    _store(git_config, source)
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    monkeypatch.setattr(sys, "stdout", FakeTty())
    asked = []
    monkeypatch.setattr("builtins.input", lambda prompt: asked.append(prompt) or "n")
    with pytest.raises(SystemExit, match="no vault at"):
        run_vault(monkeypatch, "vault", "git", "migrate", "--no-install")
    # The one answer is honoured: run()'s offer is not repeated by the command.
    assert asked == [f"No vault at {tmp_path / 'vault' / 'vault.json'}. Create it now? [y/N] "]


def test_git_commands_say_git_is_missing_without_a_traceback(git_config, tmp_path, monkeypatch):
    empty = tmp_path / "bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    for argv in (("vault", "git", "install"), ("vault", "git", "migrate", "--no-install")):
        with pytest.raises(SystemExit, match="^git is not on PATH$"):
            run_vault(monkeypatch, *argv)


# --------------------------------------------------------------------------- #
# the helper as git runs it
# --------------------------------------------------------------------------- #


class _VaultHTTP(http.server.BaseHTTPRequestHandler):
    """The vault's action tables over HTTP, for a helper in another process."""

    svc = None

    def log_message(self, *args):
        pass

    def _answer(self, status, result):
        payload = b"" if result is None else json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _serve(self, method):
        split = urllib.parse.urlsplit(self.path)
        action = split.path.rstrip("/").rsplit("/", 1)[-1]
        args = dict(urllib.parse.parse_qsl(split.query))
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = json.loads(raw) if raw else {}
        try:
            if method == "GET":
                result = handlers._GET[action](self.svc, args)
            elif method == "POST":
                result = handlers._POST[action](self.svc, body)
            else:
                result = handlers._PATCH[action](self.svc, body)
        except service.Locked as e:
            return self._answer(423, {"error": str(e)})
        except VaultError as e:
            return self._answer(400, {"error": str(e)})
        self._answer(204 if result is None else 200, result)

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")

    def do_PATCH(self):
        self._serve("PATCH")


@pytest.fixture
def vault_http(server):
    _VaultHTTP.svc = server
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _VaultHTTP)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def _git_env(tmp_path, port):
    """PATH with the installed helper and a stub jupyter, talking to the test vault."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    helper = bindir / "git-credential-jupyterlab-passkey"
    helper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable)
                      + " -m jupyterlab_passkey_extension.vault.gitcred \"$@\"\n")
    helper.chmod(0o755)
    # `jupyter server list` must find no server: JUPYTER_PORT names the test one.
    fake = bindir / "jupyter"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{bindir}{os.pathsep}{env['PATH']}"
    env["JUPYTER_PORT"] = str(port)
    env["HOME"] = str(tmp_path)
    env["GIT_TERMINAL_PROMPT"] = "0"
    root = str(pathlib.Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = os.pathsep.join(p for p in (root, env.get("PYTHONPATH")) if p)
    return env


def _git_fill(env, url="https://github.com", *config):
    return subprocess.run(["git", *config, "credential", "fill"], env=env, text=True, timeout=60,
                          input=f"url={url}\n\n", capture_output=True)


@pytest.fixture
def git_asks(ready, git_config, vault_http, tmp_path):
    """Real `git credential fill`, with the vault helper alone to answer it."""
    git_config.write_text("[credential]\n\thelper = jupyterlab-passkey\n")
    env = _git_env(tmp_path, vault_http)
    return lambda url, *config: _git_fill(env, url, *config)


def test_the_helper_answers_git_credential_fill(ready, git_config, vault_http, tmp_path,
                                                monkeypatch, capsys):
    add(monkeypatch, capsys, "github/api", "https://github.com", password="pw-one")
    git_config.write_text("[credential]\n\thelper = jupyterlab-passkey\n")
    done = _git_fill(_git_env(tmp_path, vault_http))
    assert done.returncode == 0, done.stderr
    assert "username=me" in done.stdout and "password=pw-one" in done.stdout


def test_install_after_an_empty_helper_reaches_git(ready, git_config, vault_http, tmp_path,
                                                   monkeypatch, capsys):
    add(monkeypatch, capsys, "github/api", "https://github.com", password="pw-one")
    git_config.write_text("[credential]\n\thelper =\n\thelper = store\n")
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    assert _helpers(git_config) == ["", "jupyterlab-passkey"]
    done = _git_fill(_git_env(tmp_path, vault_http))
    assert done.returncode == 0, done.stderr
    assert "password=pw-one" in done.stdout


# --------------------------------------------------------------------------- #
# what real git writes to its store and asks the helper
# --------------------------------------------------------------------------- #


def approve(source, url):
    """Let real git write this credential's line to `source`: `url` carries the username
    and password. Any line a test could type by hand can differ from git's."""
    helper = f"credential.helper=store --file {shlex.quote(str(source))}"
    done = subprocess.run(["git", "-c", helper, "-c", "credential.useHttpPath=true",
                           "credential", "approve"],
                          text=True, timeout=60, input=f"url={url}\n\n", capture_output=True)
    assert done.returncode == 0, done.stderr


def only_the_helper(git_config):
    """The vault helper alone: a store behind it would answer for it and hide a failure."""
    git_config.write_text("[credential]\n\thelper = jupyterlab-passkey\n")


def at_a_terminal(monkeypatch, answer="y"):
    monkeypatch.setattr(sys, "stdin", FakeStdin("", tty=True))
    monkeypatch.setattr(sys, "stdout", FakeTty())
    monkeypatch.setattr("builtins.input", lambda prompt: answer)


def values():
    """Every credential.helper value git reads, as git reads them, by key."""
    done = subprocess.run(["git", "config", "--get-regexp", r"^credential\..*helper$"],
                          text=True, capture_output=True)
    return [tuple(line.split(" ", 1)) for line in done.stdout.splitlines()]


HTTP_PATH = ("-c", "credential.useHttpPath=true")


@pytest.mark.parametrize("line, name, url, request_url", [
    ("https://alice:tok-one@git.example.test:8443", "git/alice@git.example.test:8443",
     "https://git.example.test:8443", "https://git.example.test:8443"),
    ("https://bob:tok-path@path.example.test/team/re%20po.git",
     "git/bob@path.example.test/team/re po.git",
     "https://path.example.test/team/re%20po.git",
     "https://path.example.test/team/re%20po.git"),
    ("https://carol:tok-six@[::1]:8443", "git/carol@[::1]:8443", "https://[::1]:8443",
     "https://[::1]:8443"),
])
def test_a_migrated_host_answers_git_after_the_store_is_gone(
        line, name, url, request_url, ready, git_config, vault_http, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    approve(source, line)
    assert "%" in source.read_text().partition("@")[2]  # what git really writes
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    entry = next(e for e in ready.list_entries() if e["name"] == name)
    assert entry["url"] == url
    only_the_helper(git_config)
    done = _git_fill(_git_env(tmp_path, vault_http), request_url, *HTTP_PATH)
    assert done.returncode == 0, done.stderr
    assert f"username={entry['username']}\n" in done.stdout
    assert ready.read(name) in done.stdout


@pytest.mark.parametrize("url, request_url", [
    ("https://git.example.test%3a8443", "https://git.example.test:8443"),
    ("https://path.example.test/team/re%20po.git", "https://path.example.test/team/re%20po.git"),
    ("https://%5b%3a%3a1%5d%3a8443", "https://[::1]:8443"),
])
def test_an_entry_an_earlier_migrate_wrote_matches(url, request_url, ready, git_config, vault_http,
                                                   tmp_path, monkeypatch, capsys):
    add(monkeypatch, capsys, "git/old", url, password="pw-old")
    only_the_helper(git_config)
    done = _git_fill(_git_env(tmp_path, vault_http), request_url, *HTTP_PATH)
    assert done.returncode == 0, done.stderr
    assert "password=pw-old" in done.stdout


@pytest.mark.parametrize("url, request_url", [
    ("localhost:8080", "https://localhost:8080"),
    ("git.example.test:8443", "https://git.example.test:8443"),
    ("localhost:8080/team", "https://localhost:8080/team/repo.git"),
])
def test_a_name_and_a_port_are_a_host_and_a_port(url, request_url, ready, git_config, vault_http,
                                                 tmp_path, monkeypatch, capsys):
    add(monkeypatch, capsys, "git/port", url, password="pw-port")
    only_the_helper(git_config)
    done = _git_fill(_git_env(tmp_path, vault_http), request_url, *HTTP_PATH)
    assert done.returncode == 0, done.stderr
    assert "password=pw-port" in done.stdout


def test_a_percent_sign_in_a_path_is_decoded_once(ready, git_config, vault_http, tmp_path,
                                                  monkeypatch, capsys):
    source = tmp_path / "credentials"
    approve(source, "https://bob:tok-pct@path.example.test/re%2520po.git")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    only_the_helper(git_config)
    env = _git_env(tmp_path, vault_http)
    assert "tok-pct" in _git_fill(env, "https://path.example.test/re%2520po.git",
                                  *HTTP_PATH).stdout
    assert _git_fill(env, "https://path.example.test/re%20po.git", *HTTP_PATH).returncode != 0


@pytest.mark.parametrize("mark", ["?", "#"])
def test_a_mark_git_leaves_bare_stays_in_the_path(mark, ready, git_config, vault_http, tmp_path,
                                                  monkeypatch, capsys):
    source = tmp_path / "credentials"
    approve(source, f"https://bob:tok-a@path.example.test/re{mark}a.git")
    approve(source, f"https://bob:tok-b@path.example.test/re{mark}b.git")
    assert f"/re{mark}a.git" in source.read_text()  # what git really writes
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert "added 2 entries" in capsys.readouterr().err
    assert ready.read(f"git/bob@path.example.test/re{mark}a.git") == "tok-a"
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert "2 already held" in capsys.readouterr().err
    only_the_helper(git_config)
    env = _git_env(tmp_path, vault_http)
    for repo, token in (("a", "tok-a"), ("b", "tok-b")):
        done = _git_fill(env, f"https://path.example.test/re{mark}{repo}.git", *HTTP_PATH)
        assert done.returncode == 0, done.stderr
        assert f"password={token}\n" in done.stdout


def test_migrate_adds_nothing_for_a_line_the_vault_holds(ready, git_config, vault_http, tmp_path,
                                                         monkeypatch, capsys):
    add(monkeypatch, capsys, "mirror/api", "https://git.example.test", "alice", "tok-one")
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    err = capsys.readouterr().err
    assert "added 0 entries" in err and "1 already held" in err and "skipped" not in err
    assert [e["name"] for e in ready.list_entries()] == ["mirror/api"]
    assert f"rm {source}" in err
    only_the_helper(git_config)
    done = _git_fill(_git_env(tmp_path, vault_http), "https://git.example.test")
    assert done.returncode == 0, done.stderr


def test_migrate_holds_a_line_an_earlier_migrate_wrote(ready, git_config, tmp_path, monkeypatch,
                                                       capsys):
    add(monkeypatch, capsys, "git/alice@git.example.test%3a8443",
        "https://git.example.test%3a8443", "alice", "tok-one")
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-one@git.example.test:8443")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert "1 already held" in capsys.readouterr().err
    assert len(ready.list_entries()) == 1


def test_a_line_with_a_username_is_its_own_entry_beside_one_with_none(
        ready, git_config, tmp_path, monkeypatch, capsys):
    add(monkeypatch, capsys, "git/token", "https://git.example.test", "", "tok-one")
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert "added 1 entry" in capsys.readouterr().err
    assert {e["name"] for e in ready.list_entries()} == {"git/alice@git.example.test", "git/token"}


def test_a_line_finds_its_account_past_another_accounts_longer_path(
        ready, git_config, tmp_path, monkeypatch, capsys):
    add(monkeypatch, capsys, "git/root", "https://git.example.test", "bob", "tok-bob")
    add(monkeypatch, capsys, "git/team", "https://git.example.test/team", "alice", "tok-alice")
    source = tmp_path / "credentials"
    approve(source, "https://bob:tok-bob@git.example.test/team/repo.git")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert "1 already held" in capsys.readouterr().err
    assert len(ready.list_entries()) == 2


@pytest.mark.parametrize("value, told", [
    ("tok-none", "1 already held"),
    ("tok-other", "skipped 1 with another value in the vault: git/root"),
])
def test_a_line_with_no_username_finds_its_entry_past_another_accounts_longer_path(
        value, told, ready, git_config, tmp_path, monkeypatch, capsys):
    add(monkeypatch, capsys, "git/root", "https://git.example.test", "", "tok-none")
    add(monkeypatch, capsys, "git/team", "https://git.example.test/team", "bob", "tok-bob")
    source = tmp_path / "credentials"
    approve(source, f"https://:{value}@git.example.test/team/repo.git")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    err = capsys.readouterr().err
    assert told in err
    assert len(ready.list_entries()) == 2
    assert ("plaintext store with: rm" in err) == (value == "tok-none")


def test_migrate_names_another_value_and_the_source_stays(ready, git_config, tmp_path, monkeypatch,
                                                          capsys):
    add(monkeypatch, capsys, "mirror/api", "https://git.example.test", "alice", "tok-old")
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-new@git.example.test")
    _store(git_config, source)
    at_a_terminal(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("asked to remove"))
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source", "--no-install") == 0
    err = capsys.readouterr().err
    assert "skipped 1 with another value in the vault: mirror/api" in err
    assert "kept git's plaintext store" in err
    assert source.exists()
    assert ready.read("mirror/api") == "tok-old"
    assert len(ready.list_entries()) == 1
    assert "tok-new" not in err and "tok-old" not in err


def test_another_username_gets_its_own_entry_and_a_line_for_the_host(
        ready, git_config, vault_http, tmp_path, monkeypatch, capsys):
    add(monkeypatch, capsys, "mirror/api", "https://git.example.test", "alice", "tok-one")
    add(monkeypatch, capsys, "other/api", "https://other.example.test", "alice", "tok-other")
    add(monkeypatch, capsys, "note/one", "", "", "not-a-host")
    add(monkeypatch, capsys, "note/two", "", "", "not-a-host")
    source = tmp_path / "credentials"
    approve(source, "https://oauth2:tok-one@git.example.test")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    err = capsys.readouterr().err
    assert "added 1 entry" in err
    assert err.count("vault entries: ") == 1
    assert ("git.example.test has 2 vault entries: git/oauth2@git.example.test, mirror/api - "
            "newest changed answers a request with no username") in err
    only_the_helper(git_config)
    env = _git_env(tmp_path, vault_http)
    for url, username in (("https://alice@git.example.test", "alice"),
                          ("https://oauth2@git.example.test", "oauth2"),
                          ("https://git.example.test", "oauth2")):
        done = _git_fill(env, url)
        assert done.returncode == 0, done.stderr
        assert f"username={username}\n" in done.stdout


def test_a_host_answers_as_the_store_answered(ready, git_config, vault_http, tmp_path, monkeypatch,
                                              capsys):
    source = tmp_path / "credentials"
    # bob is newer, so real `store` writes his line first, and he sorts after alice.
    approve(source, "https://alice:tok-a@git.example.test")
    approve(source, "https://bob:tok-b@git.example.test")
    assert source.read_text().index("bob") < source.read_text().index("alice")
    _store(git_config, source)
    env = _git_env(tmp_path, vault_http)
    by_store = _git_fill(env, "https://git.example.test")
    assert "username=bob\n" in by_store.stdout
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    only_the_helper(git_config)
    by_vault = _git_fill(env, "https://git.example.test")
    assert by_vault.returncode == 0, by_vault.stderr
    assert by_vault.stdout == by_store.stdout


def test_remove_source_runs_after_a_plain_migrate(ready, git_config, tmp_path, monkeypatch,
                                                  capsys):
    source = tmp_path / ".git-credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    git_config.write_text("[credential]\n\thelper = store\n")
    assert run_vault(monkeypatch, "vault", "git", "migrate") == 0
    err = capsys.readouterr().err
    assert "added 1 entry" in err and f"rm {source}" in err
    assert source.exists()
    assert _helpers(git_config) == ["jupyterlab-passkey"]

    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source") == 0
    err = capsys.readouterr().err
    assert "added 0 entries" in err and "1 already held" in err
    assert "removed git's plaintext store" in err
    assert not source.exists()


def test_the_same_line_in_both_stores_does_not_block_removal(ready, git_config, tmp_path,
                                                             monkeypatch, capsys):
    home = tmp_path / ".git-credentials"
    xdg = tmp_path / ".config" / "git" / "credentials"
    xdg.parent.mkdir(parents=True)
    approve(home, "https://alice:tok-one@git.example.test")
    approve(xdg, "https://alice:tok-one@git.example.test")
    git_config.write_text("[credential]\n\thelper = store\n")
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source") == 0
    err = capsys.readouterr().err
    assert "added 1 entry" in err and "1 already held" in err
    assert not home.exists() and not xdg.exists()


def test_two_values_for_one_account_in_the_stores_keep_them(ready, git_config, tmp_path,
                                                            monkeypatch, capsys):
    home = tmp_path / ".git-credentials"
    xdg = tmp_path / ".config" / "git" / "credentials"
    xdg.parent.mkdir(parents=True)
    approve(home, "https://alice:tok-one@git.example.test")
    approve(xdg, "https://alice:tok-two@git.example.test")
    git_config.write_text("[credential]\n\thelper = store\n")
    at_a_terminal(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("asked to remove"))
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source", "--no-install") == 0
    err = capsys.readouterr().err
    assert "added 1 entry" in err
    assert "skipped 1 with another value in the vault: git/alice@git.example.test" in err
    assert home.exists() and xdg.exists()
    assert ready.read("git/alice@git.example.test") == "tok-one"


def test_one_account_on_http_and_https_with_one_value_is_one_entry(
        ready, git_config, vault_http, tmp_path, monkeypatch, capsys):
    source = tmp_path / ".git-credentials"
    approve(source, "http://alice:tok-one@git.example.test")
    approve(source, "https://alice:tok-one@git.example.test")
    git_config.write_text("[credential]\n\thelper = store\n")
    assert run_vault(monkeypatch, "vault", "git", "migrate") == 0
    err = capsys.readouterr().err
    assert "added 1 entry" in err and "1 already held" in err and "skipped" not in err
    assert f"rm {source}" in err

    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source") == 0
    err = capsys.readouterr().err
    assert "added 0 entries" in err and "2 already held" in err and "skipped" not in err
    assert not source.exists()
    # The entry holds the first line's url, and real `store` writes a new line first.
    assert [e["url"] for e in ready.list_entries()] == ["https://git.example.test"]
    env = _git_env(tmp_path, vault_http)
    assert _git_fill(env, "https://git.example.test").returncode == 0
    assert _git_fill(env, "http://git.example.test").returncode != 0


def test_one_account_on_http_and_https_with_two_values_keeps_the_source(
        ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / ".git-credentials"
    approve(source, "http://alice:tok-one@git.example.test")
    approve(source, "https://alice:tok-two@git.example.test")
    git_config.write_text("[credential]\n\thelper = store\n")
    at_a_terminal(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("asked to remove"))
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source") == 0
    err = capsys.readouterr().err
    assert "added 1 entry" in err
    assert "skipped 1 with another value in the vault: git/alice@git.example.test" in err
    assert "that exist" not in err
    assert source.exists()
    assert ready.read("git/alice@git.example.test") == "tok-two"


def test_an_entry_of_the_line_name_with_another_username_keeps_the_source(
        ready, git_config, tmp_path, monkeypatch, capsys):
    add(monkeypatch, capsys, "git/alice@git.example.test", "https://git.example.test", "bob",
        "tok-one")
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run") == 0
    assert "vault entries" not in capsys.readouterr().err
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source", "--no-install") == 0
    err = capsys.readouterr().err
    assert "already held" not in err
    assert "skipped 1 that exist: git/alice@git.example.test" in err
    assert source.exists()


@pytest.mark.parametrize("url", ["", "https://[bad"])
@pytest.mark.parametrize("value, held", [("tok-one", True), ("tok-old", False)])
def test_an_entry_of_the_line_name_counts_by_its_value_whatever_its_url(
        url, value, held, ready, git_config, tmp_path, monkeypatch, capsys):
    add(monkeypatch, capsys, "git/alice@git.example.test", url, "alice", value)
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    _store(git_config, source)
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source", "--no-install") == 0
    err = capsys.readouterr().err
    assert ("1 already held" in err) == held
    assert ("skipped 1 with another value in the vault: git/alice@git.example.test" in err) != held
    assert ("the skipped lines already have a vault entry" in err) != held
    assert "invalid url" not in err
    assert source.exists() != held
    assert ready.read("git/alice@git.example.test") == value


def test_an_entry_the_helper_matches_outranks_an_entry_of_the_line_name(
        ready, git_config, tmp_path, monkeypatch, capsys):
    # The line's request is answered from mirror/api, so its value is the one that counts.
    add(monkeypatch, capsys, "mirror/api", "https://git.example.test", "alice", "tok-old")
    add(monkeypatch, capsys, "git/alice@git.example.test", "http://git.example.test", "alice",
        "tok-one")
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert "skipped 1 with another value in the vault: mirror/api" in capsys.readouterr().err


def test_a_migrate_that_leaves_a_line_out_prints_the_way_back_to_a_store_file(
        ready, git_config, tmp_path, monkeypatch, capsys):
    add(monkeypatch, capsys, "mirror/api", "https://git.example.test", "alice", "tok-old")
    source = tmp_path / "my credentials"
    approve(source, "https://alice:tok-new@git.example.test")
    subprocess.run(["git", "config", "--global", "credential.helper",
                    f"store --file {shlex.quote(str(source))}"], check=True)
    assert run_vault(monkeypatch, "vault", "git", "migrate") == 0
    err = capsys.readouterr().err
    assert f"git's plaintext store stays at {source}: no helper names it" in err
    assert "plaintext store with: rm" not in err
    assert source.exists()
    with pytest.raises(SystemExit, match="no git credential store at"):
        run_vault(monkeypatch, "vault", "git", "migrate", "--no-install")

    # The command the line prints brings the file back within reach of migrate.
    subprocess.run(err.partition("to read it again, run `")[2].partition("`")[0], shell=True,
                   check=True)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert "skipped 1 with another value in the vault: mirror/api" in capsys.readouterr().err
    # The skipped line blocks that run again until the entry it names changes.
    assert ("then change or remove mirror/api in the vault, then "
            "`jupyterlab-passkey vault git migrate --remove-source`") in err


@pytest.mark.parametrize("flags, answer", [((), None), (("--remove-source",), None),
                                           (("--remove-source",), "n")])
def test_a_migrate_that_leaves_no_line_out_prints_the_rm_line_and_the_way_back(
        flags, answer, ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / "my credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    subprocess.run(["git", "config", "--global", "credential.helper",
                    f"store --file {shlex.quote(str(source))}"], check=True)
    if answer:
        at_a_terminal(monkeypatch, answer)
    assert run_vault(monkeypatch, "vault", "git", "migrate", *flags) == 0
    err = capsys.readouterr().err
    assert "remove git's plaintext store with: rm " in err
    assert f"git's plaintext store stays at {source}: no helper names it" in err
    assert source.exists()

    # The command the line prints brings the file back within reach of migrate.
    subprocess.run(err.partition("to read it again, run `")[2].partition("`")[0], shell=True,
                   check=True)
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source") == 0
    err = capsys.readouterr().err
    assert "1 already held" in err and "removed git's plaintext store" in err
    # A removed file has no way back to print.
    assert "stays at" not in err and "to read it again" not in err
    assert not source.exists()


def test_a_store_file_kept_for_another_file_with_no_install_still_gets_the_way_back(
        ready, git_config, tmp_path, monkeypatch, capsys):
    read_elsewhere = tmp_path / "read elsewhere"
    approve(read_elsewhere, "https://alice:tok-one@git.example.test")
    named_no_more = tmp_path / "named no more"
    approve(named_no_more, "https://bob:tok-two@git.example.test")
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.chdir(repo)
    subprocess.run(["git", "config", "--local", "credential.helper",
                    f"store --file {shlex.quote(str(read_elsewhere))}"], check=True)
    subprocess.run(["git", "config", "--global", "credential.helper",
                    f"store --file {shlex.quote(str(named_no_more))}"], check=True)
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source", "--no-install") == 0
    err = capsys.readouterr().err
    assert "in another git config still reads it" in err
    assert f"git's plaintext store stays at {named_no_more}: no helper names it" in err
    assert "stays at " + str(read_elsewhere) not in err
    assert read_elsewhere.exists() and named_no_more.exists()


def test_a_migrate_that_leaves_a_line_out_of_the_home_store_can_read_it_again(
        ready, git_config, tmp_path, monkeypatch, capsys):
    add(monkeypatch, capsys, "mirror/api", "https://git.example.test", "alice", "tok-old")
    approve(tmp_path / ".git-credentials", "https://alice:tok-new@git.example.test")
    git_config.write_text("[credential]\n\thelper = store\n")
    assert run_vault(monkeypatch, "vault", "git", "migrate") == 0
    assert "stays at" not in capsys.readouterr().err
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert "skipped 1 with another value in the vault: mirror/api" in capsys.readouterr().err


def test_a_dry_run_counts_two_lines_of_one_name_as_one_entry(ready, git_config, tmp_path,
                                                             monkeypatch, capsys):
    source = tmp_path / "credentials"
    approve(source, "http://alice:tok-one@git.example.test")
    approve(source, "https://alice:tok-one@git.example.test")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run") == 0
    assert "vault entries" not in capsys.readouterr().err


def test_a_dry_run_counts_the_lines_with_a_locked_vault_and_asks_for_nothing(
        ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-a@git.example.test")
    approve(source, "https://bob:tok-b@git.example.test")
    _store(git_config, source)
    ready.lock()
    ready.calls.clear()
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run") == 0
    assert "git.example.test has 2 vault entries" in capsys.readouterr().err
    assert ready.calls == []


def test_a_dry_run_counts_the_entries_of_an_unlocked_vault_and_reads_no_value(
        ready, git_config, tmp_path, monkeypatch, capsys):
    add(monkeypatch, capsys, "mirror/api", "https://git.example.test", "alice", "tok-one")
    add(monkeypatch, capsys, "held/api", "https://held.example.test", "alice", "tok-held")
    source = tmp_path / "credentials"
    approve(source, "https://oauth2:tok-one@git.example.test")
    approve(source, "https://alice:tok-held@held.example.test")
    _store(git_config, source)
    # A read stamps the entry used, and a dry run writes nothing.
    monkeypatch.setattr(ready, "read", lambda *args: pytest.fail("a dry run read a value"))
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run") == 0
    err = capsys.readouterr().err
    assert "git.example.test has 2 vault entries" in err
    assert "held.example.test has" not in err
    assert len(ready.list_entries()) == 2


def test_a_dry_run_needs_no_server(ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    _store(git_config, source)

    def unreachable(*args, **kwargs):
        raise client.VaultClientError("cannot reach the server")

    monkeypatch.setattr(client, "request", unreachable)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run") == 0
    out, err = capsys.readouterr()
    assert "git/alice@git.example.test\tgit.example.test" in out
    assert "cannot reach" not in err


def test_the_error_lines_print_the_request_with_its_slash(ready, git_config, vault_http, tmp_path,
                                                          monkeypatch, capsys):
    only_the_helper(git_config)
    env = _git_env(tmp_path, vault_http)
    url = "https://me@path.example.test/team/re%20po.git"
    done = _git_fill(env, url, *HTTP_PATH)
    assert "no vault entry matches https://path.example.test/team/re po.git" in done.stderr

    add(monkeypatch, capsys, "path/one", "https://path.example.test/team", "", "pw")
    done = _git_fill(env, url.replace("me@", ""), *HTTP_PATH)
    assert ("path/one and https://path.example.test/team/re po.git have no username") in done.stderr


# What git sends for a client certificate's passphrase: the host is empty.
CERT_REQUEST = {"protocol": "cert", "host": "", "path": "/tmp/client.pem", "username": ""}


@pytest.mark.parametrize("notes", [1, 2])
def test_a_request_with_no_host_gets_no_answer(notes, ready, git_config, vault_http, tmp_path,
                                               monkeypatch, capsys):
    for number in range(notes):
        add(monkeypatch, capsys, f"note/{number}", "", "me", SECRET)
    only_the_helper(git_config)
    request = "".join(f"{key}={value}\n" for key, value in CERT_REQUEST.items()) + "\n"
    done = subprocess.run(["git", "credential", "fill"], env=_git_env(tmp_path, vault_http),
                          text=True, timeout=60, input=request, capture_output=True)
    unanswered(done, SECRET)
    assert "no vault entry matches cert:///tmp/client.pem\n" in done.stderr


def test_a_request_with_no_host_asks_for_no_unlock(ready, git_config, monkeypatch, capsys):
    ready.lock()
    ready.calls.clear()
    assert fill(monkeypatch, capsys, CERT_REQUEST)[:2] == (1, "")
    assert ready.calls == []


class _Remote(http.server.BaseHTTPRequestHandler):
    """A git remote that asks for Basic credentials and records each header git sends."""

    seen = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        header = self.headers.get("Authorization", "")
        self.seen.append(header)
        # git first sends a URL's username with an empty password.
        token = base64.b64decode(header.removeprefix("Basic ")).partition(b":")[2]
        self.send_response(404 if token else 401)
        self.send_header("WWW-Authenticate", 'Basic realm="git"')
        self.send_header("Content-Length", "0")
        self.end_headers()


def test_an_entry_with_no_username_sends_its_token_on_the_wire(ready, git_config, vault_http,
                                                               tmp_path, monkeypatch, capsys):
    _Remote.seen = []
    remote = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Remote)
    thread = threading.Thread(target=remote.serve_forever, daemon=True)
    thread.start()
    host = f"127.0.0.1:{remote.server_address[1]}"
    add(monkeypatch, capsys, "git/token", f"http://{host}", "", "tok-wire")
    only_the_helper(git_config)
    try:
        subprocess.run(["git", "ls-remote", f"http://oauth2@{host}/r.git"], capture_output=True,
                       env={**_git_env(tmp_path, vault_http), "no_proxy": "*"}, timeout=60)
    finally:
        remote.shutdown()
        remote.server_close()
        thread.join()
    sent = "Basic " + base64.b64encode(b"oauth2:tok-wire").decode()
    assert sent in _Remote.seen


def test_install_removes_every_store_helper_and_says_so(ready, git_config, vault_http, tmp_path,
                                                        monkeypatch, capsys):
    store_file = tmp_path / "scoped-credentials"
    plaintext = tmp_path / ".git-credentials"
    approve(plaintext, "https://alice:tok-one@git.example.test")
    before = plaintext.read_text()
    # `!true` is a helper that does nothing: a real `cache` would start a daemon below.
    git_config.write_text("[credential]\n\thelper = store\n\thelper = !true\n"
                          "[credential \"https://scoped.example.test\"]\n"
                          f"\thelper = store --file {store_file}\n"
                          "[credential \"https://other.example.test\"]\n\thelper = !true\n")
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    assert values() == [("credential.helper", "jupyterlab-passkey"),
                        ("credential.helper", "!true"),
                        ("credential.https://other.example.test.helper", "!true")]
    err = capsys.readouterr().err
    assert f"removed credential.helper = store from {git_config}" in err
    assert (f"removed credential.https://scoped.example.test.helper = store --file {store_file} "
            f"from {git_config}") in err
    # The file stays, and the next migrate is told how to import and remove it.
    assert f"git's plaintext store stays at {plaintext}: " in err
    assert "`git migrate --remove-source` imports and removes it" in err
    assert plaintext.read_text() == before
    # A --file value gets its line with no file there too: a spelling only a shell reads
    # looks the same from here. A bare `store` has nothing to restore.
    assert (f"credential.https://scoped.example.test.helper = store --file {store_file}: "
            "to read it again, run `") in err
    assert "credential.helper = store: to read it again" not in err

    # Nothing writes a credential git accepts back in plaintext.
    env = _git_env(tmp_path, vault_http)
    for host in ("git.example.test", "scoped.example.test"):
        done = subprocess.run(["git", "credential", "approve"], env=env, text=True,
                              timeout=60, capture_output=True,
                              input=f"url=https://alice:tok-new@{host}\n\n")
        assert done.returncode == 0, done.stderr
    assert plaintext.read_text() == before
    assert not store_file.exists()


def test_install_says_nothing_of_a_store_file_that_does_not_exist(git_config, monkeypatch, capsys):
    git_config.write_text("[credential]\n\thelper = store\n")
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    assert "stays at" not in capsys.readouterr().err


def test_install_names_a_store_file_no_helper_points_at_any_more(ready, git_config, tmp_path,
                                                                 monkeypatch, capsys):
    source = tmp_path / "my credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    subprocess.run(["git", "config", "--global", "credential.helper",
                    f"store --file {shlex.quote(str(source))}"], check=True)
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    err = capsys.readouterr().err
    assert f"git's plaintext store stays at {source}: no helper names it" in err
    # Nothing is imported yet, so the line must not tell the user to remove the file.
    assert "rm " not in err
    assert source.exists()
    with pytest.raises(SystemExit, match="no git credential store at"):
        run_vault(monkeypatch, "vault", "git", "migrate", "--no-install")

    # The command the line prints brings the file back within reach of migrate.
    subprocess.run(err.partition("to read it again, run `")[2].partition("`")[0], shell=True,
                   check=True)
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source") == 0
    assert ready.read("git/alice@git.example.test") == "tok-one"
    assert not source.exists()
    assert _helpers(git_config) == ["jupyterlab-passkey"]


@pytest.mark.parametrize("spelling, where", [("--file $HOME/creds", "creds"),
                                             ("--file=$HOME/creds", "creds"),
                                             ('--file "$HOME/creds"', "creds"),
                                             ("--file=\"$HOME/my creds\"", "my creds"),
                                             ("--file ${HOME}/creds", "creds"),
                                             ("--file $XDG_CONFIG_HOME/creds", ".config/creds"),
                                             ("--file $HOME/'my creds'", "my creds"),
                                             ("--file $HOME'/my creds'", "my creds")])
def test_a_store_file_named_through_a_shell_variable_is_read_and_gets_the_way_back(
        spelling, where, ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / where
    source.parent.mkdir(exist_ok=True)
    approve(source, "https://alice:tok-one@git.example.test")
    subprocess.run(["git", "config", "--global", "credential.helper", f"store {spelling}"],
                   check=True)
    # git runs the value through a shell, so the variable reaches `store` as the path.
    assert "password=tok-one" in _git_fill(dict(os.environ, GIT_TERMINAL_PROMPT="0"),
                                           "https://git.example.test").stdout
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run") == 0
    assert f"read {source}\n" in capsys.readouterr().err

    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    err = capsys.readouterr().err
    assert f"git's plaintext store stays at {source}: no helper names it" in err
    subprocess.run(err.partition("to read it again, run `")[2].partition("`")[0], shell=True,
                   check=True)
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source") == 0
    assert ready.read("git/alice@git.example.test") == "tok-one"
    assert not source.exists()


@pytest.mark.parametrize("value, where", [("store --file '$HOME/creds'", "$HOME/creds"),
                                          ("store", "$HOME/git/credentials")])
def test_a_dollar_no_shell_expands_stays_in_the_path(value, where, ready, git_config, tmp_path,
                                                     monkeypatch, capsys):
    """Single quotes keep it from the shell, and git reads XDG_CONFIG_HOME with no shell."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "$HOME"))
    source = tmp_path / where
    source.parent.mkdir(parents=True)
    approve(source, "https://alice:tok-one@git.example.test")
    subprocess.run(["git", "config", "--global", "credential.helper", value], check=True)
    assert "password=tok-one" in _git_fill(dict(os.environ, GIT_TERMINAL_PROMPT="0"),
                                           "https://git.example.test").stdout
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run") == 0
    assert f"{where}\n" in capsys.readouterr().err


@pytest.mark.parametrize("value, where", [("store --file=~/creds", "~/creds"),
                                          ('store --file "~/creds"', "~/creds"),
                                          ("store --file=\\$HOME/creds", "$HOME/creds"),
                                          ('store --file "\\$HOME/creds"', "$HOME/creds"),
                                          ("store --file other --file creds", "creds")])
def test_migrate_reads_the_file_git_reads_and_not_the_one_beside_it(
        value, where, ready, git_config, tmp_path, monkeypatch, capsys):
    """No shell expands a `~` inside a word or in quotes, or a `$` after a backslash, and
    git-credential-store takes its last --file: the file at the expanded path, and the
    first --file, are not the one git reads."""
    work = tmp_path / "work"
    (work / where).parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(work)
    approve(work / where, "https://alice:tok-git@git.example.test")
    approve(tmp_path / "creds", "https://bob:tok-home@git.example.test")
    approve(work / "other", "https://carol:tok-other@git.example.test")
    subprocess.run(["git", "config", "--global", "credential.helper", value], check=True)
    assert "password=tok-git" in _git_fill(dict(os.environ, GIT_TERMINAL_PROMPT="0"),
                                           "https://git.example.test").stdout
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run") == 0
    out, err = capsys.readouterr()
    assert out == "git/alice@git.example.test\tgit.example.test\n"
    assert f"read {where}\n" in err


SHELL_ONLY = [("store --file ${HOME%/}/'my creds'", "my creds"),
              ("store --file ${HOME%/}/creds", "creds"),
              ("store --file ${NOPE:-$HOME}/creds", "creds"),
              ("store --file $(echo $HOME)/creds", "creds"),
              ("store --file $HOME/creds$NOPE", "creds")]


@pytest.mark.parametrize("value, where", SHELL_ONLY)
def test_install_prints_a_store_value_it_cannot_read_and_the_command_that_restores_it(
        value, where, git_config, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("NOPE", raising=False)
    source = tmp_path / where
    approve(source, "https://alice:tok-one@git.example.test")
    subprocess.run(["git", "config", "--global", "credential.helper", value], check=True)
    # git runs the value through a shell, so real git reads this file.
    assert "password=tok-one" in _git_fill(dict(os.environ, GIT_TERMINAL_PROMPT="0"),
                                           "https://git.example.test").stdout
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    err = capsys.readouterr().err
    assert (f"credential.helper = {value}: to read it again, run "
            f"`git config --file {git_config} --add credential.helper ") in err
    assert "(a plain path, `~` or a set variable only)" in err
    assert "stays at" not in err
    assert source.exists()

    # The command the line prints puts the value back as it was written.
    subprocess.run(err.partition("to read it again, run `")[2].partition("`")[0], shell=True,
                   check=True)
    assert values() == [("credential.helper", "jupyterlab-passkey"), ("credential.helper", value)]


@pytest.mark.parametrize("flags", [(), ("--remove-source",), ("--remove-source", "--no-install")])
def test_migrate_prints_a_store_value_it_cannot_read_and_the_command_that_restores_it(
        flags, ready, git_config, tmp_path, monkeypatch, capsys):
    """The home store is read, so the run goes on and removes the value it cannot read."""
    approve(tmp_path / ".git-credentials", "https://alice:tok-one@git.example.test")
    unread = tmp_path / "my creds"
    approve(unread, "https://bob:tok-two@scoped.example.test")
    key = "credential.https://scoped.example.test.helper"
    value = "store --file ${HOME%/}/'my creds'"
    for pair in ((vcli.HELPER_KEY, "store"), (key, value)):
        subprocess.run(["git", "config", "--global", *pair], check=True)
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", *flags) == 0
    err = capsys.readouterr().err
    assert (f"{key} = {value}: to read it again, run "
            f"`git config --file {git_config} --add {key} ") in err
    assert unread.exists()

    subprocess.run(err.partition("to read it again, run `")[2].partition("`")[0], shell=True,
                   check=True)
    assert (key, value) in values()


def test_the_printed_command_restores_a_value_in_the_xdg_file(both_files, monkeypatch, capsys):
    home, xdg = both_files
    source = xdg.parent / "creds"
    approve(source, "https://alice:tok-one@git.example.test")
    value = f"store --file {source}"
    xdg.write_text(f"[credential]\n\thelper = {value}\n")
    home.write_text("[credential]\n\thelper = manager\n")
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    err = capsys.readouterr().err
    subprocess.run(err.partition("to read it again, run `")[2].partition("`")[0], shell=True,
                   check=True)
    assert value in xdg.read_text() and value not in home.read_text()


def test_install_local_prints_the_command_for_the_repository_config(git_config, tmp_path,
                                                                    monkeypatch, capsys):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.chdir(repo)
    value = "store --file $HOME/'my creds'"
    subprocess.run(["git", "config", "--local", "credential.helper", value], check=True)
    assert run_vault(monkeypatch, "vault", "git", "install", "--local") == 0
    err = capsys.readouterr().err
    assert "to read it again, run `git config --local --add credential.helper " in err
    subprocess.run(err.partition("to read it again, run `")[2].partition("`")[0], shell=True,
                   check=True)
    assert value in (repo / ".git" / "config").read_text()


def test_a_store_value_whose_file_migrate_still_reads_gets_its_line(git_config, tmp_path,
                                                                    monkeypatch, capsys):
    home_store = tmp_path / ".git-credentials"
    approve(home_store, "https://alice:tok-one@git.example.test")
    subprocess.run(["git", "config", "--global", "credential.helper",
                    f"store --file {home_store}"], check=True)
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    err = capsys.readouterr().err
    assert "`git migrate --remove-source` imports and removes it" in err
    assert f"credential.helper = store --file {home_store}: to read it again, run `" in err


def test_a_bare_store_no_helper_reaches_any_more_gets_the_way_back(git_config, tmp_path,
                                                                   monkeypatch, capsys):
    """A store value for every URL elsewhere takes the home store out of what migrate reads."""
    home_store = tmp_path / ".git-credentials"
    approve(home_store, "https://alice:tok-one@git.example.test")
    subprocess.run(["git", "config", "--global", "credential.helper", "store"], check=True)
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.chdir(repo)
    subprocess.run(["git", "config", "--local", "credential.helper", "store --file other"],
                   check=True)
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    err = capsys.readouterr().err
    assert f"git's plaintext store stays at {home_store}: no helper names it" in err
    assert (f"credential.helper = store: to read it again, run "
            f"`git config --file {git_config} --add credential.helper store`") in err


def test_install_local_removes_only_the_local_store(git_config, tmp_path, monkeypatch, capsys):
    git_config.write_text("[credential]\n\thelper = store\n")
    repo = tmp_path / "repo"
    (repo / "sub").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "--local", "credential.helper", "store"],
                   check=True)
    monkeypatch.chdir(repo / "sub")
    assert run_vault(monkeypatch, "vault", "git", "install", "--local") == 0
    assert "removed credential.helper = store from .git/config" in capsys.readouterr().err
    assert "store" not in (repo / ".git" / "config").read_text().replace("repositoryformat", "")
    assert "jupyterlab-passkey" in (repo / ".git" / "config").read_text()
    assert _helpers(git_config) == ["store"]


def test_remove_source_retires_a_url_scoped_store(ready, git_config, vault_http, tmp_path,
                                                  monkeypatch, capsys):
    source = tmp_path / ".git-credentials"
    approve(source, "https://alice:tok-one@scoped.example.test")
    scoped = "https://scoped.example.test"
    git_config.write_text(f"[credential \"{scoped}\"]\n\thelper = store\n")
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source", "--no-install") == 0
    err = capsys.readouterr().err
    assert "removed git's plaintext store" in err
    assert f"removed credential.{scoped}.helper = store from {git_config}" in err
    assert not source.exists()
    assert values() == []
    # git asks no store for this host now, so nothing writes the token back.
    done = subprocess.run(["git", "credential", "approve"], env=_git_env(tmp_path, vault_http),
                          text=True, timeout=60, capture_output=True,
                          input=f"url=https://alice:tok-one@{scoped.partition('//')[2]}\n\n")
    assert done.returncode == 0, done.stderr
    assert not source.exists()


def test_a_url_scoped_store_file_is_read_with_the_home_store(ready, git_config, tmp_path,
                                                             monkeypatch, capsys):
    home = tmp_path / ".git-credentials"
    scoped = tmp_path / "scoped-credentials"
    approve(home, "https://alice:tok-one@git.example.test")
    approve(scoped, "https://bob:tok-two@scoped.example.test")
    git_config.write_text("[credential \"https://scoped.example.test\"]\n"
                          f"\thelper = store --file {scoped}\n")
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert {e["name"] for e in ready.list_entries()} == {
        "git/alice@git.example.test", "git/bob@scoped.example.test"}


def test_remove_source_keeps_the_file_a_url_scoped_store_elsewhere_reads(
        ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    _store(git_config, source)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    key = "credential.https://git.example.test.helper"
    subprocess.run(["git", "-C", str(repo), "config", "--local", key, f"store --file {source}"],
                   check=True)
    monkeypatch.chdir(repo)
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source", "--no-install") == 0
    err = capsys.readouterr().err
    assert source.exists()
    assert f"{key} = store --file {source} in another git config still reads it" in err


@pytest.fixture
def both_files(git_config, tmp_path, monkeypatch):
    """~/.gitconfig and the XDG file, with no GIT_CONFIG_GLOBAL: git reads both, the XDG
    file first, and `git config --global` reads one. Each starts empty, so it exists."""
    monkeypatch.delenv("GIT_CONFIG_GLOBAL")
    xdg = tmp_path / ".config" / "git" / "config"
    xdg.parent.mkdir(parents=True)
    xdg.write_text("")
    home = tmp_path / ".gitconfig"
    home.write_text("")
    return home, xdg


def test_uninstall_reaches_the_helper_install_left_in_the_xdg_file(both_files, tmp_path,
                                                                   monkeypatch, capsys):
    home, xdg = both_files
    home.unlink()
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    assert "jupyterlab-passkey" in xdg.read_text()
    assert f"first in {xdg}" in capsys.readouterr().err
    home.write_text("")
    assert run_vault(monkeypatch, "vault", "git", "uninstall") == 0
    assert f"removed credential.helper = jupyterlab-passkey from {xdg}" in capsys.readouterr().err
    assert values() == []


def test_uninstall_removes_the_helper_from_both_files(both_files, monkeypatch, capsys):
    home, xdg = both_files
    for path in both_files:
        path.write_text("[credential]\n\thelper = jupyterlab-passkey\n\thelper = cache\n")
    assert run_vault(monkeypatch, "vault", "git", "uninstall") == 0
    err = capsys.readouterr().err
    assert f"from {home}" in err and f"from {xdg}" in err
    assert values() == [("credential.helper", "cache"), ("credential.helper", "cache")]


def test_install_goes_before_a_helper_in_the_xdg_file(both_files, monkeypatch, capsys):
    home, xdg = both_files
    xdg.write_text("[credential]\n\thelper = store\n\thelper = cache\n")
    home.write_text("[credential]\n\thelper = manager\n")
    for _ in range(2):
        assert run_vault(monkeypatch, "vault", "git", "install") == 0
        assert values() == [("credential.helper", "jupyterlab-passkey"),
                            ("credential.helper", "cache"), ("credential.helper", "manager")]
        assert f"first in {xdg}" in capsys.readouterr().err


def test_install_goes_after_an_empty_value_in_the_later_file(both_files, monkeypatch, capsys):
    home, xdg = both_files
    xdg.write_text("[credential]\n\thelper = cache\n")
    home.write_text("[credential]\n\thelper =\n\thelper = manager\n")
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    assert values() == [("credential.helper", "cache"), ("credential.helper", ""),
                        ("credential.helper", "jupyterlab-passkey"),
                        ("credential.helper", "manager")]
    assert f"first in {home}" in capsys.readouterr().err


def test_install_moves_a_copy_of_ours_to_the_one_that_runs_first(both_files, monkeypatch, capsys):
    home, xdg = both_files
    xdg.write_text("[credential]\n\thelper = cache\n")
    home.write_text("[credential]\n\thelper = jupyterlab-passkey\n")
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    assert values() == [("credential.helper", "jupyterlab-passkey"),
                        ("credential.helper", "cache")]


def test_remove_source_reaches_a_store_helper_in_the_xdg_file(ready, both_files, tmp_path,
                                                              monkeypatch, capsys):
    home, xdg = both_files
    source = tmp_path / ".git-credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    xdg.write_text("[credential]\n\thelper = store\n")
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source", "--no-install") == 0
    err = capsys.readouterr().err
    assert f"removed credential.helper = store from {xdg}" in err
    assert "in another git config" not in err
    assert not source.exists()


@pytest.mark.parametrize("content, line", [
    (b"https://[bad/\n", 1),
    (b"https://alice:pw-ONE@github.com\n\nhttps://a:SECRET@host:notaport\n", 3),
    (b"https://a:SECRET@host%3anotaport\n", 1),
    (b"https://a:SECRET@host%2fpath\n", 1),
    (b"https://a:SECRET@evil%40host\n", 1),
    (b"https://a:SECRET@ho\xffst\n", 1),
    (b"no-scheme-SECRET\n", 1),
    (b"https://alice@github.com\n", 1),
    (b"https://github.com\n", 1),
])
def test_a_malformed_store_line_is_one_error_naming_the_file_and_line(
        content, line, git_config, tmp_path, monkeypatch):
    # These lines stand for a damaged file: real git writes none of them.
    source = tmp_path / "credentials"
    source.write_bytes(content)
    _store(git_config, source)
    with pytest.raises(SystemExit) as raised:
        run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run")
    assert str(raised.value) == (f"{source}, line {line}: expected "
                                 "scheme://user:password@host[/path] (UTF-8)")


@pytest.mark.parametrize("url", ["https://alice:ab%ffcd@git.example.test",
                                 "https://al%ffice:tok-one@git.example.test"])
def test_a_credential_that_is_not_utf8_stops_the_migrate_and_keeps_the_source(
        url, ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    approve(source, url)
    approve(source, "https://bob:tok-two@git.example.test")
    before = source.read_bytes()
    assert b"%ff" in before
    _store(git_config, source)
    at_a_terminal(monkeypatch)
    with pytest.raises(SystemExit) as raised:
        run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source")
    assert str(raised.value) == (f"{source}, line 2: expected "
                                 "scheme://user:password@host[/path] (UTF-8)")
    assert source.read_bytes() == before
    assert ready.list_entries() == []


def test_a_path_with_a_control_character_stays_encoded_in_the_name(
        ready, git_config, vault_http, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-tab@git.example.test/re%09po.git")
    approve(source, "https://bob:tok-two@git.example.test")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert "added 2 entries" in capsys.readouterr().err
    assert ready.read("git/alice@git.example.test/re%09po.git") == "tok-tab"
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    assert "2 already held" in capsys.readouterr().err
    only_the_helper(git_config)
    done = _git_fill(_git_env(tmp_path, vault_http), "https://git.example.test/re%09po.git",
                     *HTTP_PATH)
    assert done.returncode == 0, done.stderr
    assert "password=tok-tab" in done.stdout


@pytest.mark.parametrize("url", ["https://al%09ice:tok-one@git.example.test",
                                 f"https://alice:tok-one@git.example.test/{'a' * 200}.git"])
def test_a_line_the_vault_cannot_name_is_one_error_naming_the_file_and_line(
        url, git_config, tmp_path, monkeypatch):
    source = tmp_path / "credentials"
    approve(source, url)
    approve(source, "https://bob:tok-two@git.example.test")
    _store(git_config, source)
    with pytest.raises(SystemExit) as raised:
        run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run")
    assert str(raised.value) == (f"{source}, line 2: "
                                 "an entry name is at most 200 printable characters")


def test_a_directory_at_the_store_path_is_one_error(git_config, tmp_path, monkeypatch):
    source = tmp_path / "credentials"
    source.mkdir()
    _store(git_config, source)
    with pytest.raises(SystemExit) as raised:
        run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run")
    assert str(raised.value) == f"{source}: Is a directory"


def test_an_unclosed_quote_in_a_store_value_is_one_error_naming_the_config(git_config,
                                                                           monkeypatch):
    git_config.write_text('[credential]\n\thelper = "store --file \\"x"\n')
    with pytest.raises(SystemExit) as raised:
        run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run")
    assert str(git_config) in str(raised.value) and "No closing quotation" in str(raised.value)


def test_an_unclosed_quote_in_another_helper_stops_nothing(git_config, monkeypatch):
    git_config.write_text('[credential]\n\thelper = "!echo \\"x"\n')
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    assert _helpers(git_config)[0] == "jupyterlab-passkey"


def _in_a_process(env, *args):
    """`vault git ...` as a real process: capsys cannot show how its stderr takes a byte."""
    return subprocess.run([sys.executable, "-m", "jupyterlab_passkey_extension.cli", "vault",
                           "git", *args], env=env, capture_output=True, timeout=60)


@pytest.mark.parametrize("args", [("install",), ("uninstall",), ("migrate", "--dry-run")])
def test_a_helper_value_that_is_not_utf8_is_kept_and_stops_no_command(args, git_config, tmp_path):
    approve(tmp_path / ".git-credentials", "https://alice:tok-one@git.example.test")
    git_config.write_bytes(b"[credential]\n\thelper = caf\xe9\n")
    done = _in_a_process(_git_env(tmp_path, 1), *args)
    assert done.returncode == 0, done.stderr
    assert b"caf\xe9" in git_config.read_bytes()


def test_a_store_file_whose_name_is_not_utf8_is_read_and_its_helper_removed(git_config, tmp_path):
    source = pathlib.Path(os.fsdecode(os.fsencode(tmp_path) + b"/caf\xe9"))
    approve(source, "https://alice:tok-one@git.example.test")
    git_config.write_bytes(b"[credential]\n\thelper = store --file "
                           + os.fsencode(source) + b"\n")
    env = _git_env(tmp_path, 1)
    done = _in_a_process(env, "migrate", "--dry-run")
    assert done.returncode == 0, done.stderr
    assert b"git/alice@git.example.test" in done.stdout
    done = _in_a_process(env, "install")
    assert done.returncode == 0, done.stderr
    assert b"stays at" in done.stderr
    assert b"store" not in git_config.read_bytes()


def test_the_printed_command_restores_a_store_file_name_that_is_not_utf8(git_config, tmp_path):
    value = b"store --file " + os.fsencode(tmp_path) + b"/caf\xe9"
    git_config.write_bytes(b"[credential]\n\thelper = " + value + b"\n")
    done = _in_a_process(_git_env(tmp_path, 1), "install")
    assert done.returncode == 0, done.stderr
    assert b"removed credential.helper = " + value + b" from " in done.stderr
    # The line carries the byte itself, so the command writes the value back unchanged.
    subprocess.run(done.stderr.partition(b"to read it again, run `")[2].partition(b"`")[0],
                   shell=True, check=True)
    assert git_config.read_bytes().endswith(b"\thelper = " + value + b"\n")


# --------------------------------------------------------------------------- #
# the real home, other spellings of a store helper, failed writes and bad input
# --------------------------------------------------------------------------- #


def test_the_guard_stops_a_process_that_would_see_the_real_home(git_config):
    for env in (dict(os.environ, HOME=str(REAL_HOME)),
                dict(os.environ, XDG_CONFIG_HOME=str(REAL_HOME / ".config"))):
        with pytest.raises(AssertionError, match="real home"):
            subprocess.run(["true"], env=env)


def test_a_write_to_a_home_git_file_by_another_process_fails_no_test(tmp_path):
    """A session whose home is `home` runs a test of this module while something outside
    the tests appends to that home's ~/.git-credentials, as any process of the user may."""
    home = tmp_path / "home"
    home.mkdir()
    store_file = home / ".git-credentials"
    store_file.write_text("")
    (tmp_path / "appender.py").write_text(
        "def pytest_runtest_call(item):\n"
        f"    with open({str(store_file)!r}, 'a') as f:\n"
        "        f.write('https://alice:tok-other@git.example.test\\n')\n")
    root = pathlib.Path(__file__).resolve().parents[2]
    env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               PYTHONPATH=os.pathsep.join([str(tmp_path), str(root)]))
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "appender",
         f"--basetemp={tmp_path / 'basetemp'}",
         f"{__file__}::test_install_and_uninstall_are_idempotent"],
        env=env, cwd=root, capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "1 passed" in done.stdout
    assert store_file.read_text() == "https://alice:tok-other@git.example.test\n"


def _exec_path():
    return subprocess.run(["git", "--exec-path"], capture_output=True, text=True,
                          check=True).stdout.strip()


@pytest.mark.parametrize("value", ["{store}", "{store} --file {source}", "!git credential-store",
                                   "!git credential-store --file {source}"])
def test_a_store_helper_by_its_full_path_or_through_git_is_retired(
        value, ready, git_config, vault_http, tmp_path, monkeypatch, capsys):
    source = tmp_path / ".git-credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    value = value.format(store=os.path.join(_exec_path(), "git-credential-store"), source=source)
    git_config.write_text(f"[credential]\n\thelper = {value}\n")
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source") == 0
    err = capsys.readouterr().err
    assert f"removed credential.helper = {value} from {git_config}" in err
    assert "removed git's plaintext store" in err
    assert ready.read("git/alice@git.example.test") == "tok-one"
    assert values() == [("credential.helper", "jupyterlab-passkey")]
    # The next credential git accepts writes no plaintext file back.
    done = subprocess.run(["git", "credential", "approve"], env=_git_env(tmp_path, vault_http),
                          text=True, timeout=60, capture_output=True,
                          input="url=https://alice:tok-new@git.example.test\n\n")
    assert done.returncode == 0, done.stderr
    assert not source.exists()


def test_a_helper_whose_name_starts_with_store_is_not_a_store(git_config, monkeypatch):
    git_config.write_text('[credential]\n\thelper = "storekeeper \\"x"\n')
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    assert values() == [("credential.helper", "jupyterlab-passkey"),
                        ("credential.helper", 'storekeeper "x')]


@pytest.mark.parametrize("where", ["sub", ".git"])
def test_install_local_removes_a_store_helper_from_a_file_the_repository_config_includes(
        where, git_config, tmp_path, monkeypatch, capsys):
    """From the git directory there is no work tree, and git names the include from there."""
    repo = tmp_path / "repo"
    (repo / "sub").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    included = tmp_path / "creds.inc"
    store_file = tmp_path / "included-credentials"
    included.write_text(f"[credential]\n\thelper = store --file {store_file}\n")
    # A relative include is read from the folder of the file that names it, .git here.
    subprocess.run(["git", "-C", str(repo), "config", "--local", "include.path",
                    "../../creds.inc"], check=True)
    monkeypatch.chdir(repo / where)
    assert run_vault(monkeypatch, "vault", "git", "install", "--local") == 0
    err = capsys.readouterr().err
    assert (f"removed credential.helper = store --file {store_file} "
            f"from {os.path.realpath(included)}") in err
    assert "store" not in included.read_text()
    assert "jupyterlab-passkey" in (repo / ".git" / "config").read_text()
    done = subprocess.run(["git", "credential", "approve"], env=_git_env(tmp_path, 1), text=True,
                          timeout=60, capture_output=True,
                          input="url=https://alice:tok-one@git.example.test\n\n")
    assert done.returncode == 0, done.stderr
    assert not store_file.exists()


def test_remove_source_prints_no_way_back_to_a_bare_store_with_no_file_left(
        ready, git_config, tmp_path, monkeypatch, capsys):
    """The home file removed and no XDG file: a bare `store` put back would read nothing
    and write tokens in plaintext again. The repository's store --file value covers every
    URL, so the home file is read through the global `store` alone."""
    home_store = tmp_path / ".git-credentials"
    approve(home_store, "https://alice:tok-one@git.example.test")
    subprocess.run(["git", "config", "--global", "credential.helper", "store"], check=True)
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.chdir(repo)
    subprocess.run(["git", "config", "--local", "credential.helper", "store --file other"],
                   check=True)
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source") == 0
    err = capsys.readouterr().err
    assert "removed git's plaintext store" in err
    assert not home_store.exists()
    assert "to read it again" not in err


@pytest.mark.parametrize("home_helpers", [["manager"], ["store --file {other}", "manager"]],
                         ids=["writing ours", "removing a second value"])
@pytest.mark.parametrize("value", ["store", "store --file {creds}"])
def test_a_failed_write_after_a_removal_prints_the_command_that_restores_it(
        value, home_helpers, both_files, tmp_path, monkeypatch, capsys):
    home, xdg = both_files
    value = value.format(creds=tmp_path / "creds")
    xdg.write_text(f"[credential]\n\thelper = {value}\n")
    home.write_text("[credential]\n" + "".join(
        f"\thelper = {helper.format(other=tmp_path / 'other')}\n" for helper in home_helpers))
    # Another git holds the lock of ~/.gitconfig, so the write there fails.
    (tmp_path / ".gitconfig.lock").write_text("")
    with pytest.raises(SystemExit, match="git config failed"):
        run_vault(monkeypatch, "vault", "git", "install")
    err = capsys.readouterr().err
    assert value not in xdg.read_text()
    assert err.count("to restore it, run `") == 1
    subprocess.run(err.partition("to restore it, run `")[2].partition("`")[0], shell=True,
                   check=True)
    assert xdg.read_text().endswith(f"\thelper = {value}\n")


def test_a_migrate_whose_install_fails_prints_the_command_for_the_store_it_retired(
        ready, both_files, tmp_path, monkeypatch, capsys):
    """The XDG `store` is retired and the file kept for the repository's `store`; then
    writing ours to ~/.gitconfig fails."""
    home, xdg = both_files
    approve(tmp_path / ".git-credentials", "https://alice:tok-one@git.example.test")
    xdg.write_text("[credential]\n\thelper = store\n")
    home.write_text("[credential]\n\thelper = manager\n")
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "--local", "credential.helper", "store"],
                   check=True)
    monkeypatch.chdir(repo)
    (tmp_path / ".gitconfig.lock").write_text("")
    at_a_terminal(monkeypatch)
    with pytest.raises(SystemExit, match="git config failed"):
        run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source")
    err = capsys.readouterr().err
    assert "in another git config still reads it" in err
    subprocess.run(err.partition("to restore it, run `")[2].partition("`")[0], shell=True,
                   check=True)
    assert xdg.read_text().endswith("\thelper = store\n")


def test_a_client_certificate_line_is_named_and_the_other_lines_are_imported(
        ready, git_config, tmp_path, monkeypatch, capsys):
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    # What git writes for a client certificate's passphrase: no host and no username.
    done = subprocess.run(["git", "-c", f"credential.helper=store --file {shlex.quote(str(source))}",
                           "credential", "approve"], text=True, timeout=60, capture_output=True,
                          input=f"protocol=cert\nhost=\npath=/tmp/client.pem\nusername=\n"
                                f"password={SECRET}\n\n")
    assert done.returncode == 0, done.stderr
    lines = source.read_text().splitlines()
    number = next(n for n, line in enumerate(lines, 1) if line.startswith("cert://"))
    _store(git_config, source)
    at_a_terminal(monkeypatch)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source") == 0
    err = capsys.readouterr().err
    assert f"{source}, line {number}: a client certificate passphrase, not imported" in err
    assert ready.read("git/alice@git.example.test") == "tok-one"
    # The passphrase is in no entry, so the file stays and no rm line is printed.
    assert "it holds a client certificate passphrase" in err
    assert SECRET in source.read_text()
    assert SECRET not in err and "plaintext store with: rm" not in err


def test_a_request_path_that_is_not_utf8_gets_its_answer(ready, git_config, vault_http, tmp_path,
                                                         monkeypatch, capsys):
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-ff@git.example.test/re%ffpo.git")
    _store(git_config, source)
    assert run_vault(monkeypatch, "vault", "git", "migrate", "--no-install") == 0
    only_the_helper(git_config)
    # git hands the helper the path's byte as it is.
    done = subprocess.run(["git", *HTTP_PATH, "credential", "fill"],
                          env=_git_env(tmp_path, vault_http), timeout=60, capture_output=True,
                          text=True, errors="surrogateescape",
                          input="url=https://alice@git.example.test/re%ffpo.git\n\n")
    assert "Traceback" not in done.stderr
    answered(done, "alice", "tok-ff")


def test_a_host_that_is_not_utf8_is_a_bad_line(git_config, tmp_path, monkeypatch):
    source = tmp_path / "credentials"
    approve(source, "https://alice:tok-one@ho%ffst.example.test")
    _store(git_config, source)
    with pytest.raises(SystemExit) as raised:
        run_vault(monkeypatch, "vault", "git", "migrate", "--dry-run")
    assert str(raised.value) == (f"{source}, line 1: expected "
                                 "scheme://user:password@host[/path] (UTF-8)")


@pytest.mark.skipif(os.geteuid() == 0, reason="root passes every permission check")
def test_a_store_file_that_cannot_be_removed_is_one_line(ready, git_config, tmp_path, monkeypatch,
                                                         capsys):
    folder = tmp_path / "locked"
    folder.mkdir()
    source = folder / "credentials"
    approve(source, "https://alice:tok-one@git.example.test")
    _store(git_config, source)
    at_a_terminal(monkeypatch)
    folder.chmod(0o500)
    try:
        with pytest.raises(SystemExit) as raised:
            run_vault(monkeypatch, "vault", "git", "migrate", "--remove-source")
    finally:
        folder.chmod(0o700)
    assert str(raised.value) == f"cannot remove {source}: Permission denied"
    assert ready.read("git/alice@git.example.test") == "tok-one"
    # The value is gone from the config: its line brings the file back within reach.
    subprocess.run(capsys.readouterr().err.partition("to read it again, run `")[2].partition("`")[0],
                   shell=True, check=True)
    assert _helpers(git_config) == [f"store --file {source}"]
