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
import urllib.parse

import pytest

from jupyterlab_passkey_extension import cli
from jupyterlab_passkey_extension.vault import client, gitcred, handlers, service
from jupyterlab_passkey_extension.vault import cli as vcli
from jupyterlab_passkey_extension.vault.store import VaultError

PASS = "correct horse battery staple"
PRF = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
SECRET = "s3cret-MUST-NOT-LEAK"


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

    def browser_step(command, args, label, message, timeout):
        calls.append(command)
        if command == client.REGISTER_COMMAND:
            n = len(svc.status()["slots"])
            svc.add_passkey(f"cred-{n}", "lab.example", "c2FsdA", PRF, args.get("label") or None,
                            {"current": PASS})
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


REAL_HOME_FILES = (pathlib.Path.home() / ".gitconfig",
                   pathlib.Path.home() / ".git-credentials",
                   pathlib.Path.home() / ".config" / "git" / "credentials")


def _real_git_state():
    return {str(path): (path.stat().st_mtime_ns, path.stat().st_size) if path.exists() else None
            for path in REAL_HOME_FILES}


@pytest.fixture(scope="session", autouse=True)
def real_home_git_files_untouched():
    """Prove the suite writes no git file under the real home: the git fixture points
    HOME at tmp_path, and these three files must be untouched when the suite ends."""
    before = _real_git_state()
    yield
    assert _real_git_state() == before, "a test wrote a git file under the real home"


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


def fill(monkeypatch, capsys, attrs, operation="get"):
    capsys.readouterr()
    request = "".join(f"{key}={value}\n" for key, value in attrs.items()) + "\n"
    monkeypatch.setattr(sys, "stdin", io.StringIO(request))
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
    add(monkeypatch, capsys, "git/github.com", "https://github.com", password="pw-root")
    add(monkeypatch, capsys, "git/github.com/foo", "https://github.com/foo", password="pw-foo")
    add(monkeypatch, capsys, "git/github.com/foo/bar", "https://github.com/foo/bar", password="pw-bar")
    # git sends the path without its leading slash, as `git credential fill` does.
    request = {"protocol": "https", "host": "github.com", "path": "foo/bar/baz"}
    assert fill(monkeypatch, capsys, request) == (0, "username=me\npassword=pw-bar\n", "")

    # Without a path attribute git applied no useHttpPath: entry paths are ignored and
    # all three entries tie.
    code, out, err = fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"})
    assert (code, out) == (1, "")
    for name in ("git/github.com", "git/github.com/foo", "git/github.com/foo/bar"):
        assert name in err


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


def test_an_ambiguous_match_names_the_candidates(ready, git_config, monkeypatch, capsys):
    add(monkeypatch, capsys, "github/me", "https://github.com", "me", "pw-me")
    add(monkeypatch, capsys, "github/you", "https://github.com", "you", "pw-you")
    code, out, err = fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"})
    assert (code, out) == (1, "")
    assert "github/me" in err and "github/you" in err
    assert "pw-me" not in err and "pw-you" not in err

    # The username the request carries breaks the tie.
    assert fill(monkeypatch, capsys,
                {"protocol": "https", "host": "github.com", "username": "you"}) == (
        0, "username=you\npassword=pw-you\n", "")


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

    def timeout(command, args, label, message, seconds):
        raise client.VaultClientError(
            f"no relay after {seconds:.0f}s - was the button clicked and the prompt approved?")

    monkeypatch.setattr(client, "browser_step", timeout)
    code, out, err = fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"})
    assert (code, out) == (1, "")
    assert "120s" in err
    assert SECRET not in err


# --------------------------------------------------------------------------- #
# first set-up from git
# --------------------------------------------------------------------------- #


def _stub_setup(monkeypatch, server, calls):
    """What the page does for the set-up step: create the vault and its passkey, and
    add the entry this request needs so the helper has an answer to give."""
    def browser_step(command, args, label, message, timeout):
        calls.append(command)
        assert command == client.SETUP_COMMAND
        if not server.status()["initialized"]:
            server.init(PASS)
            server.add_passkey("cred-1", "lab.example", "c2FsdA", PRF, None, {"current": PASS})
        server.add("github/api", {"password": "pw-one", "username": "me",
                                  "url": "https://github.com"})

    for module in (client, vcli):
        monkeypatch.setattr(module, "browser_step", browser_step)


def test_no_vault_sets_up_in_the_browser_then_answers(server, git_config, monkeypatch, capsys):
    calls = []
    _stub_setup(monkeypatch, server, calls)
    assert fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"}) == (
        0, "username=me\npassword=pw-one\n", "")
    # One browser step, and the credential is answered after it.
    assert calls == [client.SETUP_COMMAND]


def test_a_vault_without_a_passkey_adds_only_the_passkey(server, git_config, monkeypatch,
                                                         capsys):
    assert run_vault(monkeypatch, "vault", "init", "--no-passkey", stdin=PASS + "\n") == 0
    capsys.readouterr()
    server.add("github/api", {"password": "pw-one", "username": "me",
                              "url": "https://github.com"})
    monkeypatch.setattr(server, "init",
                        lambda recovery: pytest.fail("the set-up created a vault that exists"))
    calls = []

    def browser_step(command, args, label, message, timeout):
        calls.append(command)
        assert command == client.SETUP_COMMAND
        server.add_passkey("cred-1", "lab.example", "c2FsdA", PRF, None, {"current": PASS})

    for module in (client, vcli):
        monkeypatch.setattr(module, "browser_step", browser_step)
    assert fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"}) == (
        0, "username=me\npassword=pw-one\n", "")
    assert calls == [client.SETUP_COMMAND]
    assert [s["type"] for s in server.status()["slots"]] == ["recovery", "passkey"]


CANCELLED = ("ceremony failed: the passkey step was cancelled - run the command again to "
             "continue the vault set-up")


def test_a_cancelled_set_up_names_the_step_and_prints_no_secret(server, git_config, monkeypatch,
                                                               capsys):
    def browser_step(command, args, label, message, timeout):
        server.init(PASS)
        raise client.VaultClientError(CANCELLED)

    for module in (client, vcli):
        monkeypatch.setattr(module, "browser_step", browser_step)
    code, out, err = fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"})
    assert (code, out) == (1, "")
    assert err.count("\n") == 1
    assert "passkey step" in err and "cancelled" in err
    assert "run the command again" in err
    assert SECRET not in err


def test_a_second_run_after_a_cancel_completes(server, git_config, monkeypatch, capsys):
    runs = []

    def browser_step(command, args, label, message, timeout):
        runs.append(command)
        if not server.status()["initialized"]:
            server.init(PASS)
        if len(runs) == 1:
            raise client.VaultClientError(CANCELLED)
        # The vault exists, so the second run adds only what it lacks.
        server.add_passkey("cred-1", "lab.example", "c2FsdA", PRF, None, {"current": PASS})
        server.add("github/api", {"password": "pw-one", "username": "me",
                                  "url": "https://github.com"})

    for module in (client, vcli):
        monkeypatch.setattr(module, "browser_step", browser_step)
    code, out, err = fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"})
    assert (code, out) == (1, "")
    assert "passkey step" in err
    assert server.status()["initialized"] is True
    assert fill(monkeypatch, capsys, {"protocol": "https", "host": "github.com"}) == (
        0, "username=me\npassword=pw-one\n", "")
    assert runs == [client.SETUP_COMMAND, client.SETUP_COMMAND]


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
    git_config.write_text("[credential]\n\thelper = store\n\thelper = cache --timeout=60\n")
    for _ in range(2):
        assert run_vault(monkeypatch, "vault", "git", "install") == 0
        assert _helpers(git_config) == ["jupyterlab-passkey", "store", "cache --timeout=60"]


def test_install_goes_after_the_last_empty_helper(git_config, monkeypatch):
    # An empty value resets git's helper list: everything before it is discarded.
    git_config.write_text("[credential]\n\thelper =\n\thelper = store\n")
    assert run_vault(monkeypatch, "vault", "git", "install") == 0
    assert _helpers(git_config) == ["", "jupyterlab-passkey", "store"]


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
    source.write_text("https://alice:pw-ONE@example.com:8443/repo.git\n"
                      "https://bob:pw-TWO@example.com/repo.git\n")
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
    assert ("the skipped lines already have a vault entry, so their passwords "
            "were not imported") in err
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


def test_git_commands_say_git_is_missing_without_a_traceback(tmp_path, monkeypatch):
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
    env["HOME"] = str(tmp_path / "home")
    root = str(pathlib.Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = os.pathsep.join(p for p in (root, env.get("PYTHONPATH")) if p)
    return env


def _git_fill(env):
    return subprocess.run(["git", "credential", "fill"], env=env, text=True, timeout=60,
                          input="protocol=https\nhost=github.com\n\n", capture_output=True)


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
    assert _helpers(git_config) == ["", "jupyterlab-passkey", "store"]
    done = _git_fill(_git_env(tmp_path, vault_http))
    assert done.returncode == 0, done.stderr
    assert "password=pw-one" in done.stdout
