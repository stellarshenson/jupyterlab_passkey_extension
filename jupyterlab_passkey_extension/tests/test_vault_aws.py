"""The AWS CLI's credential process, `vault aws ...` and the helper.

As in test_vault_git, `client.request` is routed straight into a real VaultService and
the browser steps are stubbed to do what the page does, so the helper runs against a
real vault file. Every config a test writes is under tmp_path; AWS_CONFIG_FILE or HOME
keeps the real ~/.aws out of reach.
"""

import base64
import json
import stat
import subprocess
import sys

import pytest

from jupyterlab_passkey_extension import cli
from jupyterlab_passkey_extension.vault import awscred, client, handlers, service
from jupyterlab_passkey_extension.vault import cli as vcli
from jupyterlab_passkey_extension.vault.store import VaultError

PASS = "correct horse battery staple"
PRF = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
KEY_ID = "AKIAFAKEEXAMPLE0001"
SECRET_KEY = "fake-secret-key-MUST-NOT-LEAK"


@pytest.fixture
def server(vault_env, monkeypatch):
    """A real VaultService behind the client's request and browser step."""
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
        if command == client.UNLOCK_COMMAND:
            svc.unlock_passkey("cred-1", PRF)

    monkeypatch.setattr(client, "request", request)
    monkeypatch.setattr(client, "browser_step", browser_step)
    svc.calls = calls
    return svc


def ready_vault(svc, **fields):
    """A vault with one passkey and vault entry aws/work."""
    svc.init(PASS)
    svc.add_passkey("cred-1", "lab.example", "c2FsdA", PRF, None, {"current": PASS})
    svc.add("aws/work", {"username": KEY_ID, "password": SECRET_KEY, **fields})


def run_vault(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", *argv])
    return cli.main()


# --------------------------------------------------------------------------- #
# the helper
# --------------------------------------------------------------------------- #


def test_the_helper_prints_the_credential_process_json(server, capsys):
    ready_vault(server)
    assert awscred.main(["work"]) == 0
    out, err = capsys.readouterr()
    assert out == json.dumps({"Version": 1, "AccessKeyId": KEY_ID,
                              "SecretAccessKey": SECRET_KEY}) + "\n"
    assert err == ""


def test_a_locked_vault_raises_one_unlock_notification_then_answers(server, capsys):
    ready_vault(server)
    server.lock()
    server.calls.clear()
    assert awscred.main(["work"]) == 0
    out, err = capsys.readouterr()
    assert json.loads(out)["AccessKeyId"] == KEY_ID
    assert err == ""
    assert server.calls == [client.UNLOCK_COMMAND]


def test_a_missing_entry_exits_one_naming_the_entry_and_the_add(server, capsys):
    ready_vault(server)
    assert awscred.main(["absent"]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert "aws/absent" in err
    assert "vault add aws/absent -u" in err


@pytest.mark.parametrize("fields, field", [
    ({"username": ""}, "username"),
    ({"password": ""}, "password"),
])
def test_an_empty_field_exits_one_naming_the_entry_and_the_field(server, capsys, fields, field):
    ready_vault(server, **fields)
    assert awscred.main(["work"]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert "aws/work" in err and field in err


def test_no_key_enters_argv(server, monkeypatch, capsys):
    ready_vault(server)
    argv = [awscred.PROGRAM, "work"]
    monkeypatch.setattr(sys, "argv", argv)
    assert awscred.main() == 0
    out, _ = capsys.readouterr()
    assert SECRET_KEY in out and KEY_ID in out
    assert SECRET_KEY not in " ".join(argv) and KEY_ID not in " ".join(argv)


def test_usage_is_one_line_on_stderr(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [awscred.PROGRAM, "work", "extra"])
    assert awscred.main() == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert err.count("\n") == 1 and "usage:" in err


# --------------------------------------------------------------------------- #
# vault aws install
# --------------------------------------------------------------------------- #


def install(monkeypatch, which):
    """The aws configure calls, with shutil.which answered from `which`."""
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(vcli.subprocess, "run", run)
    monkeypatch.setattr(vcli.shutil, "which", which.get)
    return calls


def test_install_writes_the_credential_process_line(monkeypatch, capsys):
    helper = "/opt/bin/aws-credential-jupyterlab-passkey"
    calls = install(monkeypatch, {"aws-credential-jupyterlab-passkey": helper,
                                  "aws": "/usr/bin/aws"})
    assert run_vault(monkeypatch, "vault", "aws", "install", "work") == 0
    assert calls == [["/usr/bin/aws", "configure", "set", "credential_process",
                      f"{helper} work", "--profile", "work"]]
    err = capsys.readouterr().err
    assert "aws/work" in err
    assert "access key id" in err and "secret access key" in err
    assert SECRET_KEY not in err


def test_install_names_the_reinstall_without_the_helper(monkeypatch):
    install(monkeypatch, {"aws": "/usr/bin/aws"})
    with pytest.raises(SystemExit, match="make install"):
        run_vault(monkeypatch, "vault", "aws", "install", "work")


def test_install_prints_the_manual_line_without_aws(monkeypatch):
    helper = "/opt/bin/aws-credential-jupyterlab-passkey"
    install(monkeypatch, {"aws-credential-jupyterlab-passkey": helper})
    with pytest.raises(SystemExit) as raised:
        run_vault(monkeypatch, "vault", "aws", "install", "work")
    line = str(raised.value)
    assert "credential_process" in line
    assert f"{helper} work" in line


@pytest.mark.parametrize("profile", ["", "two words"])
def test_install_rejects_a_profile_with_whitespace(monkeypatch, profile):
    install(monkeypatch, {"aws-credential-jupyterlab-passkey": "/h", "aws": "/a"})
    with pytest.raises(SystemExit, match="without whitespace"):
        run_vault(monkeypatch, "vault", "aws", "install", profile)


def test_install_carries_the_stderr_of_a_failed_aws_configure(monkeypatch):
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "no such profile")

    monkeypatch.setattr(vcli.subprocess, "run", run)
    monkeypatch.setattr(vcli.shutil, "which",
                        {"aws-credential-jupyterlab-passkey": "/h", "aws": "/a"}.get)
    with pytest.raises(SystemExit, match="no such profile"):
        run_vault(monkeypatch, "vault", "aws", "install", "work")


# --------------------------------------------------------------------------- #
# vault aws uninstall
# --------------------------------------------------------------------------- #

OUR_HELPER = "aws-credential-jupyterlab-passkey"
OUR_LINE = f"credential_process = /opt/bin/{OUR_HELPER} work\n"
CONFIG = ("# a kept comment\n"
          "[profile work]\n"
          "region = eu-west-1\n"
          "output = json\n"
          f"{OUR_LINE}"
          "\n"
          "[default]\n"
          "region = us-east-1\n"
          "credential_process = /opt/bin/other-helper default\n")


def config(tmp_path, monkeypatch, text=CONFIG):
    path = tmp_path / ".aws" / "config"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(path))
    return path


def test_uninstall_removes_only_our_line_and_keeps_the_mode(tmp_path, monkeypatch, capsys):
    path = config(tmp_path, monkeypatch)
    path.chmod(0o600)
    assert run_vault(monkeypatch, "vault", "aws", "uninstall", "work") == 0
    assert path.read_text() == CONFIG.replace(OUR_LINE, "")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "removed credential_process" in capsys.readouterr().err


def test_a_second_uninstall_says_there_is_no_line(tmp_path, monkeypatch, capsys):
    config(tmp_path, monkeypatch)
    assert run_vault(monkeypatch, "vault", "aws", "uninstall", "work") == 0
    assert run_vault(monkeypatch, "vault", "aws", "uninstall", "work") == 0
    assert "no credential_process of ours" in capsys.readouterr().err


def test_a_foreign_credential_process_stays_and_exits_one(tmp_path, monkeypatch):
    foreign = "credential_process = /opt/bin/other-helper work\n"
    path = config(tmp_path, monkeypatch, f"[profile work]\n{foreign}")
    with pytest.raises(SystemExit) as raised:
        run_vault(monkeypatch, "vault", "aws", "uninstall", "work")
    assert "other-helper" in str(raised.value)
    assert path.read_text() == f"[profile work]\n{foreign}"


def test_a_foreign_helper_holding_our_name_stays_and_exits_one(tmp_path, monkeypatch):
    foreign = f"credential_process = /opt/bin/my-{OUR_HELPER}-backup work\n"
    path = config(tmp_path, monkeypatch, f"[profile work]\n{foreign}")
    with pytest.raises(SystemExit) as raised:
        run_vault(monkeypatch, "vault", "aws", "uninstall", "work")
    assert "backup" in str(raised.value)
    assert path.read_text() == f"[profile work]\n{foreign}"


def test_a_symlinked_config_keeps_the_link_and_writes_through_it(tmp_path, monkeypatch):
    target = tmp_path / "dotfiles" / "aws-config"
    target.parent.mkdir()
    target.write_text(CONFIG)
    target.chmod(0o640)
    link = tmp_path / "config"
    link.symlink_to(target)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(link))
    assert run_vault(monkeypatch, "vault", "aws", "uninstall", "work") == 0
    assert link.is_symlink()
    assert target.read_text() == CONFIG.replace(OUR_LINE, "")
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


def test_several_of_ours_are_removed_and_a_foreign_line_stays(tmp_path, monkeypatch):
    foreign = "credential_process = /opt/bin/other-helper work\n"
    path = config(tmp_path, monkeypatch, f"[profile work]\n{OUR_LINE}{OUR_LINE}{foreign}")
    with pytest.raises(SystemExit):
        run_vault(monkeypatch, "vault", "aws", "uninstall", "work")
    assert path.read_text() == f"[profile work]\n{foreign}"


def test_a_missing_config_succeeds_and_says_so(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent"))
    assert run_vault(monkeypatch, "vault", "aws", "uninstall", "work") == 0
    assert "no AWS config" in capsys.readouterr().err


def test_the_default_config_is_in_the_home(tmp_path, monkeypatch):
    monkeypatch.delenv("AWS_CONFIG_FILE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    path = tmp_path / ".aws" / "config"
    path.parent.mkdir()
    # The bare section name, the other spelling of a profile.
    path.write_text(f"[work]\n{OUR_LINE}")
    assert run_vault(monkeypatch, "vault", "aws", "uninstall", "work") == 0
    assert path.read_text() == "[work]\n"


def test_another_sections_line_is_left_alone(tmp_path, monkeypatch, capsys):
    other = f"credential_process = /opt/bin/{OUR_HELPER} other\n"
    path = config(tmp_path, monkeypatch, f"[profile other]\n{other}")
    assert run_vault(monkeypatch, "vault", "aws", "uninstall", "work") == 0
    assert path.read_text() == f"[profile other]\n{other}"
    assert "no credential_process of ours" in capsys.readouterr().err
