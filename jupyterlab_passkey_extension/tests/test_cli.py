"""Tests for the jupyterlab-passkey CLI.

The CLI is a proxy: it assembles a notification carrying a command, then reads back the
relay the server writes. Both halves are mocked here - the ceremony itself belongs to
the Galata suite. What matters is the contract between them: the right command id and
args go out, the relay is consumed exactly once, and no secret reaches stdout that
shouldn't.
"""

import contextlib
import json
import os

import pytest

from jupyterlab_passkey_extension import cli


@pytest.fixture
def relay_dir(tmp_path, monkeypatch):
    d = tmp_path / "relay"
    d.mkdir()
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(d))
    return d


@pytest.fixture
def posted(monkeypatch):
    """Capture the notification payload instead of sending it."""
    sent = []

    def fake_urlopen(req):
        sent.append({
            "url": req.full_url,
            "headers": dict(req.headers),
            "payload": json.loads(req.data.decode()),
        })

        class _R:
            def read(self):
                return b"{}"
        return _R()

    monkeypatch.setattr(cli, "_server", lambda: ("http://127.0.0.1:8888/lab", "tok123"))
    monkeypatch.setattr(cli.urllib.request, "urlopen", fake_urlopen)
    return sent


def test_trigger_posts_command_to_ingest_with_auth(posted):
    cli._trigger("passkey:run", {"nonce": "n" * 20}, "Approve", "msg")

    (sent,) = posted
    assert sent["url"] == "http://127.0.0.1:8888/lab/jupyterlab-notifications-extension/ingest"
    assert sent["headers"]["Authorization"] == "token tok123"

    action = sent["payload"]["actions"][0]
    assert action["commandId"] == "passkey:run"
    assert action["args"] == {"nonce": "n" * 20}
    assert action["label"] == "Approve"


def test_trigger_keeps_the_button_up_and_pushes_immediately(posted):
    # A ceremony needs the click; a notification that auto-closes loses the gesture.
    cli._trigger("passkey:run", {"nonce": "n" * 20}, "Approve", "msg")

    payload = posted[0]["payload"]
    assert payload["autoClose"] is False
    assert payload["immediate"] is True


def test_trigger_omits_auth_header_when_no_token(posted, monkeypatch):
    monkeypatch.setattr(cli, "_server", lambda: ("http://127.0.0.1:8888", None))
    cli._trigger("passkey:run", {"nonce": "n" * 20}, "Approve", "msg")

    assert "Authorization" not in posted[0]["headers"]


def test_get_prints_prf_and_consumes_the_relay(relay_dir, capsys, monkeypatch):
    def fake_trigger(command_id, args_obj, label, message):
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True, "cred_id": "CID", "prf": "PRFVALUE"})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    monkeypatch.setattr(cli, "_wait", lambda path, timeout: None)

    rc = cli.cmd_get(_ns(rp_id="h", cred_id="CID", prf_salt="SALT", timeout=1.0))

    assert rc == 0
    assert capsys.readouterr().out.strip() == "PRFVALUE"
    # One-shot: the relay must not survive its read.
    assert list(relay_dir.iterdir()) == []


def test_get_without_salt_prints_cred_id_not_prf(relay_dir, capsys, monkeypatch):
    def fake_trigger(command_id, args_obj, label, message):
        assert "prf_salt" not in args_obj
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True, "cred_id": "CID"})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    monkeypatch.setattr(cli, "_wait", lambda path, timeout: None)

    rc = cli.cmd_get(_ns(rp_id="h", cred_id="CID", prf_salt=None, timeout=1.0))

    assert rc == 0
    assert capsys.readouterr().out.strip() == "CID"


def test_get_with_salt_fails_loudly_when_no_prf_comes_back(relay_dir, monkeypatch):
    # prf_enabled lies on Windows Hello, so the get is authoritative - it must not
    # silently print an empty value that a caller would feed into key derivation.
    def fake_trigger(command_id, args_obj, label, message):
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True, "cred_id": "CID"})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    monkeypatch.setattr(cli, "_wait", lambda path, timeout: None)

    with pytest.raises(SystemExit, match="no PRF"):
        cli.cmd_get(_ns(rp_id="h", cred_id="CID", prf_salt="SALT", timeout=1.0))


def test_failed_ceremony_exits_with_the_error(relay_dir, monkeypatch):
    def fake_trigger(command_id, args_obj, label, message):
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": False, "error": "not-allowed"})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    monkeypatch.setattr(cli, "_wait", lambda path, timeout: None)

    with pytest.raises(SystemExit, match="not-allowed"):
        cli.cmd_get(_ns(rp_id="h", cred_id="CID", prf_salt=None, timeout=1.0))


def test_create_prints_cred_id_and_sends_a_user(relay_dir, capsys, monkeypatch):
    seen = {}

    def fake_trigger(command_id, args_obj, label, message):
        seen.update(args_obj)
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True, "cred_id": "NEWCID", "prf_enabled": False})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    monkeypatch.setattr(cli, "_wait", lambda path, timeout: None)

    rc = cli.cmd_create(_ns(rp_id="h", user_name="alice", timeout=1.0))

    assert rc == 0
    assert capsys.readouterr().out.strip() == "NEWCID"
    assert seen["op"] == "create"
    assert seen["user"]["name"] == "alice"


def test_passphrase_prints_the_path_never_the_value(relay_dir, capsys, monkeypatch):
    # The whole point of the passphrase relay: the secret must not transit the terminal.
    SECRET = "correct horse battery staple"

    def fake_trigger(command_id, args_obj, label, message):
        assert command_id == "passkey:passphrase"
        (relay_dir / f"{args_obj['nonce']}.pass").write_text(SECRET)

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    monkeypatch.setattr(cli, "_wait", lambda path, timeout: None)

    rc = cli.cmd_passphrase(_ns(prompt="Recovery passphrase", timeout=1.0))

    out = capsys.readouterr().out
    assert rc == 0
    assert SECRET not in out
    assert out.strip().endswith(".pass")
    # Left in place for the consumer to read - unlike a ceremony relay.
    assert os.path.exists(out.strip())


def test_passphrase_passes_the_prompt_through(relay_dir, monkeypatch):
    seen = {}

    def fake_trigger(command_id, args_obj, label, message):
        seen.update(args_obj)
        (relay_dir / f"{args_obj['nonce']}.pass").write_text("x")

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    monkeypatch.setattr(cli, "_wait", lambda path, timeout: None)
    cli.cmd_passphrase(_ns(prompt="Recovery passphrase", timeout=1.0))

    assert seen["prompt"] == "Recovery passphrase"


def test_nonces_satisfy_the_server_guard(relay_dir, monkeypatch):
    # The server rejects anything outside [A-Za-z0-9_-]{16,128}; a CLI-minted nonce
    # that trips that guard would fail only at the very end of a ceremony.
    import re

    guard = re.compile(r"[A-Za-z0-9_-]{16,128}")
    nonces = []

    def fake_trigger(command_id, args_obj, label, message):
        nonces.append(args_obj["nonce"])
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True, "cred_id": "C"})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    monkeypatch.setattr(cli, "_wait", lambda path, timeout: None)
    for _ in range(5):
        cli.cmd_get(_ns(rp_id="h", cred_id="C", prf_salt=None, timeout=1.0))

    assert len(set(nonces)) == 5
    assert all(guard.fullmatch(n) for n in nonces)


def test_wait_times_out_when_nothing_is_relayed(relay_dir):
    with pytest.raises(SystemExit, match="no relay"):
        cli._wait(str(relay_dir / "never.json"), timeout=0.01)


def _server_list(monkeypatch, record):
    class _Out:
        returncode = 0
        stdout = json.dumps(record)

    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: _Out())


def test_server_reads_port_and_base_url_from_the_server_list(monkeypatch):
    monkeypatch.delenv("JUPYTERHUB_API_TOKEN", raising=False)
    monkeypatch.delenv("JPY_API_TOKEN", raising=False)
    monkeypatch.delenv("JUPYTER_TOKEN", raising=False)
    _server_list(monkeypatch, {"port": 9999, "base_url": "/user/bob/", "token": "T"})

    assert cli._server() == ("http://127.0.0.1:9999/user/bob", "T")


def test_hub_token_beats_the_server_list_token(monkeypatch):
    # Under JupyterHub the server's own token is rejected by its API with a 403 - only
    # the hub-issued token authenticates. Preferring the server list here is a live
    # 403 that no amount of mocking the transport would reveal.
    monkeypatch.setenv("JUPYTERHUB_API_TOKEN", "HUBTOK")
    _server_list(monkeypatch, {"port": 8888, "base_url": "/user/bob/", "token": "SERVERTOK"})

    _, token = cli._server()
    assert token == "HUBTOK"


def test_server_list_token_is_the_last_resort(monkeypatch):
    for var in ("JUPYTERHUB_API_TOKEN", "JPY_API_TOKEN", "JUPYTER_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    _server_list(monkeypatch, {"port": 8888, "base_url": "/", "token": "SERVERTOK"})

    assert cli._server()[1] == "SERVERTOK"


def test_server_falls_back_to_the_jupyterhub_prefix(monkeypatch):
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError))
    monkeypatch.setenv("JUPYTER_PORT", "7777")
    monkeypatch.setenv("JUPYTERHUB_SERVICE_PREFIX", "/user/carol/")
    monkeypatch.setenv("JUPYTERHUB_API_TOKEN", "HUBTOK")

    assert cli._server() == ("http://127.0.0.1:7777/user/carol", "HUBTOK")


def _drive_main(monkeypatch, argv, seen):
    """Run main() far enough to see what timeout reached the wait, then let it die.

    A ceremony subcommand dies on the relay that never appears (FileNotFoundError);
    passphrase just prints a path. An argparse rejection raises SystemExit, which is
    deliberately NOT suppressed - that is the failure this test exists to catch.
    """
    monkeypatch.setattr(cli, "_trigger", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_wait", lambda path, timeout: seen.update(timeout=timeout))
    monkeypatch.setattr(cli.sys, "argv", ["jupyterlab-passkey", *argv])
    with contextlib.suppress(FileNotFoundError):
        cli.main()


@pytest.mark.parametrize("argv", [
    ["get", "--rp-id", "h", "--cred-id", "C", "--timeout", "5"],
    ["create", "--rp-id", "h", "--timeout", "5"],
    ["passphrase", "--timeout", "5"],
])
def test_timeout_is_accepted_after_the_subcommand(argv, monkeypatch, relay_dir):
    # argparse binds main-parser options before the subcommand, so a top-level
    # --timeout would reject `get --timeout 5` - the form anyone would actually type.
    seen = {}
    _drive_main(monkeypatch, argv, seen)

    assert seen["timeout"] == 5.0


def test_timeout_defaults_to_120_when_omitted(monkeypatch, relay_dir):
    seen = {}
    _drive_main(monkeypatch, ["passphrase"], seen)

    assert seen["timeout"] == 120.0


class _ns:
    """Stand-in for the argparse namespace each subcommand receives."""

    def __init__(self, **kw):
        self.__dict__.update(kw)
