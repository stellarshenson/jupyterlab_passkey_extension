"""Tests for the jupyterlab-passkey CLI.

The CLI is a proxy: it assembles a notification carrying a command, then reads back the
relay the server writes. Both halves are mocked here - the ceremony itself belongs to
the Galata suite. What matters is the contract between them: the right command id and
args go out, the relay is consumed exactly once, and no secret reaches stdout that
shouldn't.
"""

import argparse
import contextlib
import json
import os
import subprocess

import pytest

from jupyterlab_passkey_extension import cli
from jupyterlab_passkey_extension.routes import NONCE_RE, relay_dir as server_relay_dir


@pytest.fixture
def relay_dir(tmp_path, monkeypatch):
    d = tmp_path / "relay"
    d.mkdir()
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(d))
    return d


@pytest.fixture
def no_wait(monkeypatch):
    """Skip the relay poll.

    One fixture, not nine copies of the lambda: the last signature change to `_wait`
    forced nine identical edits. Note these tests would pass without it - their
    fake_trigger writes the relay before the poll starts - so stubbing here keeps them
    honest about which side they are exercising, and keeps a real sleep out of the loop.
    """
    monkeypatch.setattr(cli, "_wait", lambda path, timeout, on_timeout: None)


@pytest.fixture
def posted(monkeypatch):
    """Capture the notification payload instead of sending it."""
    sent = []

    def fake_urlopen(req, timeout=None):
        sent.append({
            "url": req.full_url,
            "headers": dict(req.headers),
            "payload": json.loads(req.data.decode()),
            "timeout": timeout,
        })

        class _R:
            def read(self):
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False
        return _R()

    monkeypatch.setattr(cli, "_server", lambda: ("http://127.0.0.1:8888/lab", "tok123"))
    monkeypatch.setattr(cli.urllib.request, "urlopen", fake_urlopen)
    return sent


def test_cli_and_server_resolve_the_same_relay_dir(monkeypatch):
    # The one coupling that makes the bridge work. Every other test overrides the env
    # var, so a divergent default would sail through the whole suite and strand every
    # real relay - the CLI polling one path while the server writes another.
    monkeypatch.delenv("JLAB_PASSKEY_RELAY_DIR", raising=False)

    assert cli.relay_dir is server_relay_dir
    assert cli.relay_dir() == server_relay_dir()


def test_trigger_posts_command_to_ingest_with_auth(posted):
    cli._trigger("passkey:run", {"nonce": "n" * 20}, "Approve", "msg")

    (sent,) = posted
    assert sent["url"] == f"http://127.0.0.1:8888/lab/{cli.INGEST}"
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


def test_trigger_is_bounded_by_its_own_timeout(posted):
    # --timeout governs the wait for the click, never this call. Unbounded, a server
    # that accepts the connection and stalls hangs the CLI forever.
    cli._trigger("passkey:run", {"nonce": "n" * 20}, "Approve", "msg")

    assert posted[0]["timeout"] == cli.TRIGGER_TIMEOUT


def test_a_404_trigger_names_the_missing_extension(monkeypatch):
    # The CLI's hard dependency. A bare "404 Not Found" sends the user hunting through
    # their own config instead of at the one installable that is missing.
    monkeypatch.setattr(cli, "_server", lambda: ("http://127.0.0.1:8888", None))

    def boom(req, timeout=None):
        raise cli.urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    monkeypatch.setattr(cli.urllib.request, "urlopen", boom)

    with pytest.raises(SystemExit, match="notifications extension"):
        cli._trigger("passkey:run", {"nonce": "n" * 20}, "Approve", "msg")


def test_get_prints_prf_and_consumes_the_relay(relay_dir, capsys, monkeypatch, no_wait):
    def fake_trigger(command_id, args_obj, label, message):
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True, "cred_id": "CID", "prf": "PRFVALUE"})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)

    rc = cli.cmd_get(_ns(rp_id="h", cred_id="CID", prf_salt="SALT", timeout=1.0))

    assert rc == 0
    assert capsys.readouterr().out.strip() == "PRFVALUE"
    # One-shot: the relay must not survive its read.
    assert list(relay_dir.iterdir()) == []


def test_get_without_salt_prints_cred_id_not_prf(relay_dir, capsys, monkeypatch, no_wait):
    def fake_trigger(command_id, args_obj, label, message):
        assert "prf_salt" not in args_obj
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True, "cred_id": "CID"})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)

    rc = cli.cmd_get(_ns(rp_id="h", cred_id="CID", prf_salt=None, timeout=1.0))

    assert rc == 0
    assert capsys.readouterr().out.strip() == "CID"


def test_get_with_salt_fails_loudly_when_no_prf_comes_back(relay_dir, monkeypatch, no_wait):
    # prf_enabled lies on Windows Hello, so the get is authoritative - it must not
    # silently print an empty value that a caller would feed into key derivation.
    def fake_trigger(command_id, args_obj, label, message):
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True, "cred_id": "CID"})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)

    with pytest.raises(SystemExit, match="no PRF"):
        cli.cmd_get(_ns(rp_id="h", cred_id="CID", prf_salt="SALT", timeout=1.0))


def test_failed_ceremony_exits_with_the_error(relay_dir, monkeypatch, no_wait):
    def fake_trigger(command_id, args_obj, label, message):
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": False, "error": "not-allowed"})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)

    with pytest.raises(SystemExit, match="not-allowed"):
        cli.cmd_get(_ns(rp_id="h", cred_id="CID", prf_salt=None, timeout=1.0))


def test_create_prints_cred_id_and_sends_a_user(relay_dir, capsys, monkeypatch, no_wait):
    seen = {}

    def fake_trigger(command_id, args_obj, label, message):
        seen.update(args_obj)
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True, "cred_id": "NEWCID", "prf_enabled": False})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)

    rc = cli.cmd_create(_ns(rp_id="h", user_name="alice", timeout=1.0))

    assert rc == 0
    assert capsys.readouterr().out.strip() == "NEWCID"
    assert seen["op"] == "create"
    assert seen["user"]["name"] == "alice"


def test_passphrase_prints_the_path_never_the_value(relay_dir, capsys, monkeypatch, no_wait):
    # The whole point of the passphrase relay: the secret must not transit the terminal.
    SECRET = "correct horse battery staple"

    def fake_trigger(command_id, args_obj, label, message):
        assert command_id == "passkey:passphrase"
        (relay_dir / f"{args_obj['nonce']}.pass").write_text(SECRET)

    monkeypatch.setattr(cli, "_trigger", fake_trigger)

    rc = cli.cmd_passphrase(_ns(prompt="Recovery passphrase", timeout=1.0))

    out = capsys.readouterr().out
    assert rc == 0
    assert SECRET not in out
    assert out.strip().endswith(".pass")
    # Left in place for the consumer to read - unlike a ceremony relay.
    assert os.path.exists(out.strip())


def test_passphrase_passes_the_prompt_through(relay_dir, monkeypatch, no_wait):
    seen = {}

    def fake_trigger(command_id, args_obj, label, message):
        seen.update(args_obj)
        (relay_dir / f"{args_obj['nonce']}.pass").write_text("x")

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    cli.cmd_passphrase(_ns(prompt="Recovery passphrase", timeout=1.0))

    assert seen["prompt"] == "Recovery passphrase"


def test_nonces_satisfy_the_server_guard(relay_dir, monkeypatch, no_wait):
    # Assert against the SERVER's own NONCE_RE, never a copy of it. A private regex here
    # would keep passing if routes.py tightened its guard, while every real ceremony
    # 400s at the very last step.
    guard = NONCE_RE
    nonces = []

    def fake_trigger(command_id, args_obj, label, message):
        nonces.append(args_obj["nonce"])
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True, "cred_id": "C"})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    for _ in range(5):
        cli.cmd_get(_ns(rp_id="h", cred_id="C", prf_salt=None, timeout=1.0))

    assert len(set(nonces)) == 5
    assert all(guard.fullmatch(n) for n in nonces)


def test_wait_times_out_when_nothing_is_relayed(relay_dir):
    with pytest.raises(SystemExit, match="no relay"):
        cli._wait(str(relay_dir / "never.json"), timeout=0.01, on_timeout="was it clicked?")


def _server_list(monkeypatch, record, argv_sink=None):
    """Stub `jupyter server list`, recording the argv it was actually asked to run."""
    def fake_run(cmd, *a, **k):
        if argv_sink is not None:
            argv_sink.extend(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(record), stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)


def test_server_list_is_asked_for_json(monkeypatch):
    # Without --json the command prints human text, json.loads throws, _server_list
    # swallows it into {}, and the JupyterHub base_url is silently lost -> 404. A mock
    # that ignores argv cannot see that, so assert the argv itself.
    argv = []
    _server_list(monkeypatch, {"port": 8888, "base_url": "/", "token": "T"}, argv)
    cli._server()

    assert argv[:3] == ["jupyter", "server", "list"]
    assert "--json" in argv


def test_server_reads_port_and_base_url_from_the_server_list(monkeypatch):
    for var in ("JUPYTERHUB_API_TOKEN", "JPY_API_TOKEN", "JUPYTER_TOKEN"):
        monkeypatch.delenv(var, raising=False)
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


def test_server_list_token_beats_a_stale_generic_env_token(monkeypatch):
    # JUPYTER_TOKEN is generic and easily stale (an old export in a shell rc). The
    # running server just handed us its real token; letting the stale value outrank it
    # is a 403 that reads like a config error.
    for var in ("JUPYTERHUB_API_TOKEN", "JPY_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("JUPYTER_TOKEN", "STALE")
    _server_list(monkeypatch, {"port": 8888, "base_url": "/", "token": "SERVERTOK"})

    assert cli._server()[1] == "SERVERTOK"


def test_tokenless_server_yields_no_token(monkeypatch):
    # The Galata test server sets IdentityProvider.token = "" - the empty-token branch
    # must resolve to None so no Authorization header is sent at all.
    for var in ("JUPYTERHUB_API_TOKEN", "JPY_API_TOKEN", "JUPYTER_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    _server_list(monkeypatch, {"port": 8888, "base_url": "/", "token": ""})

    assert cli._server()[1] is None


def test_a_tokenless_server_is_not_overridden_by_a_stale_env_token(monkeypatch):
    # token "" is the server ANSWERING "I want none" - not the absence of an answer.
    # Deleting JUPYTER_TOKEN here (as the sibling test does) would hide the bug: an
    # `or` chain falls through "" and sends the stale header to a server wanting none.
    for var in ("JUPYTERHUB_API_TOKEN", "JPY_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("JUPYTER_TOKEN", "STALE")
    _server_list(monkeypatch, {"port": 8888, "base_url": "/", "token": ""})

    assert cli._server()[1] is None


def test_generic_env_token_is_used_when_there_is_no_server_record(monkeypatch):
    # No server list at all - now JUPYTER_TOKEN is the only answer available.
    for var in ("JUPYTERHUB_API_TOKEN", "JPY_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("JUPYTER_TOKEN", "ENVTOK")
    monkeypatch.setattr(
        cli.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError)
    )

    assert cli._server()[1] == "ENVTOK"


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
    monkeypatch.setattr(cli, "_wait", lambda path, timeout, on_timeout: seen.update(timeout=timeout))
    monkeypatch.setattr(cli.sys, "argv", ["jupyterlab-passkey", *argv])
    try:
        cli.main()
    except SystemExit as e:
        # argparse rejects a bad option with code 2 - that IS the failure this test
        # exists to catch, so let it through. Anything else is just the relay that
        # never appears, which is expected once _wait has recorded what it was given.
        if e.code == 2:
            raise


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


def test_wait_accepts_a_relay_that_lands_in_the_final_sleep(relay_dir):
    """A near-miss must be a success, not a lost ceremony.

    `_wait` sleeps 0.4s between looks, so the last sleep straddles the deadline. Without
    a final check the relay is declared missing while sitting on disk: the user clicked
    in time, the ceremony is failed anyway, and the PRF is stranded because the caller
    that would have consumed it is the one raising.
    """
    relay = relay_dir / "landed.json"
    relay.write_text("{}")

    # Already past the deadline - the loop body never runs, only the final look can save
    # it. Deliberately not a sleep race: the assertion is that the check exists at all.
    cli._wait(str(relay), 0.0, "never seen")


def test_a_relay_that_lands_as_we_give_up_is_not_left_on_disk(relay_dir, monkeypatch):
    """The PRF must not outlive the run that timed out.

    `_wait` raises SystemExit, so with the wait outside `_run`'s try/finally the unlink
    never ran and key material stayed on disk with nobody left to collect it.
    """
    monkeypatch.setattr(cli, "_trigger", lambda *a, **k: None)
    nonce = "n" * 20
    relay = relay_dir / f"{nonce}.json"

    def wait_then_strand(path, timeout, on_timeout):
        # The relay lands, then we give up on it - the exact ordering that stranded it.
        relay.write_text(json.dumps({"ok": True, "prf": "KEY_MATERIAL"}))
        raise SystemExit("no relay")

    monkeypatch.setattr(cli, "_wait", wait_then_strand)

    with pytest.raises(SystemExit):
        cli._run({"nonce": nonce}, "label", "message", 1.0)

    assert not relay.exists(), "timing out left the PRF on disk"


def _ns(**kw):
    """The namespace each subcommand receives - the same type main() builds."""
    return argparse.Namespace(**kw)
