"""Tests for the jupyterlab-passkey CLI.

The CLI is a proxy: it assembles a notification carrying a command, then reads back the
relay the server writes. Both halves are mocked here - the ceremony itself belongs to
the Galata suite. What matters is the contract between them: the right command id and
args go out, the relay is consumed exactly once, and no secret reaches stdout that
shouldn't.
"""

import argparse
import contextlib
import io
import json
import os
import stat
import subprocess
import sys

import pytest

from jupyterlab_passkey_extension import cli
from jupyterlab_passkey_extension.routes import (
    NONCE_RE,
    ensure_relay_dir as server_ensure_relay_dir,
    relay_dir as server_relay_dir,
)

# For the tests that must run the CLI in a real subprocess to see a real exit code.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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

    # The identity is the assertion: one function, so the two cannot disagree about
    # either the path OR the ownership check that now guards it.
    assert cli.ensure_relay_dir is server_ensure_relay_dir
    # ...and the default it resolves. Asserted through relay_dir, not ensure_relay_dir,
    # because ensure_relay_dir would mkdir the real /dev/shm path as a side effect of a
    # unit test - the env var is deliberately unset here.
    assert server_relay_dir() == f"/dev/shm/jlab-passkey-{os.getuid()}"


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


@pytest.mark.parametrize("run", [
    lambda: cli.cmd_get(_ns(rp_id="h", cred_id="CID", prf_salt=None, timeout=1.0)),
    lambda: cli.cmd_create(_ns(rp_id="h", user_name="alice", timeout=1.0)),
])
def test_an_ok_relay_without_cred_id_answers_with_a_line_not_a_keyerror(
    relay_dir, monkeypatch, no_wait, run
):
    # The server writes any authenticated body verbatim, so ok:true with no cred_id is
    # reachable - a malformed writer, not a KeyError of ours.
    def fake_trigger(command_id, args_obj, label, message):
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)

    with pytest.raises(SystemExit, match="no cred_id"):
        run()


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

    rc = cli.cmd_passphrase(_ns(prompt="Recovery passphrase", once=False, timeout=1.0))

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
    cli.cmd_passphrase(_ns(prompt="Recovery passphrase", once=False, timeout=1.0))

    assert seen["prompt"] == "Recovery passphrase"


def test_passphrase_leaves_the_prompt_out_when_not_given(relay_dir, monkeypatch, no_wait):
    # The frontend picks the wording that suits the mode; sending a stale default here
    # would tell a one-field dialog to say "Enter the passphrase twice".
    seen = {}

    def fake_trigger(command_id, args_obj, label, message):
        seen.update(args_obj)
        (relay_dir / f"{args_obj['nonce']}.pass").write_text("x")

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    cli.cmd_passphrase(_ns(prompt=None, once=False, timeout=1.0))

    assert "prompt" not in seen
    assert "once" not in seen


def test_passphrase_once_asks_for_a_single_entry(relay_dir, monkeypatch, no_wait):
    seen = {}

    def fake_trigger(command_id, args_obj, label, message):
        seen.update(args_obj)
        (relay_dir / f"{args_obj['nonce']}.pass").write_text("x")

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    cli.cmd_passphrase(_ns(prompt=None, once=True, timeout=1.0))

    assert seen["once"] is True


COPY_SECRET = "s3cr3t-token-value"


class _FakeStdin:
    """A stdin the CLI can read the way it does in production.

    io.StringIO would not do: cmd_copy reads `sys.stdin.buffer` and decodes it
    strictly, because sys.stdin itself decodes with surrogateescape and would let
    bad bytes through to fail much later. A fake without a .buffer would let a
    regression back to sys.stdin.read() pass every test here.
    """

    def __init__(self, data, tty=False):
        self.buffer = io.BytesIO(data if isinstance(data, bytes) else data.encode())
        self._tty = tty

    def isatty(self):
        return self._tty


def test_copy_never_puts_the_secret_in_the_notification(relay_dir, tmp_path, posted):
    # The reason the copy flow has a relay at all. The notifications extension parks
    # every payload in an in-memory queue and pushes it to EVERY connected socket, so
    # the notification carries the ticket and the relay carries the secret. Asserted
    # against the real payload `_trigger` builds, not a stub's idea of it.
    src = tmp_path / "token.txt"
    src.write_text(COPY_SECRET)

    assert cli.cmd_copy(_copy_ns(file=str(src), label=None)) == 0

    payload = posted[0]["payload"]
    assert COPY_SECRET not in json.dumps(payload)
    args_obj = payload["actions"][0]["args"]
    assert set(args_obj) == {"nonce"}
    assert payload["actions"][0]["commandId"] == "passkey:copy"
    assert NONCE_RE.fullmatch(args_obj["nonce"])


@pytest.mark.parametrize(
    "boom",
    [
        # What _trigger actually raises: a lab without the notifications extension
        # (404), a rejected POST, an unreachable server - all SystemExit.
        SystemExit("cannot reach http://127.0.0.1:8888 - is JupyterLab running?"),
        # And Ctrl+C between the stage and the POST, which is why the unstage
        # catches BaseException rather than Exception.
        KeyboardInterrupt(),
    ],
)
def test_copy_unstages_the_secret_when_the_trigger_fails(relay_dir, tmp_path, monkeypatch, boom):
    # The nonce dies with this process, so a relay left behind by a failed trigger is
    # not "uncollected" - it is uncollectable, and every retry strands another
    # plaintext copy while the CLI reports failure. `_run` puts its unlink in a
    # finally for exactly this reason; copy has to as well.
    src = tmp_path / "token.txt"
    src.write_text(COPY_SECRET)

    def fake_trigger(command_id, args_obj, label, message):
        raise boom

    monkeypatch.setattr(cli, "_trigger", fake_trigger)

    with pytest.raises(type(boom)):
        cli.cmd_copy(_copy_ns(file=str(src), label=None))

    assert list(relay_dir.iterdir()) == []


def test_copy_keeps_the_secret_when_only_the_confirmation_print_fails(relay_dir, tmp_path, posted, monkeypatch):
    # The POST has landed and the button is live by the time _trigger prints. A
    # broken stderr - a full log volume, a pipe whose reader has gone - must not
    # look like a failed trigger, because copy answers a failed trigger by
    # destroying the secret the live button is about to ask for.
    src = tmp_path / "token.txt"
    src.write_text(COPY_SECRET)

    class _BrokenStderr:
        def write(self, *a):
            raise BrokenPipeError(32, "Broken pipe")

        def flush(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(cli.sys, "stderr", _BrokenStderr())

    assert cli.cmd_copy(_copy_ns(file=str(src), label=None)) == 0

    # The notification went out, so the secret must still be there to collect.
    nonce = posted[0]["payload"]["actions"][0]["args"]["nonce"]
    assert (relay_dir / f"{nonce}.secret").read_text() == COPY_SECRET


@pytest.mark.skipif(
    not os.path.exists("/dev/full"), reason="needs /dev/full to fill a real stderr"
)
def test_a_broken_stderr_does_not_fail_the_process_at_shutdown():
    # In a REAL process, because nothing else can see this. stderr is buffered, so a
    # failed write leaves bytes behind and CPython retries that flush at interpreter
    # shutdown - after main() has returned, where no except reaches - then exits 120.
    # Catching the write error does not help; for a short line-buffered message the
    # write often does not raise at all, and the whole failure happens at shutdown.
    # A fake stderr whose flush() is a no-op holds no buffer and cannot reproduce it,
    # and asserting on a function's RETURN value never sees a process exit code.
    #
    # 120 is not cosmetic: it tells a caller the command failed while `copy`'s button
    # is live and its secret staged, so the retry it invites strands another copy -
    # the exact harm the unstage exists to prevent.
    #
    # The message must be short and realistic. A large write flushes through a
    # different path that exits 0 even when this is broken, so an 'x' * 4096 here
    # would pass against the bug.
    script = (
        "import sys; sys.path.insert(0, %r);"
        "from jupyterlab_passkey_extension.cli import _say;"
        "_say(\"click 'Copy to clipboard' in your JupyterLab tab\");"
        "print('stdout still works')" % str(REPO_ROOT)
    )
    with open("/dev/full", "w") as full:
        r = subprocess.run(
            [sys.executable, "-c", script],
            stderr=full, stdout=subprocess.PIPE, text=True,
        )

    assert r.returncode == 0, f"exit {r.returncode} - stderr poisoned the shutdown flush"
    assert "stdout still works" in r.stdout


@pytest.mark.skipif(
    not os.path.exists("/dev/full"), reason="needs /dev/full to fill a real stderr"
)
def test_a_second_message_survives_the_first_dropping_stderr():
    # cmd_copy says two things, and the first one drops the stream when it is broken.
    # The second then meets a CLOSED stderr, and printing to one raises ValueError,
    # not OSError - so a handler that catches only OSError takes the whole command
    # down over a progress message. Needs a real TextIOWrapper: a hand-rolled fake
    # does not raise ValueError when closed, and would pass against the bug.
    script = (
        "import sys; sys.path.insert(0, %r);"
        "from jupyterlab_passkey_extension.cli import _say;"
        "_say('first - poisons and drops it');"
        "_say('second - meets a closed stream');"
        "print('stdout still works')" % str(REPO_ROOT)
    )
    with open("/dev/full", "w") as full:
        r = subprocess.run(
            [sys.executable, "-c", script],
            stderr=full, stdout=subprocess.PIPE, text=True,
        )

    assert r.returncode == 0, f"exit {r.returncode} - a second message broke the command"
    assert "stdout still works" in r.stdout


def test_copy_refuses_to_read_a_secret_from_a_terminal(relay_dir, monkeypatch):
    # sys.stdin.read() on a tty echoes the secret onto the screen and into the
    # scrollback - the exact leak the rest of this CLI is built to avoid.
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin(COPY_SECRET, tty=True))
    monkeypatch.setattr(cli, "_trigger", _never_triggered)

    with pytest.raises(SystemExit, match="refusing to read a secret from a terminal"):
        cli.cmd_copy(_copy_ns(file="-", label=None))
    assert list(relay_dir.iterdir()) == []


def test_copy_label_names_the_secret_without_carrying_it(relay_dir, tmp_path, posted):
    # Two staged secrets raise two never-expiring toasts; without a label they are
    # byte-identical and the user cannot tell which button yields which.
    src = tmp_path / "token.txt"
    src.write_text(COPY_SECRET)

    cli.cmd_copy(_copy_ns(file=str(src), label="GitHub token"))

    payload = posted[0]["payload"]
    assert payload["message"] == "A secret is waiting: GitHub token"
    # The label names the secret; it must not become a place to leak one.
    assert COPY_SECRET not in json.dumps(payload)
    # It rides in the command args too, so the frontend can name the secret if
    # it has to ask for a second click after a refused clipboard write.
    args = payload["actions"][0]["args"]
    assert args["label"] == "GitHub token"
    assert set(args) == {"nonce", "label"}


def test_copy_stages_the_secret_readable_only_by_us(relay_dir, tmp_path, capsys, monkeypatch):
    src = tmp_path / "token.txt"
    src.write_text(COPY_SECRET)
    seen = {}

    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: seen.update(a))
    cli.cmd_copy(_copy_ns(file=str(src), label=None))

    relay = relay_dir / f"{seen['nonce']}.secret"
    assert relay.read_text() == COPY_SECRET
    assert stat.S_IMODE(os.stat(relay).st_mode) == 0o600
    # A secret echoed back to the terminal would defeat the whole exercise.
    assert COPY_SECRET not in capsys.readouterr().out


def test_copy_reads_stdin_when_no_file_is_given(relay_dir, monkeypatch):
    seen = {}
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin(COPY_SECRET + "\n"))
    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: seen.update(a))

    assert cli.cmd_copy(_copy_ns(file="-", label=None)) == 0
    assert (relay_dir / f"{seen['nonce']}.secret").read_text() == COPY_SECRET


@pytest.mark.parametrize(
    "raw,staged",
    [
        ("tok\n", "tok"),  # echo, cat, a here-string: the newline is the shell's, not the user's
        ("tok", "tok"),  # printf %s - nothing to strip
        ("tok\n\n", "tok\n"),  # only ONE goes; a deliberate blank line survives
        ("-----BEGIN-----\nabc\n-----END-----\n", "-----BEGIN-----\nabc\n-----END-----"),
    ],
)
def test_copy_strips_exactly_one_trailing_newline(relay_dir, monkeypatch, raw, staged):
    # A trailing newline pasted into a login field submits it early; a multi-line key
    # must survive intact. One newline is the line $(...) already draws.
    seen = {}
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin(raw))
    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: seen.update(a))

    cli.cmd_copy(_copy_ns(file="-", label=None))

    assert (relay_dir / f"{seen['nonce']}.secret").read_text() == staged


@pytest.mark.parametrize("raw", ["", "\n"])
def test_copy_refuses_empty_input(relay_dir, monkeypatch, raw):
    # Staging nothing would raise a button that copies an empty string over whatever
    # the user already had on their clipboard.
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin(raw))
    monkeypatch.setattr(cli, "_trigger", _never_triggered)

    with pytest.raises(SystemExit, match="nothing to copy"):
        cli.cmd_copy(_copy_ns(file="-", label=None))
    assert list(relay_dir.iterdir()) == []


def test_copy_rejects_stdin_bytes_that_are_not_text(relay_dir, monkeypatch):
    # sys.stdin decodes with surrogateescape whatever the locale, so `printf
    # 'caf\xe9' | jupyterlab-passkey copy` would NOT raise where it is guarded: the
    # bad bytes become lone surrogates, sail past the empty check, and die inside
    # write_relay as a UnicodeEncodeError - a ValueError, caught by nothing, so the
    # user gets a traceback on the invocation the README documents. Reading
    # sys.stdin.buffer and decoding strictly is what puts the error at the boundary.
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin(b"caf\xe9"))
    monkeypatch.setattr(cli, "_trigger", _never_triggered)

    with pytest.raises(SystemExit, match="stdin is not text"):
        cli.cmd_copy(_copy_ns(file="-", label=None))
    assert list(relay_dir.iterdir()) == []


def test_copy_names_stdin_rather_than_a_dash_in_its_errors(relay_dir, monkeypatch):
    # "- is not text" reads like a typo, not a diagnosis.
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin(b"\xff\xfe"))
    monkeypatch.setattr(cli, "_trigger", _never_triggered)

    with pytest.raises(SystemExit) as exc:
        cli.cmd_copy(_copy_ns(file="-", label=None))
    assert "- is not text" not in str(exc.value)


def test_copy_fails_loudly_on_an_unreadable_file(relay_dir, monkeypatch):
    monkeypatch.setattr(cli, "_trigger", _never_triggered)

    with pytest.raises(SystemExit, match="cannot read"):
        cli.cmd_copy(_copy_ns(file=str(relay_dir / "nope.txt"), label=None))
    assert list(relay_dir.iterdir()) == []


def test_copy_defaults_to_stdin_through_main(relay_dir, monkeypatch):
    # Through main(), not cmd_copy: every CLI bug this project has shipped lived in
    # argv parsing, which calling the subcommand directly never touches.
    seen = {}
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin(COPY_SECRET + "\n"))
    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: seen.update(a))
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "copy"])

    assert cli.main() == 0
    assert (relay_dir / f"{seen['nonce']}.secret").read_text() == COPY_SECRET


def test_copy_without_block_does_not_wait(relay_dir, tmp_path, monkeypatch):
    # The default is fire and forget, and the secret is left staged for the click that
    # has not happened yet. A _wait_gone called here would hang the caller for two
    # minutes on a command documented to return at once.
    src = tmp_path / "token.txt"
    src.write_text(COPY_SECRET)

    def never(*a, **kw):
        raise AssertionError("copy waited without --block")

    monkeypatch.setattr(cli, "_wait_gone", never)
    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: None)

    assert cli.cmd_copy(_copy_ns(file=str(src), label=None)) == 0
    # Still staged: the button is live and the secret is what it will ask for.
    assert len(list(relay_dir.iterdir())) == 1


def test_copy_block_returns_when_the_browser_collects_the_secret(relay_dir, tmp_path, monkeypatch):
    # The `secret` endpoint reads its relay and unlinks it in the same breath, so the
    # file disappearing IS the collection signal - there is nothing else to watch.
    src = tmp_path / "token.txt"
    src.write_text(COPY_SECRET)
    seen = {}

    def collect_it(command_id, args_obj, label, message):
        # Stand in for the click: the server consumed the relay.
        seen.update(args_obj)
        os.unlink(relay_dir / f"{args_obj['nonce']}.secret")

    monkeypatch.setattr(cli, "_trigger", collect_it)

    assert cli.cmd_copy(_copy_ns(file=str(src), label=None, block=True, timeout=5.0)) == 0
    assert seen["nonce"]
    assert list(relay_dir.iterdir()) == []


def test_copy_block_shreds_the_secret_it_gave_up_on(relay_dir, tmp_path, monkeypatch):
    # A timeout means nobody collected it. Leaving it staged hands a live button to
    # whoever clicks next, long after the caller gave up and moved on - and the caller
    # has already been told, by the exit 1, that the secret did not land.
    src = tmp_path / "token.txt"
    src.write_text(COPY_SECRET)

    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: None)
    # Stub the wait rather than drive its clock: what is under test here is cmd_copy's
    # finally, not the deadline arithmetic - which the _wait_gone tests below own.
    def timed_out(path, timeout, on_timeout):
        raise SystemExit(f"not copied after {timeout:.0f}s - {on_timeout}")

    monkeypatch.setattr(cli, "_wait_gone", timed_out)

    with pytest.raises(SystemExit, match="not copied after"):
        cli.cmd_copy(_copy_ns(file=str(src), label=None, block=True, timeout=5.0))

    assert list(relay_dir.iterdir()) == []


def test_copy_rejects_a_timeout_that_would_do_nothing(relay_dir, tmp_path, monkeypatch):
    # Without --block nothing waits, so accepting --timeout and ignoring it would tell
    # a caller they had bounded something they had not.
    src = tmp_path / "token.txt"
    src.write_text(COPY_SECRET)
    monkeypatch.setattr(cli, "_trigger", _never_triggered)

    with pytest.raises(SystemExit, match="--timeout only applies with --block"):
        cli.cmd_copy(_copy_ns(file=str(src), label=None, block=False, timeout=5.0))

    # Refused before staging: nothing to clean up.
    assert list(relay_dir.iterdir()) == []


def test_copy_block_through_main_waits_and_defaults_its_timeout(relay_dir, monkeypatch):
    # Through main(), because --block is only real if argv parsing produces it.
    waited = {}
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin(COPY_SECRET + "\n"))
    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: None)
    monkeypatch.setattr(
        cli, "_wait_gone",
        lambda path, timeout, on_timeout: waited.update(path=path, timeout=timeout),
    )
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "copy", "--block"])

    assert cli.main() == 0
    assert waited["timeout"] == cli.CLICK_TIMEOUT
    assert waited["path"].endswith(".secret")


def test_wait_gone_returns_the_moment_the_relay_disappears(relay_dir):
    relay = relay_dir / "n.secret"
    relay.write_text("x")

    # Already gone: the fast path, and the one --block hits whenever the user is
    # quicker than the first poll.
    relay.unlink()
    cli._wait_gone(str(relay), 5.0, "why")


def test_wait_gone_takes_a_last_look_after_the_deadline(relay_dir, monkeypatch):
    # The mirror of _wait's final check. The last sleep straddles the deadline, so a
    # click landing in that window would be reported as a timeout - and cmd_copy would
    # then shred the secret it had just delivered, and exit 1 on a success.
    relay = relay_dir / "n.secret"
    relay.write_text("x")

    # deadline = 0 + 5. The poll at 0.1 still sees the file; the click lands during the
    # sleep; the next read of the clock is already past the deadline, so the loop ends
    # without ever having seen it gone. Only the check after the loop can notice.
    clock = iter([0.0, 0.1, 100.0])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(cli.time, "sleep", lambda _: relay.unlink())

    cli._wait_gone(str(relay), 5.0, "why")

    assert not relay.exists()


def test_wait_gone_gives_up_on_a_relay_nobody_collects(relay_dir, monkeypatch):
    relay = relay_dir / "n.secret"
    relay.write_text("x")

    clock = iter([0.0, 0.1, 100.0])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(cli.time, "sleep", lambda _: None)

    with pytest.raises(SystemExit, match="not copied after 5s"):
        cli._wait_gone(str(relay), 5.0, "was the button clicked?")


def test_a_squatted_relay_dir_answers_with_a_line_not_a_traceback(tmp_path, monkeypatch):
    """A co-tenant squatting /dev/shm is a real, fixable condition - diagnose it.

    ensure_relay_dir raises PermissionError out of os.lstat. Unwrapped, that reaches the
    user as a traceback on the invocation the README documents, which is precisely the
    failure quality every other error path here exists to avoid.
    """
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    squatted = tmp_path / "relay"
    squatted.symlink_to(attacker)
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(squatted))
    monkeypatch.setattr(cli.sys, "stdin", _FakeStdin("s3cret\n"))
    monkeypatch.setattr(cli, "_trigger", _never_triggered)

    with pytest.raises(SystemExit, match="refusing to use the relay directory"):
        cli.cmd_copy(_copy_ns(file="-", label=None))

    # The diagnosis is secondary; not handing the attacker the secret is the point.
    assert list(attacker.iterdir()) == []


def _never_triggered(command_id, args_obj, label, message):
    raise AssertionError("a notification was raised for a secret that never staged")


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


def test_a_base64url_value_starting_with_a_dash_survives_argv(relay_dir, capsys, monkeypatch, no_wait):
    """base64url's alphabet includes "-", so ~1 in 64 cred_ids and salts begin with one.

    argparse reads any leading-dash token as an option, so the documented
    `--cred-id "$cred"` died with "expected one argument" before any ceremony ran - on
    an unlucky credential only, which is how it reached a release. Every other test in
    this file calls cmd_get/cmd_create directly with a namespace, so argv parsing was
    never exercised and nothing here could have caught it. Drive main() for that reason.
    """
    seen = {}

    def fake_trigger(command_id, args_obj, label, message):
        seen.update(args_obj)
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True, "cred_id": "-CID", "prf": "PRFVALUE"})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    monkeypatch.setattr(sys, "argv", [
        "jupyterlab-passkey", "get", "--rp-id", "h",
        "--cred-id", "-Ab7xK9mQ2vLpZ", "--prf-salt", "-DashSalt",
    ])

    assert cli.main() == 0
    # Not merely parsed - the dash must reach the ceremony unmangled, or the
    # authenticator is handed a different credential than the caller named.
    assert seen["cred_id"] == "-Ab7xK9mQ2vLpZ"
    assert seen["prf_salt"] == "-DashSalt"
    assert capsys.readouterr().out.strip() == "PRFVALUE"


def test_the_equals_form_still_parses(relay_dir, capsys, monkeypatch, no_wait):
    """The glue must not double-handle a value the caller already attached with "=" ."""
    seen = {}

    def fake_trigger(command_id, args_obj, label, message):
        seen.update(args_obj)
        (relay_dir / f"{args_obj['nonce']}.json").write_text(
            json.dumps({"nonce": args_obj["nonce"], "ok": True, "cred_id": "CID", "prf": "P"})
        )

    monkeypatch.setattr(cli, "_trigger", fake_trigger)
    monkeypatch.setattr(sys, "argv", [
        "jupyterlab-passkey", "get", "--rp-id=h", "--cred-id=-Ab7", "--prf-salt=-S",
    ])

    assert cli.main() == 0
    assert seen["cred_id"] == "-Ab7"
    assert seen["prf_salt"] == "-S"


def test_a_flag_with_no_value_still_errors(monkeypatch):
    """The glue must not swallow a genuine mistake into a silent misparse."""
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "get", "--rp-id", "h", "--cred-id"])
    with pytest.raises(SystemExit):
        cli.main()


def _ns(**kw):
    """The namespace each subcommand receives - the same type main() builds."""
    return argparse.Namespace(**kw)


def _copy_ns(**kw):
    """A `copy` namespace, defaulted exactly as its subparser defaults it.

    The defaults are duplicated from main(), so they can drift from it - which is why
    test_copy_defaults_match_the_parser below parses a real argv and asserts they
    still agree. Without that, every test here could keep passing against a flag main()
    no longer sets.
    """
    return argparse.Namespace(**{"file": "-", "label": None, "block": False, "timeout": None, **kw})


def test_copy_defaults_match_the_parser(monkeypatch):
    """_copy_ns must be what argparse actually hands cmd_copy for a bare `copy`."""
    seen = {}
    monkeypatch.setattr(cli, "cmd_copy", lambda a: seen.update(vars(a)) or 0)
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "copy"])
    cli.main()
    defaults = vars(_copy_ns())
    for name, value in defaults.items():
        assert seen[name] == value, f"copy --{name} defaults to {seen[name]!r}, not {value!r}"
