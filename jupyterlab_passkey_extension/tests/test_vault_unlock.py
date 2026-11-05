"""One shared unlock: `Vault.unlock` on an open vault, a wait that ends on vault status,
and real processes against a real vault over HTTP.

The page is played by the test: a press unlocks the vault and answers the relay, as
`passkey:vault-unlock` does. A notification is a POST to the ingest route, counted here.
"""

import base64
import contextlib
import http.server
import json
import os
import signal
import subprocess
import sys
import threading
import time

import pytest

from jupyterlab_passkey_extension import cli, relay
from jupyterlab_passkey_extension.vault import cli as vcli
from jupyterlab_passkey_extension.vault import client, handlers, service

from .test_vault_git import _git_env, _VaultHTTP

PASS = "correct horse battery staple"
PRF = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
SECRET = "s3cret-MUST-NOT-LEAK"
PROCESSES = 8
# The helper as git runs it, with the fixed click wait shortened from outside, so a test
# of nobody answering does not last 120 s.
CHILD = """
import sys, time
from jupyterlab_passkey_extension import cli
from jupyterlab_passkey_extension.vault import gitcred
cli.CLICK_TIMEOUT = float(sys.argv[1])
start = time.monotonic()
code = gitcred.main(["get"])
print(f"took {time.monotonic() - start}", file=sys.stderr)
sys.exit(code)
"""
EXPLICIT = """
import sys
from jupyterlab_passkey_extension import cli
sys.argv = ["jupyterlab-passkey", "vault", "unlock", "--timeout", sys.argv[1]]
sys.exit(cli.main())
"""
GET = """
import sys
from jupyterlab_passkey_extension import cli
sys.argv = ["jupyterlab-passkey", "vault", "get", "github/api"]
sys.exit(cli.main())
"""
# The helper with no vault: the set-up has its own wait, shortened the same way.
SETTING_UP = CHILD.replace("cli.CLICK_TIMEOUT = float(sys.argv[1])",
                           "from jupyterlab_passkey_extension.vault import cli as vcli\n"
                           "vcli.REGISTER_TIMEOUT = float(sys.argv[1])")


@pytest.fixture
def vault(vault_env, monkeypatch):
    """A locked vault with one passkey and one entry; `client.request` runs in-process."""
    svc = handlers._service
    svc.init(PASS)
    svc.add_passkey("cred-1", "lab.example", "c2FsdA", PRF, None, {"current": PASS})
    svc.add("github/api", {"username": "me", "password": SECRET, "url": "https://github.com"})
    svc.lock()

    def request(method, action, body=None, params=None):
        table = {"GET": handlers._GET, "POST": handlers._POST}[method]
        try:
            return table[action](svc, (params or {}) if method == "GET" else (body or {}))
        except service.Locked as e:
            raise client.VaultLocked(str(e))

    monkeypatch.setattr(client, "request", request)
    return svc


def _record():
    with open(os.path.join(relay.relay_dir(), relay.UNLOCK_WAIT)) as f:
        return json.load(f)


def _steps(monkeypatch, step=None):
    """Count the notifications `Vault.unlock` raises, running `step` for each."""
    raised = []

    def browser_step(command, args, label, message, timeout, poll=None):
        raised.append(args)
        if step:
            step(timeout)

    monkeypatch.setattr(client, "browser_step", browser_step)
    return raised


def test_an_unlocked_vault_raises_no_notification(vault, monkeypatch):
    raised = _steps(monkeypatch)
    vault.unlock_recovery(PASS)
    assert client.Vault().unlock()["unlocked"] is True
    assert raised == []


def test_a_locked_vault_raises_one(vault, monkeypatch):
    raised = _steps(monkeypatch, lambda _: vault.unlock_recovery(PASS))
    assert client.Vault().unlock()["unlocked"] is True
    assert len(raised) == 1


def test_the_wait_for_the_notification_ends_when_status_reports_unlocked(vault, monkeypatch):
    # The press happened elsewhere, so no relay ever comes for this nonce.
    monkeypatch.setattr(cli, "_trigger", lambda *a, **k: threading.Timer(
        0.2, vault.unlock_recovery, [PASS]).start())
    start = time.monotonic()
    assert client.Vault(timeout=30).unlock()["unlocked"] is True
    assert time.monotonic() - start < 10


def test_a_process_with_a_pending_unlock_raises_none_and_goes_on_when_it_opens(
        vault, monkeypatch, capsys):
    raised = _steps(monkeypatch)
    assert client._claim_unlock(30, client.UNLOCK_COMMAND) is None
    monkeypatch.setattr(client, "WAIT_POLL", 0.05)
    threading.Timer(0.2, vault.unlock_recovery, [PASS]).start()
    assert client.Vault(timeout=30).unlock()["unlocked"] is True
    assert raised == []
    assert "waiting for the notification" in capsys.readouterr().err


def test_a_shared_wait_ends_at_its_own_deadline_and_blocks_nobody(vault, monkeypatch):
    assert client._claim_unlock(30, client.UNLOCK_COMMAND) is None
    monkeypatch.setattr(client, "WAIT_POLL", 0.05)
    start = time.monotonic()
    with pytest.raises(client.VaultClientError) as refused:
        client.Vault(timeout=0.2).unlock()
    assert time.monotonic() - start < 10
    assert str(refused.value) == client.LOCKED
    assert _record()["state"] == "pending"


def test_a_new_claim_ends_the_wait_on_the_unlock_before_it(vault, monkeypatch):
    # A process that starts as soon as a failed one exits can claim before a wait reads
    # the failure: its claim keeps the failure's line, and the wait ends with it.
    why = "ceremony failed: the unlock was cancelled"
    client._end_unlock("failed", client.FAILED_SECONDS, why, client.UNLOCK_COMMAND)
    assert client._claim_unlock(40, client.UNLOCK_COMMAND) is None
    assert (_record()["state"], _record()["why"]) == ("pending", why)
    client._put_wait("pending", 30, "", client.UNLOCK_COMMAND)
    monkeypatch.setattr(client, "WAIT_POLL", 0.05)
    threading.Timer(0.2, client._put_wait,
                    ["pending", 40, why, client.UNLOCK_COMMAND]).start()
    start = time.monotonic()
    with pytest.raises(client.VaultClientError, match="the unlock was cancelled"):
        client.Vault(timeout=30).unlock()
    assert time.monotonic() - start < 10


def _claimed_by(pid):
    client._put_wait("pending", 600, "", client.UNLOCK_COMMAND)
    record = _record()
    record["pid"] = pid
    # Atomic, as _put_wait writes it: a reader must never see a half-written record.
    relay.write_relay("unlock-wait", relay.UNLOCK_WAIT, json.dumps(record))


def test_a_wait_on_a_process_that_stops_raises_its_own_notification(vault, monkeypatch):
    # The first process stops with its notification unanswered: that ends no wait.
    first = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    _claimed_by(first.pid)
    waits = []
    raised = _steps(monkeypatch, lambda seconds: waits.append(seconds)
                    or vault.unlock_recovery(PASS))
    monkeypatch.setattr(client, "WAIT_POLL", 0.05)
    # Reaped, as the shell or git reaps it: a zombie still answers a signal.
    threading.Timer(0.3, lambda: first.kill() or first.wait()).start()
    try:
        assert client.Vault(timeout=30).unlock()["unlocked"] is True
    finally:
        first.kill()
        first.wait()
    assert raised == [{}]
    # The seconds left of its own wait: no process waits past its deadline.
    assert 0 < waits[0] < 30


def test_a_wait_shares_the_claim_that_replaced_one_whose_process_stopped(vault, monkeypatch):
    # Another waiting process claimed first: this one shares that claim, and raises none.
    # Events, not delays: the test knows the wait has claimed and has read the claim
    # that replaced the stopped process's before it opens the vault, whatever the load.
    first = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    second = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        _claimed_by(first.pid)
        raised = _steps(monkeypatch)
        monkeypatch.setattr(client, "WAIT_POLL", 0.05)

        claimed, shared = threading.Event(), threading.Event()
        real_claim, real_record = client._claim_unlock, client._wait_record

        def claim(seconds, command):
            record = real_claim(seconds, command)
            claimed.set()
            return record

        def wait_record():
            record = real_record()
            if record is not None and record.get("pid") == second.pid:
                shared.set()
            return record

        monkeypatch.setattr(client, "_claim_unlock", claim)
        monkeypatch.setattr(client, "_wait_record", wait_record)
        result = {}

        def wait():
            result["status"] = client.Vault(timeout=30).unlock()

        thread = threading.Thread(target=wait, daemon=True)
        thread.start()
        assert claimed.wait(30)
        _claimed_by(second.pid)
        first.kill()
        assert shared.wait(30)
        vault.unlock_recovery(PASS)
        thread.join(30)
        assert not thread.is_alive()
        assert result["status"]["unlocked"] is True
        assert raised == []
    finally:
        for p in (first, second):
            p.kill()
            p.wait()


def test_a_set_up_wait_raises_no_set_up_for_a_vault_made_and_locked(vault_env, monkeypatch):
    # The vault was made, which removes the claim, and locked before the next round: no
    # claim and a locked status, but a vault exists, so the wait ends and asks nothing.
    svc = handlers._service
    monkeypatch.setattr(client, "request", lambda method, action, body=None, params=None:
                        handlers._GET[action](svc, params or {}))
    # Another process raised the set-up, the operation this wait belongs to.
    assert client._claim_unlock(30, client.SETUP_COMMAND) is None
    raised = _steps(monkeypatch)
    monkeypatch.setattr(client, "WAIT_POLL", 0.05)

    def made_and_locked():
        svc.init(PASS)
        svc.lock()

    timer = threading.Timer(0.2, made_and_locked)
    timer.start()
    start = time.monotonic()
    client.Vault()._setup(30)
    timer.join()
    assert time.monotonic() - start < 10
    assert raised == []


def test_an_unanswered_unlock_fails_later_reads_at_once_and_names_the_command(
        vault, monkeypatch):
    def nobody(_):
        raise client.NoClick("no relay after 1s")

    raised = _steps(monkeypatch, nobody)
    reader = client.Vault(timeout=1)
    with pytest.raises(client.VaultClientError) as first:
        reader.get("github/api")
    assert len(raised) == 1
    with pytest.raises(client.VaultClientError) as later:
        reader.get("github/api")
    assert len(raised) == 1
    for line in (str(first.value), str(later.value)):
        assert line.startswith("the vault is locked")
        assert "`jupyterlab-passkey vault unlock`" in line
    record = _record()
    assert (record["state"], record["seconds"]) == ("unanswered", 600)


def test_a_press_in_the_last_round_of_the_wait_is_no_failure(vault, monkeypatch):
    def pressed_at_the_deadline(_):
        vault.unlock_recovery(PASS)
        raise client.NoClick("no relay after 1s")

    _steps(monkeypatch, pressed_at_the_deadline)
    assert client.Vault(timeout=1).unlock()["unlocked"] is True
    assert not os.path.exists(os.path.join(relay.relay_dir(), relay.UNLOCK_WAIT))


def test_the_refusal_lasts_ten_minutes(vault, monkeypatch):
    raised = _steps(monkeypatch)
    start = time.time()
    client._put_wait("unanswered", 600, "the vault is locked", client.UNLOCK_COMMAND)
    monkeypatch.setattr(client.time, "time", lambda: start + 599)
    with pytest.raises(client.VaultClientError, match="the vault is locked"):
        client.Vault().list()
    assert raised == []
    monkeypatch.setattr(client.time, "time", lambda: start + 601)
    with pytest.raises(client.VaultLocked):
        client.Vault().list()
    assert len(raised) == 1


def test_a_clock_set_back_ends_a_refusal(vault, monkeypatch):
    raised = _steps(monkeypatch)
    client._put_wait("unanswered", 600, "the vault is locked", client.UNLOCK_COMMAND)
    start = time.time()
    monkeypatch.setattr(client.time, "time", lambda: start - 3600)
    with pytest.raises(client.VaultLocked):
        client.Vault().list()
    assert len(raised) == 1


def test_an_explicit_unlock_asks_anew_through_a_refusal(vault, monkeypatch):
    raised = _steps(monkeypatch, lambda _: vault.unlock_recovery(PASS))
    client._put_wait("unanswered", 600, "the vault is locked", client.UNLOCK_COMMAND)
    assert client.Vault().unlock()["unlocked"] is True
    assert len(raised) == 1


def _nobody(_):
    raise client.NoClick("no relay after 1s")


def test_an_unlock_refusal_does_not_answer_for_a_set_up(vault_env, monkeypatch):
    # The record is one per user: the locked line of another vault's unlock must not
    # make a context with no vault report it locked instead of offering set-up.
    client._put_wait("unanswered", 600, client.LOCKED, client.UNLOCK_COMMAND)
    svc = handlers._service
    monkeypatch.setattr(client, "request", lambda method, action, body=None, params=None:
                        handlers._GET[action](svc, params or {}))
    raised = _steps(monkeypatch, _nobody)
    with pytest.raises(client.VaultClientError) as refused:
        client.Vault()._setup(30)
    assert len(raised) == 1
    line = str(refused.value)
    assert "the vault is locked" not in line
    assert line.startswith("no vault yet")
    assert "`jupyterlab-passkey vault init`" in line


def test_a_set_up_refusal_does_not_answer_for_an_unlock(vault, monkeypatch):
    # The mirror: the no-vault line of a set-up nobody answered must not make an
    # existing locked vault report no vault.
    client._put_wait("unanswered", 600, client.NOT_SET_UP, client.SETUP_COMMAND)
    raised = _steps(monkeypatch, _nobody)
    with pytest.raises(client.VaultClientError) as refused:
        client.Vault().list()
    assert len(raised) == 1
    line = str(refused.value)
    assert "no vault yet" not in line
    assert line.startswith("the vault is locked")


def test_a_set_up_claim_over_an_unlock_end_starts_with_no_line(vault_env):
    # The line of another operation's end says nothing about this one: it must not ride
    # into the set-up's claim and be raised as this wait's own.
    client._put_wait("unanswered", 600, client.LOCKED, client.UNLOCK_COMMAND)
    assert client._claim_unlock(30, client.SETUP_COMMAND) is None
    record = _record()
    assert (record["state"], record["why"], record["command"]) == (
        "pending", "", client.SETUP_COMMAND)


def test_a_set_up_claim_over_a_set_up_end_keeps_its_line(vault_env):
    # The same operation's end is this claim's own line, kept for the waits behind it.
    client._put_wait("unanswered", 600, client.NOT_SET_UP, client.SETUP_COMMAND)
    assert client._claim_unlock(30, client.SETUP_COMMAND) is None
    record = _record()
    assert (record["state"], record["why"], record["command"]) == (
        "pending", client.NOT_SET_UP, client.SETUP_COMMAND)


def test_a_set_up_wait_over_an_unlock_end_raises_the_set_up_line(vault_env, monkeypatch):
    # A set-up takes an unanswered unlock record over: its deadline must name the
    # set-up, never the unlock's locked line.
    client._put_wait("unanswered", 600, client.LOCKED, client.UNLOCK_COMMAND)
    assert client._claim_unlock(30, client.SETUP_COMMAND) is None
    svc = handlers._service
    monkeypatch.setattr(client, "request", lambda method, action, body=None, params=None:
                        handlers._GET[action](svc, params or {}))
    monkeypatch.setattr(client, "WAIT_POLL", 0.05)
    with pytest.raises(client.VaultClientError) as refused:
        client.Vault()._setup(0.05)
    line = str(refused.value)
    assert "the vault is locked" not in line
    assert line.startswith("no vault yet")
    assert "`jupyterlab-passkey vault init`" in line


def test_a_pending_unlock_is_not_shared_by_a_set_up(vault_env, monkeypatch):
    # Sharing belongs to the operation: a set-up raises its own notification beside a
    # pending unlock of another vault, and a window nobody answers names the set-up.
    client._claim_unlock(30, client.UNLOCK_COMMAND)
    svc = handlers._service
    monkeypatch.setattr(client, "request", lambda method, action, body=None, params=None:
                        handlers._GET[action](svc, params or {}))
    raised = _steps(monkeypatch, _nobody)
    with pytest.raises(client.VaultClientError) as refused:
        client.Vault()._setup(30)
    assert len(raised) == 1
    line = str(refused.value)
    assert "the vault is locked" not in line
    assert line.startswith("no vault yet")
    assert "`jupyterlab-passkey vault init`" in line
    assert _record()["command"] == client.SETUP_COMMAND


def test_a_pending_set_up_is_not_shared_by_an_unlock(vault, monkeypatch):
    # The mirror: an unlock raises its own notification beside a pending set-up, and a
    # window nobody answers names the unlock.
    client._claim_unlock(30, client.SETUP_COMMAND)
    raised = _steps(monkeypatch, _nobody)
    with pytest.raises(client.VaultClientError) as refused:
        client.Vault().list()
    assert len(raised) == 1
    line = str(refused.value)
    assert "no vault yet" not in line
    assert line.startswith("the vault is locked")
    assert "`jupyterlab-passkey vault unlock`" in line
    assert _record()["command"] == client.UNLOCK_COMMAND


def test_an_unanswered_record_from_an_older_version_refuses_nothing(vault, monkeypatch):
    # A record with no command cannot say which operation raised it: it stays inert.
    client._put_wait("unanswered", 600, client.LOCKED)
    raised = _steps(monkeypatch, lambda _: vault.unlock_recovery(PASS))
    assert [entry["name"] for entry in client.Vault().list()] == ["github/api"]
    assert len(raised) == 1


@pytest.mark.parametrize("unlock", [
    lambda svc: svc.unlock_recovery(PASS),
    lambda svc: svc.unlock_passkey("cred-1", PRF),
], ids=["recovery", "passkey"])
def test_any_unlock_ends_a_refusal_on_the_server(vault, unlock):
    client._put_wait("unanswered", 600, "the vault is locked", client.UNLOCK_COMMAND)
    unlock(vault)
    assert not os.path.exists(os.path.join(relay.relay_dir(), relay.UNLOCK_WAIT))


def test_a_refused_unlock_keeps_the_record(vault):
    client._put_wait("unanswered", 600, "the vault is locked", client.UNLOCK_COMMAND)
    with pytest.raises(Exception):
        vault.unlock_recovery("not the passphrase")
    assert _record()["why"] == "the vault is locked"


def test_a_failed_unlock_is_on_record_for_the_others(vault, monkeypatch):
    def failed(_):
        raise client.VaultClientError("ceremony failed: the unlock was cancelled")

    _steps(monkeypatch, failed)
    with pytest.raises(client.VaultClientError, match="the unlock was cancelled"):
        client.Vault().unlock()
    record = _record()
    assert (record["state"], record["why"]) == (
        "failed", "ceremony failed: the unlock was cancelled")
    assert record["seconds"] == client.FAILED_SECONDS
    # Only an unanswered notification refuses: the next process asks again.
    raised = _steps(monkeypatch, lambda _: vault.unlock_recovery(PASS))
    assert [entry["name"] for entry in client.Vault().list()] == ["github/api"]
    assert len(raised) == 1


def test_a_relay_directory_that_is_not_ours_is_one_line(vault, monkeypatch, tmp_path):
    squatted = tmp_path / "squat"
    squatted.write_text("")
    monkeypatch.setenv("JUPYTERLAB_PASSKEY_RELAY_DIR", str(squatted))
    _steps(monkeypatch)
    with pytest.raises(client.VaultClientError, match="cannot use the relay directory"):
        client.Vault().unlock()


no_root = pytest.mark.skipif(os.geteuid() == 0, reason="root passes every permission check")


@no_root
@pytest.mark.parametrize("mode, lock_file", [
    pytest.param(0o500, False, id="the lock cannot be made"),
    pytest.param(0o500, True, id="the record cannot be written"),
    pytest.param(0o000, False, id="the record cannot be read"),
])
def test_a_relay_directory_that_refuses_is_one_line(vault, monkeypatch, mode, lock_file):
    directory = relay.ensure_relay_dir()
    if lock_file:
        open(os.path.join(directory, relay.UNLOCK_WAIT + ".lock"), "w").close()
    raised = _steps(monkeypatch)
    os.chmod(directory, mode)
    try:
        with pytest.raises(client.VaultClientError, match="cannot use the relay directory"):
            client.Vault().list()
    finally:
        os.chmod(directory, 0o700)
    assert raised == []


@no_root
def test_a_relay_directory_that_refuses_the_end_of_an_unlock_is_one_line(vault, monkeypatch):
    directory = relay.ensure_relay_dir()

    def failed(_):
        os.chmod(directory, 0o500)
        raise client.VaultClientError("ceremony failed: the unlock was cancelled")

    _steps(monkeypatch, failed)
    try:
        with pytest.raises(client.VaultClientError, match="cannot use the relay directory"):
            client.Vault().unlock()
    finally:
        os.chmod(directory, 0o700)


def test_the_record_holds_no_secret(vault):
    assert client._claim_unlock(30, client.UNLOCK_COMMAND) is None
    assert set(_record()) == {"at", "seconds", "state", "why", "pid", "command"}
    assert _record()["why"] == ""
    assert _record()["pid"] == os.getpid()
    assert _record()["command"] == client.UNLOCK_COMMAND


# --------------------------------------------------------------------------- #
# what the shared unlock left: DEF-VAULT-74 to 78
# --------------------------------------------------------------------------- #


def _status_fails(monkeypatch, after, times):
    """Answer the next `times` status reads after the first `after` with a 500."""
    real = client.request
    reads = {"n": 0, "failed": 0}

    def request(method, action, body=None, params=None):
        if action == "status":
            reads["n"] += 1
            if reads["n"] > after and reads["failed"] < times:
                reads["failed"] += 1
                raise client.VaultClientError("the vault answered 500 Internal Server Error")
        return real(method, action, body, params)

    monkeypatch.setattr(client, "request", request)
    return reads


def _no_trigger(monkeypatch, then=None):
    """The notification goes nowhere; the real wait and its poll run. `then` runs in
    0.5 s, as a press or an unlock elsewhere would, on a timer in `timers` that the
    test joins before it ends."""
    raised, timers = [], []

    def trigger(command_id, args, label, message, seconds=None):
        raised.append(command_id)
        if then:
            timers.append(threading.Timer(0.5, then))
            timers[-1].start()

    monkeypatch.setattr(cli, "_trigger", trigger)
    return raised, timers


def test_a_failed_status_read_does_not_end_the_wait_of_the_one_that_asked(vault, monkeypatch):
    raised, timers = _no_trigger(monkeypatch, lambda: vault.unlock_recovery(PASS))
    # The first read is the one before the claim; the poll's first two reads fail.
    reads = _status_fails(monkeypatch, after=1, times=2)
    s = client.Vault(timeout=30).unlock()
    for timer in timers:
        timer.join()
    assert s["unlocked"] is True
    assert reads["failed"] == 2
    assert len(raised) == 1
    assert not os.path.exists(os.path.join(relay.relay_dir(), relay.UNLOCK_WAIT))


def test_a_failed_status_read_does_not_end_a_shared_wait(vault, monkeypatch):
    raised = _steps(monkeypatch)
    assert client._claim_unlock(30, client.UNLOCK_COMMAND) is None
    monkeypatch.setattr(client, "WAIT_POLL", 0.05)
    reads = _status_fails(monkeypatch, after=1, times=3)
    timer = threading.Timer(0.5, vault.unlock_recovery, [PASS])
    timer.start()
    s = client.Vault(timeout=30).unlock()
    timer.join()
    assert s["unlocked"] is True
    assert reads["failed"] == 3
    assert raised == []


def test_a_failed_status_read_does_not_end_the_wait_of_a_set_up(vault_env, monkeypatch):
    svc = handlers._service
    monkeypatch.setattr(client, "request", lambda method, action, body=None, params=None:
                        handlers._GET[action](svc, params or {}))
    _, timers = _no_trigger(monkeypatch, lambda: svc.init(PASS))
    reads = _status_fails(monkeypatch, after=0, times=2)
    start = time.monotonic()
    client.Vault()._setup(30)
    for timer in timers:
        timer.join()
    assert time.monotonic() - start < 10
    assert reads["failed"] == 2


def test_a_vault_made_in_the_panel_ends_the_wait_of_the_set_up(vault_env, monkeypatch):
    # Nobody presses the notification: the panel's Create makes the vault.
    svc = handlers._service
    monkeypatch.setattr(client, "request", lambda method, action, body=None, params=None:
                        handlers._GET[action](svc, params or {}))
    raised, timers = _no_trigger(monkeypatch, lambda: svc.init(PASS))
    start = time.monotonic()
    client.Vault()._setup(30)
    for timer in timers:
        timer.join()
    assert time.monotonic() - start < 10
    assert raised == [client.SETUP_COMMAND]
    assert not os.path.exists(os.path.join(relay.relay_dir(), relay.UNLOCK_WAIT))


def _unlock_before_the_claim(monkeypatch, unlock):
    """The order a long-lived process can meet: a locked status read, an unlock from
    elsewhere, which removes no record yet, then this process's claim."""
    real = client._claim_unlock

    def claim(seconds, command):
        unlock()
        return real(seconds, command)

    monkeypatch.setattr(client, "_claim_unlock", claim)
    return real


def test_a_claim_written_just_after_an_unlock_goes_when_its_process_sees_it_open(
        vault, monkeypatch):
    real = _unlock_before_the_claim(monkeypatch, lambda: vault.unlock_recovery(PASS))
    _no_trigger(monkeypatch)
    start = time.monotonic()
    assert client.Vault(timeout=30).unlock()["unlocked"] is True
    assert time.monotonic() - start < 10
    assert not os.path.exists(os.path.join(relay.relay_dir(), relay.UNLOCK_WAIT))
    vault.lock()
    monkeypatch.setattr(client, "_claim_unlock", real)
    raised = _steps(monkeypatch, lambda _: vault.unlock_recovery(PASS))
    assert [entry["name"] for entry in client.Vault(timeout=2).list()] == ["github/api"]
    assert len(raised) == 1


def test_a_claim_written_just_after_init_goes_when_its_process_sees_the_vault(
        vault_env, monkeypatch):
    svc = handlers._service

    def request(method, action, body=None, params=None):
        table = {"GET": handlers._GET, "POST": handlers._POST}[method]
        try:
            return table[action](svc, (params or {}) if method == "GET" else (body or {}))
        except service.Locked as e:
            raise client.VaultLocked(str(e))

    monkeypatch.setattr(client, "request", request)
    real = _unlock_before_the_claim(monkeypatch, lambda: svc.init(PASS))
    _no_trigger(monkeypatch)
    start = time.monotonic()
    client.Vault()._setup(30)
    assert time.monotonic() - start < 10
    assert not os.path.exists(os.path.join(relay.relay_dir(), relay.UNLOCK_WAIT))
    svc.lock()
    monkeypatch.setattr(client, "_claim_unlock", real)
    raised = _steps(monkeypatch, lambda _: svc.unlock_recovery(PASS))
    assert client.Vault(timeout=2).unlock()["unlocked"] is True
    assert len(raised) == 1


def test_an_interrupt_in_a_process_that_lives_on_removes_its_claim(vault, monkeypatch):
    # A notebook kernel: Ctrl-C ends the wait, and the process goes on.
    def interrupted(_):
        raise KeyboardInterrupt

    _steps(monkeypatch, interrupted)
    with pytest.raises(KeyboardInterrupt):
        client.Vault().unlock()
    assert not os.path.exists(os.path.join(relay.relay_dir(), relay.UNLOCK_WAIT))
    raised = _steps(monkeypatch, lambda _: vault.unlock_recovery(PASS))
    assert client.Vault(timeout=2).unlock()["unlocked"] is True
    assert len(raised) == 1


def test_the_claim_of_a_process_that_is_gone_is_void(vault, monkeypatch):
    gone = subprocess.Popen([sys.executable, "-c", "pass"])
    gone.wait()
    _claimed_by(gone.pid)
    assert client._wait_record() is None
    raised = _steps(monkeypatch, lambda _: vault.unlock_recovery(PASS))
    assert client.Vault(timeout=2).unlock()["unlocked"] is True
    assert len(raised) == 1


def test_the_end_of_a_wait_leaves_the_claim_of_another_process(vault, monkeypatch):
    # The vault opened and locked again, and another process claimed, before this
    # process's wait ended: that claim is the other process's to remove.
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        _steps(monkeypatch, lambda _: _claimed_by(other.pid))
        client.Vault().unlock()
        assert _record()["pid"] == other.pid
    finally:
        other.kill()
        other.wait()


def test_an_end_on_record_outlives_its_process(vault):
    # Only a claim dies with its process: the 10 minutes after nobody answered do not.
    client._put_wait("unanswered", 600, "the vault is locked", client.UNLOCK_COMMAND)
    record = _record()
    record["pid"] = 2 ** 22 + 1
    with open(os.path.join(relay.relay_dir(), relay.UNLOCK_WAIT), "w") as f:
        json.dump(record, f)
    assert client._wait_record()["state"] == "unanswered"


@pytest.mark.parametrize("content", [
    "", "garbage", "[]", "{}", "null", '"text"', '{"at": 1}',
    '{"at": "now", "seconds": 600, "state": "unanswered", "why": "x", "pid": 1}',
    '{"at": %(at)s, "seconds": 600, "state": "unanswered", "pid": 1}',
    '{"at": %(at)s, "seconds": 600, "state": "pending", "why": "", "pid": "me"}',
    '{"at": %(at)s, "seconds": 600, "state": "pending", "why": "", "pid": -1}',
    '{"at": %(at)s, "seconds": 600, "state": "pending", "why": ""}',
], ids=["empty", "garbage", "list", "no keys", "null", "text", "no seconds", "text time",
        "no why", "text pid", "negative pid", "no pid"])
def test_a_malformed_record_is_no_record(vault, monkeypatch, content):
    with open(os.path.join(relay.ensure_relay_dir(), relay.UNLOCK_WAIT), "w") as f:
        f.write(content % {"at": time.time()} if "%(at)s" in content else content)
    assert client._wait_record() is None
    raised = _steps(monkeypatch, lambda _: vault.unlock_recovery(PASS))
    assert [entry["name"] for entry in client.Vault(timeout=2).list()] == ["github/api"]
    assert len(raised) == 1


@pytest.fixture
def unusable(vault, tmp_path, monkeypatch):
    """The keyctl backend with a relay directory under a plain file."""
    blocker = tmp_path / "blocker"
    blocker.write_text("")
    monkeypatch.setenv("JUPYTERLAB_PASSKEY_RELAY_DIR", str(blocker / "relay"))
    monkeypatch.setattr(relay, "_backend_cache", "keyctl")
    return vault


def test_an_unusable_relay_directory_on_keyctl_raises_its_own_notification(
        unusable, monkeypatch):
    raised = _steps(monkeypatch, lambda _: unusable.unlock_recovery(PASS))
    assert [entry["name"] for entry in client.Vault().list()] == ["github/api"]
    assert len(raised) == 1


def test_an_unusable_relay_directory_on_keyctl_keeps_the_line_of_a_failed_unlock(
        unusable, monkeypatch):
    def failed(_):
        raise client.VaultClientError("ceremony failed: the unlock was cancelled")

    _steps(monkeypatch, failed)
    with pytest.raises(client.VaultClientError) as refused:
        client.Vault().unlock()
    assert str(refused.value) == "ceremony failed: the unlock was cancelled"


def test_an_unusable_relay_directory_on_keyctl_raises_its_own_set_up(vault_env, tmp_path,
                                                                    monkeypatch):
    blocker = tmp_path / "blocker"
    blocker.write_text("")
    monkeypatch.setenv("JUPYTERLAB_PASSKEY_RELAY_DIR", str(blocker / "relay"))
    monkeypatch.setattr(relay, "_backend_cache", "keyctl")
    svc = handlers._service
    monkeypatch.setattr(client, "request", lambda method, action, body=None, params=None:
                        handlers._GET[action](svc, params or {}))
    raised = _steps(monkeypatch, lambda _: svc.init(PASS))
    client.Vault()._setup(30)
    assert raised == [{}]
    assert svc.status()["initialized"] is True


class _Clock:
    """The wait's clock: a sleep moves it on at once. The wall clock stays real, because
    the record holds a time of the wall clock."""

    time = staticmethod(time.time)

    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def test_a_process_waiting_on_another_set_up_waits_the_set_up_time(vault_env, monkeypatch):
    """A process that shares the set-up waits REGISTER_TIMEOUT, as the one that raised it
    does, and not the 120 s of a click."""
    svc = handlers._service
    monkeypatch.setattr(client, "request", lambda method, action, body=None, params=None:
                        handlers._GET[action](svc, params or {}))
    # Another process raised the set-up and nobody answers it.
    assert client._claim_unlock(vcli.REGISTER_TIMEOUT, client.SETUP_COMMAND) is None
    clock = _Clock()
    monkeypatch.setattr(client, "time", clock)
    monkeypatch.setattr(client, "WAIT_POLL", 50)
    with pytest.raises(client.VaultClientError, match=client.NOT_SET_UP):
        vcli.setup_in_browser(client.Vault())
    assert vcli.REGISTER_TIMEOUT <= clock.now <= vcli.REGISTER_TIMEOUT + client.WAIT_POLL


# --------------------------------------------------------------------------- #
# real processes
# --------------------------------------------------------------------------- #


class _Lab(_VaultHTTP):
    """The vault's routes and the notifications extension's ingest route."""

    notifications = []
    locked_reads = []
    # Holds the status reads until every process has made one, for a start at once.
    gate = None
    # Held by a press, which the processes must see as one step.
    pressing = threading.Lock()

    def _answer(self, status, result):
        if status == 423:
            self.locked_reads.append(self.path)
        super()._answer(status, result)

    def _serve(self, method):
        if self.path.rstrip("/").endswith("/ingest"):
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.notifications.append(json.loads(raw))
            return self._answer(200, {})
        gate = _Lab.gate
        if gate is not None and "/status" in self.path:
            gate.wait(timeout=60)
        with _Lab.pressing:
            pass
        super()._serve(method)


class _LabServer(http.server.ThreadingHTTPServer):
    # The real server queues 128. The default of 5 overflows when 8 processes connect at
    # once, and a dropped connection waits 1 s for its next attempt.
    request_queue_size = 64


@contextlib.contextmanager
def _serving(svc, tmp_path):
    _Lab.svc = svc
    _Lab.notifications = []
    _Lab.locked_reads = []
    httpd = _LabServer(("127.0.0.1", 0), _Lab)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    request = tmp_path / "request"
    request.write_text("protocol=https\nhost=github.com\n\n")
    try:
        yield _git_env(tmp_path, httpd.server_address[1]), request
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


@pytest.fixture
def lab(vault, tmp_path):
    with _serving(vault, tmp_path) as served:
        yield served


@pytest.fixture
def no_vault(vault_env, tmp_path):
    """The lab with no vault; the status reads of the first round wait for each other."""
    with _serving(handlers._service, tmp_path) as served:
        _Lab.gate = threading.Barrier(PROCESSES, action=lambda: setattr(_Lab, "gate", None))
        yield served
    _Lab.gate = None


def _spawn(lab, seconds, count=PROCESSES, code=CHILD):
    env, request = lab
    procs = []
    for _ in range(count):
        with open(request) as stdin:
            procs.append(subprocess.Popen(
                [sys.executable, "-c", code, str(seconds)], env=env, stdin=stdin, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE))
    return procs


def _finish(procs):
    return [(p.communicate(timeout=60), p.returncode) for p in procs]


def _until(condition, seconds=30):
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "the processes never reached this point"
        time.sleep(0.02)


def _press(vault, notification, body=None):
    """What the page does on a click: unlock, or post the failure `body`. A success is
    not posted: the processes read it in vault status (`answerCli` in plugin.ts)."""
    nonce = notification["actions"][0]["args"]["nonce"]
    if body is None:
        vault.unlock_passkey("cred-1", PRF)
    else:
        relay.stage(nonce, "json", json.dumps({"nonce": nonce, **body}))


def _relays_left():
    """The relays in the relay directory: the record of the shared unlock is none."""
    return [name for name in os.listdir(relay.relay_dir())
            if not name.startswith(relay.UNLOCK_WAIT)]


def _all_at_the_lock():
    """Every process read 423 and has had the time to raise its own, if it would."""
    _until(lambda: len(_Lab.locked_reads) >= PROCESSES and _Lab.notifications)
    time.sleep(1)


def test_eight_processes_raise_one_notification_and_one_press_lets_all_go_on(vault, lab):
    procs = _spawn(lab, 60)
    _all_at_the_lock()
    assert len(_Lab.notifications) == 1
    _press(vault, _Lab.notifications[0])
    start = time.monotonic()
    done = _finish(procs)
    assert time.monotonic() - start < 15
    for (out, err), code in done:
        assert code == 0, err
        assert out == f"username=me\npassword={SECRET}\n"
    assert len(_Lab.notifications) == 1
    assert _relays_left() == []


def test_the_unlock_notification_names_its_command_and_its_wait(vault, lab):
    # A tab drops the notification once the vault is open or this wait has run out
    # (`dismissStale` in src/vault/plugin.ts).
    proc, = _spawn(lab, 45, 1)
    _until(lambda: _Lab.notifications)
    data = _Lab.notifications[0]["data"]
    assert data["command"] == client.UNLOCK_COMMAND and data["seconds"] == 45
    _press(vault, _Lab.notifications[0])
    ((out, err), code), = _finish([proc])
    assert code == 0, err


def test_an_unlock_from_elsewhere_ends_all_eight_waits(vault, lab):
    # The notification stands unclicked: the panel or a terminal opened the vault.
    procs = _spawn(lab, 60)
    _all_at_the_lock()
    vault.unlock_recovery(PASS)
    start = time.monotonic()
    done = _finish(procs)
    assert time.monotonic() - start < 15
    assert all(code == 0 for _, code in done)
    assert len(_Lab.notifications) == 1


def test_a_cancelled_unlock_ends_all_eight_waits_at_once(vault, lab):
    procs = _spawn(lab, 60)
    _all_at_the_lock()
    _press(vault, _Lab.notifications[0], {"ok": False, "error": "the unlock was cancelled"})
    start = time.monotonic()
    done = _finish(procs)
    assert time.monotonic() - start < 15
    for (out, err), code in done:
        assert (code, out) == (1, "")
        assert "the unlock was cancelled" in err
    assert len(_Lab.notifications) == 1
    assert _relays_left() == []
    # A cancel refuses nobody: the next process asks again.
    _finish(_spawn(lab, 1, 1))
    assert len(_Lab.notifications) == 2


def test_nobody_pressing_gives_one_wait_then_failures_at_once(vault, lab):
    wait = 6
    start = time.monotonic()
    first = _finish(_spawn(lab, wait))
    took = time.monotonic() - start
    # The lines come first, so a wait that ended early names its cause.
    for (out, err), code in first:
        assert (code, out) == (1, "")
        assert "the vault is locked" in err
        assert "`jupyterlab-passkey vault unlock`" in err
        assert "no relay" not in err
    assert wait <= took < wait + 15
    assert len(_Lab.notifications) == 1

    later = _finish(_spawn(lab, wait))
    assert len(_Lab.notifications) == 1
    for (out, err), code in later:
        assert (code, out) == (1, "")
        assert "the vault is locked" in err
        assert "`jupyterlab-passkey vault unlock`" in err
        assert "waiting for the notification" not in err
        # Measured in the process: starting 8 interpreters is not part of the wait.
        assert float(err.rsplit("took ", 1)[1]) < wait

    # The command the line names does not stop at the refusal, and it clears it.
    explicit = _spawn(lab, 30, 1, EXPLICIT)
    _until(lambda: len(_Lab.notifications) == 2)
    _press(vault, _Lab.notifications[1])
    assert [code for _, code in _finish(explicit)] == [0]
    vault.lock()
    _Lab.locked_reads.clear()
    after = _spawn(lab, 1, 1)
    _until(lambda: len(_Lab.notifications) == 3)
    _finish(after)


@no_root
@pytest.mark.parametrize("code", [CHILD, GET], ids=["the git helper", "vault get"])
def test_a_relay_directory_that_refuses_reaches_a_process_as_one_line(vault, lab, code):
    directory = relay.ensure_relay_dir()
    os.chmod(directory, 0o500)
    try:
        ((out, err), status), = _finish(_spawn(lab, 1, 1, code))
    finally:
        os.chmod(directory, 0o700)
    assert (status, out) == (1, "")
    assert "cannot use the relay directory" in err
    assert "Traceback" not in err
    assert _Lab.notifications == []


@pytest.mark.parametrize("stop, code", [
    pytest.param(signal.SIGKILL, CHILD, id="a kill"),
    pytest.param(signal.SIGINT, GET, id="Ctrl-C"),
])
def test_a_process_that_stops_leaves_no_claim(vault, lab, stop, code):
    owner, = _spawn(lab, 60, 1, code)
    _until(lambda: _Lab.notifications)
    owner.send_signal(stop)
    owner.wait()
    if stop == signal.SIGINT:
        # The interrupt runs the way out of the wait, which removes the claim.
        assert not os.path.exists(os.path.join(relay.relay_dir(), relay.UNLOCK_WAIT))
    # The claim held 70 s: the next process raises its own notification at once.
    next_one, = _spawn(lab, 30, 1)
    _until(lambda: len(_Lab.notifications) == 2, 15)
    _press(vault, _Lab.notifications[1])
    ((out, err), status), = _finish([next_one])
    assert status == 0, err
    assert "waiting for the notification" not in err


@pytest.mark.parametrize("stop", [signal.SIGKILL, signal.SIGINT], ids=["a kill", "Ctrl-C"])
def test_a_stopped_first_process_ends_no_wait(vault, lab, stop):
    owner, = _spawn(lab, 60, 1, GET)
    _until(lambda: _Lab.notifications)
    waiters = _spawn(lab, 60, 3, GET)
    _until(lambda: len(_Lab.locked_reads) >= 4)
    owner.send_signal(stop)
    owner.wait()
    # One waiting process raises the notification in its place; the others share it.
    _until(lambda: len(_Lab.notifications) == 2, 15)
    time.sleep(1.5)
    assert len(_Lab.notifications) == 2
    assert all(p.poll() is None for p in waiters)
    _press(vault, _Lab.notifications[1])
    for (out, err), code in _finish(waiters):
        assert code == 0, err
        assert out == f"{SECRET}\n"


@pytest.mark.keyctl
@pytest.mark.skipif(not relay._keyctl_probe(), reason="keyctl not functional on this host")
def test_a_relay_directory_that_cannot_be_used_on_keyctl_fails_no_unlock(vault, lab,
                                                                          tmp_path):
    env, request = lab
    blocker = tmp_path / "blocker"
    blocker.write_text("")
    env = {**env, "JUPYTERLAB_PASSKEY_RELAY_BACKEND": "keyctl",
           "JUPYTERLAB_PASSKEY_RELAY_DIR": str(blocker / "relay")}
    proc = subprocess.Popen([sys.executable, "-c", GET], env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _until(lambda: _Lab.notifications)
    _press(vault, _Lab.notifications[0])
    ((out, err), status), = _finish([proc])
    assert status == 0, err
    assert out == f"{SECRET}\n"
    assert "cannot use the relay directory" not in err


# --------------------------------------------------------------------------- #
# real processes, no vault: one set-up
# --------------------------------------------------------------------------- #


def _all_saw_no_vault():
    """Every process read no vault and has had the time to raise its own, if it would."""
    _until(lambda: _Lab.gate is None and _Lab.notifications)
    time.sleep(1)


def _press_set_up(notification, body=None):
    """What the page does on a click: the vault, or a post of the failure `body`. The
    processes see the vault and its entry as one step, and read them in vault status."""
    assert notification["actions"][0]["commandId"] == client.SETUP_COMMAND
    if body is None:
        with _Lab.pressing:
            handlers._service.init(PASS)
            handlers._service.add("github/api", {"username": "me", "password": SECRET,
                                                 "url": "https://github.com"})
    else:
        nonce = notification["actions"][0]["args"]["nonce"]
        relay.stage(nonce, "json", json.dumps({"nonce": nonce, **body}))


def test_eight_processes_raise_one_set_up_and_one_press_lets_all_go_on(no_vault):
    procs = _spawn(no_vault, 60, code=SETTING_UP)
    _all_saw_no_vault()
    assert len(_Lab.notifications) == 1
    _press_set_up(_Lab.notifications[0])
    start = time.monotonic()
    done = _finish(procs)
    assert time.monotonic() - start < 15
    for (out, err), code in done:
        assert code == 0, err
        assert out == f"username=me\npassword={SECRET}\n"
    assert sum("waiting for the set-up notification" in err for (_, err), _ in done) == 7
    assert len(_Lab.notifications) == 1
    assert _relays_left() == []


def test_the_set_up_notification_names_its_command_and_its_wait(no_vault):
    _Lab.gate = None
    proc, = _spawn(no_vault, 45, 1, SETTING_UP)
    _until(lambda: _Lab.notifications)
    data = _Lab.notifications[0]["data"]
    assert data["command"] == client.SETUP_COMMAND and data["seconds"] == 45
    _press_set_up(_Lab.notifications[0])
    ((out, err), code), = _finish([proc])
    assert code == 0, err


def test_a_killed_set_up_process_leaves_no_claim(no_vault):
    _Lab.gate = None
    owner, = _spawn(no_vault, 60, 1, SETTING_UP)
    _until(lambda: _Lab.notifications)
    owner.send_signal(signal.SIGKILL)
    owner.wait()
    next_one, = _spawn(no_vault, 30, 1, SETTING_UP)
    _until(lambda: len(_Lab.notifications) == 2, 15)
    _press_set_up(_Lab.notifications[1])
    ((out, err), status), = _finish([next_one])
    assert status == 0, err
    assert "waiting for the set-up notification" not in err


def test_a_stopped_first_set_up_process_ends_no_wait(no_vault):
    _Lab.gate = None
    owner, = _spawn(no_vault, 60, 1, SETTING_UP)
    _until(lambda: _Lab.notifications)
    waiter, = _spawn(no_vault, 60, 1, SETTING_UP)
    time.sleep(2.5)
    owner.send_signal(signal.SIGINT)
    owner.wait()
    _until(lambda: len(_Lab.notifications) == 2, 15)
    assert waiter.poll() is None
    _press_set_up(_Lab.notifications[1])
    ((out, err), status), = _finish([waiter])
    assert status == 0, err
    assert out == f"username=me\npassword={SECRET}\n"


def test_a_cancelled_set_up_ends_all_eight_waits_at_once(no_vault):
    procs = _spawn(no_vault, 60, code=SETTING_UP)
    _all_saw_no_vault()
    _press_set_up(_Lab.notifications[0], {"ok": False, "error": "the recovery step was cancelled"})
    start = time.monotonic()
    done = _finish(procs)
    assert time.monotonic() - start < 15
    for (out, err), code in done:
        assert (code, out) == (1, "")
        assert "the recovery step was cancelled" in err
    assert len(_Lab.notifications) == 1
    assert _relays_left() == []


def test_nobody_pressing_the_set_up_gives_one_wait_then_failures_at_once(no_vault):
    wait = 6
    start = time.monotonic()
    first = _finish(_spawn(no_vault, wait, code=SETTING_UP))
    took = time.monotonic() - start
    for (out, err), code in first:
        assert (code, out) == (1, "")
        assert "no vault yet" in err
        assert "`jupyterlab-passkey vault init`" in err
    assert wait <= took < wait + 15
    assert len(_Lab.notifications) == 1

    later = _finish(_spawn(no_vault, wait, code=SETTING_UP))
    assert len(_Lab.notifications) == 1
    for (out, err), code in later:
        assert (code, out) == (1, "")
        assert "`jupyterlab-passkey vault init`" in err
        assert "waiting for the set-up notification" not in err
        assert float(err.rsplit("took ", 1)[1]) < wait
