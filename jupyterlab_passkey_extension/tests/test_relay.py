"""Tests for the relay backend selection and the keyctl backend itself.

The shm backend is exercised by every other test in the suite (the conftest fixture
pins it). This file covers what only the backend split introduced: choosing between
keyctl and shm, the fallback warning, and the keyctl round-trip with its one-shot,
TTL and no-argv-leak properties. The keyctl-marked tests skip where the kernel
keyring is not functional (some CI runners), so they never turn a missing keyutils
into a red suite.
"""

import subprocess

import pytest

from jupyterlab_passkey_extension import relay

# Probe once at import: the marked tests need a working @u round-trip, and there is no
# point registering them where it cannot run.
_KEYCTL_WORKS = relay._keyctl_probe()
keyctl = pytest.mark.keyctl
needs_keyctl = pytest.mark.skipif(
    not _KEYCTL_WORKS, reason="keyctl not functional on this host"
)

NONCE = "relay_nonce_0123456789"


# --------------------------------------------------------------------------- #
# Backend selection.
# --------------------------------------------------------------------------- #


def test_backend_forced_shm(monkeypatch):
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "shm")
    monkeypatch.setattr(relay, "_backend_cache", None)
    assert relay.backend() == "shm"


def test_auto_falls_back_to_shm_with_one_warning(monkeypatch, capsys):
    # keyctl present but non-functional (the linking caveat) must degrade, not crash.
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "auto")
    monkeypatch.setattr(relay, "_backend_cache", None)
    monkeypatch.setattr(relay, "_warned", False)
    monkeypatch.setattr(relay, "_keyctl_probe", lambda: False)

    assert relay.backend() == "shm"
    err = capsys.readouterr().err
    assert "keyctl unavailable" in err
    assert "keyutils" in err
    # Nothing to stdout - it carries the CLI result.
    assert capsys.readouterr().out == ""


def test_fallback_warning_fires_once(monkeypatch, capsys):
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "auto")
    monkeypatch.setattr(relay, "_backend_cache", None)
    monkeypatch.setattr(relay, "_warned", False)
    monkeypatch.setattr(relay, "_keyctl_probe", lambda: False)

    relay.backend()
    relay.backend()  # cached; must not warn again
    assert capsys.readouterr().err.count("keyctl unavailable") == 1


def test_forced_keyctl_fails_loud_when_broken(monkeypatch):
    # An operator who demanded keyctl must hear that it is not there, not be handed a
    # silent file relay that lacks the properties they asked for. It is an OSError so the
    # handlers' `except OSError` guards answer with a clean 500 / one line, not a
    # traceback.
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "keyctl")
    monkeypatch.setattr(relay, "_backend_cache", None)
    monkeypatch.setattr(relay, "_keyctl_probe", lambda: False)

    with pytest.raises(OSError, match="not functional"):
        relay.backend()


def test_auto_prefers_keyctl_when_it_works(monkeypatch):
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "auto")
    monkeypatch.setattr(relay, "_backend_cache", None)
    monkeypatch.setattr(relay, "_keyctl_probe", lambda: True)
    assert relay.backend() == "keyctl"


def test_reference_scheme_per_backend(monkeypatch):
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "shm")
    monkeypatch.setattr(relay, "_backend_cache", None)
    assert relay.reference(NONCE, "pass").startswith("file:")
    assert relay.reference(NONCE, "pass").endswith(f"{NONCE}.pass")

    monkeypatch.setattr(relay, "_backend_cache", None)
    monkeypatch.setattr(relay, "_keyctl_probe", lambda: True)
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "keyctl")
    assert relay.reference(NONCE, "pass") == f"keyctl:jlab-passkey:{NONCE}.pass"


def _fake_keyctl_runner(timeout_rc=0, padd_rc=0, kid=b"4242"):
    """A subprocess.run stand-in answering each keyctl subcommand, so _keyctl_stage can
    be driven with no kernel keyring. Records every argv for assertions."""
    calls = []

    def run(cmd, *a, **kw):
        calls.append(cmd)
        op = cmd[1] if len(cmd) > 1 else ""
        if op == "search":
            rc, out, err = 1, b"", b""  # no stale key of this description
        elif op == "padd":
            rc, out, err = padd_rc, kid + b"\n", b"padd boom"
        elif op == "timeout":
            rc, out, err = timeout_rc, b"", b"timeout boom"
        else:  # unlink, pipe
            rc, out, err = 0, b"", b""
        return subprocess.CompletedProcess(cmd, rc, out, err)

    return run, calls


def test_keyctl_stage_unlinks_and_raises_when_the_ttl_cannot_be_set(monkeypatch):
    # A key we cannot give an expiry to must not be left staged: it would hold the
    # secret with no self-destruct, defeating keyctl's one guarantee over the file -
    # most sharply for passphrase, which we never unlink ourselves.
    run, calls = _fake_keyctl_runner(timeout_rc=1)
    monkeypatch.setattr(relay.subprocess, "run", run)

    with pytest.raises(OSError, match="keyctl timeout failed"):
        relay._keyctl_stage(NONCE, "secret", "x")

    # Unlinked on the way out - no no-expiry secret left behind.
    assert ["keyctl", "unlink", "4242", "@u"] in calls


def test_unstage_is_best_effort_when_the_backend_is_unavailable(monkeypatch):
    # unstage runs only on an unwind path (a finally / exception handler). If it raised -
    # e.g. a forced-but-broken keyctl making backend() raise - it would MASK the error
    # actually propagating. It must swallow and return, never raise.
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "keyctl")
    monkeypatch.setattr(relay, "_backend_cache", None)
    monkeypatch.setattr(relay, "_keyctl_probe", lambda: False)

    relay.unstage(NONCE, "json")  # must not raise


def test_keyctl_stage_honours_a_ttl_override(monkeypatch):
    # The copy block-wait passes a TTL past its deadline so the key outlives the wait;
    # the override must reach `keyctl timeout`, not the per-kind default.
    run, calls = _fake_keyctl_runner()
    monkeypatch.setattr(relay.subprocess, "run", run)

    relay._keyctl_stage(NONCE, "secret", "x", ttl=7)

    timeouts = [c for c in calls if len(c) >= 2 and c[1] == "timeout"]
    assert timeouts and timeouts[0][-1] == "7"
    assert timeouts[0][-1] != str(relay._TTL["secret"])


# --------------------------------------------------------------------------- #
# The keyctl backend proper - real kernel keyring, skipped where unavailable.
# --------------------------------------------------------------------------- #


@needs_keyctl
@keyctl
def test_keyctl_round_trip_and_one_shot():
    relay.stage(NONCE, "secret", "kernel-value")
    assert relay.relay_exists(NONCE, "secret")
    assert relay.collect(NONCE, "secret") == "kernel-value"
    # One shot: collecting destroyed it.
    assert not relay.relay_exists(NONCE, "secret")
    assert relay.collect(NONCE, "secret") is None


@needs_keyctl
@keyctl
def test_keyctl_cross_process_handoff():
    # Add from a separate process, read from this one - the actual writer/reader split
    # between the Jupyter server and the CLI.
    desc = relay._key_desc(NONCE, "secret")
    subprocess.run(
        ["keyctl", "padd", "user", desc, "@u"],
        input=b"from-another-process",
        capture_output=True,
        check=True,
    )
    assert relay.collect(NONCE, "secret") == "from-another-process"


@needs_keyctl
@keyctl
def test_keyctl_exact_bytes():
    value = "café\nsecond-line\ttab"
    relay.stage(NONCE, "pass", value)
    assert relay.collect(NONCE, "pass") == value


@needs_keyctl
@keyctl
def test_keyctl_unstage_destroys():
    relay.stage(NONCE, "secret", "gone-soon")
    relay.unstage(NONCE, "secret")
    assert not relay.relay_exists(NONCE, "secret")


@keyctl
def test_keyctl_stage_never_puts_the_secret_on_argv(monkeypatch):
    # padd reads its payload from stdin; the process list must never carry it. Spy on
    # every keyctl call and prove the secret rode `input`, never `args`.
    calls = []
    real_run = subprocess.run

    def spy(cmd, *a, **kw):
        calls.append((cmd, kw.get("input")))
        return real_run(cmd, *a, **kw)

    monkeypatch.setattr(relay.subprocess, "run", spy)
    monkeypatch.setattr(relay, "_backend_cache", None)
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "keyctl")
    if not relay._keyctl_probe():
        pytest.skip("keyctl not functional on this host")
    monkeypatch.setattr(relay, "_backend_cache", None)

    secret = "ARGV_MUST_NOT_CARRY_THIS"
    relay.stage(NONCE, "secret", secret)
    relay._keyctl_unstage(NONCE, "secret")

    argv_blob = " ".join(" ".join(cmd) for cmd, _ in calls)
    assert secret not in argv_blob
    # ...and it really did travel: some call carried it on stdin.
    assert any(inp == secret.encode() for _, inp in calls)


@needs_keyctl
@keyctl
def test_keyctl_sets_a_ttl(monkeypatch):
    # The self-destruct is the whole point over the file; assert the timeout is set.
    calls = []
    real_run = subprocess.run

    def spy(cmd, *a, **kw):
        calls.append(cmd)
        return real_run(cmd, *a, **kw)

    monkeypatch.setattr(relay.subprocess, "run", spy)
    relay.stage(NONCE, "secret", "ttl-check")
    relay._keyctl_unstage(NONCE, "secret")

    timeouts = [c for c in calls if len(c) >= 2 and c[1] == "timeout"]
    assert timeouts, "no keyctl timeout was set on the staged key"
    assert timeouts[0][-1] == str(relay._TTL["secret"])


# --------------------------------------------------------------------------- #
# Cross-backend read - a keyctl reader still collects a relay a shm writer staged.
# The writer and the reader are different processes and can split (a server still on
# the pre-keyctl file relay, a newer keyctl-preferred CLI); the keyctl reader must
# fall back to the file store or the handoff strands silently.
# --------------------------------------------------------------------------- #


def test_keyctl_reader_falls_back_to_the_shm_relay(monkeypatch, tmp_path):
    # The version-skew split that stranded a real unlock: a Jupyter server still on the
    # pre-keyctl code stages the ceremony result as a /dev/shm file while a newer,
    # keyctl-preferred CLI reads. No real keyring needed - the keyctl store is mocked
    # empty and the value is placed in shm; the reader must cross-read it.
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(tmp_path))
    monkeypatch.setattr(relay, "_backend_cache", "keyctl")
    monkeypatch.setattr(relay, "_keyctl_collect", lambda n, k: None)
    monkeypatch.setattr(relay, "_keyctl_exists", lambda n, k: False)

    relay.write_relay(NONCE, f"{NONCE}.json", "from-a-shm-server")

    assert relay.backend() == "keyctl"
    assert relay.relay_exists(NONCE, "json")  # the wait loop sees the shm store
    assert relay.collect(NONCE, "json") == "from-a-shm-server"  # and cross-reads it
    # One-shot across the split: the file is unlinked, a second collect finds nothing.
    assert relay.collect(NONCE, "json") is None
    assert not relay.relay_exists(NONCE, "json")


def test_keyctl_unstage_also_clears_the_shm_relay(monkeypatch, tmp_path):
    # unstage runs on an unwind path; a stage that landed on the OTHER backend must not
    # be left behind. A keyctl-primary unstage clears the file relay too.
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(tmp_path))
    monkeypatch.setattr(relay, "_backend_cache", "keyctl")
    monkeypatch.setattr(relay, "_keyctl_unstage", lambda n, k: None)  # keyring side no-op

    relay.write_relay(NONCE, f"{NONCE}.secret", "orphan")
    assert relay._shm_exists(NONCE, "secret")
    relay.unstage(NONCE, "secret")
    assert not relay._shm_exists(NONCE, "secret")


def test_keyctl_cross_read_is_best_effort_on_a_squatted_shm(monkeypatch, tmp_path):
    # A co-tenant squatting the predictable shm path must not become a crash on a keyctl
    # reader that would otherwise never touch shm. The cross-read swallows the squat
    # guard's error and reports nothing staged.
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(tmp_path))
    monkeypatch.setattr(relay, "_backend_cache", "keyctl")
    monkeypatch.setattr(relay, "_keyctl_collect", lambda n, k: None)
    relay.write_relay(NONCE, f"{NONCE}.json", "irrelevant")  # a file is plainly present

    def boom(n, k):
        raise PermissionError("relay dir is owned by someone else")

    monkeypatch.setattr(relay, "_shm_collect", boom)  # ...but reading it raises
    assert relay.collect(NONCE, "json") is None  # swallowed, not propagated


@needs_keyctl
def test_keyctl_reader_collects_a_real_shm_staged_relay(monkeypatch, tmp_path):
    # End to end on a real keyring: a shm-staged relay is collected by a genuine
    # keyctl-primary process (its own kernel key empty), exercising the real cross-read.
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(tmp_path))
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "shm")
    monkeypatch.setattr(relay, "_backend_cache", None)
    relay.stage(NONCE, "json", "real-cross-read")

    monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "keyctl")
    monkeypatch.setattr(relay, "_backend_cache", None)
    assert relay.backend() == "keyctl"
    assert relay.collect(NONCE, "json") == "real-cross-read"


def test_reference_names_the_shm_file_when_a_shm_writer_staged_the_pass(
    monkeypatch, tmp_path
):
    # passphrase resolves OUT of process via reference(), not collect(). On the skew split
    # (old shm server stages the pass file, new keyctl CLI prints the handle), a keyctl:
    # handle resolves to an empty keyring and hands the consumer nothing while the secret
    # orphans in the file. reference() must point at the file where the value actually is.
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(tmp_path))
    monkeypatch.setattr(relay, "_backend_cache", "keyctl")
    monkeypatch.setattr(relay, "_keyctl_exists", lambda n, k: False)  # keyring empty
    relay.write_relay(NONCE, f"{NONCE}.pass", "the-passphrase")  # value in shm

    ref = relay.reference(NONCE, "pass")
    assert ref.startswith("file:")
    assert ref.endswith(f"{NONCE}.pass")

    # When the kernel key IS present it still prefers the keyctl handle.
    monkeypatch.setattr(relay, "_keyctl_exists", lambda n, k: True)
    assert relay.reference(NONCE, "pass") == f"keyctl:jlab-passkey:{NONCE}.pass"


def test_keyctl_cross_read_warns_once_on_a_squatted_shm(monkeypatch, tmp_path, capsys):
    # The swallowed squat is a real security signal; a keyctl reader that only touches
    # shm as a fallback must not crash, but it must not bury the squat in a bare timeout
    # either - it surfaces one stderr line and reports nothing staged.
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(tmp_path))
    monkeypatch.setattr(relay, "_backend_cache", "keyctl")
    monkeypatch.setattr(relay, "_keyctl_collect", lambda n, k: None)
    relay.write_relay(NONCE, f"{NONCE}.json", "irrelevant")  # a file is plainly present

    def squat(n, k):
        raise PermissionError("owned by uid 9999, not ours")

    monkeypatch.setattr(relay, "_shm_collect", squat)
    assert relay.collect(NONCE, "json") is None  # swallowed, not propagated
    err = capsys.readouterr().err
    assert "shm relay dir unreadable" in err  # ...but surfaced once
