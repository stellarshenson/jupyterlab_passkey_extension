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
    # silent file relay that lacks the properties they asked for.
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "keyctl")
    monkeypatch.setattr(relay, "_backend_cache", None)
    monkeypatch.setattr(relay, "_keyctl_probe", lambda: False)

    with pytest.raises(RuntimeError, match="not functional"):
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
