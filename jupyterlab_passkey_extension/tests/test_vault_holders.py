"""The vault key holders: one interface, three mechanisms, capabilities per host.

keyctl and gpg-agent run for real where this host allows them (skipped otherwise);
the process memory holder always runs. gpg-agent runs from a throwaway GnuPG home
under a short /tmp path, since a Unix socket path is limited to 107 bytes.
"""

import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import time

import pytest

from jupyterlab_passkey_extension import relay
from jupyterlab_passkey_extension.vault import holders

KEY = bytes(range(32))
KEY2 = bytes(range(32, 64))
# Vault ids of this test process only, so a run never touches a real vault's key.
VID = f"7e57{os.getpid():012x}"
VID2 = f"7e58{os.getpid():012x}"

_KEYCTL = relay._keyctl_probe()
_GPG = all(shutil.which(t) for t in holders._GPG_TOOLS)

needs_keyctl = pytest.mark.skipif(not _KEYCTL, reason="keyctl not functional on this host")
needs_gpg = pytest.mark.skipif(not _GPG, reason="GnuPG not installed")


@pytest.fixture(autouse=True)
def _fresh_selection(monkeypatch):
    monkeypatch.setattr(holders, "_selected", None)
    monkeypatch.setattr(holders, "_skipped", {})
    monkeypatch.setattr(holders, "_notice", None)
    monkeypatch.delenv(holders.ENV, raising=False)


@pytest.fixture
def gnupg_state(monkeypatch):
    state = tempfile.mkdtemp(prefix="jv", dir="/tmp")
    monkeypatch.setenv("XDG_STATE_HOME", state)
    yield state
    subprocess.run(
        ["gpgconf", "--kill", "gpg-agent"],
        env=dict(os.environ, GNUPGHOME=holders._gnupg_home()), capture_output=True,
    )
    shutil.rmtree(state, ignore_errors=True)


def _make(name):
    if name == "keyctl":
        return holders.KeyctlHolder()
    if name == "gpg-agent":
        assert holders.GpgAgentHolder.unusable_reason() is None
        return holders.GpgAgentHolder()
    return holders.MemoryHolder()


HOLDERS = [
    pytest.param("keyctl", marks=needs_keyctl),
    pytest.param("gpg-agent", marks=needs_gpg),
    "memory",
]


@pytest.fixture(params=HOLDERS)
def holder(request):
    if request.param == "gpg-agent":
        request.getfixturevalue("gnupg_state")
    h = _make(request.param)
    yield h
    h.clear(VID)


# --------------------------------------------------------------------------- #
# the contract every holder keeps
# --------------------------------------------------------------------------- #


def test_every_holder_says_what_it_is_and_that_it_works_here(holder):
    # The Key holder tooltip and `vault status` read "<name> - <about>".
    assert holder.name and holder.about
    # The check `auto` selects by: keyctl's is its own code, not the probe that runs
    # this test, so a broken one would move every host to gpg-agent unnoticed.
    assert type(holder).unusable_reason() is None


def test_put_then_get_returns_the_key(holder):
    holder.put(VID, KEY, 60)
    assert holder.get(VID) == KEY
    assert 55 <= holder.remaining(VID) <= 60


def test_a_second_put_replaces_the_first(holder):
    holder.put(VID, KEY, 60)
    holder.put(VID, KEY2, 60)
    assert holder.get(VID) == KEY2


def test_clear_empties_the_holder(holder):
    holder.put(VID, KEY, 60)
    holder.clear(VID)
    assert holder.get(VID) is None
    assert holder.remaining(VID) is None


def test_the_key_is_gone_after_its_ttl(holder):
    holder.put(VID, KEY, 1)
    time.sleep(2.5)
    assert holder.get(VID) is None
    assert holder.remaining(VID) is None


def test_a_held_key_reports_at_least_one_second_left(holder):
    # `status` reads a None from remaining() as locked; rounding 0.9s down to 0 once
    # reported a freshly unlocked vault as locked. 2 s, not 1: keyctl expires a key
    # at the next whole second after the timeout, so a 1 s key set late in a second
    # can be gone within milliseconds.
    holder.put(VID, KEY, 2)
    assert holder.remaining(VID) in (1, 2)
    assert holder.get(VID) == KEY


def test_a_key_is_only_ever_read_back_for_its_own_vault(holder):
    # Two vaults under one user once shared one key name: unlocking B made A decrypt
    # with B's key. keyctl and gpg-agent keep both keys; memory (one key at a time)
    # drops A's - but no holder ever hands out B's for it.
    holder.put(VID, KEY, 60)
    holder.put(VID2, KEY2, 60)
    assert holder.get(VID2) == KEY2
    assert holder.get(VID) in (KEY, None)
    held_a = holder.get(VID)
    holder.clear(VID2)
    assert holder.get(VID2) is None
    assert holder.get(VID) == held_a
    holder.clear(VID)


@needs_gpg
def test_gpg_agent_keeps_both_keys_when_the_expiry_is_the_same(gnupg_state):
    # A reload empties the agent's cache; it happens only when the config differs from
    # the one the agent loaded, so a second server (a second holder on the same state
    # dir) unlocking with the same duration does not lock the first's vault.
    first, second = _make("gpg-agent"), _make("gpg-agent")
    first.put(VID, KEY, 60)
    second.put(VID2, KEY2, 60)
    assert (first.get(VID), second.get(VID2)) == (KEY, KEY2)


@needs_gpg
def test_gpg_agent_clears_the_key_when_its_expiry_cannot_be_set(gnupg_state, monkeypatch):
    # The key without its expiry entry would read as locked yet still open the vault.
    h = _make("gpg-agent")
    real = holders.GpgAgentHolder._preset
    calls = []

    def second_refused(cache_id, value):
        calls.append(cache_id)
        if len(calls) == 2:
            raise OSError("gpg-agent refused the preset")
        return real(cache_id, value)

    monkeypatch.setattr(holders.GpgAgentHolder, "_preset", staticmethod(second_refused))
    with pytest.raises(OSError, match="refused the preset"):
        h.put(VID, KEY, 60)
    assert h.get(VID) is None and h.remaining(VID) is None


@needs_gpg
def test_a_failed_gpg_agent_reload_is_retried_on_the_next_put(gnupg_state, monkeypatch):
    # A reload happens only when the config differs from the one the agent loaded; a
    # reload that failed must not leave the agent on the old expiry for good.
    h = _make("gpg-agent")
    h.put(VID, KEY, 60)  # loaded: the 60 s config
    real = holders.GpgAgentHolder._agent
    refusals = [["ERR 67109139 Unknown IPC command"]]
    reloads = []

    def once_refused(commands, autostart=True):
        if commands == ["RELOADAGENT"]:
            reloads.append(1)
            if refusals:
                return refusals.pop()
        return real(commands, autostart)

    monkeypatch.setattr(holders.GpgAgentHolder, "_agent", staticmethod(once_refused))
    with pytest.raises(OSError, match="did not reload"):
        h.put(VID, KEY, 30)  # the file now says 30; the agent still runs 60
    h.put(VID, KEY, 30)  # the file is current, the record is not: reload again
    assert reloads == [1, 1]
    assert h.get(VID) == KEY
    h.clear(VID)


@needs_gpg
def test_gpg_agent_reloads_a_config_it_has_not_loaded(gnupg_state, monkeypatch):
    # The conf can already say what the agent never loaded (a server killed between
    # the write and the reload): no record of it being loaded, so the put reloads.
    h = _make("gpg-agent")
    holders.GpgAgentHolder._write_conf(30)  # the file already current
    real = holders.GpgAgentHolder._agent
    reloads = []

    def spy(commands, autostart=True):
        if commands == ["RELOADAGENT"]:
            reloads.append(1)
        return real(commands, autostart)

    monkeypatch.setattr(holders.GpgAgentHolder, "_agent", staticmethod(spy))
    h.put(VID, KEY, 30)
    h.put(VID, KEY, 30)
    assert reloads == [1]
    h.clear(VID)


@needs_keyctl
def test_keyctl_keeps_one_key_per_vault():
    h = holders.KeyctlHolder()
    try:
        h.put(VID, KEY, 60)
        h.put(VID2, KEY2, 60)
        assert (h.get(VID), h.get(VID2)) == (KEY, KEY2)
    finally:
        h.clear(VID)
        h.clear(VID2)


def test_an_empty_holder_reports_nothing(holder):
    assert holder.get(VID) is None
    assert holder.remaining(VID) is None


@pytest.mark.parametrize("key,ttl", [
    (b"short", 60), (KEY + b"x", 60), ("x" * 32, 60),
    (KEY, 0), (KEY, -1), (KEY, holders.MAX_TTL + 1), (KEY, 1.5), (KEY, True),
])
def test_put_refuses_a_malformed_key_or_ttl(holder, key, ttl):
    with pytest.raises(ValueError):
        holder.put(VID, key, ttl)


# --------------------------------------------------------------------------- #
# capabilities
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("locked,no_dump,ttl,summary", [
    (True, True, True, "strong"),
    (True, True, False, "strong"),
    (True, False, True, "reduced"),
    (False, True, False, "reduced"),
    (False, False, True, "basic"),
    (False, False, False, "basic"),
])
def test_the_summary_follows_the_protections(locked, no_dump, ttl, summary):
    caps = holders.Capabilities(locked, no_dump, ttl, False, False)
    assert caps.summary == summary


def test_the_protection_names_what_it_counts_with_the_container_caveat():
    caps = {"locked_memory": True, "no_core_dump": True, "holder_ttl": True,
            "locks_on_restart": False, "container_isolated": False}
    assert holders._protection(caps) == (
        "kept out of swap, kept out of core dumps; "
        "other containers running as the same user id can read it")
    # memfd_secret: a timer in the server, not the holder, ends the key; not a gap.
    assert holders._protection({**caps, "holder_ttl": False, "container_isolated": True}) == (
        "kept out of swap, kept out of core dumps")
    assert holders._protection({**caps, "locked_memory": False}).startswith(
        "not kept out of swap;")


def test_describe_explains_every_capability_in_order():
    d = holders.describe(holders.MemoryHolder())
    assert d["about"] == "this extension's own code, in the server's memory"
    assert [x["key"] for x in d["details"]] == list(d["capabilities"])
    assert [x["label"] for x in d["details"]] == [
        "Never in swap", "Never in crash dumps", "Expires on its own", "Locks on server restart",
        "Isolated from containers"]
    expiry = next(x for x in d["details"] if x["key"] == "holder_ttl")
    assert expiry == {"key": "holder_ttl", "label": "Expires on its own",
                      "text": "a timer in the Jupyter server deletes the key at expiry"}


@needs_keyctl
def test_keyctl_capabilities():
    caps = holders.KeyctlHolder.capabilities
    assert (caps.locked_memory, caps.no_core_dump, caps.holder_ttl, not caps.locks_on_restart) == (
        True, True, True, True)
    # The kernel keyring is per uid and user namespace, not per container.
    assert caps.container_isolated is False


@needs_gpg
def test_gpg_agent_capabilities_are_measured_from_the_agent(gnupg_state, monkeypatch):
    seen = []
    monkeypatch.setattr(holders, "_proc_locks_memory", lambda pid: seen.append(pid) or False)
    monkeypatch.setattr(holders, "_proc_core_disabled", lambda pid: True)
    h = _make("gpg-agent")
    assert seen and isinstance(seen[0], int)
    assert h.capabilities.locked_memory is False
    assert h.capabilities.no_core_dump is True
    assert h.capabilities.holder_ttl and not h.capabilities.locks_on_restart


@needs_gpg
@pytest.mark.parametrize("where,isolated", [("state", False), ("run", True)])
def test_gpg_agent_isolation_follows_where_its_socket_is(gnupg_state, monkeypatch, where, isolated):
    # Without /run/user the socket sits in the GnuPG home, under the (often shared)
    # home directory; a container mounting the same home could connect to it.
    socket = (os.path.join(holders._gnupg_home(), "S.gpg-agent") if where == "state"
              else "/run/user/1000/gnupg/S.gpg-agent")
    monkeypatch.setattr(holders, "_agent_socket", lambda: socket)
    assert _make("gpg-agent").capabilities.container_isolated is isolated


def test_memory_prefers_memfd_secret():
    if holders._open_memfd_secret(holders._PAGE) is None:
        pytest.skip("memfd_secret not available on this kernel")
    h = holders.MemoryHolder()
    assert h.name == "memory/memfd_secret"
    assert h.capabilities.locked_memory and h.capabilities.no_core_dump
    assert not h.capabilities.holder_ttl and h.capabilities.locks_on_restart


def test_a_late_expiry_timer_leaves_a_fresh_key_alone():
    # A timer that fired while a new put held the lock runs after it: it must not wipe
    # the key that put just stored.
    h = holders.MemoryHolder()
    h.put(VID, KEY, 60)
    stale = h._expiry
    h.put(VID, KEY2, 60)
    h._expire(stale)  # the first put's timer, firing late
    assert h.get(VID) == KEY2
    h.clear(VID)


def test_memory_falls_back_to_mlock(monkeypatch):
    monkeypatch.setattr(holders, "_open_memfd_secret", lambda size: None)
    h = holders.MemoryHolder()
    assert h.name == "memory/mlock"
    assert h.capabilities.locked_memory and h.capabilities.no_core_dump
    h.put(VID, KEY, 60)
    assert h.get(VID) == KEY


def test_memory_falls_back_to_plain_memory(monkeypatch):
    monkeypatch.setattr(holders, "_open_memfd_secret", lambda size: None)
    monkeypatch.setattr(holders, "_mlock", lambda mapping, size: False)
    h = holders.MemoryHolder()
    assert h.name == "memory/plain"
    assert h.capabilities.locked_memory is False
    h.put(VID, KEY, 60)
    assert h.get(VID) == KEY


def test_memory_clear_zeroes_the_page():
    h = holders.MemoryHolder()
    h.put(VID, KEY, 60)
    h.clear(VID)
    assert h._map[:] == bytes(holders._PAGE)


def test_memory_wipes_the_page_at_expiry_without_being_asked():
    h = holders.MemoryHolder()
    h.put(VID, KEY, 1)
    time.sleep(1.6)
    # No get() in between: the timer, not the next request, did the wiping.
    assert h._map[:] == bytes(holders._PAGE)


# --------------------------------------------------------------------------- #
# the key never on a command line
# --------------------------------------------------------------------------- #


def _spy_argv(monkeypatch):
    seen = []
    real_run = subprocess.run

    def spy(cmd, *a, **kw):
        seen.append(" ".join(map(str, cmd)))
        return real_run(cmd, *a, **kw)

    monkeypatch.setattr(subprocess, "run", spy)
    return seen


@pytest.mark.parametrize("name", [
    pytest.param("keyctl", marks=needs_keyctl), pytest.param("gpg-agent", marks=needs_gpg),
])
def test_the_key_never_appears_in_a_command_line(name, request, monkeypatch):
    if name == "gpg-agent":
        request.getfixturevalue("gnupg_state")
    h = _make(name)
    seen = _spy_argv(monkeypatch)
    try:
        h.put(VID, KEY, 60)
        assert h.get(VID) == KEY
    finally:
        h.clear(VID)
    assert seen, "the holder ran no subprocess - the spy saw nothing"
    for argv in seen:
        assert KEY.hex() not in argv
        assert KEY.hex().encode().hex() not in argv
        assert KEY.decode("latin-1") not in argv


# --------------------------------------------------------------------------- #
# gpg-agent: its own home
# --------------------------------------------------------------------------- #


@needs_gpg
def test_gpg_agent_runs_from_its_own_home(gnupg_state):
    user_gnupg = os.path.expanduser("~/.gnupg")
    before = sorted(os.listdir(user_gnupg)) if os.path.isdir(user_gnupg) else None
    h = _make("gpg-agent")
    h.put(VID, KEY, 5)
    home = holders._gnupg_home()
    assert home.startswith(gnupg_state)
    with open(os.path.join(home, "gpg-agent.conf")) as f:
        conf = f.read()
    assert "max-cache-ttl 5" in conf and "allow-preset-passphrase" in conf
    assert oct(os.stat(home).st_mode & 0o777) == "0o700"
    assert holders._agent_socket() != os.path.join(user_gnupg, "S.gpg-agent")
    after = sorted(os.listdir(user_gnupg)) if os.path.isdir(user_gnupg) else None
    assert before == after


def test_a_socket_path_over_the_limit_makes_gpg_agent_unusable(monkeypatch, tmp_path):
    if not _GPG:
        pytest.skip("GnuPG not installed")
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr(holders, "_agent_socket", lambda: "/" + "d" * 120 + "/S.gpg-agent")
    reason = holders.GpgAgentHolder.unusable_reason()
    assert reason and "107-byte" in reason and "XDG_STATE_HOME" in reason


def test_missing_gnupg_makes_gpg_agent_unusable(monkeypatch):
    monkeypatch.setattr(holders.shutil, "which", lambda name: None)
    reason = holders.GpgAgentHolder.unusable_reason()
    assert "not found" in reason and "apt install gnupg" in reason


# --------------------------------------------------------------------------- #
# selection
# --------------------------------------------------------------------------- #


def _fake(name, reason=None):
    cls = type(f"Fake{name}", (holders.Holder,), {
        "name": name,
        "capabilities": holders.Capabilities(True, True, True, True, True),
        "unusable_reason": classmethod(lambda c: reason),
    })
    return cls


def _order(monkeypatch, keyctl_reason, gpg_reason):
    fk, fg = _fake("keyctl", keyctl_reason), _fake("gpg-agent", gpg_reason)
    monkeypatch.setattr(holders, "_ORDER", (fk, fg, holders.MemoryHolder))
    monkeypatch.setattr(holders, "_BY_NAME", {
        "keyctl": fk, "gpg-agent": fg, "memory": holders.MemoryHolder})
    return fk, fg


def test_auto_takes_keyctl_first(monkeypatch):
    fk, _ = _order(monkeypatch, None, None)
    assert isinstance(holders.select(), fk)


def test_auto_takes_gpg_agent_when_keyctl_is_refused(monkeypatch):
    _, fg = _order(monkeypatch, "the kernel refused the keyring syscall", None)
    assert isinstance(holders.select(), fg)
    assert holders.describe(holders.select())["notice"] is None


def test_auto_lands_on_memory_with_one_notice(monkeypatch, capsys):
    _order(monkeypatch, "keyctl refused", "gpg-agent, gpg-connect-agent, gpgconf not found - install GnuPG (apt install gnupg)")
    first = holders.select()
    assert isinstance(first, holders.MemoryHolder)
    assert holders.select() is first
    out, err = capsys.readouterr()
    assert out == ""
    assert err.count("\n") == 1
    assert "gpg-agent unavailable" in err and "own code" in err and "apt install gnupg" in err


@pytest.mark.skipif(not os.path.exists("/dev/full"), reason="needs /dev/full to fail a write")
def test_the_memory_notice_never_fails_select(monkeypatch):
    # A server whose stderr broke (a full log disk, a closed terminal): the notice must
    # not turn the first vault/status into a 500.
    _order(monkeypatch, "keyctl refused", "gpg-agent not found")
    full = open("/dev/full", "w", buffering=1)
    monkeypatch.setattr(sys, "stderr", full)
    try:
        assert isinstance(holders.select(), holders.MemoryHolder)
    finally:
        with contextlib.suppress(OSError):
            full.close()


def test_a_pinned_holder_that_cannot_work_fails_loud(monkeypatch):
    _order(monkeypatch, None, "gpg-agent not found")
    monkeypatch.setenv(holders.ENV, "gpg-agent")
    with pytest.raises(OSError, match="gpg-agent not found"):
        holders.select()


def test_a_pinned_memory_holder_gives_no_notice(monkeypatch, capsys):
    _order(monkeypatch, "refused", "missing")
    monkeypatch.setenv(holders.ENV, "memory")
    assert isinstance(holders.select(), holders.MemoryHolder)
    assert holders.describe(holders.select())["notice"] is None
    assert capsys.readouterr().err == ""


def test_an_unknown_pin_is_refused(monkeypatch):
    monkeypatch.setenv(holders.ENV, "tpm")
    with pytest.raises(OSError, match="not one of auto, keyctl, gpg-agent, memory"):
        holders.select()


def test_debug_report_names_the_decision_and_never_the_key(monkeypatch):
    _order(monkeypatch, "the kernel refused the keyring syscall", "missing")
    h = holders.select()
    h.put(VID, KEY, 60)
    try:
        report = holders.debug_report()
    finally:
        h.clear(VID)
    assert "skipped keyctl - the kernel refused the keyring syscall" in report
    assert f"holder={h.name}" in report
    assert "locked_memory=" in report
    assert KEY.hex() not in report


def test_describe_carries_name_summary_capabilities_and_notice(monkeypatch):
    _order(monkeypatch, "refused", "missing")
    h = holders.select()
    d = holders.describe(h)
    assert d["name"] == h.name
    assert d["summary"] == h.capabilities.summary
    assert set(d["capabilities"]) == {
        "locked_memory", "no_core_dump", "holder_ttl", "locks_on_restart", "container_isolated"}
    assert "own code" in d["notice"]
