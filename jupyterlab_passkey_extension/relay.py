"""Where a relayed secret lives between the browser and a local client.

Two backends, one chosen per process at first use:

- **keyctl** - a uid-scoped kernel `user` key the kernel destroys at a TTL. The
  value never swaps to disk and nothing survives a crash. It grants no isolation
  from the user's own processes - same-uid read is identical to the 0600 file -
  so the win is no-swap, self-destruct, and no disk artifact, not access control.
- **shm** - the /dev/shm 0600 file relay, guarded against a co-tenant squatting
  the predictable path. The fallback when keyctl is not functional.

The writer and the reader are different processes (the Jupyter server and the
CLI), so the backend must be a property of the environment, not a per-call
choice: both probe independently and, being same-uid on one host, agree. A
reader that somehow guessed wrong finds nothing rather than the wrong value.

This module has no tornado dependency: the CLI imports it too.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile

# One kernel-key description per relay: `jlab-passkey:<nonce>.<kind>`. The nonce is
# already validated by the caller (it is a filename in the shm backend), so the
# description is safe to build from it.
_KEY_PREFIX = "jlab-passkey:"

# Seconds a staged secret lives before the kernel destroys it, per kind. The key
# only has to survive the gap between the writer staging it and the reader
# collecting it, plus a margin - `copy` gets the widest window because the user
# may not click its notification at once. An uncollected key self-destructs at
# its TTL, which is the whole point over the file that lingers until reboot.
_TTL = {"json": 300, "pass": 300, "secret": 900}

_backend_cache = None
_warned = False


# --------------------------------------------------------------------------- #
# shm backend - the /dev/shm 0600 file relay, with its squat guard.
# --------------------------------------------------------------------------- #


def relay_dir():
    """Per-user relay directory - the one definition, shared with the CLI.

    The default path is uid-scoped but PREDICTABLE, and /dev/shm is world-writable
    (1777), so anyone can get there first. This function only names the path; it
    promises nothing about who owns it. `ensure_relay_dir` is what makes it safe to
    use, and every read and write goes through that.

    Public because `cli` reads it too: the writer and the reader must agree on this
    path or every relay silently strands, so a second copy of the default is a bug
    waiting to happen rather than a convenience.
    """
    return os.environ.get(
        "JLAB_PASSKEY_RELAY_DIR", f"/dev/shm/jlab-passkey-{os.getuid()}"
    )


def ensure_relay_dir():
    """Return the relay dir, having proved it is ours and private. Raise if it is not.

    /dev/shm is 1777, so a co-tenant can create our predictable path before we do -
    as a directory they own, or as a symlink pointing anywhere. Neither is exotic and
    both used to succeed silently: `makedirs(exist_ok=True)` accepts a pre-existing
    directory whatever its owner, and follows a symlink without a word.

    Owning the DIRECTORY is enough to attack us even though every relay file is 0600.
    They cannot read a secret we wrote, but they can unlink it and drop their own
    `<nonce>.json` in its place - and the CLI reads that file and hands its `prf`
    straight to a keystore that derives a key from it. So this guards reads as much as
    writes, and is the reason every caller resolves the directory through here rather
    than through `relay_dir`.

    Fails loud rather than defaulting quietly: there is no safe fallback for "someone
    else owns the place I keep secrets", and a caller that got an error can be trusted
    not to have written one.
    """
    dest_dir = relay_dir()
    try:
        os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    except FileExistsError:
        # A DANGLING symlink lands here: makedirs' own exist_ok check asks isdir(),
        # which follows the link to a target that is not there and says no, so it
        # re-raises a bare "[Errno 17] File exists". Fall through rather than surface
        # that - it is the same squat as any other, and the lstat below names it.
        pass

    # lstat, never stat: stat() resolves the symlink and would happily report the
    # attacker's directory as a fine 0700 directory of ours. The whole check turns on
    # NOT following it.
    st = os.lstat(dest_dir)
    if not stat.S_ISDIR(st.st_mode):
        raise PermissionError(
            f"{dest_dir} is not a directory - a symlink or a file is squatting "
            "the relay path"
        )
    if st.st_uid != os.getuid():
        raise PermissionError(
            f"{dest_dir} is owned by uid {st.st_uid}, not {os.getuid()} - somebody "
            "else controls the relay directory"
        )
    if st.st_mode & 0o077:
        # Ours, merely loose - a 0755 left by an older release, or an inherited umask.
        # We own it, so this cannot fail on permissions; if it fails at all, that is a
        # real error and the caller should hear about it rather than write anyway.
        os.chmod(dest_dir, 0o700)
    return dest_dir


def write_relay(nonce, filename, content):
    """Write `content` to <relay_dir>/<filename> as a 0600 file, atomically.

    mkstemp makes a fresh 0600 file with O_EXCL and a random name (no symlink to
    follow, no world-readable window); os.replace then renames it onto the final
    name, so a reader never sees a partial write. Atomicity is what this buys - a
    relay is never read half-written and never appended to. It does NOT make the
    file single-read: reading it once and deleting it is the consumer's job.
    The caller must validate `nonce` first.

    Public for the same reason `relay_dir` is: `cli` writes a relay too (the
    `copy` flow stages a secret here for the browser to collect), and a second
    copy of these semantics is a bug waiting to happen - one of the two would
    eventually drift on the mode or the atomicity.
    """
    dest_dir = ensure_relay_dir()
    fd, tmp_path = tempfile.mkstemp(dir=dest_dir, prefix=f".{nonce}.", suffix=".tmp")
    try:
        # utf-8 pinned, not the process locale: for the `copy` flow the writer is the
        # CLI process and the reader is the Jupyter server process, so the two
        # locales are independent and a non-ASCII secret staged from a utf-8 shell
        # would be unreadable to a server running under LANG=C. Sharing this function
        # is what keeps the mode and the atomicity from drifting; the encoding has to
        # be pinned to travel with them.
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, os.path.join(dest_dir, filename))
    except BaseException:
        # A write that fails (a full /dev/shm) would otherwise leave a PARTIAL secret
        # at 0600 under the .tmp name, which nothing collects and nothing cleans.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _shm_path(nonce, kind):
    """The guarded relay path for a read or write. Raises on a squatted dir."""
    return os.path.join(ensure_relay_dir(), f"{nonce}.{kind}")


def _shm_collect(nonce, kind):
    """Read the relay file and unlink it, whether or not the read worked."""
    path = _shm_path(nonce, kind)
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _shm_exists(nonce, kind):
    # Existence is a boolean, not a read of contents, so it need not pass the squat
    # guard: a squatted-in file only makes this return True, and `collect` re-guards
    # before it ever reads. Polling the bare path also avoids a makedirs/chmod on
    # every 0.4s tick of the CLI's wait loop.
    return os.path.exists(os.path.join(relay_dir(), f"{nonce}.{kind}"))


def _shm_unstage(nonce, kind):
    try:
        os.unlink(os.path.join(relay_dir(), f"{nonce}.{kind}"))
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# keyctl backend - a uid-scoped kernel user key, destroyed at its TTL.
# --------------------------------------------------------------------------- #


def _key_desc(nonce, kind):
    return f"{_KEY_PREFIX}{nonce}.{kind}"


def _keyctl(args, input_bytes=None):
    """Run `keyctl <args>`. The payload, when there is one, rides stdin - never argv,
    so a secret is not exposed in the process list. Returns the CompletedProcess."""
    return subprocess.run(
        ["keyctl", *args],
        input=input_bytes,
        capture_output=True,
    )


def _keyctl_search(desc):
    """Return the key id as a string, or None if no such key on @u."""
    r = _keyctl(["search", "@u", "user", desc])
    if r.returncode != 0:
        return None
    return r.stdout.decode().strip()


def _keyctl_stage(nonce, kind, content, ttl=None):
    desc = _key_desc(nonce, kind)
    # Defensively clear any key already staged under this exact description before
    # adding. On @u `keyctl padd` replaces a same-description key in place (the kernel
    # updates the existing key's payload), so this is belt-and-suspenders - a nonce+kind
    # is used once - not duplicate-prevention; it just guarantees a clean slate.
    stale = _keyctl_search(desc)
    if stale:
        _keyctl(["unlink", stale, "@u"])
    r = _keyctl(["padd", "user", desc, "@u"], input_bytes=content.encode("utf-8"))
    if r.returncode != 0:
        # Full per-uid key quota is the realistic one; answer with a line, not a
        # traceback, exactly as a full /dev/shm does.
        raise OSError(f"keyctl padd failed: {r.stderr.decode().strip()}")
    kid = r.stdout.decode().strip()
    # The TTL is keyctl's whole reason for being here: the key self-destructs even if
    # the consumer crashes. So a key we cannot give an expiry to must not be left
    # staged - it would hold the secret until logout, defeating that guarantee, most
    # sharply for passphrase (never unlinked by us; the TTL is its only backstop).
    # Check the timeout call and, on failure, unlink and fail loud rather than leave a
    # no-expiry secret behind. The padd->timeout pair is not atomic; an interrupt
    # between them is the one residue this cannot close, and it is no worse than the
    # shm file the tmpfs bounds anyway.
    t = _keyctl(["timeout", kid, str(ttl if ttl is not None else _TTL[kind])])
    if t.returncode != 0:
        _keyctl(["unlink", kid, "@u"])
        raise OSError(f"keyctl timeout failed: {t.stderr.decode().strip()}")


def _keyctl_collect(nonce, kind):
    kid = _keyctl_search(_key_desc(nonce, kind))
    if kid is None:
        return None
    try:
        r = _keyctl(["pipe", kid])
        return r.stdout.decode("utf-8") if r.returncode == 0 else None
    finally:
        # Destroy the key on any read ATTEMPT, not just a successful one - the same
        # contract as the file backend, which unlinks in its finally whether or not
        # the open succeeded. A failed pipe must not leave the key for a second
        # collector.
        _keyctl(["unlink", kid, "@u"])


def _keyctl_exists(nonce, kind):
    return _keyctl_search(_key_desc(nonce, kind)) is not None


def _keyctl_unstage(nonce, kind):
    kid = _keyctl_search(_key_desc(nonce, kind))
    if kid:
        _keyctl(["unlink", kid, "@u"])


def _keyctl_probe():
    """True only when a full add -> search -> pipe -> unlink round-trip works on @u.

    Presence of the binary is not enough: without the session keyring linked to @u
    a key can be added but not found, so the only honest test is the round-trip
    itself. Everything here explicitly names @u, which sidesteps the session-keyring
    resolution the linking caveat is about.
    """
    if shutil.which("keyctl") is None:
        return False
    desc = f"{_KEY_PREFIX}probe.{os.getpid()}"
    try:
        r = _keyctl(["padd", "user", desc, "@u"], input_bytes=b"probe")
        if r.returncode != 0:
            return False
        # Unlink in a finally keyed off padd's own id: a search that fails or a pipe
        # that raises must not leave the probe key lingering to logout (it holds only
        # b"probe", so this is a resource leak, not a disclosure).
        kid = r.stdout.decode().strip()
        try:
            found = _keyctl_search(desc)
            if found is None:
                return False
            piped = _keyctl(["pipe", found])
            return piped.returncode == 0 and piped.stdout == b"probe"
        finally:
            _keyctl(["unlink", kid, "@u"])
    except (OSError, subprocess.SubprocessError):
        return False


# --------------------------------------------------------------------------- #
# Backend selection and the dispatch API both processes call.
# --------------------------------------------------------------------------- #


def _warn_shm_fallback():
    global _warned
    if _warned:
        return
    _warned = True
    # stderr, never stdout: stdout carries the CLI's result (a cred_id, a PRF, a
    # relay reference), and a warning there would contaminate a `$(...)` capture. In
    # the server this lands in the Jupyter log, which is the right place for it.
    print(
        "keyctl unavailable; using /dev/shm relay (swappable, orphaned on crash) - "
        "install keyutils for kernel-keyring relays",
        file=sys.stderr,
    )


def backend():
    """'keyctl' or 'shm', decided once per process and cached.

    JLAB_PASSKEY_RELAY_BACKEND pins it: `keyctl` fails loud if the probe fails,
    `shm` forces the file relay, `auto` (the default) prefers keyctl and falls back
    to shm with a one-time warning.
    """
    global _backend_cache
    if _backend_cache is not None:
        return _backend_cache
    choice = os.environ.get("JLAB_PASSKEY_RELAY_BACKEND", "auto")
    if choice == "shm":
        _backend_cache = "shm"
    elif choice == "keyctl":
        if not _keyctl_probe():
            # OSError, not RuntimeError: every relay-failure path this project surfaces
            # is an OSError, and the handlers (routes `_relay_unavailable`, the CLI's
            # `except OSError` lines) catch that family - so a forced-but-broken keyctl
            # answers with a clean 500 / one line, never a traceback.
            raise OSError(
                "JLAB_PASSKEY_RELAY_BACKEND=keyctl but keyctl is not functional here"
            )
        _backend_cache = "keyctl"
    else:
        if _keyctl_probe():
            _backend_cache = "keyctl"
        else:
            _warn_shm_fallback()
            _backend_cache = "shm"
    return _backend_cache


def stage(nonce, kind, content, ttl=None):
    """Put `content` where the reader will collect it, under this nonce and kind.

    `ttl` overrides the per-kind default expiry on the keyctl backend - the copy
    block-wait uses it so the key always outlives the wait (a key that self-destructs
    mid-wait would read as a collection). shm files never expire, so it is ignored
    there.
    """
    if backend() == "keyctl":
        _keyctl_stage(nonce, kind, content, ttl)
    else:
        write_relay(nonce, f"{nonce}.{kind}", content)


def collect(nonce, kind):
    """Return the staged value and destroy it, or None if there is none.

    Always one-shot: peeking without consuming is `relay_exists`, so a read is always
    a destructive collect. The value is gone on any read attempt, so a failed read
    cannot leave it for a second collector.
    """
    if backend() == "keyctl":
        return _keyctl_collect(nonce, kind)
    return _shm_collect(nonce, kind)


def relay_exists(nonce, kind):
    """Whether a value is staged - for the CLI's wait loops. Reads nothing."""
    if backend() == "keyctl":
        return _keyctl_exists(nonce, kind)
    return _shm_exists(nonce, kind)


def unstage(nonce, kind):
    """Best-effort destroy, for unwinding a stage that can no longer be collected.

    Best-effort means it never raises. It runs only on an unwind path - a `finally`, or
    an exception handler cleaning up a stage - where a raised OSError would REPLACE the
    error actually being handled (an exception in a `finally` masks the propagating one).
    A backend that has since become unavailable, or a relay already gone, is nothing to
    surface here: there was nothing to collect anyway.
    """
    try:
        if backend() == "keyctl":
            _keyctl_unstage(nonce, kind)
        else:
            _shm_unstage(nonce, kind)
    except OSError:
        pass


def reference(nonce, kind):
    """The scheme-prefixed handle the CLI prints for an EXTERNAL consumer.

    Only `passphrase` uses this: its reader is a vault tool outside this extension,
    so it needs a handle it can resolve whichever backend is live. keyctl has no
    path, so the two forms are distinguished by scheme:

        keyctl:jlab-passkey:<nonce>.pass   ->  keyctl pipe $(keyctl search @u user <desc>)
        file:<relay_dir>/<nonce>.pass      ->  read the file

    The value itself never passes through this process on the way out - the
    consumer reads the key or the file directly.
    """
    if backend() == "keyctl":
        return f"keyctl:{_key_desc(nonce, kind)}"
    return f"file:{os.path.join(relay_dir(), f'{nonce}.{kind}')}"
