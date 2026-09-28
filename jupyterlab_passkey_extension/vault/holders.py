"""Where the unlocked vault's data key is kept while the vault is open.

The data key is unwrapped once, at unlock, and must then be kept for the unlock
duration. What a host allows differs: a seccomp profile may forbid the kernel keyring,
GnuPG may not be installed. So there are three holders behind one small interface,
tried in a fixed order, and each reports in `capabilities` what it actually protects
on this host - measured where it can be, never assumed. Callers never branch on which
holder they have; `vault status` and the panel show the capabilities to the user.

    keyctl     the kernel keyring (@u, one per uid and user namespace): kernel memory,
               kernel-enforced expiry, kept across a server restart in the same user
               namespace - but shared by every container of that uid in it
    gpg-agent  a dedicated gpg-agent with its own GnuPG home: expiry enforced by the
               agent (max-cache-ttl), kept across a server restart that leaves the
               agent running (a restart of the server's container ends it)
    memory     this process's own memory: memfd_secret, else an mlock'd mapping
               excluded from core dumps, else plain memory

Every call names the vault (its random `id`), and the holder keeps each vault's key
under that name, so two vaults under one user never read each other's key.

This is the part expected to need maintenance as hosts change. A new mechanism is a
new class with the same members, added to `_ORDER`.
"""

import ctypes
import math
import mmap
import os
import platform
import shutil
import subprocess
import threading
import time
from dataclasses import asdict, dataclass

from .. import relay

ENV = "JLAB_PASSKEY_VAULT_HOLDER"
KEY_BYTES = 32
# The unlock duration setting tops out at 1440 minutes; the bound also keeps a TTL
# far below keyctl's 32-bit timeout field.
MAX_TTL = 24 * 3600

# sockaddr_un.sun_path is 108 bytes including the terminating NUL.
_SUN_PATH_MAX = 107
_AGENT_TIMEOUT = 10


@dataclass(frozen=True)
class Capabilities:
    locked_memory: bool  # the holder's copy of the key is never written to swap
    no_core_dump: bool  # the holder's copy of the key is left out of core dumps
    holder_ttl: bool  # expiry is enforced by the holder, not by a timer in this process
    locks_on_restart: bool  # a Jupyter server restart locks the vault: the key dies with it
    container_isolated: bool  # another container running as the same uid cannot read it

    @property
    def summary(self) -> str:
        # Every holder ends the key at the unlock duration - by its own expiry, or with
        # the server - so the expiry is not counted.
        if self.locked_memory and self.no_core_dump:
            return "strong"
        if self.locked_memory or self.no_core_dump:
            return "reduced"
        return "basic"


def _seconds_left(expiry_epoch):
    """Whole seconds until an expiry stored as epoch text - at least 1 while the key is
    held, since `status` reads "nothing left" as locked."""
    try:
        return max(1, int(expiry_epoch) - int(time.time()))
    except (TypeError, ValueError):
        return 1


def _check(key, ttl):
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError(f"the key must be {KEY_BYTES} bytes")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 0 < ttl <= MAX_TTL:
        raise ValueError(f"ttl must be a whole number of seconds from 1 to {MAX_TTL}")


class Holder:
    """The interface every holder implements."""

    name = "holder"
    about = ""  # what the holder is, for a reader who does not know the name
    capabilities: Capabilities

    @classmethod
    def unusable_reason(cls):
        """None when this holder works here, else one line saying why it does not."""
        return None

    def put(self, vault_id: str, key: bytes, ttl: int) -> None:
        raise NotImplementedError

    def get(self, vault_id: str):
        """The key, or None when nothing is held or it has expired."""
        raise NotImplementedError

    def clear(self, vault_id: str) -> None:
        raise NotImplementedError

    def remaining(self, vault_id: str):
        """Whole seconds until expiry, or None when nothing is held."""
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# keyctl - the kernel keyring
# --------------------------------------------------------------------------- #

def _key_desc(vault_id):
    return f"{relay._KEY_PREFIX}vault-key:{vault_id}"


def _expiry_desc(vault_id):
    return f"{relay._KEY_PREFIX}vault-expiry:{vault_id}"


class KeyctlHolder(Holder):
    """A `user` key on @u with a kernel timeout.

    The expiry time rides a second key with the same timeout, so `remaining` is exact
    (/proc/keys shows only the largest whole unit, such as 1h for 1h 56m) and vanishes with the key.
    """

    name = "keyctl"
    about = "the kernel keyring"
    capabilities = Capabilities(
        locked_memory=True, no_core_dump=True, holder_ttl=True,
        locks_on_restart=False, container_isolated=False,
    )

    @classmethod
    def unusable_reason(cls):
        # The relay's probe links @u into the session keyring first, then runs a real
        # add/search/read round-trip - a present binary proves nothing.
        if relay._keyctl_probe():
            return None
        return relay._probe_detail or "the keyctl round-trip failed"

    def _add(self, desc, payload, ttl):
        r = relay._keyctl(["padd", "user", desc, "@u"], input_bytes=payload)
        if r.returncode != 0:
            raise OSError(f"keyctl padd failed: {r.stderr.decode(errors='replace').strip()}")
        kid = r.stdout.decode().strip()
        t = relay._keyctl(["timeout", kid, str(ttl)])
        if t.returncode != 0:
            # A key with no expiry would hold the data key until logout.
            relay._keyctl(["unlink", kid, "@u"])
            raise OSError(f"keyctl timeout failed: {t.stderr.decode(errors='replace').strip()}")

    def put(self, vault_id, key, ttl):
        _check(key, ttl)
        self.clear(vault_id)
        try:
            self._add(_key_desc(vault_id), key, ttl)
            self._add(_expiry_desc(vault_id), str(int(time.time()) + ttl).encode(), ttl)
        except OSError:
            self.clear(vault_id)
            raise

    def _read(self, desc):
        kid = relay._keyctl_search(desc)
        if kid is None:
            return None
        r = relay._keyctl(["pipe", kid])
        return r.stdout if r.returncode == 0 else None

    def get(self, vault_id):
        key = self._read(_key_desc(vault_id))
        return key if key is not None and len(key) == KEY_BYTES else None

    def clear(self, vault_id):
        # Every match, not the first: a key added while @u was not searchable from
        # this session is a duplicate rather than an update.
        for desc in (_key_desc(vault_id), _expiry_desc(vault_id)):
            for _ in range(16):
                kid = relay._keyctl_search(desc)
                if kid is None:
                    break
                relay._keyctl(["unlink", kid, "@u"])

    def remaining(self, vault_id):
        if relay._keyctl_search(_key_desc(vault_id)) is None:
            return None
        return _seconds_left(self._read(_expiry_desc(vault_id)))


# --------------------------------------------------------------------------- #
# gpg-agent - a dedicated agent with its own GnuPG home
# --------------------------------------------------------------------------- #

_PROBE_ID = "jlab-passkey-vault-probe"


def _cache_id(vault_id):
    return f"jlab-passkey-vault-key-{vault_id}"


def _expiry_id(vault_id):
    return f"jlab-passkey-vault-expiry-{vault_id}"


_GPG_TOOLS = ("gpg-agent", "gpg-connect-agent", "gpgconf")


def _state_dir():
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )
    return os.path.join(base, "jupyterlab-passkey")


def _gnupg_home():
    return os.path.join(_state_dir(), "gnupg")


def _agent_socket():
    """The agent socket path gpgconf reports for the vault's GnuPG home."""
    try:
        r = subprocess.run(
            ["gpgconf", "--list-dirs", "agent-socket"], capture_output=True, text=True,
            env=dict(os.environ, GNUPGHOME=_gnupg_home()), timeout=_AGENT_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise OSError(f"could not run gpgconf: {e}")
    return r.stdout.strip()


class GpgAgentHolder(Holder):
    """A gpg-agent of the vault's own, never the user's ~/.gnupg one.

    The agent only accepts a preset passphrase with no per-entry timeout
    (`PRESET_PASSPHRASE <id> -1 <hex>`); a given timeout answers "Not implemented".
    Expiry therefore comes from `max-cache-ttl` in this home's gpg-agent.conf, which is
    why the agent must be a separate one: changing that setting in ~/.gnupg would change
    the user's own gpg and ssh caching. The key is sent on the agent's stdin as hex,
    never on a command line. A reload empties the agent's cache, so it happens only
    when the config differs from the one the agent last loaded - recorded in
    gpg-agent.conf.loaded once a reload answers OK. Two vaults that share this state
    directory share one unlock duration and keep each other's keys, and a reload that
    failed or never ran is retried on the next put.
    """

    name = "gpg-agent"
    about = "a GnuPG agent of its own"

    def __init__(self):
        pid = self._agent_pid()
        # Without /run/user the socket lands in the GnuPG home, under the user's home
        # directory - reachable from any container that mounts the same home.
        socket = os.path.realpath(_agent_socket())
        self.capabilities = Capabilities(
            locked_memory=_proc_locks_memory(pid),
            no_core_dump=_proc_core_disabled(pid),
            holder_ttl=True,
            locks_on_restart=False,
            container_isolated=not socket.startswith(os.path.realpath(_state_dir()) + os.sep),
        )

    @staticmethod
    def _agent(commands, autostart=True):
        """Send Assuan commands to the vault's agent on stdin; return its stdout lines."""
        argv = ["gpg-connect-agent"] + ([] if autostart else ["--no-autostart"])
        env = dict(os.environ, GNUPGHOME=_gnupg_home())
        try:
            r = subprocess.run(
                argv, input="\n".join(list(commands) + ["/bye"]) + "\n",
                capture_output=True, text=True, env=env, timeout=_AGENT_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError) as e:
            raise OSError(f"could not run gpg-connect-agent: {e}")
        return r.stdout.splitlines()

    @classmethod
    def _preset(cls, cache_id, value: str):
        out = cls._agent([f"PRESET_PASSPHRASE {cache_id} -1 {value.encode().hex()}"])
        if not out or not out[-1].startswith("OK"):
            raise OSError(f"gpg-agent refused the key: {out[-1] if out else 'no answer'}")

    @classmethod
    def _fetch(cls, cache_id):
        try:
            out = cls._agent([f"GET_PASSPHRASE --data --no-ask {cache_id} X X X"], autostart=False)
        except OSError:
            return None
        data = [line[2:] for line in out if line.startswith("D ")]
        return data[0] if data and out[-1].startswith("OK") else None

    @classmethod
    def _agent_pid(cls):
        try:
            out = cls._agent(["GETINFO pid"])
        except OSError:
            return None
        data = [line[2:] for line in out if line.startswith("D ")]
        return int(data[0]) if data and data[0].isdigit() else None

    @classmethod
    def _write_conf(cls, ttl=None):
        """Write gpg-agent.conf when it differs; return the text it now holds."""
        path = os.path.join(_gnupg_home(), "gpg-agent.conf")
        lines = ["allow-preset-passphrase"]
        if ttl is not None:
            lines += [f"default-cache-ttl {ttl}", f"max-cache-ttl {ttl}"]
        text = "\n".join(lines) + "\n"
        if _read_text(path) != text:
            _write_private(path, text)
        return text

    @classmethod
    def unusable_reason(cls):
        missing = [t for t in _GPG_TOOLS if shutil.which(t) is None]
        if missing:
            return f"{', '.join(missing)} not found - install GnuPG (apt install gnupg)"
        home = _gnupg_home()
        try:
            os.makedirs(home, mode=0o700, exist_ok=True)
            os.chmod(home, 0o700)
        except OSError as e:
            return f"cannot create the vault's GnuPG home {home}: {e}"
        try:
            socket = _agent_socket()
        except OSError as e:
            return str(e)
        if len(socket.encode()) > _SUN_PATH_MAX:
            return (
                f"the gpg-agent socket path {socket} is {len(socket.encode())} bytes, over "
                f"the {_SUN_PATH_MAX}-byte Unix socket limit - point XDG_STATE_HOME at a "
                "shorter directory"
            )
        try:
            if not os.path.exists(os.path.join(home, "gpg-agent.conf")):
                cls._write_conf()
            cls._preset(_PROBE_ID, "probe")
            ok = cls._fetch(_PROBE_ID) == "probe"
            cls._agent([f"CLEAR_PASSPHRASE {_PROBE_ID}"], autostart=False)
        except OSError as e:
            return str(e)
        return None if ok else "gpg-agent did not return the probe value"

    def put(self, vault_id, key, ttl):
        _check(key, ttl)
        # The expiry lives in the agent's config. A reload flushes the cache, so it
        # happens only when the expiry changed, and before the preset.
        text = self._write_conf(ttl)
        loaded = os.path.join(_gnupg_home(), "gpg-agent.conf.loaded")
        if _read_text(loaded) != text:
            out = self._agent(["RELOADAGENT"])
            if not out or not out[-1].startswith("OK"):
                raise OSError(f"gpg-agent did not reload: {out[-1] if out else 'no answer'}")
            _write_private(loaded, text)
        self._preset(_cache_id(vault_id), key.hex())
        try:
            self._preset(_expiry_id(vault_id), str(int(time.time()) + ttl))
        except OSError:
            # A key with no expiry entry reads as locked yet still opens: clear it.
            self.clear(vault_id)
            raise

    def get(self, vault_id):
        value = self._fetch(_cache_id(vault_id))
        try:
            key = bytes.fromhex(value) if value else None
        except ValueError:
            return None
        return key if key is not None and len(key) == KEY_BYTES else None

    def clear(self, vault_id):
        try:
            self._agent([f"CLEAR_PASSPHRASE {_cache_id(vault_id)}",
                         f"CLEAR_PASSPHRASE {_expiry_id(vault_id)}"], autostart=False)
        except OSError:
            pass

    def remaining(self, vault_id):
        # The expiry entry only: it is preset and cleared with the key and shares its
        # max-cache-ttl, and reading it does not pull the key into this process - the
        # status endpoint calls this on every panel refresh.
        raw = self._fetch(_expiry_id(vault_id))
        return None if raw is None else _seconds_left(raw)


def _read_text(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def _write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def _proc_locks_memory(pid):
    """True when the process has locked memory (VmLck above 0 kB)."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmLck:"):
                    return int(line.split()[1]) > 0
    except (OSError, ValueError):
        pass
    return False


def _proc_core_disabled(pid):
    """True when the process's core file size limit is 0."""
    try:
        with open(f"/proc/{pid}/limits") as f:
            for line in f:
                if line.startswith("Max core file size"):
                    return line.split()[4] == "0"
    except (OSError, IndexError):
        pass
    return False


# --------------------------------------------------------------------------- #
# memory - this process
# --------------------------------------------------------------------------- #

_PAGE = mmap.PAGESIZE
# memfd_secret(2), Linux 5.14+; the same number on x86_64 and aarch64.
_NR_MEMFD_SECRET = {"x86_64": 447, "aarch64": 447}.get(platform.machine())


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _open_memfd_secret(size):
    """A mapping of secret memory, or None where the call is missing or refused.

    The kernel removes these pages from its own direct map and marks the mapping
    locked and excluded from core dumps.
    """
    if _NR_MEMFD_SECRET is None:
        return None
    libc = _libc()
    libc.syscall.restype = ctypes.c_long
    fd = libc.syscall(ctypes.c_long(_NR_MEMFD_SECRET), ctypes.c_uint(0))
    if fd < 0:
        return None
    try:
        os.ftruncate(fd, size)
        return mmap.mmap(fd, size)
    except OSError:
        return None
    finally:
        os.close(fd)


def _mlock(mapping, size):
    """Lock an anonymous mapping into RAM. False when the kernel refuses."""
    libc = _libc()
    libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    buf = (ctypes.c_char * size).from_buffer(mapping)
    try:
        return libc.mlock(ctypes.addressof(buf), size) == 0
    finally:
        del buf


class MemoryHolder(Holder):
    """The extension's own code: the key in this process, wiped at expiry by a timer.

    One key at a time - this process serves one vault file - kept with its vault id, so
    a key held for a vault since replaced is never handed out for the new one.
    """

    name = "memory"
    about = "this extension's own code, in the server's memory"

    def __init__(self):
        secret = _open_memfd_secret(_PAGE)
        if secret is not None:
            self._map = secret
            self.name = "memory/memfd_secret"
            locked = no_dump = True
        else:
            self._map = mmap.mmap(-1, _PAGE)
            try:
                self._map.madvise(mmap.MADV_DONTDUMP)
                no_dump = True
            except (AttributeError, OSError):
                no_dump = False
            locked = _mlock(self._map, _PAGE)
            self.name = "memory/mlock" if locked else "memory/plain"
        self.capabilities = Capabilities(
            locked_memory=locked, no_core_dump=no_dump, holder_ttl=False,
            locks_on_restart=True, container_isolated=True,
        )
        self._lock = threading.Lock()
        self._vault_id = None
        self._expiry = None
        self._timer = None

    def put(self, vault_id, key, ttl):
        _check(key, ttl)
        with self._lock:
            self._wipe()
            self._map[0] = len(key)
            self._map[1:1 + len(key)] = key
            self._vault_id = vault_id
            self._expiry = time.monotonic() + ttl
            # A timer wipes the page at expiry, so the key does not sit in memory until
            # the next request happens to notice it has expired.
            self._timer = threading.Timer(ttl, self._expire, args=(self._expiry,))
            self._timer.daemon = True
            self._timer.start()

    def _wipe(self):
        self._map[:] = bytes(_PAGE)
        self._vault_id = None
        self._expiry = None
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _expire(self, expiry):
        # Only the key this timer was set for: a timer that fired while a new put held
        # the lock must not wipe the key that put just stored. Compared by the expiry
        # it was scheduled for, not the clock - a timer can fire a hair early.
        with self._lock:
            if self._expiry == expiry:
                self._wipe()

    def _left(self, vault_id):
        """Seconds left for this vault's key, wiping it once it has run out. Call with
        the lock held."""
        if self._vault_id != vault_id or self._expiry is None:
            return None
        left = self._expiry - time.monotonic()
        if left <= 0:
            self._wipe()
            return None
        return left

    def get(self, vault_id):
        with self._lock:
            if self._left(vault_id) is None:
                return None
            return bytes(self._map[1:1 + self._map[0]])

    def clear(self, vault_id):
        with self._lock:
            if self._vault_id == vault_id:
                self._wipe()

    def remaining(self, vault_id):
        with self._lock:
            left = self._left(vault_id)
            return None if left is None else math.ceil(left)


# --------------------------------------------------------------------------- #
# selection
# --------------------------------------------------------------------------- #

_ORDER = (KeyctlHolder, GpgAgentHolder, MemoryHolder)
_BY_NAME = {cls.name: cls for cls in _ORDER}

_selected = None
_skipped = {}
_notice = None


def select() -> Holder:
    """The holder for this process, chosen once."""
    global _selected, _notice
    if _selected is not None:
        return _selected
    choice = os.environ.get(ENV, "auto")
    if choice == "auto":
        for cls in _ORDER:
            reason = cls.unusable_reason()
            if reason is None:
                _selected = cls()
                break
            _skipped[cls.name] = reason
        if isinstance(_selected, MemoryHolder):
            _notice = (
                f"gpg-agent unavailable ({_skipped['gpg-agent']}); the vault "
                f"key is held by this extension's own code in process memory "
                f"({_selected.name}) instead."
            )
            relay._say(_notice)
        return _selected
    cls = _BY_NAME.get(choice)
    if cls is None:
        raise OSError(f"{ENV}={choice!r} is not one of auto, keyctl, gpg-agent, memory")
    reason = cls.unusable_reason()
    if reason is not None:
        raise OSError(f"{ENV}={choice} but {reason}")
    _selected = cls()
    return _selected


# Each capability as the user reads it: (label, when true, when false). `vault status`
# prints the label and the explanation for the current value; the panel shows the label and yes or no, the explanation as the
# row's tooltip, for all but the ones it leaves to `vault status` (its CLI_ONLY).
CAPABILITY_TEXT = {
    "locked_memory": (
        "Never in swap", "the holder's copy of the key is never written to swap",
        "the holder's copy of the key can be written to swap"),
    "no_core_dump": (
        "Never in crash dumps", "a crash dump never contains the holder's copy of the key",
        "a crash dump can contain the holder's copy of the key"),
    "holder_ttl": (
        "Expires on its own", "the key is deleted at expiry even if the server stops",
        "a timer in the Jupyter server deletes the key at expiry"),
    "locks_on_restart": (
        "Locks on server restart",
        "a Jupyter server restart deletes the key, so the vault must be unlocked again",
        "the key can outlive a Jupyter server restart, so the vault can stay unlocked until "
        "the unlock duration ends"),
    "container_isolated": (
        "Isolated from containers", "other containers cannot read the key",
        "other containers running as the same user id can read the key"),
}

# What the protection level counts, as the words for each protection.
_COUNTED = (
    ("locked_memory", "kept out of swap"),
    ("no_core_dump", "kept out of core dumps"),
)


def _protection(caps: dict) -> str:
    """The protection level as one clause naming what it has or lacks."""
    missing = [text for key, text in _COUNTED if not caps[key]]
    text = "not " + ", not ".join(missing) if missing else ", ".join(t for _, t in _COUNTED)
    if not caps["container_isolated"]:
        text += "; other containers running as the same user id can read it"
    return text


def describe(holder: Holder) -> dict:
    """What the status endpoint and the panel show about a holder."""
    caps = asdict(holder.capabilities)
    return {
        "name": holder.name,
        "about": holder.about,
        "summary": holder.capabilities.summary,
        "protection": _protection(caps),
        "capabilities": caps,
        "details": [
            {"key": key, "label": label, "text": yes if caps[key] else no}
            for key, (label, yes, no) in CAPABILITY_TEXT.items()
        ],
        "notice": _notice,
    }


def debug_report() -> str:
    """The holder decision as text for --debug. Never contains the key."""
    lines = [f"vault: {ENV}={os.environ.get(ENV, 'auto')}"]
    for name, reason in _skipped.items():
        lines.append(f"vault: skipped {name} - {reason}")
    caps = asdict(_selected.capabilities)
    lines.append(f"vault: holder={_selected.name} ({_selected.capabilities.summary})")
    lines.append("vault: " + " ".join(f"{k}={'yes' if v else 'no'}" for k, v in caps.items()))
    return "\n".join(lines)
