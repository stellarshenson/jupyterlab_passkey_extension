import json
import os
import re
import stat
import tempfile

from jupyter_server.base.handlers import APIHandler
from jupyter_server.utils import url_path_join
import tornado

# Full-match guard (re.fullmatch, so a trailing newline is rejected too - Python's
# `$` would otherwise match just before a final "\n").
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")


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


class PasskeyResultHandler(APIHandler):
    # The following decorator should be present on all verb methods (head, get, post,
    # patch, put, delete, options) to ensure only authorized user can request the
    # Jupyter server
    @tornado.web.authenticated
    def post(self):
        body = self.get_json_body()
        nonce = body.get("nonce") if isinstance(body, dict) else None
        # Validate the nonce before it becomes a filename (prevents path traversal)
        if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
            self.set_status(400)
            return

        write_relay(nonce, f"{nonce}.json", json.dumps(body))

        # Never log prf or the body
        self.set_status(204)
        self.finish()


class PasskeyPassphraseHandler(APIHandler):
    """Relay a passphrase captured in the browser to a local client.

    The frontend dialog collects the passphrase (entered twice, confirmed to
    match there) and POSTs it here; it is written raw - no JSON envelope, no
    trailing newline - so a consumer can use the file directly, e.g.
    PASS_RECOVERY_FILE=<relay_dir>/<nonce>.pass pass-cli-open --ensure
    """

    @tornado.web.authenticated
    def post(self):
        body = self.get_json_body()
        nonce = body.get("nonce") if isinstance(body, dict) else None
        passphrase = body.get("passphrase") if isinstance(body, dict) else None
        # Validate the nonce before it becomes a filename (prevents path traversal)
        if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
            self.set_status(400)
            return
        # An empty passphrase is a client bug, not a valid secret
        if not isinstance(passphrase, str) or passphrase == "":
            self.set_status(400)
            return

        write_relay(nonce, f"{nonce}.pass", passphrase)

        # Never log the passphrase or the body
        self.set_status(204)
        self.finish()


class PasskeySecretHandler(APIHandler):
    """Hand a secret a local client staged in a relay to the browser, once.

    This runs the opposite way to every other handler here. The others take a
    value the page produced and put it on disk for a local client; this takes a
    value a local client already had - a token piped in from a file or a
    stream - and hands it up to the page, which copies it to the clipboard.
    So the CLI is the writer (via `write_relay`) and this is the reader.

    POST, not GET, though it only reads: the read is destructive, and a GET
    would carry the nonce in the query string, straight into the server's
    access log. The nonce is not the secret, but it is the ticket to collect
    one, and there is no reason to write tickets to a log file.

    One shot. The relay is unlinked on the way out whether or not the read
    worked, so a secret is never left behind for a second collector - which
    also means a failed clipboard write loses it and the caller must re-run
    `jupyterlab-passkey copy`. That is the deliberate trade: a lost secret is
    an inconvenience, a lingering one is a liability.
    """

    @tornado.web.authenticated
    def post(self):
        body = self.get_json_body()
        nonce = body.get("nonce") if isinstance(body, dict) else None
        # Validate the nonce before it becomes a filename (prevents path traversal)
        if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
            self.set_status(400)
            return

        path = os.path.join(ensure_relay_dir(), f"{nonce}.secret")
        try:
            # utf-8 to match write_relay - the writer here is a different process
            # with its own locale, so neither end can be left to guess.
            with open(path, encoding="utf-8") as f:
                value = f.read()
        except OSError:
            # Never staged, already collected, or not ours to read. All the same
            # answer, and none of them worth distinguishing for a caller.
            self.set_status(404)
            return
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

        # Never log the value or the body
        self.finish(json.dumps({"value": value}))


class PasskeyHealthHandler(APIHandler):
    @tornado.web.authenticated
    def get(self):
        self.finish(json.dumps({"ok": True}))


def setup_route_handlers(web_app):
    host_pattern = ".*$"
    base_url = web_app.settings["base_url"]

    result_pattern = url_path_join(base_url, "jupyterlab-passkey-extension", "result")
    health_pattern = url_path_join(base_url, "jupyterlab-passkey-extension", "health")
    passphrase_pattern = url_path_join(
        base_url, "jupyterlab-passkey-extension", "passphrase"
    )
    secret_pattern = url_path_join(base_url, "jupyterlab-passkey-extension", "secret")
    handlers = [
        (result_pattern, PasskeyResultHandler),
        (health_pattern, PasskeyHealthHandler),
        (passphrase_pattern, PasskeyPassphraseHandler),
        (secret_pattern, PasskeySecretHandler),
    ]

    web_app.add_handlers(host_pattern, handlers)
