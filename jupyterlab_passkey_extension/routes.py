import json
import os
import re
import tempfile

from jupyter_server.base.handlers import APIHandler
from jupyter_server.utils import url_path_join
import tornado

# Full-match guard (re.fullmatch, so a trailing newline is rejected too - Python's
# `$` would otherwise match just before a final "\n").
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")


def _relay_dir():
    """Per-user relay directory.

    Defaults to a uid-scoped path so a co-tenant sharing /dev/shm cannot squat or
    pre-create the predictable directory. Overridable via env for tests.
    """
    return os.environ.get(
        "JLAB_PASSKEY_RELAY_DIR", f"/dev/shm/jlab-passkey-{os.getuid()}"
    )


def _write_relay(nonce, filename, content):
    """Write `content` to <relay_dir>/<filename> as a one-shot 0600 file.

    mkstemp makes a fresh 0600 file with O_EXCL and a random name (no symlink to
    follow, no world-readable window); os.replace then renames it onto the final
    name so the relay is one-shot. The caller must validate `nonce` first.
    """
    relay_dir = _relay_dir()
    os.makedirs(relay_dir, exist_ok=True)
    try:
        os.chmod(relay_dir, 0o700)  # best-effort; tolerate a pre-existing dir
    except OSError:
        pass

    fd, tmp_path = tempfile.mkstemp(dir=relay_dir, prefix=f".{nonce}.", suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.replace(tmp_path, os.path.join(relay_dir, filename))


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

        _write_relay(nonce, f"{nonce}.json", json.dumps(body))

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

        _write_relay(nonce, f"{nonce}.pass", passphrase)

        # Never log the passphrase or the body
        self.set_status(204)
        self.finish()


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
    handlers = [
        (result_pattern, PasskeyResultHandler),
        (health_pattern, PasskeyHealthHandler),
        (passphrase_pattern, PasskeyPassphraseHandler),
    ]

    web_app.add_handlers(host_pattern, handlers)
