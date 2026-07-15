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

        relay_dir = _relay_dir()
        os.makedirs(relay_dir, exist_ok=True)
        try:
            os.chmod(relay_dir, 0o700)  # best-effort; tolerate a pre-existing dir
        except OSError:
            pass

        # mkstemp makes a fresh 0600 file with O_EXCL and a random name (no symlink
        # to follow, no world-readable window); os.replace then renames it onto the
        # final <nonce>.json so the relay is one-shot.
        fd, tmp_path = tempfile.mkstemp(
            dir=relay_dir, prefix=f".{nonce}.", suffix=".tmp"
        )
        with os.fdopen(fd, "w") as f:
            json.dump(body, f)
        os.replace(tmp_path, os.path.join(relay_dir, f"{nonce}.json"))

        # Never log prf or the body
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
    handlers = [
        (result_pattern, PasskeyResultHandler),
        (health_pattern, PasskeyHealthHandler),
    ]

    web_app.add_handlers(host_pattern, handlers)
