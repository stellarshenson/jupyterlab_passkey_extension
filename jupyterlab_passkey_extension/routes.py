import json
import re

from jupyter_server.base.handlers import APIHandler
from jupyter_server.utils import url_path_join
import tornado

from . import relay

# Re-exported so callers and tests keep importing the relay primitives from here,
# where they lived before the backend split. `relay` owns them now - a keyctl key
# or a 0600 file, chosen per process - but the shm names stay reachable for the
# tests that exercise the file backend directly.
relay_dir = relay.relay_dir
ensure_relay_dir = relay.ensure_relay_dir
write_relay = relay.write_relay

# Full-match guard (re.fullmatch, so a trailing newline is rejected too - Python's
# `$` would otherwise match just before a final "\n").
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")


def _relay_unavailable(handler):
    """Answer a relay-backend failure with a clean 500, never a traceback.

    A keyctl quota, a missing keyctl binary, or a squatted shm dir raises OSError out
    of stage/collect. The CLI turns the same errors into a one-line message; the
    server must not answer with a stack trace in the Jupyter log. No secret is ever in
    the exception - the value rides stdin or the file, never an argument - but the
    response stays generic regardless.
    """
    handler.set_status(500)
    handler.finish(json.dumps({"error": "relay backend unavailable"}))


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

        try:
            relay.stage(nonce, "json", json.dumps(body))
        except OSError:
            return _relay_unavailable(self)

        # Never log prf or the body
        self.set_status(204)
        self.finish()


class PasskeyPassphraseHandler(APIHandler):
    """Relay a passphrase captured in the browser to a local client.

    The frontend dialog collects the passphrase (entered twice, confirmed to
    match there) and POSTs it here; it is staged raw - no JSON envelope, no
    trailing newline - and the CLI prints the consumer a scheme-prefixed
    reference (`keyctl:...` or `file:...`) that resolves to the value directly.
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

        try:
            relay.stage(nonce, "pass", passphrase)
        except OSError:
            return _relay_unavailable(self)

        # Never log the passphrase or the body
        self.set_status(204)
        self.finish()


class PasskeySecretHandler(APIHandler):
    """Hand a secret a local client staged in a relay to the browser, once.

    This runs the opposite way to every other handler here. The others take a
    value the page produced and put it on disk for a local client; this takes a
    value a local client already had - a token piped in from a file or a
    stream - and hands it up to the page, which copies it to the clipboard.
    So the CLI is the writer (via `relay.stage`) and this is the reader.

    POST, not GET, though it only reads: the read is destructive, and a GET
    would carry the nonce in the query string, straight into the server's
    access log. The nonce is not the secret, but it is the ticket to collect
    one, and there is no reason to write tickets to a log file.

    One shot. The relay is destroyed on the way out whether or not the read
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

        # The value is destroyed as it is read, whichever backend holds it, so a
        # second collector finds nothing.
        try:
            value = relay.collect(nonce, "secret")
        except OSError:
            return _relay_unavailable(self)
        if value is None:
            # Never staged, already collected, or expired. All the same answer,
            # and none of them worth distinguishing for a caller.
            self.set_status(404)
            return

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
