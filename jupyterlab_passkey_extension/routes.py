import base64
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

    A keyctl quota, a missing keyctl binary, a squatted shm dir, or a forced-but-broken
    `JLAB_PASSKEY_RELAY_BACKEND=keyctl` raises OSError out of stage/collect. The CLI
    turns the same errors into a one-line message; the
    server must not answer with a stack trace in the Jupyter log. No secret is ever in
    the exception - the value rides stdin or the file, never an argument - but the
    response stays generic regardless.
    """
    handler.set_status(500)
    handler.finish(json.dumps({"error": "relay backend unavailable"}))


def json_body(handler):
    """The request body parsed as JSON, or None when it is not JSON.

    Not `get_json_body`: that logs a malformed body at DEBUG, and these bodies carry a
    PRF, a passphrase or a vault secret. Every caller answers 400 to a None.
    """
    try:
        return json.loads(handler.request.body or b"null")
    except ValueError:
        return None


class PasskeyResultHandler(APIHandler):
    # The following decorator should be present on all verb methods (head, get, post,
    # patch, put, delete, options) to ensure only authorized user can request the
    # Jupyter server
    @tornado.web.authenticated
    def post(self):
        body = json_body(self)
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
        body = json_body(self)
        nonce = body.get("nonce") if isinstance(body, dict) else None
        passphrase = body.get("passphrase") if isinstance(body, dict) else None
        # Validate the nonce before it becomes a filename (prevents path traversal)
        if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
            self.set_status(400)
            return

        # A dismissed dialog says so, rather than saying nothing. The relay is the only
        # channel back to the waiting CLI, so a cancel that stages nothing is
        # indistinguishable from a button nobody has clicked yet - and the CLI sits out
        # its whole timeout before reporting what the user already decided. This marker
        # carries no secret; it exists to be seen.
        if body.get("cancelled") is True:
            try:
                relay.stage(nonce, "cancel", "1")
            except OSError:
                return _relay_unavailable(self)
            self.set_status(204)
            self.finish()
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
    """Hand a staged secret to the browser, once.

    This runs the opposite way to the handlers that write: they take a value the
    page produced and put it in a relay for a local client; this, like `render`,
    takes a value already staged - by a local client (a token piped in from a
    file or a stream), or by the server for `vault copy` - and hands it up to the
    page, which copies it to the clipboard. `relay.stage` is the writer and this
    is the reader.

    POST, not GET, though it only reads: the read is destructive, and a GET
    would carry the nonce in the query string, straight into the server's
    access log. The nonce is not the secret, but it is the ticket to collect
    one, and there is no reason to write tickets to a log file.

    One shot. The relay is destroyed on the way out whether or not the read
    worked, so a secret is never left behind for a second collector. A refused
    clipboard write is retried from page memory (copy.ts); a failed fetch, or the
    tab closing before the retry, loses the secret, and the caller runs the copy
    again. That is the deliberate
    trade: a lost secret is an inconvenience, a lingering one is a liability.
    """

    @tornado.web.authenticated
    def post(self):
        body = json_body(self)
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


class PasskeyRenderHandler(APIHandler):
    """Render a staged code as a distorted image, once.

    A one-shot reader of a relay staged by a local client, or by the server for
    `vault show`, like the secret handler - but the
    value is turned into a PNG here and only the image leaves, never the text. So a
    scraper reading the page, the notifications broadcast, or the accessibility
    tree never sees the code; an OCR pass on a screenshot still has to beat the
    distortion. The value is drawn to pixels and dropped: never logged, never
    returned as text.

    The relay is consumed before the render runs, so a render failure loses the
    code - the same trade the secret handler makes, and the caller runs the show
    again. Pillow is imported here rather than at module load so
    a render-time failure gives this one endpoint a clean 500 rather than a
    traceback, and an unexpectedly broken Pillow does not fail the whole server
    extension at import.
    """

    @tornado.web.authenticated
    def post(self):
        body = json_body(self)
        nonce = body.get("nonce") if isinstance(body, dict) else None
        # Validate the nonce before it becomes a filename (prevents path traversal)
        if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
            self.set_status(400)
            return

        try:
            value = relay.collect(nonce, "code")
        except OSError:
            return _relay_unavailable(self)
        if value is None:
            # Never staged, already rendered, or expired - all the same 404.
            self.set_status(404)
            return

        # Both writers cap this before staging (`cli show`, `VaultService.stage`);
        # guard here too, since the render cost grows with length and runs on the
        # server's event loop.
        if len(value) > relay.MAX_CODE_CHARS:
            self.set_status(400)
            self.finish(json.dumps({"error": "code too long to render"}))
            return

        try:
            from .captcha import render_code_png

            png = render_code_png(value)
        except Exception:
            # The value is already consumed; a render failure loses it. Answer
            # cleanly - the exception carries no secret, but the message is generic
            # regardless, and the value is never logged.
            self.set_status(500)
            self.finish(json.dumps({"error": "could not render the code"}))
            return

        # Only the image leaves, base64 in JSON - never the code as text.
        self.finish(json.dumps({"png": base64.b64encode(png).decode("ascii")}))


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
    render_pattern = url_path_join(base_url, "jupyterlab-passkey-extension", "render")
    handlers = [
        (result_pattern, PasskeyResultHandler),
        (health_pattern, PasskeyHealthHandler),
        (passphrase_pattern, PasskeyPassphraseHandler),
        (secret_pattern, PasskeySecretHandler),
        (render_pattern, PasskeyRenderHandler),
    ]

    web_app.add_handlers(host_pattern, handlers)

    from .vault.handlers import setup_vault_handlers

    setup_vault_handlers(web_app)
