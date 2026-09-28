"""The vault as seen from outside the server: the CLI and the Python API share this.

Everything goes through the server's authenticated REST API. The two passkey steps -
unlocking with a passkey and registering one - raise a notification
whose button runs a vault command in the JupyterLab tab; the page sends the PRF
straight to the server, and only `ok` or the error comes back here through the
result relay. So the PRF never passes through this process.
"""

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

from .. import cli as _cli

UNLOCK_COMMAND = "passkey:vault-unlock"
REGISTER_COMMAND = "passkey:vault-register"
REQUEST_TIMEOUT = 30


def no_vault(path):
    """The refusal when there is no vault file: the path looked at, and the next step."""
    return f"no vault at {path} - run `jupyterlab-passkey vault init`"


class VaultClientError(Exception):
    """A refusal from the vault or the server, as one line."""


class VaultLocked(VaultClientError):
    pass


def request(method, action, body=None, params=None):
    """Call `vault/<action>`; returns the JSON answer, or None for an empty one."""
    base, token = _cli._server()
    url = f"{base}/jupyterlab-passkey-extension/vault/{action}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"token {token}"
    data = json.dumps(body if body is not None else {}).encode() if method != "GET" else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _cli._LOOPBACK.open(req, timeout=REQUEST_TIMEOUT) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        try:
            message = json.loads(e.read() or b"{}").get("error")
        except (ValueError, AttributeError):
            message = None
        # A refused token, not a refused proof: the vault's own 403 carries an error.
        if e.code == 401 or (e.code == 403 and not message):
            _cli._forget_server()
        if e.code == 423:
            raise VaultLocked(message or "the vault is locked")
        if e.code == 404 and not message:
            # The server runs without the vault's routes, as after an install into a
            # running server - the panel says the same (src/vault/api.ts).
            message = "the vault is not loaded on this Jupyter server - restart the server"
        raise VaultClientError(message or f"the vault answered {e.code} {e.reason}")
    except OSError as e:
        _cli._forget_server()
        reason = getattr(e, "reason", e)
        raise VaultClientError(f"cannot reach {base} ({reason}) - is JupyterLab running?")
    return json.loads(raw) if raw else None


def browser_step(command, args, label, message, timeout):
    """Raise the notification for a vault command and wait for the page to finish it."""
    try:
        _cli._run({**args, "nonce": secrets.token_urlsafe(24)}, label, message, timeout,
                  command_id=command)
    except SystemExit as e:
        raise VaultClientError(str(e))


class Vault:
    """The vault from Python code or a notebook.

        vault = Vault()
        vault.get("github/api")                    # the password
        vault.get("github/api", field="username")
    """

    def __init__(self, timeout=_cli.CLICK_TIMEOUT):
        self.timeout = timeout

    def status(self):
        return request("GET", "status")

    def unlock(self, recovery=None):
        """Unlock with the passkey (a notification to click), or with the recovery
        passphrase when one is given."""
        if recovery is not None:
            return request("POST", "unlock", {"recovery": recovery})
        s = self.status()
        # Not a notification whose click can only answer that no passkey matches.
        if not s["initialized"]:
            raise VaultClientError(no_vault(s["path"]))
        if not any(slot["type"] == "passkey" for slot in s["slots"]):
            raise VaultClientError(
                "no passkey is registered with the vault - unlock with the recovery"
                " passphrase: jupyterlab-passkey vault unlock --recovery"
            )
        browser_step(
            UNLOCK_COMMAND, {}, "Unlock vault",
            "Unlock the vault with your passkey - click to approve.", self.timeout,
        )
        return self.status()

    def lock(self):
        request("POST", "lock")

    def _unlocked(self, call):
        """Run `call`; when the vault is locked, unlock with the passkey and run it again."""
        try:
            return call()
        except VaultLocked:
            self.unlock()
            return call()

    def list(self):
        return self._unlocked(lambda: request("GET", "entries"))["entries"]

    def get(self, name, field="password"):
        return self._unlocked(
            lambda: request("POST", "reveal", {"name": name, "field": field})
        )["value"]
