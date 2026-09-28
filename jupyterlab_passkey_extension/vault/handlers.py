"""REST endpoints of the vault: `<base>/jupyterlab-passkey-extension/vault/<action>`.

One handler dispatches on the action. Bodies are parsed with the bridge's `json_body`,
which never logs them - a vault body can carry a password, a passphrase or a PRF.
Nothing below logs a body, a value or a result.
"""

import json

from jupyter_server.base.handlers import APIHandler
from jupyter_server.utils import url_path_join
import tornado

from ..routes import json_body
from .service import (GENERATE_LENGTH, Conflict, Denied, Locked, NotFound, VaultError, VaultService,
                      generate)

_service = VaultService()


def _unlock(s, body):
    if "recovery" in body:
        s.unlock_recovery(body.get("recovery"))
    else:
        s.unlock_passkey(body.get("cred_id"), body.get("prf"))
    return s.status()


def _reveal(s, body):
    # With a PRF, the panel's passkey-checked reveal; without, the CLI's `vault get`.
    if "prf" in body:
        return {"value": s.reveal_with_passkey(body.get("name"), body.get("cred_id"), body.get("prf"))}
    return {"value": s.read(body.get("name"), body.get("field") or "password")}


def _generate(s, args):
    try:
        length = int(args.get("length", GENERATE_LENGTH))
    except ValueError:
        raise VaultError("length must be a whole number")
    return {"value": generate(length, args.get("symbols", "1") != "0")}


_GET = {
    "status": lambda s, args: s.status(),
    "entries": lambda s, args: {"entries": s.list_entries()},
    "generate": _generate,
}

_POST = {
    "config": lambda s, b: s.set_config(b.get("unlock_minutes")),
    "init": lambda s, b: s.init(b.get("recovery")),
    "unlock": _unlock,
    "lock": lambda s, b: s.lock(),
    "entries": lambda s, b: s.add(b.get("name"), b.get("fields") or {}),
    "delete": lambda s, b: s.delete(b.get("name")),
    "reveal": _reveal,
    "stage": lambda s, b: {"nonce": s.stage(b.get("name"), b.get("field") or "password", b.get("kind"))},
    "import": lambda s, b: s.import_entries(b.get("entries")),
    "passkeys": lambda s, b: s.add_passkey(
        b.get("cred_id"), b.get("rp_id"), b.get("prf_salt"), b.get("prf"), b.get("label"),
        b.get("proof")),
    "passkeys-remove": lambda s, b: s.remove_passkey(b.get("cred_id")),
    "recovery": lambda s, b: s.replace_recovery(b.get("recovery"), b.get("proof")),
}

_PATCH = {
    "entries": lambda s, b: s.edit(b.get("name"), b.get("fields") or {}),
}


class VaultHandler(APIHandler):
    def _answer(self, table, action, arg):
        fn = table.get(action)
        if fn is None:
            self.set_status(404)
            self.finish(json.dumps({"error": f"no vault action {action!r}"}))
            return
        try:
            result = fn(_service, arg)
        except Locked as e:
            return self._error(423, e)
        except Denied as e:
            return self._error(403, e)
        except NotFound as e:
            return self._error(404, e)
        except Conflict as e:
            return self._error(409, e)
        except VaultError as e:
            return self._error(400, e)
        except (OSError, ValueError) as e:
            # A key holder or file failure. The messages carry no secret (values ride
            # stdin or the file, never an argument or an exception), and the log line
            # names the action and the exception type, never its message.
            self.log.warning("vault %s failed: %s", action, type(e).__name__)
            return self._error(500, f"vault {action} failed: {e}")
        if result is None:
            self.set_status(204)
            self.finish()
        else:
            self.finish(json.dumps(result))

    def _error(self, status, message):
        self.set_status(status)
        self.finish(json.dumps({"error": str(message)}))

    def _body(self):
        body = json_body(self) if self.request.body else {}
        if not isinstance(body, dict):
            self._error(400, "the request body must be a JSON object")
            return None
        return body

    @tornado.web.authenticated
    def get(self, action):
        args = {k: self.get_argument(k) for k in self.request.arguments}
        self._answer(_GET, action, args)

    @tornado.web.authenticated
    def post(self, action):
        body = self._body()
        if body is not None:
            self._answer(_POST, action, body)

    @tornado.web.authenticated
    def patch(self, action):
        body = self._body()
        if body is not None:
            self._answer(_PATCH, action, body)


def setup_vault_handlers(web_app):
    base_url = web_app.settings["base_url"]
    pattern = url_path_join(base_url, "jupyterlab-passkey-extension", "vault", "([a-z-]+)")
    web_app.add_handlers(".*$", [(pattern, VaultHandler)])
