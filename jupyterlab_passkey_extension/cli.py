#!/usr/bin/env python3
"""jupyterlab-passkey - drive the browser passkey ceremony from a local process.

A proxy to the extension's JupyterLab commands. WebAuthn needs a user gesture and a
browser; a terminal has neither. So each subcommand posts a notification whose action
button is bound to the command, waits for the one-shot relay the server writes, and
returns the result - turning a browser ceremony into a blocking call.

    cred_id=$(jupyterlab-passkey create --rp-id lab.example)
    prf=$(jupyterlab-passkey get --rp-id lab.example --cred-id "$cred_id" --prf-salt "$salt")
    PASS_RECOVERY_FILE=$(jupyterlab-passkey passphrase) pass-cli-open --ensure

Run it in a terminal on the same Jupyter server, keep a JupyterLab tab open, and click
the button when it pops.
"""

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

INGEST = "jupyterlab-notifications-extension/ingest"
RUN_COMMAND = "passkey:run"
PASSPHRASE_COMMAND = "passkey:passphrase"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def relay_dir() -> str:
    return os.environ.get("JLAB_PASSKEY_RELAY_DIR", f"/dev/shm/jlab-passkey-{os.getuid()}")


def _server_list() -> dict:
    """The running server's own record: port, base_url, and its token."""
    try:
        out = subprocess.run(
            ["jupyter", "server", "list", "--json"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return json.loads(out.stdout.strip().split("\n")[0])
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return {}


def _base_url(info: dict) -> str:
    """Where the server answers, always on loopback."""
    if info:
        return f"http://127.0.0.1:{info.get('port', 8888)}{info.get('base_url', '/').rstrip('/')}"
    port = os.environ.get("JUPYTER_PORT", "8888")
    return f"http://127.0.0.1:{port}{os.environ.get('JUPYTERHUB_SERVICE_PREFIX', '').rstrip('/')}"


def _token(info: dict) -> str | None:
    """The token that authenticates to that server.

    Environment first, exactly as jupyterlab-notify resolves it. Under JupyterHub the
    server's own token from `jupyter server list` is NOT accepted by its API - only the
    hub-issued token is - so preferring the server list here earns a 403.
    """
    return (
        os.environ.get("JUPYTERHUB_API_TOKEN")
        or os.environ.get("JPY_API_TOKEN")
        or os.environ.get("JUPYTER_TOKEN")
        or info.get("token")
        or None
    )


def _server() -> tuple[str, str | None]:
    info = _server_list()
    return _base_url(info), _token(info)


def _trigger(command_id: str, args_obj: dict, label: str, message: str) -> None:
    """Post the notification whose button runs `command_id` with `args_obj`."""
    base, token = _server()
    payload = {
        "message": message,
        "type": "info",
        "autoClose": False,
        "immediate": True,
        "actions": [{
            "label": label,
            "displayType": "default",
            "commandId": command_id,
            "caption": f"Execute: {command_id}",
            "args": args_obj,
        }],
    }
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"token {token}"

    req = urllib.request.Request(
        f"{base}/{INGEST}", data=json.dumps(payload).encode(), headers=headers, method="POST",
    )
    try:
        urllib.request.urlopen(req).read()
    except urllib.error.HTTPError as e:
        raise SystemExit(f"trigger rejected ({e.code} {e.reason}) by {base}/{INGEST}")
    except urllib.error.URLError as e:
        raise SystemExit(f"cannot reach {base} ({e.reason}) - is JupyterLab running?")

    print(f"click '{label}' in your JupyterLab tab", file=sys.stderr)


def _wait(path: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.4)
    raise SystemExit(f"no relay after {timeout:.0f}s - was the button clicked and the prompt approved?")


def _run(args_obj: dict, label: str, message: str, timeout: float) -> dict:
    """Drive passkey:run and consume its one-shot relay."""
    relay = os.path.join(relay_dir(), f"{args_obj['nonce']}.json")
    _trigger(RUN_COMMAND, args_obj, label, message)
    _wait(relay, timeout)
    with open(relay) as f:
        data = json.load(f)
    os.unlink(relay)
    if not data.get("ok"):
        raise SystemExit(f"ceremony failed: {data.get('error')}")
    return data


def cmd_create(a) -> int:
    user = {
        "id": b64url(secrets.token_bytes(16)),
        "name": a.user_name,
        "displayName": a.user_name,
    }
    data = _run(
        {"op": "create", "nonce": secrets.token_urlsafe(24), "rp_id": a.rp_id, "user": user},
        "Register passkey", "Register a passkey - click to approve.", a.timeout,
    )
    print(data["cred_id"])
    return 0


def cmd_get(a) -> int:
    args_obj = {
        "op": "get", "nonce": secrets.token_urlsafe(24),
        "rp_id": a.rp_id, "cred_id": a.cred_id,
    }
    if a.prf_salt:
        args_obj["prf_salt"] = a.prf_salt
    data = _run(args_obj, "Approve passkey", "Approve the passkey request - click to approve.", a.timeout)

    if a.prf_salt:
        if not data.get("prf"):
            raise SystemExit("no PRF returned - the authenticator did not evaluate the salt")
        print(data["prf"])
    else:
        print(data["cred_id"])
    return 0


def cmd_passphrase(a) -> int:
    """Capture a passphrase in the browser and leave it in a 0600 relay.

    Prints the file's path, never the value - the passphrase must reach its consumer
    without passing through the terminal, shell history, or a process argument.
    """
    nonce = secrets.token_urlsafe(24)
    relay = os.path.join(relay_dir(), f"{nonce}.pass")
    _trigger(
        PASSPHRASE_COMMAND, {"nonce": nonce, "prompt": a.prompt},
        "Enter passphrase", "Enter the passphrase - click to open the dialog.",
    )
    _wait(relay, a.timeout)
    print(relay)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="jupyterlab-passkey",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # --timeout hangs off a parent parser so it is accepted after the subcommand, which
    # is where anyone would think to type it.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--timeout", type=float, default=120.0, help="seconds to wait for the click (default 120)",
    )
    sub = p.add_subparsers(dest="op", required=True)

    c = sub.add_parser("create", parents=[common], help="register a passkey; prints its cred_id")
    c.add_argument("--rp-id", required=True, help="WebAuthn RP ID = your JupyterLab hostname")
    c.add_argument("--user-name", default="jupyterlab-passkey", help="credential user name")
    c.set_defaults(func=cmd_create)

    g = sub.add_parser("get", parents=[common], help="assert a passkey; prints its PRF (with --prf-salt) or cred_id")
    g.add_argument("--rp-id", required=True, help="WebAuthn RP ID = your JupyterLab hostname")
    g.add_argument("--cred-id", required=True, help="base64url credential id from a prior create")
    g.add_argument("--prf-salt", help="base64url 32-byte salt; evaluates the WebAuthn PRF")
    g.set_defaults(func=cmd_get)

    s = sub.add_parser("passphrase", parents=[common], help="capture a passphrase; prints the relay file's path")
    s.add_argument("--prompt", default="Enter the passphrase twice", help="dialog prompt text")
    s.set_defaults(func=cmd_passphrase)

    a = p.parse_args()
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
