#!/usr/bin/env python3
"""jupyterlab-passkey - drive the browser passkey ceremony from a local process.

A proxy to the extension's JupyterLab commands. WebAuthn needs a user gesture and a
browser; a terminal has neither. So each subcommand posts a notification whose action
button is bound to the command, waits for the relay the server writes, and
returns the result - turning a browser ceremony into a blocking call.

    cred_id=$(jupyterlab-passkey create --rp-id lab.example)
    prf=$(jupyterlab-passkey get --rp-id lab.example --cred-id "$cred_id" --prf-salt "$salt")
    pass_file=$(jupyterlab-passkey passphrase) || exit 1
    PASS_RECOVERY_FILE=$pass_file pass-cli-open --ensure

Take the `|| exit 1` seriously: a prefix assignment does not propagate the exit status
of a command substitution, so `PASS_RECOVERY_FILE=$(jupyterlab-passkey passphrase)
pass-cli-open` would run the consumer with an EMPTY passphrase file after a timeout or
a cancel.

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

from .routes import relay_dir

INGEST = "jupyterlab-notifications-extension/ingest"
RUN_COMMAND = "passkey:run"
PASSPHRASE_COMMAND = "passkey:passphrase"

# The trigger POST is a local, non-interactive call - only the click it asks for is slow.
# --timeout governs the wait for the click, never this; without a bound here a wedged
# server event loop hangs the CLI forever, ignoring --timeout entirely.
TRIGGER_TIMEOUT = 10


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


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

    Order matters and both ends are a real 403:

    - The hub vars win outright. Under JupyterHub the server's own token from
      `jupyter server list` is NOT accepted by its API - only the hub-issued one is.
    - The server list then beats JUPYTER_TOKEN, which is generic and easily stale (an
      old export in a shell rc). Letting a stale env value outrank the token the running
      server just handed us is a 403 that reads like a config error.
    """
    hub = os.environ.get("JUPYTERHUB_API_TOKEN") or os.environ.get("JPY_API_TOKEN")
    if hub:
        return hub
    # `in`, not truthiness: a server reporting token "" is answering "I want none", which
    # is a different thing from having no server record at all. An `or` chain conflates
    # them and lets a stale env var send an Authorization header to a tokenless server.
    if "token" in info:
        return info["token"] or None
    return os.environ.get("JUPYTER_TOKEN") or None


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
        with urllib.request.urlopen(req, timeout=TRIGGER_TIMEOUT) as r:
            r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise SystemExit(
                f"trigger rejected (404) by {base}/{INGEST} - the notifications extension "
                "is not installed in that lab; the CLI needs it to raise the button"
            )
        raise SystemExit(f"trigger rejected ({e.code} {e.reason}) by {base}/{INGEST}")
    except urllib.error.URLError as e:
        raise SystemExit(f"cannot reach {base} ({e.reason}) - is JupyterLab running?")

    print(f"click '{label}' in your JupyterLab tab", file=sys.stderr)


def _wait(path: str, timeout: float, on_timeout: str) -> None:
    """Block until the relay appears.

    Existence is enough: the write lands atomically, so the value is whole - see
    `routes._write_relay`.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.4)
    # One last look. The final sleep straddles the deadline, so a relay landing in that
    # window would otherwise be declared missing while sitting on disk - failing a
    # ceremony the user completed in time AND stranding its PRF, since the caller that
    # would have consumed the file is the one raising here.
    if os.path.exists(path):
        return
    raise SystemExit(f"no relay after {timeout:.0f}s - {on_timeout}")


def _run(args_obj: dict, label: str, message: str, timeout: float) -> dict:
    """Drive passkey:run and consume its relay, deleting it on every path out of here.

    The relay carries the PRF, so the unlink sits in a finally that also covers the
    timeout - `_wait` is inside the try for exactly that reason. A malformed body, or a
    relay that landed just as we gave up, would otherwise leave key material on disk
    precisely when nobody is left to collect it.

    It is best effort and cannot be more: the server writes whenever the ceremony
    finishes, so a click that lands after this process has exited strands a relay no
    matter what we do here. That residue is bounded by the relay dir living in /dev/shm
    (tmpfs, gone at reboot) and is why shredding is documented as the consumer's job.
    """
    relay = os.path.join(relay_dir(), f"{args_obj['nonce']}.json")
    _trigger(RUN_COMMAND, args_obj, label, message)
    try:
        _wait(relay, timeout, "was the button clicked and the prompt approved?")
        with open(relay) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"unreadable relay {relay}: {e}")
    finally:
        try:
            os.unlink(relay)
        except OSError:
            pass
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
    # The dialog relays nothing on cancel or on two entries that differ, so a timeout
    # here usually means a deliberate refusal, not an unnoticed button.
    _wait(relay, a.timeout, "cancelled, the two entries differed, or the button was never clicked")
    print(relay)
    return 0


# The values these flags carry are base64url, whose alphabet includes "-", so roughly
# one in 64 begins with one. argparse reads ANY leading-dash token as an option, so the
# documented `--cred-id "$cred"` dies with "expected one argument" before the ceremony
# runs - not flakily but for that credential always, which is how it survives a release
# and then strands a passkey that registered perfectly well.
_B64URL_FLAGS = ("--cred-id", "--prf-salt")


def _glue_b64url(argv: list[str]) -> list[str]:
    """Rewrite `--cred-id VALUE` to `--cred-id=VALUE`, the form argparse cannot misread.

    Only the separator changes; the value is passed through untouched. A flag already
    written as `--cred-id=...` never matches and is left alone, and a flag with no value
    left to take is left alone too, so argparse still reports the real mistake.
    """
    out: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] in _B64URL_FLAGS and i + 1 < len(argv):
            out.append(f"{argv[i]}={argv[i + 1]}")
            i += 2
        else:
            out.append(argv[i])
            i += 1
    return out


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

    a = p.parse_args(_glue_b64url(sys.argv[1:]))
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
