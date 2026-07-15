#!/usr/bin/env python3
"""On-demand manual passkey test - runs the real ceremony against your own device.

Exercises the installed extension end to end with your actual authenticator
(Windows Hello / security key / platform passkey):

    browser console -> passkey:run -> navigator.credentials.* (OS prompt)
    -> POST /result -> server writes 0600 relay -> this script reads + verifies it.

Run this in a JupyterLab *terminal* (same server as the browser tab). It prints a
one-line snippet; paste each into the JupyterLab tab's DevTools console and
approve the OS prompt. The script reads back the server relay and reports PASS/FAIL.

Prereq: start JupyterLab with `--expose-app-in-browser` (or
`c.LabApp.expose_app_in_browser = True`) so `window.jupyterapp` exists - that is
the only hook a hand-typed console call has to reach the command.

Usage:
    python scripts/passkey_selftest.py                 # create, then get (PRF)
    python scripts/passkey_selftest.py --op create     # register only
    python scripts/passkey_selftest.py --op get --cred-id <b64url> [--prf-salt <b64url>]
"""

import argparse
import base64
import json
import os
import secrets
import time


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def relay_dir() -> str:
    return os.environ.get(
        "JLAB_PASSKEY_RELAY_DIR", f"/dev/shm/jlab-passkey-{os.getuid()}"
    )


USER = {"id": b64url(b"passkey-selftest"), "name": "selftest", "displayName": "Passkey Self-Test"}


def trigger_and_wait(args_obj: dict, timeout: float) -> dict:
    """Print the console snippet for this ceremony, then read back its relay."""
    nonce = args_obj["nonce"]
    relay = os.path.join(relay_dir(), f"{nonce}.json")
    try:
        os.unlink(relay)  # clear any stale file for this nonce
    except FileNotFoundError:
        pass

    snippet = (
        "jupyterapp.commands.execute('passkey:run', "
        f"Object.assign({{rp_id: location.hostname}}, {json.dumps(args_obj)}))"
    )
    print("\n  Paste into the JupyterLab tab's DevTools console, then approve the OS prompt:\n")
    print(f"    {snippet}\n")

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(relay):
            with open(relay) as f:
                data = json.load(f)
            os.unlink(relay)
            return data
        time.sleep(0.4)

    raise TimeoutError(
        f"no relay after {timeout:.0f}s. Check: JupyterLab started with "
        "--expose-app-in-browser, snippet pasted in the *lab* tab, prompt approved."
    )


def report(op: str, data: dict) -> bool:
    if not data.get("ok"):
        print(f"  FAIL ({op}): error={data.get('error')!r}")
        return False
    if op == "create":
        print(f"  PASS (create): cred_id={data.get('cred_id')}  prf_enabled={data.get('prf_enabled')}")
        return bool(data.get("cred_id"))
    # get
    prf = data.get("prf")
    print(f"  PASS (get): cred_id={data.get('cred_id')}  prf={'present, %d chars' % len(prf) if prf else 'none'}")
    return True


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--op", choices=["both", "create", "get"], default="both")
    p.add_argument("--cred-id", help="required for --op get")
    p.add_argument("--prf-salt", help="b64url 32-byte salt (default: random) to evaluate PRF")
    p.add_argument("--timeout", type=float, default=60.0)
    a = p.parse_args()

    print(f"relay dir: {relay_dir()}")
    salt = a.prf_salt or b64url(secrets.token_bytes(32))

    if a.op == "get":
        if not a.cred_id:
            p.error("--op get requires --cred-id")
        got = trigger_and_wait(
            {"op": "get", "nonce": secrets.token_urlsafe(24), "cred_id": a.cred_id, "prf_salt": salt},
            a.timeout,
        )
        return 0 if report("get", got) else 1

    created = trigger_and_wait({"op": "create", "nonce": secrets.token_urlsafe(24), "user": USER}, a.timeout)
    ok = report("create", created)
    if a.op == "create":
        return 0 if ok else 1
    if not (ok and created.get("cred_id")):
        return 1

    got = trigger_and_wait(
        {"op": "get", "nonce": secrets.token_urlsafe(24), "cred_id": created["cred_id"], "prf_salt": salt},
        a.timeout,
    )
    ok = report("get", got)
    if created.get("prf_enabled") is False and got.get("prf"):
        print("  note: prf_enabled was false at create but PRF is present at assertion (the Windows Hello case).")
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TimeoutError as e:
        print(f"  TIMEOUT: {e}")
        raise SystemExit(1)
