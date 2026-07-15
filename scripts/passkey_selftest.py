#!/usr/bin/env python3
"""On-demand manual passkey test - runs the real ceremony against your own device.

Uses the production trigger: a `jupyterlab-notify` notification whose action button
is bound to `passkey:run`. Clicking the button in your JupyterLab tab supplies the
WebAuthn user gesture; the browser runs the ceremony against your real authenticator
(Windows Hello / security key), POSTs the result, and the server writes a one-shot
0600 relay that this script reads back and verifies.

No `--expose-app-in-browser` and no console paste - the notify button holds the app
reference inside a real extension, so `passkey:run` is reachable directly.

Run it in a JupyterLab *terminal* (same server as the tab), keep the tab open, click
the button when it pops, and approve the OS prompt.

Usage (--rp-id is your JupyterLab hostname = the WebAuthn RP ID):
    python scripts/passkey_selftest.py --rp-id <host>                     # create, then get (PRF)
    python scripts/passkey_selftest.py --rp-id <host> --op create        # register only
    python scripts/passkey_selftest.py --rp-id <host> --op get --cred-id <b64url> [--prf-salt <b64url>]
"""

import argparse
import base64
import json
import os
import secrets
import subprocess
import time

NOTIFY = "/opt/conda/bin/jupyterlab-notify"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def relay_dir() -> str:
    return os.environ.get("JLAB_PASSKEY_RELAY_DIR", f"/dev/shm/jlab-passkey-{os.getuid()}")


def trigger_and_wait(args_obj: dict, label: str, message: str, timeout: float) -> dict:
    """Send the notify button bound to passkey:run, then read back its relay."""
    nonce = args_obj["nonce"]
    relay = os.path.join(relay_dir(), f"{nonce}.json")
    try:
        os.unlink(relay)  # clear any stale file for this nonce
    except FileNotFoundError:
        pass

    subprocess.run(
        [NOTIFY, "--now", "--no-auto-close", "-t", "info", "-m", message,
         "--action", label, "--cmd", "passkey:run", "--command-args", json.dumps(args_obj)],
        check=True,
    )
    print(f"  sent notification - click '{label}' in your JupyterLab tab and approve the prompt")

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(relay):
            with open(relay) as f:
                data = json.load(f)
            os.unlink(relay)
            return data
        time.sleep(0.4)

    raise TimeoutError(
        f"no relay after {timeout:.0f}s - was the notification clicked and the prompt approved?"
    )


def report(op: str, data: dict) -> bool:
    if not data.get("ok"):
        print(f"  FAIL ({op}): error={data.get('error')!r}")
        return False
    if op == "create":
        print(f"  PASS (create): cred_id={data.get('cred_id')}  prf_enabled={data.get('prf_enabled')}")
        return bool(data.get("cred_id"))
    prf = data.get("prf")
    print(f"  PASS (get): cred_id={data.get('cred_id')}  prf={'present, %d chars' % len(prf) if prf else 'none'}")
    return True


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--op", choices=["both", "create", "get"], default="both")
    p.add_argument("--rp-id", required=True, help="WebAuthn RP ID = your JupyterLab hostname")
    p.add_argument("--cred-id", help="required for --op get")
    p.add_argument("--prf-salt", help="b64url 32-byte salt (default: random) to evaluate PRF")
    p.add_argument("--timeout", type=float, default=120.0)
    a = p.parse_args()

    print(f"relay dir: {relay_dir()}   rp_id: {a.rp_id}")
    salt = a.prf_salt or b64url(secrets.token_bytes(32))
    user = {"id": b64url(secrets.token_bytes(16)), "name": "selftest", "displayName": "Passkey Self-Test"}

    if a.op == "get":
        if not a.cred_id:
            p.error("--op get requires --cred-id")
        got = trigger_and_wait(
            {"op": "get", "nonce": secrets.token_urlsafe(24), "rp_id": a.rp_id,
             "cred_id": a.cred_id, "prf_salt": salt},
            "Assert test passkey", "Passkey self-test - click to assert (PRF).", a.timeout,
        )
        return 0 if report("get", got) else 1

    created = trigger_and_wait(
        {"op": "create", "nonce": secrets.token_urlsafe(24), "rp_id": a.rp_id, "user": user},
        "Register test passkey", "Passkey self-test - click to register a disposable test passkey.", a.timeout,
    )
    ok = report("create", created)
    if a.op == "create":
        return 0 if ok else 1
    if not (ok and created.get("cred_id")):
        return 1

    got = trigger_and_wait(
        {"op": "get", "nonce": secrets.token_urlsafe(24), "rp_id": a.rp_id,
         "cred_id": created["cred_id"], "prf_salt": salt},
        "Assert test passkey", "Passkey self-test - click to assert the passkey just created (PRF).", a.timeout,
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
