"""`aws-credential-jupyterlab-passkey`: the vault as the AWS CLI's credential process.

The AWS CLI runs a profile's `credential_process` command with no arguments and reads
the JSON on its stdout. This helper takes the profile the line names, reads vault entry
`aws/<profile>` - username the access key id, password the secret access key - and
prints `{"Version": 1, "AccessKeyId": ..., "SecretAccessKey": ...}`. Static access
keys only: no session token, no expiry, and an SSO or session profile gets nothing
from it.
"""

import json
import os
import sys

from .. import cli as _cli, env
from . import cli as _vcli
from .client import Vault, VaultClientError

PROGRAM = "aws-credential-jupyterlab-passkey"


def _credential(profile):
    """The access key id and secret key of `aws/<profile>`, or None after a line on stderr.

    Set-up follows the git helper: the offer at a terminal, otherwise the page runs it.
    The AWS CLI runs this with stdout piped, so the browser set-up is the normal path.
    """
    vault = Vault(timeout=_cli.CLICK_TIMEOUT)
    if _vcli._terminal():
        entries = _vcli.ensure_vault(vault, vault.list)
    else:
        if not vault.status()["initialized"]:
            _vcli.setup_in_browser(vault)
        entries = vault.list()
    name = f"aws/{profile}"
    if not any(entry["name"] == name for entry in entries):
        print(f"{PROGRAM}: no vault entry {name} - run `jupyterlab-passkey vault add "
              f"{name} -u <access-key-id>`", file=sys.stderr)
        return None
    # A read opens a locked vault through the existing notification and wait.
    username = vault.get(name, "username")
    if not username:
        print(f"{PROGRAM}: vault entry {name} has an empty username", file=sys.stderr)
        return None
    password = vault.get(name, "password")
    if not password:
        print(f"{PROGRAM}: vault entry {name} has an empty password", file=sys.stderr)
        return None
    return username, password


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(f"usage: {PROGRAM} PROFILE", file=sys.stderr)
        return 1
    if env.get("CALLER") is None:
        os.environ["JUPYTERLAB_PASSKEY_CALLER"] = "aws"
    try:
        found = _credential(argv[0])
    except (VaultClientError, SystemExit) as e:
        print(f"{PROGRAM}: {e}", file=sys.stderr)
        return 1
    if found is None:
        return 1
    username, password = found
    print(json.dumps({"Version": 1, "AccessKeyId": username, "SecretAccessKey": password}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
