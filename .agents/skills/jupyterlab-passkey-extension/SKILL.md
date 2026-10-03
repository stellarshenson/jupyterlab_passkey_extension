---
name: jupyterlab-passkey-extension
description: Passwords, API keys and passkeys on a Jupyter server, through the `jupyterlab-passkey` CLI and the Python `Vault` class of jupyterlab_passkey_extension. Use when reading, storing or handing over a credential or token without printing it, taking a secret from the user in the browser, giving one to the user, or when a local tool needs a passkey PRF or a passphrase typed in the browser.
---

# jupyterlab-passkey

Runs on Jupyter server machine. `vault`: encrypted passwords server keeps, unlocked by passkey or recovery passphrase. Bridge (`passphrase`, `copy`, `show`, `create`, `get`): one secret between browser and local process. Commands, flags, output, waits, errors, environment: `jupyterlab-passkey --help`, `jupyterlab-passkey vault <command> --help`. Read first.

## Rules

- Command output goes into transcript. Never `vault get` to screen. Value to command: `vault exec`. Value to user: `vault copy` or `vault show`
- Python keeps value in process: `from jupyterlab_passkey_extension.vault import Vault; Vault().get("github/api")`. Refusal raises `VaultClientError` from `jupyterlab_passkey_extension.vault.client`
- Never secret on command line. New secret: `--in-browser`, user types it in JupyterLab dialog. Agent shell has no terminal for hidden prompt
- Tell user before command that waits. Locked vault, passkey step or dialog raises notification; command blocks until user clicks
- Notification must name who asks: it starts `Asked by <name>:`. Default name: project directory command runs in (nearest `.git` upwards). Run from your project's directory. Elsewhere, or when project name does not say who you are: `JLAB_PASSKEY_CALLER="<project or caller>" jupyterlab-passkey ...`; in Python set `os.environ["JLAB_PASSKEY_CALLER"]` before `Vault()` raises one. Never another project's name
- Never ask user for recovery passphrase in chat. Use `vault unlock --recovery --in-browser`
