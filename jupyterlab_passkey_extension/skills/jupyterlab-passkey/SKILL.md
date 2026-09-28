---
name: jupyterlab-passkey
description: Password vault kept by the Jupyter server, and the passkey bridge, through the `jupyterlab-passkey` CLI and the Python `Vault` class of jupyterlab_passkey_extension. Use when reading, storing or handing over credentials, API keys or tokens on a Jupyter server with this extension, when taking a secret from the user or giving one to the user without it entering the transcript, or when a local tool needs a passkey PRF or a passphrase typed in the browser.
---

# Passkey vault and bridge (`jupyterlab-passkey`)

`jupyterlab-passkey` ships with `jupyterlab_passkey_extension` and runs on the machine of the Jupyter server. It has two parts:

- **Vault** - `jupyterlab-passkey vault ...`: one encrypted vault the Jupyter server keeps. It is unlocked with a passkey or with the recovery passphrase, and it stays unlocked for the `unlockMinutes` setting (default 240) for the CLI, the Python `Vault` class and the sidebar panel alike
- **Bridge** - `passphrase`, `copy`, `show`, `create`, `get`: move one secret between the browser and a local process, for secrets that are not in the vault

A step that needs the browser raises a JupyterLab notification. The user's click on its button is the gesture WebAuthn requires, so the command waits for it: 120 s by default, 600 s for `vault init` and `vault passkey add`, `--timeout SECONDS` to change it. No click in time exits 1.

## Rules for an agent

Everything a shell command prints reaches the agent's context and the session transcript.

- **Never print a vault value** - run `vault get` only into a pipe or a file, never to the screen. Give a value to a command with `vault exec`, to the user with `vault copy` or `vault show`
- **Never put a secret on a command line** - no option takes one, and argv is visible in the process list and the transcript
- **Take a new secret with `--in-browser`** - the user types it in a JupyterLab dialog. The agent's shell has no terminal, so the hidden terminal prompt is not available
- **Tell the user before a command that waits** - a read on a locked vault first raises the unlock notification, and the command blocks until the user clicks it and approves the passkey
- **One Jupyter server** - the CLI uses the first server `jupyter server list` reports. With two running, the notification can appear in a tab nobody is watching, and the command times out

## Reading

```bash
jupyterlab-passkey vault status                         # locked or unlocked, time left, key holder, passkeys
jupyterlab-passkey vault list                           # name, username, category, url - never passwords
jupyterlab-passkey vault list --category infrastructure --json
jupyterlab-passkey vault exec --env GITHUB_TOKEN=github/api -- gh repo list
jupyterlab-passkey vault exec --env DB_USER=db/prod:username --env DB_PASS=db/prod -- ./migrate.sh
```

- `exec --env VAR=NAME[:FIELD]` sets `VAR` in the command's environment only; repeatable
- Fields: `password` (the default), `username`, `url`, `category`, `notes`, `name`
- `exec` replaces itself with the command, so the exit status, the signals and the output are the command's own. Its output is shown like any other output: do not run a command that prints the values it was given
- `get NAME [--field F]` prints one value and a newline to stdout

In Python, in a notebook or a script, the value stays in the process:

```python
from jupyterlab_passkey_extension.vault import Vault

vault = Vault()
token = vault.get("github/api")                         # unlocks with the passkey first if locked
user = vault.get("github/api", field="username")
```

`Vault` also has `status()`, `list()`, `unlock(recovery=None)` and `lock()`. A refusal raises `VaultClientError` from `jupyterlab_passkey_extension.vault.client`, with the reason as its message.

## Handing a secret to the user

```bash
jupyterlab-passkey vault copy github/api                # the click copies the value to the browser clipboard
jupyterlab-passkey vault copy github/api --field username
jupyterlab-passkey vault show wifi/guest                # the click shows the value as a distorted image, to type elsewhere
```

- The server gives the value to the browser; it never enters the CLI process
- Exit 0 means the notification was raised, not that the user clicked. Nothing is reported back
- One click collects the value. An unclicked value stays staged until its TTL on the kernel keyring, or until reboot in `/dev/shm`; `vault lock` does not remove it

For a secret that is not in the vault, pipe it to the bridge:

```bash
<producer> | jupyterlab-passkey copy --label "DB password" --block || exit 1
```

`--label` names the value in the notification. `--block` waits until the browser collects the value, and removes it and exits 1 if that does not happen in time. `copy` refuses a terminal on stdin.

## Storing

```bash
jupyterlab-passkey vault add github/api -u me -c infrastructure --url https://github.com --in-browser
jupyterlab-passkey vault add db/prod -u app --generate --length 32
jupyterlab-passkey vault edit github/api --password --in-browser        # a new password
jupyterlab-passkey vault edit github/api --notes "rotated 2026-09"      # only the fields given change
jupyterlab-passkey vault rm old/entry
<producer> | jupyterlab-passkey vault add gitlab/api -u me              # the password piped on stdin
<producer> | jupyterlab-passkey vault import                            # a JSON list of entries
```

- `--in-browser` for a password shows the value field twice, and Submit stays disabled until both match. Cancel exits 1
- `--generate` creates the password on the server: 24 characters by default, without `l I 1 | O 0`, quotes, backslash, backtick and space
- `import` takes a list of objects with `name` (or pass-cli's `service`), `username`, `password`, `url`, `category` and `notes`. It skips names that already exist and refuses a terminal on stdin. A file of entries holds plaintext passwords: pipe them in instead of writing one
- `notes` is free text

## Unlock, lock and the recovery passphrase

```bash
jupyterlab-passkey vault unlock                         # passkey: a notification, then the passkey prompt
jupyterlab-passkey vault unlock --recovery --in-browser # recovery passphrase, typed in a dialog
jupyterlab-passkey vault lock                           # removes the key from its holder now
jupyterlab-passkey vault recovery --in-browser          # replace the recovery passphrase: the current one, then the new one twice
```

Use the recovery passphrase when no passkey is registered for the tab's hostname or the passkey is lost. Only the user knows it; never ask for it in the chat.

## Passkeys

- A passkey opens the vault only from the hostname it was registered on, or a subdomain of it. Register one for each hostname JupyterLab is opened on
- A tab opened at an IP address such as `127.0.0.1` cannot use a passkey. Open JupyterLab by name: over HTTPS, or at `localhost`
- `vault passkey add [--label "Work laptop"]` registers one from the tab. The browser first asks for a proof: a passkey already registered for this hostname, or the recovery passphrase when there is none or it does not answer
- `vault passkey list` prints cred_id, label, hostname and date for each. `vault passkey rm --cred-id=<id>` removes one on an unlocked vault; write `--cred-id=`, because a cred_id can begin with `-`

## Creating the vault

```bash
jupyterlab-passkey vault init --in-browser --label "Work laptop"
```

It asks for the recovery passphrase twice, then registers a passkey, which asks for the passphrase once more as its proof. The user must store the recovery passphrase offline: it is the only way in without a passkey. `--no-passkey` skips the registration.

## Taking a secret for another tool

`passphrase` takes a secret in a browser dialog and prints a reference to it, never the value:

```bash
ref=$(jupyterlab-passkey passphrase --once --prompt "GitHub token") || exit 1
case "$ref" in
  keyctl:*) keyctl pipe "$(keyctl search @u user "${ref#keyctl:}")" | <consumer> ;;
  file:*)   <consumer> < "${ref#file:}"; shred -u "${ref#file:}" ;;
esac
```

- `keyctl:jlab-passkey:<nonce>.pass` is a kernel key that is removed after 300 s; `file:<path>` is a `0600` file that stays until it is removed
- `--once` shows one field, for a pasted value; without it the value is typed twice
- Keep `|| exit 1` on its own line. `VAR=$(jupyterlab-passkey passphrase ...) consumer` drops the exit status, so a cancel runs the consumer with an empty value
- For a vault entry, `vault add --in-browser` does this in one step

`create` and `get` run a WebAuthn registration or assertion for a tool that keeps its own keys: `get --prf-salt` prints a deterministic 32-byte PRF, for key derivation. `show` is the bridge form of `vault show` for a value that is not in the vault.

## Errors

| Message on stderr | Next step |
| --- | --- |
| `the vault is not loaded on this Jupyter server - restart the server` | the extension was installed into a running server; the user restarts it |
| `no vault at <path> - run jupyterlab-passkey vault init` | create the vault |
| `no passkey is registered with the vault - ...` | `vault unlock --recovery --in-browser` |
| `the vault is locked - run jupyterlab-passkey vault unlock` | unlock, then run the command again |
| `cannot reach <url> (...) - is JupyterLab running?` | JupyterLab is not running, or `jupyter server list` does not show it |
| `no relay after <N>s - ...` | nobody clicked in time; ask the user, then run it again |

Exit status: 0 success, 1 a refusal or a timeout (one line on stderr, nothing on stdout), 2 an argument the parser rejects. `vault exec` exits with its command's status.

## Server side

- The vault file is `$XDG_DATA_HOME/jupyterlab-passkey/vault.json` (`~/.local/share/...` by default), mode `0600`. `JLAB_PASSKEY_VAULT` sets another path
- While unlocked, the key is in the first key holder that works: the kernel keyring (`keyctl`), a gpg-agent of the vault's own, or the server's memory. `JLAB_PASSKEY_VAULT_HOLDER` pins one; `vault status` shows the holder and what it protects on the host
- The Jupyter server reads both variables, not the CLI: set them where the server starts
- `--debug` on any command prints the relay backend and, for vault commands, the key-holder decision on stderr

Full reference: [docs/cli-reference.md](https://github.com/stellarshenson/jupyterlab_passkey_extension/blob/main/docs/cli-reference.md).
