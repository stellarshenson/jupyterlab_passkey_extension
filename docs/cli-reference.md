# CLI reference

`jupyterlab-passkey` turns a browser ceremony into a blocking local call. It is a thin proxy to the [JupyterLab commands](commands-reference.md): it posts the notification that carries the command, waits for the relay the server writes, and prints the result. It deletes the ceremony relay after reading it; the passphrase relay is left for its consumer to shred. A consumer never learns the relay contract.

- **Ships with the package** - `pip install jupyterlab_passkey_extension` puts it on `PATH`
- **Subcommands** - `create`, `get`, `passphrase`, mirroring the commands one-to-one
- **Transport** - HTTP only; it finds the server and token via `jupyter server list --json`, taking the **first** server reported
- **Where to run it** - a terminal on the same Jupyter server, with a JupyterLab tab open
- **Blocking** - each call waits for you to click the button and approve the prompt
- **Timeout** - `--timeout` seconds, default `120`; exit `1` if no relay arrives
- **Failure** - a failed ceremony exits `1` with the error on stderr, nothing on stdout

The click is not incidental - WebAuthn requires a user gesture, and a terminal has none. The notification button is the gesture.

> [!IMPORTANT]
> The CLI assumes **one** running Jupyter server, and there is no flag to select one. It takes the first entry `jupyter server list` reports, and that order follows the runtime directory's filesystem order rather than anything meaningful. With a second server running, the notification can be raised in a tab you are not watching, and the call then fails on its timeout as though the button was never clicked. Run it where exactly one server is live.

### How the server is found

Discovery has a fallback, and it is worth knowing because it is silent:

- **Normally** - the first entry of `jupyter server list --json` supplies the port, base URL, and token
- **When that list is empty** - the CLI guesses instead: `JUPYTER_PORT` (defaulting to **8888**) with `JUPYTERHUB_SERVICE_PREFIX`, authenticating with `JUPYTERHUB_API_TOKEN`, `JPY_API_TOKEN` or `JUPYTER_TOKEN`

The hub variables take priority over the server list's own token, because under JupyterHub a server rejects its own listed token and accepts only the hub-issued one.

Pointing `JUPYTER_RUNTIME_DIR` at a specific runtime folder therefore narrows discovery only if that folder actually holds the server's record. Point it somewhere empty and the list is empty, so the CLI falls through to the guess above and quietly targets port 8888 - which is the likeliest port for some _other_ lab.

## Requirements

- A JupyterLab tab open on the same server, to receive the notification and run the ceremony
- [`jupyterlab_notifications_extension`](https://github.com/stellarshenson/jupyterlab_notifications_extension) - a hard dependency, installed for you; the CLI posts to its `ingest` endpoint to raise the button. A lab without it answers `404`

## `create`

Registers a passkey. Prints its `cred_id` to stdout - keep it; `get` needs it.

| Flag          | Required | Meaning                                                                        |
| ------------- | -------- | ------------------------------------------------------------------------------ |
| `--rp-id`     | yes      | WebAuthn RP ID - your JupyterLab tab's hostname, bare: no scheme, port or path |
| `--user-name` | no       | credential user name; defaults to the tool                                     |

```bash
# the hostname of the tab you will click in - not a URL
cred_id=$(jupyterlab-passkey create --rp-id lab.example.com)
```

## `get`

Asserts a passkey. With `--prf-salt` it prints the PRF; without, the `cred_id`.

| Flag         | Required | Meaning                                          |
| ------------ | -------- | ------------------------------------------------ |
| `--rp-id`    | yes      | same hostname the credential was created with    |
| `--cred-id`  | yes      | base64url credential id from a prior `create`    |
| `--prf-salt` | no       | base64url 32-byte salt; prints the PRF it yields |

The PRF is deterministic - the same credential and the same salt always yield the same 32 bytes, which is what makes it usable as key material. It goes to stdout for a `$(...)` capture, so redirect with care.

```bash
prf=$(jupyterlab-passkey get --rp-id lab.example.com --cred-id "$cred_id" --prf-salt "$salt")
```

## `passphrase`

Opens a dialog that takes a passphrase twice and relays it only when both entries match. Prints the **path** of the `0600` relay file, never the value - the passphrase reaches its consumer without passing through the terminal, shell history, or a process argument.

| Flag       | Required | Meaning                                                      |
| ---------- | -------- | ------------------------------------------------------------ |
| `--prompt` | no       | dialog prompt text; defaults to `Enter the passphrase twice` |

Cancelling, or accepting two entries that differ, relays nothing - the call times out and exits `1`. The file is left in place for the consumer to read; shred it when done.

```bash
pass_file=$(jupyterlab-passkey passphrase --prompt "Recovery passphrase")
PASS_RECOVERY_FILE="$pass_file" pass-cli-open --ensure
shred -u "$pass_file"
```

## Keystore use

The two secret sources a passkey-backed keystore needs, each one command:

- **Passkey slot** - `get --prf-salt` yields the PRF; the keystore derives its key from it
- **Recovery slot** - `passphrase` yields the file the keystore reads its passphrase from
- **Division of labour** - this CLI only moves secrets out of the browser; wrapping, slots and key derivation belong to the keystore

```bash
salt=$(head -c32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')
prf=$(jupyterlab-passkey get --rp-id lab.example.com --cred-id "$cred_id" --prf-salt "$salt")
```

See [example-secret-unlock.md](example-secret-unlock.md) for a worked end-to-end example.
