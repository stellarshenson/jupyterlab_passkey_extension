# CLI reference

`jupyterlab-passkey` turns a browser ceremony into a blocking local call. It is a thin proxy to the [JupyterLab commands](commands-reference.md): it posts the notification that carries the command, waits for the relay the server writes, prints the result, and cleans up. A consumer never learns the relay contract.

- **Ships with the package** - `pip install jupyterlab_passkey_extension` puts it on `PATH`
- **Subcommands** - `create`, `get`, `passphrase`, mirroring the commands one-to-one
- **Transport** - HTTP only; it finds the server and token via `jupyter server list --json`
- **Where to run it** - a terminal on the same Jupyter server, with a JupyterLab tab open
- **Blocking** - each call waits for you to click the button and approve the prompt
- **Timeout** - `--timeout` seconds, default `120`; exit `1` if no relay arrives
- **Failure** - a failed ceremony exits `1` with the error on stderr, nothing on stdout

The click is not incidental - WebAuthn requires a user gesture, and a terminal has none. The notification button is the gesture.

## Requirements

- A JupyterLab tab open on the same server, to receive the notification and run the ceremony
- The notifications extension installed in that lab - the CLI posts to its `ingest` endpoint

## `create`

Registers a passkey. Prints its `cred_id` to stdout - keep it; `get` needs it.

| Flag          | Required | Meaning                                    |
| ------------- | -------- | ------------------------------------------ |
| `--rp-id`     | yes      | WebAuthn RP ID - your JupyterLab hostname  |
| `--user-name` | no       | credential user name; defaults to the tool |

```bash
cred_id=$(jupyterlab-passkey create --rp-id your.host)
```

## `get`

Asserts a passkey. With `--prf-salt` it prints the PRF; without, the `cred_id`.

| Flag         | Required | Meaning                                          |
| ------------ | -------- | ------------------------------------------------ |
| `--rp-id`    | yes      | WebAuthn RP ID - your JupyterLab hostname        |
| `--cred-id`  | yes      | base64url credential id from a prior `create`    |
| `--prf-salt` | no       | base64url 32-byte salt; prints the PRF it yields |

The PRF is deterministic - the same credential and the same salt always yield the same 32 bytes, which is what makes it usable as key material. It goes to stdout for a `$(...)` capture, so redirect with care.

```bash
prf=$(jupyterlab-passkey get --rp-id your.host --cred-id "$cred_id" --prf-salt "$salt")
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
prf=$(jupyterlab-passkey get --rp-id your.host --cred-id "$cred_id" --prf-salt "$salt")
```

See [example-secret-unlock.md](example-secret-unlock.md) for a worked end-to-end example.
