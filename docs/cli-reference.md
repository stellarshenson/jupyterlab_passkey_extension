# CLI reference

Everything the bridge exposes to a local client with no browser of its own. There is no CLI binary - a `jupyterlab-notify` button runs one of two frontend commands, and the result lands in a one-shot relay file.

- **Trigger** - a notify action button runs the command; the click is the user gesture WebAuthn requires
- **Relay dir** - `/dev/shm/jlab-passkey-$(id -u)`, mode `0700`
- **Dir override** - `JLAB_PASSKEY_RELAY_DIR`
- **Relay file** - `<nonce>.json` for a ceremony, `<nonce>.pass` for a passphrase
- **File mode** - `0600`, written mkstemp-then-rename, never logged
- **Nonce** - `[A-Za-z0-9_-]{16,128}`, and it is the filename - anything else is `400`
- **Lifecycle** - the server only writes; the consumer reads then `shred -u`

## Commands

Two commands, both invoked through a notify button.

### `passkey:run`

Runs a WebAuthn ceremony and relays the result to `<relay_dir>/<nonce>.json`.

| Arg        | Required | Meaning                                            |
| ---------- | -------- | -------------------------------------------------- |
| `op`       | yes      | `create` (register) or `get` (assert)              |
| `nonce`    | yes      | relay filename; `[A-Za-z0-9_-]{16,128}`            |
| `rp_id`    | yes      | WebAuthn RP ID - your JupyterLab hostname          |
| `cred_id`  | `get`    | base64url credential id from a prior `create`      |
| `prf_salt` | no       | base64url 32-byte salt; evaluates PRF when present |
| `user`     | `create` | `{id, name, displayName}`; `id` is base64url       |

```bash
NONCE=$(head -c18 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')
jupyterlab-notify --now --no-auto-close -t info \
  -m "Approve the passkey request" --action "Approve" \
  --cmd passkey:run \
  --command-args "{\"op\":\"get\",\"nonce\":\"$NONCE\",\"rp_id\":\"your.host\",\"cred_id\":\"<b64url>\",\"prf_salt\":\"<b64url>\"}"

RELAY="/dev/shm/jlab-passkey-$(id -u)/$NONCE.json"
until [ -f "$RELAY" ]; do sleep 0.4; done
prf=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['prf'])" "$RELAY")
shred -u "$RELAY"
```

### `passkey:passphrase`

Prompts for a passphrase in a dialog - entered twice, relayed only when both entries match - and writes it **raw** to `<relay_dir>/<nonce>.pass`. No JSON envelope and no trailing newline, so the file is usable as-is.

| Arg      | Required | Meaning                                                      |
| -------- | -------- | ------------------------------------------------------------ |
| `nonce`  | yes      | relay filename; same guard as above                          |
| `prompt` | no       | dialog prompt text; defaults to `Enter the passphrase twice` |

- **Path** - browser → server → tmpfs; never the terminal, shell history, or a process argument
- **Confirmation** - the two entries must match before anything is relayed
- **Cancel or mismatch** - relays nothing, so the file never appears and a consumer's wait loop times out
- **Consumer** - point `PASS_RECOVERY_FILE` at the file directly, no parsing

```bash
NONCE=$(head -c18 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')
jupyterlab-notify --now --no-auto-close -t info \
  -m "Enter the recovery passphrase" --action "Enter" \
  --cmd passkey:passphrase \
  --command-args "{\"nonce\":\"$NONCE\",\"prompt\":\"Recovery passphrase\"}"

PASS_FILE="/dev/shm/jlab-passkey-$(id -u)/$NONCE.pass"
until [ -f "$PASS_FILE" ]; do sleep 0.4; done
PASS_RECOVERY_FILE="$PASS_FILE" pass-cli-open --ensure
shred -u "$PASS_FILE"
```

## Result shapes

`<nonce>.json` always carries `nonce` and `ok`.

| Outcome                              | Body                                       |
| ------------------------------------ | ------------------------------------------ |
| `create` ok                          | `{nonce, ok: true, cred_id, prf_enabled}`  |
| `get` ok                             | `{nonce, ok: true, cred_id, prf?}`         |
| PRF requested, none returned         | `{nonce, ok: false, error: "no-prf"}`      |
| user cancelled or credential unknown | `{nonce, ok: false, error: "not-allowed"}` |
| any other ceremony failure           | `{nonce, ok: false, error: "error"}`       |

`prf_enabled` reports the create-time flag only. Windows Hello returns `false` there yet still yields a PRF at `get`, so a follow-up `get` is the authoritative test - never gate on `prf_enabled`.

## Server endpoints

All endpoints sit under `<base_url>/jupyterlab-passkey-extension/` and require Jupyter authentication.

| Method | Path         | Purpose                                                      |
| ------ | ------------ | ------------------------------------------------------------ |
| `POST` | `result`     | ceremony result → `<nonce>.json`; `204` on success           |
| `POST` | `passphrase` | `{nonce, passphrase}` → raw `<nonce>.pass`; `204` on success |
| `GET`  | `health`     | `{"ok": true}`                                               |

Both `POST` endpoints answer `400` on a bad nonce, and write nothing when they do.

## Self-test script

`scripts/passkey_selftest.py` drives the real authenticator through the same notify trigger. Run it from a JupyterLab terminal on the same server, keep the tab open, click the button, approve the OS prompt.

| Flag         | Default  | Meaning                                   |
| ------------ | -------- | ----------------------------------------- |
| `--rp-id`    | required | WebAuthn RP ID - your JupyterLab hostname |
| `--op`       | `both`   | `both`, `create`, or `get`                |
| `--cred-id`  | -        | required for `--op get`                   |
| `--prf-salt` | random   | base64url 32-byte salt to evaluate PRF    |
| `--timeout`  | `120.0`  | seconds to wait for the relay file        |

```bash
python scripts/passkey_selftest.py --rp-id your.host                  # create, then get
python scripts/passkey_selftest.py --rp-id your.host --op create      # register only
python scripts/passkey_selftest.py --rp-id your.host --op get --cred-id <b64url>
```

The PRF is redacted in its output.

## Notify flags used here

| Flag                  | Why                                              |
| --------------------- | ------------------------------------------------ |
| `--now`               | post immediately rather than on a cell finishing |
| `--no-auto-close`     | keep the button up until clicked                 |
| `-t info`             | notification type                                |
| `--action LABEL`      | button label                                     |
| `--cmd ID`            | command the button runs                          |
| `--command-args JSON` | arguments passed to the command                  |

See [example-secret-unlock.md](example-secret-unlock.md) for a worked end-to-end example.
