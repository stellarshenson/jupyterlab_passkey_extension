# Commands reference

The JupyterLab commands the extension registers, and the server contract behind them. These run **in the browser** - a consumer reaches them through a notification button, whose click supplies the user gesture WebAuthn requires. For a ready-made local wrapper, see [cli-reference.md](cli-reference.md).

- **Commands** - `passkey:run` (ceremony), `passkey:passphrase` (secret capture), `passkey:copy` (secret to clipboard)
- **Trigger** - a `jupyterlab-notify` action button bound to the command id
- **Return path** - the frontend POSTs to the server, which writes an atomic relay file
- **Relay dir** - `/dev/shm/jlab-passkey-$(id -u)`, mode `0700`; override with `JLAB_PASSKEY_RELAY_DIR`. Verified before every read and write the extension or CLI makes: a real directory owned by the current uid - a symlink or a co-tenant's directory squatting the path raises rather than being used; a loose mode on a directory that is ours is tightened to `0700`
- **Relay file** - `<nonce>.json` for a ceremony, raw `<nonce>.pass` for a captured secret, raw `<nonce>.secret` for one going out to the clipboard
- **File mode** - `0600`, written mkstemp-then-rename, never logged
- **Nonce** - `[A-Za-z0-9_-]{16,128}`, and it is the filename - anything else is `400`
- **Lifecycle** - the server writes for `run` and `passphrase` and the consumer shreds; `copy` inverts it - a local client writes and the server reads once, deleting as it goes

Secrets move both ways. `passkey:passphrase` takes one **from** the user and leaves it on disk for a local client; `passkey:copy` takes one a local client already holds and puts it **on the user's clipboard**. Both keep the value out of the notification itself, which the notifications extension broadcasts to every connected socket and parks in an in-memory queue until a client drains it - so a notification carries a nonce, never a secret.

## `passkey:run`

Runs a WebAuthn ceremony and relays the result to `<relay_dir>/<nonce>.json`.

| Arg        | Required | Meaning                                            |
| ---------- | -------- | -------------------------------------------------- |
| `op`       | yes      | `create` (register) or `get` (assert)              |
| `nonce`    | yes      | relay filename; `[A-Za-z0-9_-]{16,128}`            |
| `rp_id`    | yes      | WebAuthn RP ID - your JupyterLab hostname          |
| `cred_id`  | `get`    | base64url credential id from a prior `create`      |
| `prf_salt` | no       | base64url 32-byte salt; evaluates PRF when present |
| `user`     | `create` | `{id, name, displayName}`; `id` is base64url       |

The challenge is a random 32-byte value the frontend generates itself - anti-replay plumbing nothing here verifies, so callers never supply it.

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

> [!NOTE]
> The squat verification above covers the extension's and CLI's own file operations - this hand-rolled read is not guarded, and the nonce rides on a command line, which `/proc` makes readable to co-tenants. The nonce is a collection ticket, not a secret, but on a multi-user host prefer `jupyterlab-passkey get`, which guards the read and keeps the nonce off argv.

## `passkey:passphrase`

Prompts for a secret in a dialog and writes it **raw** to `<relay_dir>/<nonce>.pass`. No JSON envelope and no trailing newline, so the file is usable as-is. Entered twice and relayed only on a match by default; `once` asks for a single entry.

| Arg      | Required | Meaning                                                            |
| -------- | -------- | ------------------------------------------------------------------ |
| `nonce`  | yes      | relay filename; same guard as above                                |
| `prompt` | no       | dialog prompt text; defaults per mode (see below)                  |
| `once`   | no       | `true` asks once, with no confirm field - for a value being pasted |

- **Path** - browser → server → tmpfs; never the terminal, shell history, or a process argument
- **Confirmation** - the two entries must match before anything is relayed; `once` only requires non-empty
- **Default prompt** - `Enter the passphrase twice`, or `Enter the secret` under `once`
- **Cancel or mismatch** - relays nothing, so the file never appears and a consumer's wait loop times out
- **Consumer** - point `PASS_RECOVERY_FILE` (or `PASS_SECRET_FILE`, or anything else) at the file directly, no parsing

Double entry catches a typo in a passphrase being **set**, where nothing else will - get it wrong and the mistake surfaces at the next unlock, by which time the right value is forgotten. It earns nothing for a token being **pasted** out of a password manager, which is what `once` is for.

## `passkey:copy`

Collects the secret a local client staged at `<relay_dir>/<nonce>.secret` and writes it to the user's clipboard. The only command that carries a value **out** to the browser rather than in.

| Arg     | Required | Meaning                                                          |
| ------- | -------- | ---------------------------------------------------------------- |
| `nonce` | yes      | relay filename; same guard as above                              |
| `label` | no       | names the secret if the page must ask for a second click (below) |

- **Staging** - the local client writes the relay itself (`0600`, atomic); the server never creates one here
- **Collection** - the command POSTs the nonce to `secret`, which reads the relay and unlinks it in the same breath
- **One shot** - a second click finds nothing and gets `404`; the clipboard is left untouched
- **Refused write** - the browser only honours a clipboard write for a focused window within ~5s of a user gesture, so a click followed by an absence can be refused. The relay is already spent, but the value is not lost: the page retries quietly for 15s, then raises a "clipboard needs another click" notification (naming the secret by `label`) whose button finishes the copy under a fresh gesture. The value waits in page memory - never back on disk - and dies with the tab
- **After the copy** - the value is an OS-wide clipboard entry, readable by any app until overwritten

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

| Method | Path         | Purpose                                                                    |
| ------ | ------------ | -------------------------------------------------------------------------- |
| `POST` | `result`     | ceremony result → `<nonce>.json`; `204` on success                         |
| `POST` | `passphrase` | `{nonce, passphrase}` → raw `<nonce>.pass`; `204` on success               |
| `POST` | `secret`     | `{nonce}` ← raw `<nonce>.secret`; `{"value": "..."}`, `404` once collected |
| `GET`  | `health`     | `{"ok": true}`                                                             |

Every `POST` endpoint answers `400` on a bad nonce, and touches no file when it does - including `secret`, which is the one that turns a nonce into a path it reads and then unlinks.

`secret` is a `POST` despite only reading: the read is destructive, and a `GET` would carry the nonce in the query string straight into the server's access log. The nonce is not the secret, but it is the ticket to collect one.

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
