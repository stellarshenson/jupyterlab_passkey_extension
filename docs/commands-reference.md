# Commands reference

The JupyterLab commands the extension registers, and the server contract behind them. These run **in the browser** - a consumer reaches them through a notification button, whose click supplies the user gesture WebAuthn requires. For a ready-made local wrapper, see [cli-reference.md](cli-reference.md).

- **Commands** - `passkey:run` (ceremony), `passkey:passphrase` (secret capture), `passkey:copy` (secret to clipboard), `passkey:show` (code as a scraper-resistant image), and for the [vault](../README.md#vault) `passkey:vault-unlock` and `passkey:vault-register`
- **Trigger** - a `jupyterlab-notify` action button bound to the command id
- **Return path** - the frontend POSTs to the server, which stages the value in a relay
- **Relay backend** - a uid-scoped kernel `keyctl` key (preferred, no swap, self-destructs at a TTL) or a `/dev/shm` `0600` file (fallback); chosen once per process, forced with `JLAB_PASSKEY_RELAY_BACKEND=keyctl|shm|auto`
- **keyctl key** - type `user`, description `jlab-passkey:<nonce>.<kind>`, keyring `@u`, TTL by kind (ceremony/passphrase 300s, copy and show 900s, a cancel marker 60s)
- **shm dir** - `/dev/shm/jlab-passkey-$(id -u)`, mode `0700`; override with `JLAB_PASSKEY_RELAY_DIR`. Verified before every read and write the extension or CLI makes: a real directory owned by the current uid - a symlink or a co-tenant's directory squatting the path raises rather than being used; a loose mode on a directory that is ours is tightened to `0700`
- **shm file** - `<nonce>.json` for a ceremony, raw `<nonce>.pass` for a captured secret, raw `<nonce>.secret` for one going out to the clipboard, raw `<nonce>.code` for one going out as an image, `<nonce>.cancel` (no secret) for a dismissed passphrase dialog; mode `0600`, written mkstemp-then-rename, never logged
- **Nonce** - `[A-Za-z0-9_-]{16,128}`, and it becomes the key description or the filename - anything else is `400`
- **Lifecycle** - the server stages for `run` and `passphrase` and the consumer reads; `copy` and `show` invert it - a local client, or the server itself for `vault copy` and `vault show`, stages, and the server reads once, destroying as it goes

Secrets move both ways. `passkey:passphrase` takes one **from** the user and stages it for a local client; `passkey:copy` takes one a local client (or the server, for `vault copy`) already holds and puts it **on the user's clipboard**. Both keep the value out of the notification itself, which the notifications extension broadcasts to every connected socket and parks in an in-memory queue until a client drains it - so a notification carries a nonce, never a secret.

Neither backend isolates a secret from the user's own processes: a same-uid process can read the `0600` file or `keyctl search @u`. keyctl buys no-swap, self-destruct and no disk artifact, not access control.

## `passkey:run`

Runs a WebAuthn ceremony and relays the result under the nonce (a kernel key on keyctl, a `<relay_dir>/<nonce>.json` file on shm).

| Arg        | Required | Meaning                                                                |
| ---------- | -------- | ---------------------------------------------------------------------- |
| `op`       | yes      | `create` (register) or `get` (assert)                                  |
| `nonce`    | yes      | relay key/filename; `[A-Za-z0-9_-]{16,128}`                            |
| `rp_id`    | yes      | WebAuthn RP ID - your JupyterLab hostname; a name, never an IP address |
| `cred_id`  | `get`    | base64url credential id from a prior `create`                          |
| `prf_salt` | no       | base64url 32-byte salt; evaluates PRF when present                     |
| `user`     | `create` | `{id, name, displayName}`; `id` is base64url                           |

The challenge is a random 32-byte value the frontend generates itself - anti-replay plumbing nothing here verifies, so callers never supply it.

```bash
NONCE=$(head -c18 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')
jupyterlab-notify --now --no-auto-close -t info \
  -m "Approve the passkey request" --action "Approve" \
  --cmd passkey:run \
  --command-args "{\"op\":\"get\",\"nonce\":\"$NONCE\",\"rp_id\":\"your.host\",\"cred_id\":\"<b64url>\",\"prf_salt\":\"<b64url>\"}"

# shm backend - the server wrote a file:
RELAY="/dev/shm/jlab-passkey-$(id -u)/$NONCE.json"
until [ -f "$RELAY" ]; do sleep 0.4; done
prf=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['prf'])" "$RELAY")
shred -u "$RELAY"

# keyctl backend - the server staged a key; there is no file:
DESC="jlab-passkey:$NONCE.json"
until keyctl search @u user "$DESC" >/dev/null 2>&1; do sleep 0.4; done
prf=$(keyctl pipe "$(keyctl search @u user "$DESC")" | python3 -c "import json,sys;print(json.load(sys.stdin)['prf'])")
keyctl unlink "$(keyctl search @u user "$DESC")" @u
```

> [!NOTE]
> Which of the two reads applies depends on the live backend (`JLAB_PASSKEY_RELAY_BACKEND`); the CLI hides that difference, this hand-rolled flow does not. The squat verification covers the extension's and CLI's own operations - neither hand-rolled read is guarded. The nonce is a collection ticket, not a secret, but on a multi-user host prefer `jupyterlab-passkey get`, which picks the backend for you and keeps the nonce out of your shell history and off the notify command line (under keyctl it does spawn `keyctl` with the key description, briefly visible in `/proc` to your own uid - which can read the key regardless).

## `passkey:passphrase`

Prompts for a secret in a dialog and stages it **raw** - no JSON envelope, no trailing newline. Entered twice and staged only on a match by default; `once` asks for a single entry. The CLI prints the consumer a scheme-prefixed reference (`keyctl:jlab-passkey:<nonce>.pass` or `file:<path>`), never the value.

| Arg      | Required | Meaning                                                            |
| -------- | -------- | ------------------------------------------------------------------ |
| `nonce`  | yes      | relay key/filename; same guard as above                            |
| `prompt` | no       | dialog prompt text; defaults per mode (see below)                  |
| `once`   | no       | `true` asks once, with no confirm field - for a value being pasted |

- **Path** - browser → server → kernel key or tmpfs; never the terminal, shell history, a process argument, or the bridge CLI
- **Confirmation** - the two entries must match before anything is staged; `once` only requires non-empty
- **Default prompt** - `Enter the passphrase twice`, or `Enter the secret` under `once`
- **Cancel** - stages a `<nonce>.cancel` marker (no secret; 60s on keyctl) that a consumer can watch to stop waiting at once; a mismatch cannot be submitted
- **Consumer** - a keyctl-aware consumer branches on the reference scheme: `keyctl pipe $(keyctl search @u user <desc>)` or read the `file:` path; the value never passes through the bridge

Double entry catches a typo in a passphrase being **set**, where nothing else will - get it wrong and the mistake surfaces at the next unlock, by which time the right value is forgotten. It earns nothing for a token being **pasted** out of a password manager, which is what `once` is for.

## `passkey:copy`

Collects the secret staged under the nonce - by a local client, or by the server for `vault copy` - (a kernel key on keyctl, a `<relay_dir>/<nonce>.secret` file on shm) and writes it to the user's clipboard. With `passkey:show`, one of the two commands that carry a value **out** to the browser rather than in.

| Arg     | Required | Meaning                                                          |
| ------- | -------- | ---------------------------------------------------------------- |
| `nonce` | yes      | relay key/filename; same guard as above                          |
| `label` | no       | names the secret if the page must ask for a second click (below) |

- **Staging** - the local client writes the relay itself (a kernel key, or an atomic `0600` file), or the server does for `vault copy`
- **Collection** - the command POSTs the nonce to `secret`, which reads the relay and unlinks it in the same breath
- **One shot** - a second click finds nothing and gets `404`; the clipboard is left untouched
- **Refused write** - the browser only honours a clipboard write for a focused window within ~5s of a user gesture, so a click followed by an absence can be refused. The relay is already spent, but the value is not lost: the page retries quietly for 15s, then raises a "clipboard needs another click" notification (naming the secret by `label`) whose button finishes the copy under a fresh gesture. The value waits in page memory - never back on disk - and dies with the tab
- **After the copy** - the value is an OS-wide clipboard entry, readable by any app until overwritten

## `passkey:show`

Collects the code staged under the nonce - by a local client, or by the server for `vault show` - (a kernel key on keyctl, a `<relay_dir>/<nonce>.code` file on shm), has the server render it to a distorted PNG, and shows that image in a dialog. The counterpart of `copy` for a value the user must **read** rather than paste.

| Arg     | Required | Meaning                                            |
| ------- | -------- | -------------------------------------------------- |
| `nonce` | yes      | relay key/filename; same guard as above            |
| `label` | no       | name shown in the notification and above the image |

- **Staging** - the local client writes the relay itself (a kernel key, or an atomic `0600` file), or the server does for `vault show`
- **Rendering** - the command POSTs the nonce to `render`, which reads the relay, unlinks it, and returns only image bytes - the code never leaves the server as text
- **One shot** - a second call finds nothing and gets `404`; a dismissed dialog cannot be reopened
- **Image only** - the code is absent from the notification broadcast, the page DOM as text, and the accessibility tree; the dialog image carries empty `alt` text by design

## `passkey:vault-unlock` and `passkey:vault-register`

The two vault passkey steps; `jupyterlab-passkey vault unlock` and `vault passkey add` raise them. The page runs the ceremony and sends the PRF straight to the vault endpoint, so the PRF never enters a relay. Only the outcome comes back: the page POSTs `{nonce, ok: true}` or `{nonce, ok: false, error}` to `result`, which stages it for the waiting CLI.

| Arg     | Required | Meaning                                                      |
| ------- | -------- | ------------------------------------------------------------ |
| `nonce` | no       | relay key for the outcome; without it nothing is posted back |
| `label` | no       | `vault-register` only: the name offered for the passkey      |

`vault-unlock` uses every passkey slot added for the tab's hostname. `vault-register` first gets the proof the server asks for a new slot - a request with a passkey added for the tab's hostname. When the hostname has none, that request gets no answer (the passkey is on another device, or lost) or the passkey gives no PRF, it asks a code of the authenticator app while the vault has one and is unlocked, or the recovery passphrase. On a tab at an IP address it asks for nothing and answers where to open JupyterLab. It then asks for the passkey's name in a dialog whose button is the click that lets the browser create the passkey, creates it, asks for a confirming click, evaluates a fresh PRF salt with `get`, and adds the slot.

## Result shapes of `passkey:run`

`<nonce>.json` always carries `nonce` and `ok`.

| Outcome                                                                                                                                                | Body                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------- |
| `create` ok                                                                                                                                            | `{nonce, ok: true, cred_id, prf_enabled}`     |
| `get` ok                                                                                                                                               | `{nonce, ok: true, cred_id, prf?}`            |
| PRF requested, none returned                                                                                                                           | `{nonce, ok: false, error: "no-prf"}`         |
| user cancelled or credential unknown                                                                                                                   | `{nonce, ok: false, error: "not-allowed"}`    |
| `rp_id` not the tab's hostname or a parent of it, or the tab is at an IP address (in a secure context: a loopback address such as 127.0.0.1, or HTTPS) | `{nonce, ok: false, error: "rp-id-mismatch"}` |
| another browser error, by its name                                                                                                                     | `{nonce, ok: false, error: "error: <name>"}`  |
| any other ceremony failure                                                                                                                             | `{nonce, ok: false, error: "error"}`          |

`prf_enabled` reports the create-time flag only. Windows Hello returns `false` there yet still yields a PRF at `get`, so a follow-up `get` is the authoritative test - never gate on `prf_enabled`.

## Server endpoints

All endpoints sit under `<base_url>/jupyterlab-passkey-extension/` and require Jupyter authentication.

| Method                 | Path             | Purpose                                                                                                                 |
| ---------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `POST`                 | `result`         | ceremony result → `<nonce>.json`; `204` on success                                                                      |
| `POST`                 | `passphrase`     | `{nonce, passphrase}` → raw `<nonce>.pass`, or `{nonce, cancelled: true}` → a `<nonce>.cancel` marker; `204` on success |
| `POST`                 | `secret`         | `{nonce}` ← raw `<nonce>.secret`; `{"value": "..."}`, `404` once collected                                              |
| `POST`                 | `render`         | `{nonce}` ← raw `<nonce>.code`; `{"png": "<base64>"}`, `404` once rendered                                              |
| `GET`                  | `health`         | `{"ok": true}`                                                                                                          |
| `GET`, `POST`, `PATCH` | `vault/<action>` | the vault's own API - `status`, `entries`, `unlock`, `lock` and the rest; `423` while locked                            |

Every relay `POST` endpoint answers `400` on a bad nonce, and touches no file when it does - including `secret` and `render`, the two that turn a nonce into a path they read and then unlink.

`secret` and `render` are `POST`s despite only reading: the read is destructive, and a `GET` would carry the nonce in the query string straight into the server's access log. The nonce is not the secret, but it is the ticket to collect one.

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
