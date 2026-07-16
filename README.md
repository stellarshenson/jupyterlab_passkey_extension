# jupyterlab_passkey_extension

[![GitHub Actions](https://github.com/stellarshenson/jupyterlab_passkey_extension/actions/workflows/build.yml/badge.svg)](https://github.com/stellarshenson/jupyterlab_passkey_extension/actions/workflows/build.yml)
[![npm version](https://img.shields.io/npm/v/jupyterlab_passkey_extension.svg)](https://www.npmjs.com/package/jupyterlab_passkey_extension)
[![PyPI version](https://img.shields.io/pypi/v/jupyterlab-passkey-extension.svg)](https://pypi.org/project/jupyterlab-passkey-extension/)
[![Total PyPI downloads](https://static.pepy.tech/badge/jupyterlab-passkey-extension)](https://pepy.tech/project/jupyterlab-passkey-extension)
[![JupyterLab 4](https://img.shields.io/badge/JupyterLab-4-orange.svg)](https://jupyterlab.readthedocs.io/en/stable/)
[![Brought To You By KOLOMOLO](https://img.shields.io/badge/Brought%20To%20You%20By-KOLOMOLO-00ffff?style=flat)](https://kolomolo.com)
[![Donate PayPal](https://img.shields.io/badge/Donate-PayPal-blue?style=flat)](https://www.paypal.com/donate/?hosted_button_id=B4KPBJDLLXTSA)

A generic passkey bridge for JupyterLab. It exposes the passkey (WebAuthn) capability of the user's browser or operating system to local clients that have no browser of their own - the JupyterLab terminal and the CLI or API clients running on the Jupyter server. The extension runs the browser-side ceremony and hands the result back to the requesting local process.

It is purpose-agnostic and performs no cryptography of its own. Every caller supplies its own parameters, and the extension holds no secret. A vault that unlocks with a passkey, a CLI that needs a WebAuthn PRF value, or any tool that wants a signed assertion is just a consumer - the key handling stays in the consumer, never here.

## How it works

A browser page can only talk back to the Jupyter server over HTTP. A terminal or CLI process on the server cannot receive anything from the page directly. So the ceremony runs in the page, and its result returns through a small authenticated server endpoint that writes an atomic `0600` relay file the local client reads and shreds.

```mermaid
flowchart LR
    subgraph BROWSER["Browser - JupyterLab page"]
        direction TB
        TRIG["consumer triggers<br/>passkey:run"]
        CER["navigator.credentials<br/>get / create"]
        OS(["OS / authenticator<br/>Windows Hello, security key"])
        TRIG --> CER
        CER <--> OS
    end
    subgraph SERVER["Jupyter server"]
        direction TB
        EP["POST /result<br/>authenticated"]
        RELAY[("atomic 0600 relay<br/>/dev/shm/jlab-passkey-uid")]
        EP --> RELAY
    end
    LOCAL["local client<br/>terminal / CLI / API"]
    CER -->|"POST JSON result"| EP
    RELAY -->|"reads, then shreds"| LOCAL

    style BROWSER stroke:#6b7280,stroke-width:3px
    style SERVER stroke:#6b7280,stroke-width:3px
    style TRIG stroke:#f59e0b,stroke-width:2px
    style CER stroke:#10b981,stroke-width:2px
    style OS stroke:#0284c7,stroke-width:2px
    style EP stroke:#10b981,stroke-width:2px
    style RELAY stroke:#3b82f6,stroke-width:2px
    style LOCAL stroke:#10b981,stroke-width:2px
```

## The interface

### Frontend command `passkey:run`

One command runs a ceremony and POSTs the result. It reaches `navigator.credentials.*` before any `await`, so a trigger's user gesture (for example a notification button click) survives into the ceremony.

| Argument   | Op     | Description                                                                |
| ---------- | ------ | -------------------------------------------------------------------------- |
| `op`       | both   | `"get"` to assert an existing credential, `"create"` to register a new one |
| `nonce`    | both   | correlation key and relay filename; must match `[A-Za-z0-9_-]{16,128}`     |
| `rp_id`    | both   | WebAuthn Relying Party ID; normally the page hostname                      |
| `cred_id`  | get    | base64url credential id to assert                                          |
| `prf_salt` | get    | base64url 32-byte salt; evaluates the WebAuthn PRF (hmac-secret) extension |
| `user`     | create | `{ id, name, displayName }` for the new credential (`id` is base64url)     |

The challenge is a random 32-byte value the frontend generates itself - it is anti-replay plumbing that nothing here verifies, so callers never supply it.

### Result shapes

The frontend POSTs one of these JSON bodies to the server, keyed by `nonce`:

```jsonc
// create success
{ "nonce": "...", "ok": true, "cred_id": "<b64url>", "prf_enabled": false }

// get success (prf present only when prf_salt was supplied and evaluated)
{ "nonce": "...", "ok": true, "cred_id": "<b64url>", "prf": "<b64url>" }

// failure
{ "nonce": "...", "ok": false, "error": "no-prf" | "not-allowed" | "error" }
```

`create` never rejects on the create-time PRF flag - it always returns `cred_id` and a plain `prf_enabled`. Some authenticators (Windows Hello) report `prf_enabled: false` at registration yet yield a real PRF at assertion, so PRF availability is confirmed by a follow-up `get` with a `prf_salt`. `not-allowed` is WebAuthn's deliberate conflation of user-cancel, no-matching-credential, and wrong-RP into one privacy-preserving code.

### Frontend command `passkey:passphrase`

A second command captures a passphrase in the browser and relays it to the same directory, for the case where a local client needs a secret a passkey cannot supply - a keystore's recovery passphrase, for example. The dialog takes the passphrase twice and relays it only when both entries match; it never enters the terminal, shell history, or a process argument.

| Argument | Description                                                      |
| -------- | ---------------------------------------------------------------- |
| `nonce`  | correlation key and relay filename; same `[A-Za-z0-9_-]{16,128}` |
| `prompt` | optional dialog prompt; defaults to `Enter the passphrase twice` |

The value lands **raw** in `<relay_dir>/<nonce>.pass` - no JSON envelope and no trailing newline - so a consumer can point at the file directly:

```bash
PASS_RECOVERY_FILE="/dev/shm/jlab-passkey-$(id -u)/<nonce>.pass" pass-cli-open --ensure
```

Submit stays disabled until the two entries match, so a mismatch cannot be relayed; Cancel and Submit are the only ways out, and Escape cancels. Cancelling relays nothing - the file never appears.

### Server endpoints

All live under the server base URL and require Jupyter authentication.

- `POST <base_url>/jupyterlab-passkey-extension/result` - validates the nonce, writes the body to an atomic `0600` relay, returns `204`. The body, including any PRF value, is never logged
- `POST <base_url>/jupyterlab-passkey-extension/passphrase` - validates the nonce, writes the passphrase raw to an atomic `0600` `<nonce>.pass`, returns `204`. The passphrase is never logged
- `GET <base_url>/jupyterlab-passkey-extension/health` - returns `{ "ok": true }`

The relay directory defaults to the uid-scoped `/dev/shm/jlab-passkey-<uid>` and is overridable with the `JLAB_PASSKEY_RELAY_DIR` environment variable.

## Triggering a ceremony

WebAuthn requires a user gesture, and this extension builds no request-submission UI of its own - that is the consumer's job. The reference trigger is a [`jupyterlab-notify`](https://github.com/stellarshenson/jupyterlab_notifications_extension) notification whose action button is bound to `passkey:run`; clicking it supplies the gesture and reaches the command with the app already in hand.

```bash
jupyterlab-notify --now --no-auto-close -t info \
  -m "Approve passkey" \
  --action "Approve" \
  --cmd "passkey:run" \
  --command-args '{"op":"get","nonce":"<16-128 url-safe chars>","rp_id":"your.host","cred_id":"<b64url>","prf_salt":"<b64url>"}'
```

The local client then reads `<relay_dir>/<nonce>.json` to collect the result.

> [!NOTE]
> Do not start JupyterLab with `--expose-app-in-browser` just to trigger the command by hand. A notify button (or any extension that holds the app reference) reaches `passkey:run` directly with a genuine gesture and no global.

See [docs/commands-reference.md](docs/commands-reference.md) for the full command, relay and endpoint reference, [docs/cli-reference.md](docs/cli-reference.md) for the CLI, and [docs/example-secret-unlock.md](docs/example-secret-unlock.md) for a worked consumer walkthrough that seals and opens a secret with a passkey.

## Security

- Both endpoints are gated by `@tornado.web.authenticated` - a caller needs the Jupyter token or session
- The relay is created with `mkstemp` + `os.replace`, giving a fresh `0600` file with no world-readable window, then renamed onto `<nonce>.json` atomically - a reader never sees a partial write, and the file is never appended to. Single-read is the consumer's responsibility, not an enforced guarantee: the server does not delete relays, so a consumer must `shred -u` what it reads
- The relay directory is uid-scoped, so a co-tenant sharing `/dev/shm` cannot pre-create or squat the path
- The result body and any PRF value are never written to logs
- The extension performs no cryptography and stores no secret; every parameter and all key handling belong to the caller

## Requirements

- JupyterLab >= 4.0.0
- A consumer to trigger `passkey:run` and a local client to read the relay. [`jupyterlab_notifications_extension`](https://github.com/stellarshenson/jupyterlab_notifications_extension) provides the reference trigger and is installed automatically - the `jupyterlab-passkey` CLI posts to it

## Install

```bash
pip install jupyterlab_passkey_extension
```

## Command line

`jupyterlab-passkey` ships with the package and proxies the commands above, so a local process can drive a ceremony as a blocking call without knowing the relay contract. It posts the trigger over HTTP, waits for your click, and prints the result. It deletes the ceremony relay after reading it; the passphrase relay is left for its consumer, so shred that one yourself.

```bash
cred_id=$(jupyterlab-passkey create --rp-id your.jupyterlab.host)
prf=$(jupyterlab-passkey get --rp-id your.jupyterlab.host --cred-id "$cred_id" --prf-salt "$salt")

pass_file=$(jupyterlab-passkey passphrase) || exit 1
PASS_RECOVERY_FILE="$pass_file" pass-cli-open --ensure
shred -u "$pass_file"
```

The `|| exit 1` matters: a prefix assignment does not propagate a command substitution's exit status, so `PASS_RECOVERY_FILE=$(jupyterlab-passkey passphrase) pass-cli-open` would run the consumer with an empty passphrase file after a timeout or a cancel.

Full flags in [docs/cli-reference.md](docs/cli-reference.md).

## Development install

```bash
# from a clone of this repository
pip install -e "."
jupyter labextension develop . --overwrite
jlpm build
```

Rebuild after changes with `jlpm build`, or run `jlpm watch` in one terminal alongside JupyterLab. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development, testing, and release workflow.

## Uninstall

```bash
pip uninstall jupyterlab_passkey_extension
```

## License

BSD-3-Clause. See [LICENSE](LICENSE).
