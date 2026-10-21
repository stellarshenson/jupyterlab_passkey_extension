# jupyterlab_passkey_extension

[![GitHub Actions](https://github.com/stellarshenson/jupyterlab_passkey_extension/actions/workflows/build.yml/badge.svg)](https://github.com/stellarshenson/jupyterlab_passkey_extension/actions/workflows/build.yml)
[![npm version](https://img.shields.io/npm/v/jupyterlab_passkey_extension.svg)](https://www.npmjs.com/package/jupyterlab_passkey_extension)
[![PyPI version](https://img.shields.io/pypi/v/jupyterlab-passkey-extension.svg)](https://pypi.org/project/jupyterlab-passkey-extension/)
[![Total PyPI downloads](https://static.pepy.tech/badge/jupyterlab-passkey-extension)](https://pepy.tech/project/jupyterlab-passkey-extension)
[![JupyterLab 4](https://img.shields.io/badge/JupyterLab-4-orange.svg)](https://jupyterlab.readthedocs.io/en/stable/)
[![Brought To You By KOLOMOLO](https://img.shields.io/badge/Brought%20To%20You%20By-KOLOMOLO-00ffff?style=flat)](https://kolomolo.com)
[![Donate PayPal](https://img.shields.io/badge/Donate-PayPal-blue?style=flat)](https://www.paypal.com/donate/?hosted_button_id=B4KPBJDLLXTSA)

A passkey bridge for JupyterLab that exposes the passkey (WebAuthn) capability of the user's browser or operating system to local clients with no browser of their own and returns the browser-side ceremony result to the requesting local process.

- **Purpose** - the bridge commands perform no cryptography, each caller supplies its parameters, and a tool that needs a WebAuthn PRF value keeps all key handling to itself
- **Scope** - the CLI (`jupyterlab-passkey`, installed with the package) sends every request over an authenticated HTTP API, and the [password vault](#vault) is the one part that encrypts and stores secrets

## Standards

| Standard                            | Status     | What the vault does                                                                                   |
| ----------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------- |
| NIST SP 800-38D, RFC 5116           | ✅ Met     | AES-256-GCM for all entries under one random 32-byte data key                                         |
| RFC 7914 scrypt                     | ✅ Met     | the recovery and unlock-password slots, N=2^17, r=8, p=1, from the OWASP Password Storage Cheat Sheet |
| RFC 5869 HKDF-SHA256                | ✅ Met     | the passkey slots, keyed from the WebAuthn PRF                                                        |
| RFC 6238 TOTP                       | ✅ Met     | 6-digit codes of the authenticator app, a used code refused                                           |
| W3C WebAuthn Level 3, PRF extension | ✅ Met     | each passkey slot is bound to one hostname                                                            |
| NIST SP 800-63B, AAL2 idle limit    | ✅ Met     | 30-minute default unlock duration                                                                     |
| NIST SP 800-57 key management       | ⚠️ Not met | the data key is not rotated                                                                           |

## Features

- **Passkeys** - `create` registers and `get` asserts Windows Hello, Touch ID or a security key from a process with no browser
- **Approval** - the user approves the ceremony in the open tab, and the call blocks until the result returns
- **PRF** - `get --prf-salt` returns the same 32 bytes for the same credential and salt, so a vault can derive its key and store none
- **`passphrase`** - prompts in the browser and prints only a reference to the staged value (`keyctl:...` or `file:...`)
- **No terminal copy** - the value never appears in the terminal, the shell history, a process argument or the CLI
- **`copy`** - places a value on the clipboard through a one-shot relay
- **`show`** - renders a code as a distorted image absent from the DOM text and the accessibility tree

### Working with an AI agent

`passphrase` and `copy` let an AI agent handle a secret without printing it.

- **Secret entry** - `passphrase --once --prompt "..."` gives an agent a reference, never a secret
- **Pipe** - `pass-cli` can send bytes into `copy` without printing them
- **Help and skill** - `--help` says what each subcommand prints and whether it waits, and [`SKILL.md`](.agents/skills/jupyterlab-passkey-extension/SKILL.md) adds the rules it cannot state
- **Why link** - the wheel installs the skill at `<sys.prefix>/share/jupyter/agents/skills/jupyterlab-passkey-extension/SKILL.md`, and no agent reads that directory, so one of the two links below makes it readable

```bash
mkdir -p ~/.agents/skills && ln -sfn "$(python -c 'import sys; print(sys.prefix)')/share/jupyter/agents/skills/jupyterlab-passkey-extension" ~/.agents/skills/jupyterlab-passkey-extension
ln -sfn "$PWD/.agents/skills/jupyterlab-passkey-extension" ~/.claude/skills/jupyterlab-passkey-extension
```

> [!IMPORTANT]
> This is not a sandbox and not a defence against a hostile caller: any process running as your uid can also read the relay named in the reference, a kernel key or a `0600` file. It prevents a secret from being captured incidentally - not echoed to a terminal, printed into a transcript, left in `~/.bash_history` or a process argument, or broadcast in a notification payload.

## How it works

A browser page can send data only over HTTP, so the ceremony result returns through an authenticated endpoint that writes a relay - a `keyctl` key or an atomic `0600` file - the local client reads.

- **Ceremony** - the browser sends the ceremony result to the local client
- **`copy`** - the local client sends a secret to the browser, and the notification contains only a nonce (see [Security](#security))

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
        RELAY[("relay<br/>keyctl key or 0600 file")]
        EP --> RELAY
    end
    LOCAL["local client<br/>terminal / CLI / API"]
    CER -->|"POST JSON result"| EP
    RELAY -->|"reads, then deletes"| LOCAL

    style BROWSER stroke:#6b7280,stroke-width:3px
    style SERVER stroke:#6b7280,stroke-width:3px
    style TRIG stroke:#f59e0b,stroke-width:2px
    style CER stroke:#10b981,stroke-width:2px
    style OS stroke:#0284c7,stroke-width:2px
    style EP stroke:#10b981,stroke-width:2px
    style RELAY stroke:#3b82f6,stroke-width:2px
    style LOCAL stroke:#10b981,stroke-width:2px
```

```mermaid
flowchart LR
    LOCAL2["local client<br/>CLI / agent"]
    subgraph SERVER2["Jupyter server"]
        direction TB
        ING["notifications ingest<br/>separate extension"]
        RELAY2[("relay<br/>keyctl key or 0600 file")]
        EP2["POST /secret<br/>authenticated"]
        RELAY2 -->|"reads, then unlinks"| EP2
    end
    subgraph BROWSER2["Browser - JupyterLab page"]
        direction TB
        BTN["notification button<br/>passkey:copy"]
        CLIP(["user's clipboard"])
        BTN --> CLIP
    end
    LOCAL2 -->|"stages the secret"| RELAY2
    LOCAL2 -->|"posts the nonce only"| ING
    ING -.->|"sends to the page"| BTN
    BTN -->|"collects, once"| EP2
    EP2 -->|"the value"| BTN

    style BROWSER2 stroke:#6b7280,stroke-width:3px
    style SERVER2 stroke:#6b7280,stroke-width:3px
    style LOCAL2 stroke:#10b981,stroke-width:2px
    style ING stroke:#f59e0b,stroke-width:2px
    style RELAY2 stroke:#3b82f6,stroke-width:2px
    style EP2 stroke:#10b981,stroke-width:2px
    style BTN stroke:#f59e0b,stroke-width:2px
    style CLIP stroke:#0284c7,stroke-width:2px
```

## Install

```bash
pip install jupyterlab_passkey_extension
```

## Command line

`jupyterlab-passkey` is installed with the package and posts the notification with the request, waits for your click, and prints the result.

- **Caller** - every notification starts with `Asked by <name>:`, set with `--caller NAME` on any subcommand or `JLAB_PASSKEY_CALLER` from Python
- **Caller default** - without a name the caller is the project directory, which tells the person who clicks which project asks and proves nothing
- **Server** - the CLI posts only to the Jupyter server its environment names, and stops when it cannot identify which running server is the lab (flags: [cli-reference.md](docs/cli-reference.md))
- **Exit status** - `0` succeeded, `1` refused, timed out or could not reach the server, `2` an argument the parser rejects
- **Stdout** - only the result goes to stdout, so `$(...)` captures only the result
- **`copy`** - returns once posted, `--block` waits for collection only, and a terminal stdin is refused
- **`show`** - reports nothing back

| Command      | Does                                      | Prints                                                        |
| ------------ | ----------------------------------------- | ------------------------------------------------------------- |
| `create`     | registers a new passkey                   | its `cred_id`                                                 |
| `get`        | asserts a passkey                         | the PRF (with `--prf-salt`) or the `cred_id`                  |
| `passphrase` | prompts you for a secret in the browser   | a **reference** (`keyctl:...` or `file:...`), never the value |
| `copy`       | puts a secret on your clipboard           | nothing - it posts a button and returns                       |
| `show`       | shows a code as a scraper-resistant image | nothing - it posts a button and returns                       |

```bash
cred_id=$(jupyterlab-passkey create --rp-id lab.example.com)
salt=$(head -c32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')
prf=$(jupyterlab-passkey get --rp-id lab.example.com --cred-id "$cred_id" --prf-salt "$salt")

pass-cli get github/api --field password --quiet --no-clipboard \
  | jupyterlab-passkey copy --label "GitHub token"
```

## Vault

The Jupyter server holds one encrypted file that the panel, the CLI and Python use through its authenticated API, unlocked with a passkey, an unlock password plus authenticator code, or the recovery passphrase; the design is in [docs/design-vault.md](docs/design-vault.md).

- **Encryption** - every entry, names included, is one AES-256-GCM ciphertext under a random 32-byte data key, which is wrapped once per keyslot with `HKDF(PRF)` or `Scrypt` (n=2^17, r=8, p=1)
- **Unlock** - any slot decrypts the data key, and the recovery passphrase is mandatory
- **Authenticator code** - the code is a server check that takes no part in encryption, so the file and the unlock password alone decrypt
- **File** - `$XDG_DATA_HOME/jupyterlab-passkey/vault.json` (`~/.local/share/...`), mode `0600`, path set by `JLAB_PASSKEY_VAULT`
- **Hostnames** - a passkey opens the vault only from its hostname or a subdomain
- **Other hosts** - unlock with the unlock password and an authenticator code, or the recovery passphrase
- **Settings** - `unlockMinutes` (default 30, range 1 to 1440, the NIST SP 800-63B AAL2 idle limit) and `revealSeconds` (default 60, range 0 to 3600, the no-proof window after a proof, with 0 asking every time)

### Panel

The Vault panel is in the right sidebar. The `sidebar` setting places it on the left.

- **Unlock and list** - creates and unlocks the vault, lists entries by category, shows nothing while locked, and opens a row read-only with Edit, Delete and Close
- **Password and proof** - the value shows dots until you click the eye button, which asks a passkey PRF or, without one, a code, password or recovery passphrase
- **`revealSeconds`** - after a proof the panel skips the proof for `revealSeconds` seconds (default 60), or until the tab locks the vault or the page reloads
- **Security view** - the cog shows the key holder and unlock methods, with Remove or Change, and adds a passkey or a password plus authenticator app (`passwordMinLength`, default 12)
- **Sensitive changes** - changing the recovery passphrase or adding a method needs a proof in the same step, so an unlocked vault is not enough

### Command line and Python

```bash
jupyterlab-passkey vault init                      # recovery passphrase, then a passkey
jupyterlab-passkey vault add github/api -u me      # password prompted, piped, or --generate
jupyterlab-passkey vault get github/api            # the password on stdout; unlocks if needed
jupyterlab-passkey vault exec --env GITHUB_TOKEN=github/api -- gh repo list
jupyterlab-passkey vault status                    # state, time left, key holder, each protection explained
```

```python
from jupyterlab_passkey_extension.vault import Vault
token = Vault().get("github/api")  # unlocks with the passkey (a notification) if locked
```

- **No secret options** - no option holds a secret
- **Import** - `import FILE` or `import --pass-cli` adds entries
- **Reference** - [cli-reference.md](docs/cli-reference.md#vault) lists every subcommand

### Where the unlocked key is kept

While the vault is unlocked the server holds its data key in a key holder - the first of these that works on the host:

| Holder      | Where                                                                                            | Needs                                                                                                                                                    |
| ----------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `keyctl`    | the kernel keyring, with a kernel-enforced expiry                                                | the `keyctl` command (keyutils), and a seccomp profile that allows `add_key`, `keyctl` and `request_key` - Docker's default profile blocks them; no root |
| `gpg-agent` | a gpg-agent of the vault's own, with its own GnuPG home; expiry from its `max-cache-ttl`         | GnuPG (`apt install gnupg`)                                                                                                                              |
| `memory`    | the Jupyter server process: `memfd_secret`, else `mlock` with `MADV_DONTDUMP`, else plain memory | nothing - this is the extension's own code                                                                                                               |

- **Reports** - each holder reports five properties: never in swap, never in crash dumps, expiry, lock on restart and container isolation
- **Server copy** - the server also keeps the key in ordinary memory per request, which Python cannot wipe, so the key can be written to swap until reused even after a lock
- **Debug** - `vault status` and `--debug` show all five properties, and the panel shows three: never in swap, never in crash dumps and lock on restart
- **Pin** - `JLAB_PASSKEY_VAULT_HOLDER=keyctl|gpg-agent|memory` selects one holder, and a pinned holder that does not work is an error
- **Fallback** - the server logs the fallback reason only when it chooses the holder automatically
- **Before changing** - run `vault lock` before changing the holder, `JLAB_PASSKEY_VAULT` or the vault file, because a key held before a restart can outlive the change until its unlock duration ends

> [!WARNING]
> The kernel keyring is per uid and user namespace, not per container. On a host where several containers run as the same uid, allow keyctl only where every user has a distinct uid, or pin `JLAB_PASSKEY_VAULT_HOLDER=gpg-agent`; gpg-agent is isolated only while its socket is not on a home directory the other containers mount, and without `/run/user/<uid>` the socket is in its GnuPG home under `$XDG_STATE_HOME`, and `vault status` then reports it as not isolated.

## Server API

All endpoints are under the server base URL and require Jupyter authentication (`@tornado.web.authenticated` - a caller needs the Jupyter token or session).

- **Relay endpoints** - `POST <base_url>/jupyterlab-passkey-extension/{result,passphrase,secret,render}` write or read one relay, and answer `204` or a JSON body
- **Vault endpoint** - `GET`, `POST` and `PATCH <base_url>/jupyterlab-passkey-extension/vault/<action>` answer `423` while locked
- **Bad nonce** - answers `400` and creates no file, and the nonce matches `[A-Za-z0-9_-]{16,128}`
- **POST for reads** - `secret` and `render` are `POST`s to keep the nonce out of the access log

### The relay contract

- **Directory** - `/dev/shm/jlab-passkey-$(id -u)`, mode `0700`, ownership checked, override `JLAB_PASSKEY_RELAY_DIR`
- **Files** - `<nonce>.json`, `.pass`, `.secret`, `.code`, `.cancel`
- **Lifecycle** - mode `0600`, written with `mkstemp`-then-`os.replace`
- **Deletion** - the consumer deletes `.json` and `.pass`, while `.secret` and `.code` are one-shot enforced by the server

```jsonc
{ "nonce": "...", "ok": true, "cred_id": "<b64url>", "prf_enabled": false } // create success
{ "nonce": "...", "ok": true, "cred_id": "<b64url>", "prf": "<b64url>" } // get success, prf only when prf_salt was supplied and evaluated
{ "nonce": "...", "ok": false, "error": "no-prf" | "not-allowed" | "rp-id-mismatch" | "error: <name>" | "error" } // failure
```

- **`create`** - returns `cred_id` and `prf_enabled`
- **Errors** - `not-allowed` hides three causes, and `rp-id-mismatch` is a separate `SecurityError`

## For extension authors: the frontend commands

Six JupyterLab commands POST to the API above. Use them only when an extension triggers a ceremony itself, since everything else is better served by the CLI.

- **Commands** - `passkey:run`, `passkey:passphrase`, `passkey:copy`, `passkey:show`, `passkey:vault-unlock` and `passkey:vault-register` ([reference](docs/commands-reference.md))
- **Gesture** - `passkey:run` reaches `navigator.credentials.*` before any `await` so the click's gesture survives
- **Challenge** - the frontend generates the 32-byte challenge, and a notify button supplies the gesture

```bash
jupyterlab-notify --now --no-auto-close -t info -m "Approve passkey" --action "Approve" --cmd "passkey:run" \
  --command-args '{"op":"get","nonce":"<16-128 url-safe chars>","rp_id":"lab.example.com","cred_id":"<b64url>","prf_salt":"<b64url>"}'
```

> [!NOTE]
> Do not start JupyterLab with `--expose-app-in-browser` just to trigger the command by hand. A notify button (or any extension that holds the app reference) reaches `passkey:run` directly with a genuine gesture and no global.

## Security

Every endpoint requires Jupyter authentication, and the bridge stores no secret. The vault is the one part that encrypts and stores secrets.

- **Auth and backends** - every endpoint needs a Jupyter token or session, and a secret stages in a keyctl key or a `/dev/shm` `0600` file set by `JLAB_PASSKEY_RELAY_BACKEND=keyctl|shm|auto`
- **Same-uid exposure** - neither backend isolates a secret from your processes, and keyctl gives no access control
- **Notification and shm** - a notification contains a nonce, never a secret, and the shm directory must be a real uid-owned directory
- **Logs and cryptography** - bodies, passphrases and PRFs are never logged, and keyctl payloads are sent on stdin
- **Clipboard and screen** - a clipboard value is OS-wide until overwritten, and `show` returns only image bytes with empty `alt`, which limits OCR but not a person seeing the screen
- **SIGHUP** - commands ignore SIGHUP, so a detached run waits like an attached one
- **Detached vault** - `vault exec` under `nohup` or `setsid` outlives the terminal, and a hangup during its unlock wait does not stop it

## Requirements

- **Server and gesture** - JupyterLab >= 4.0.0 over HTTPS or localhost (a secure context), and an open tab supplies the gesture
- **Hostname** - a passkey belongs to a hostname, never an IP
- **Dependencies** - the [notifications extension](https://github.com/stellarshenson/jupyterlab_notifications_extension) is installed with the package
- **Passkeys** - `create` and `get` need a passkey, while `passphrase`, `copy` and `show` need none
- **GnuPG** - the vault needs it (`apt install gnupg`) so gpg-agent can hold the unlocked key where the kernel keyring is not allowed
- **Without GnuPG** - the vault still works with the key in server memory and reports this

## Development install

```bash
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

BSD-3-Clause; see [LICENSE](LICENSE).
