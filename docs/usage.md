# Vault, server API and security

## Vault

The Jupyter server holds one encrypted file that the panel, the CLI and Python use through its authenticated API, unlocked with a passkey, an unlock password plus authenticator code, or the recovery passphrase; the design is in [docs/design-vault.md](design-vault.md).

- **Encryption** - every entry, names included, is one AES-256-GCM ciphertext under a random 32-byte data key; the data key is sealed under a random 32-byte root key, and every keyslot wraps that root key with `HKDF(PRF)` or `Argon2id` (m=65536 KiB, t=3, p=1), so any slot opens the root and the root opens the data key; `Scrypt` (n=2^17, r=8, p=1) opens only older recovery and password slots, which upgrade on their next unlock; any recovery or password slot this build writes, at init, at a recovery change or at an unlock upgrade, is Argon2id and an older build cannot open it, while passkey slots remain readable
- **Rotation** - a passkey or the current recovery passphrase re-seals the entries and the authenticator secret under a new random data key and discards the previous one; an unlock rotates the data key automatically once `rotate_days` has passed, and a code alone cannot rotate
- **Unlock** - any slot unwraps the root key, which opens the data key, and the recovery passphrase is mandatory
- **Authenticator code** - the code is a server check that takes no part in encryption, so the file and the unlock password alone decrypt
- **File** - `$XDG_DATA_HOME/jupyterlab-passkey/vault.json` (`~/.local/share/...`), mode `0600`, path set by `JLAB_PASSKEY_VAULT`
- **Hostnames** - a passkey opens the vault only from its hostname or a subdomain; on another host unlock with the unlock password and an authenticator code, or the recovery passphrase

### Configuration

The four vault policy keys are organisation-controlled: the server administrator sets them in a JSON file, and the Settings Editor does not carry them. The file is `$XDG_STATE_HOME/jupyterlab-passkey/vault-config.json`, which is `~/.local/state/jupyterlab-passkey/vault-config.json` by default. The server reads the file on each call, so a change applies to the next call with no server restart. A key that is absent, not a whole number, or outside its range uses its default.

```json
{
  "unlock_minutes": 30,
  "password_min_length": 12,
  "reveal_seconds": 60,
  "rotate_days": 365
}
```

| Setting               | Default | Range     | Effect                                                                                                      |
| --------------------- | ------- | --------- | ----------------------------------------------------------------------------------------------------------- |
| `unlock_minutes`      | 30      | 1 to 1440 | minutes the server holds the key after an unlock; 30 is the NIST SP 800-63B AAL2 idle limit                 |
| `password_min_length` | 12      | 8 to 128  | fewest characters of an unlock password                                                                     |
| `reveal_seconds`      | 60      | 0 to 3600 | seconds a tab skips the proof after a proof; 0 asks at every reveal and an unlock does not start the window |
| `rotate_days`         | 365     | 0 to 3650 | days a data key serves before an unlock rotates it; 0 turns automatic rotation off                          |

Only the `sidebar` setting remains in the Settings Editor.

### Panel

The Vault panel is in the right sidebar. The `sidebar` setting places it on the left.

- **Unlock and list** - creates and unlocks the vault, lists entries by category with how long ago each key was last used, shows nothing while locked, and opens a row read-only with Edit, Delete and Close
- **Row tooltip** - hovering an entry shows its name, then Username, URL, Category, Last used, Updated and Created as ages, and never the password
- **Category** - the Add and Edit dialogs list the vault's existing categories beside the Category field; a choice fills the field, which still accepts a typed category
- **Password and proof** - the value shows dots until you click the eye button, which asks a passkey PRF or, without one, a code, password or recovery passphrase
- **`reveal_seconds`** - after a proof the panel skips the proof for the `reveal_seconds` setting (default 60), or until the tab locks the vault or the page reloads
- **Security view** - the cog shows the key holder, the unlock methods with Remove or Change, and the data key's age with Rotate data key; it adds a passkey or a password plus authenticator app (`password_min_length`, default 12)
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
- **Reference** - [cli-reference.md](cli-reference.md#vault) lists every subcommand

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

- **Commands** - `passkey:run`, `passkey:passphrase`, `passkey:copy`, `passkey:show`, `passkey:vault-unlock` and `passkey:vault-register` ([reference](commands-reference.md))
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
