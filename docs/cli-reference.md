# CLI reference

`jupyterlab-passkey` turns a browser ceremony into a blocking local call. It is a thin proxy to the [JupyterLab commands](commands-reference.md): it posts the notification that carries the command, waits for the relay the server writes, and prints the result. It deletes the ceremony relay after reading it; the passphrase relay is left for its consumer (on shm, to shred). A consumer never learns the relay contract.

- **Ships with the package** - `pip install jupyterlab_passkey_extension` puts it on `PATH`
- **Subcommands** - `create`, `get`, `passphrase`, `copy`, `show`, mirroring the commands (`create` and `get` both run `passkey:run`), and the [`vault`](#vault) group
- **Transport** - HTTP only; it finds the server and token via `jupyter server list --json`, taking the **first** server reported
- **Where to run it** - a terminal on the same Jupyter server, with a JupyterLab tab open
- **Blocking** - `create`, `get` and `passphrase` wait for you to click the button and approve the prompt; `copy` and `show` return at once (`copy` unless given `--block`); a [`vault`](#vault) subcommand waits only for its browser steps
- **Timeout** - `--timeout` seconds, default `120` (`600` for `vault init` and `vault passkey add`); exit `1` if no relay arrives. On `copy` it applies only with `--block`, and is rejected without it; `show`, `vault lock`, `vault status`, `vault generate`, `vault passkey list` and `vault passkey rm` never wait and take none
- **Failure** - a failed ceremony exits `1` with the error on stderr, nothing on stdout
- **Debug** - `--debug` on any subcommand reports the relay backend decision on stderr before running: which backend was chosen, where `keyctl` was found, and, when keyctl was rejected, the step that failed with the kernel's own message

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

| Flag          | Required | Meaning                                                                                                     |
| ------------- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `--rp-id`     | yes      | WebAuthn RP ID - your JupyterLab tab's hostname, bare: no scheme, port or path; a name, never an IP address |
| `--user-name` | no       | credential user name; defaults to the tool                                                                  |

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

Opens a dialog that takes a secret and stages it. Prints a **reference** to it, never the value - the secret reaches its consumer without passing through the terminal, shell history, a process argument, or this CLI itself. This is the command for getting a secret **out of your head and into something else**: a vault entry, a `.env`, a keystore's recovery slot.

| Flag       | Required | Meaning                                          |
| ---------- | -------- | ------------------------------------------------ |
| `--prompt` | no       | dialog prompt text; defaults per mode            |
| `--once`   | no       | ask once instead of twice, with no confirm field |

By default the value is entered twice and Submit stays disabled until they match, so a mismatch cannot be submitted. `--once` drops the confirm field for a secret you are pasting rather than typing - the source of truth is already on your clipboard, and asking twice only invites two pastes of the same mistake. Either way Cancel and Submit are the only ways out, and Escape cancels; cancelling stages no secret and tells the CLI so, which exits `1` at once rather than waiting out its timeout.

The reference is **scheme-prefixed** (see [Relay backend](#relay-backend)), so one consumer handles both backends:

- `keyctl:jlab-passkey:<nonce>.pass` - the value is a kernel key; read it with `keyctl pipe $(keyctl search @u user <desc>)`
- `file:<path>` - the value is a `0600` file; read the path, and shred it when done

The value never passes through this CLI on the way out - a keyctl-aware consumer resolves the reference and reads the secret itself.

A `keyctl:` reference is **time-bounded**: the kernel key self-destructs at its TTL (300s), so the consumer must resolve it promptly - a resolve more than five minutes after entry reads nothing where the same flow succeeds on shm. A `file:` reference persists until reboot (shred it when done).

```bash
# a passphrase you are setting - typed twice, confirmed. The consumer resolves the ref:
pass_ref=$(jupyterlab-passkey passphrase --prompt "Recovery passphrase") || exit 1
PASS_RECOVERY_REF="$pass_ref" pass-cli-open --ensure

# a token you are pasting - once is enough
tok_ref=$(jupyterlab-passkey passphrase --once --prompt "GitHub token") || exit 1
PASS_SECRET_REF="$tok_ref" pass-cli-save github/api -u stellarshenson -c infrastructure

# resolving a reference by hand, either backend:
case "$pass_ref" in
  keyctl:*) keyctl pipe "$(keyctl search @u user "${pass_ref#keyctl:}")" ;;
  file:*)   cat "${pass_ref#file:}" ;;
esac
```

Take the `|| exit 1` seriously here too - a cancel or a timeout otherwise feeds the consumer an empty reference. The consumer (`pass-cli`) must understand the reference scheme; that side is updated separately from this extension.

## `copy`

Reads a secret from `FILE` or stdin and raises a notification whose button copies it to your browser's clipboard. The mirror of `passphrase`: that one brings a secret **in** from you, this one sends one **out** to you, to paste wherever it is wanted.

| Argument / flag | Required | Meaning                                                                           |
| --------------- | -------- | --------------------------------------------------------------------------------- |
| `FILE`          | no       | file to read the secret from; omit or `-` for stdin                               |
| `--label`       | no       | name shown in the notification, to tell two staged secrets apart                  |
| `--block`       | no       | wait until the browser collects the secret; delete it and exit `1` if it does not |
| `--timeout`     | no       | with `--block`: seconds to wait, default `120`; rejected without `--block`        |

- **Fire and forget by default** - it posts the notification and returns; it does not wait for the click, so exit `0` means _posted_, not _copied_
- **One shot** - the click collects the secret and the relay is deleted in the same breath. Click twice and the second finds nothing
- **Never in the notification** - the secret is staged in a one-shot relay (a kernel key or a `0600` file, see [Relay backend](#relay-backend)) and the notification carries only a nonce, which is useless without your Jupyter token
- **Trailing newline** - exactly one is stripped, as `$(...)` would; a multi-line secret survives intact
- **No terminal input** - it refuses a stdin that is a terminal, which would echo the secret into your scrollback. Pipe it in, pass a `FILE`, or use `passphrase --once` to type one
- **Uncollected** - a secret nobody clicks self-destructs at its TTL on keyctl, or sits in tmpfs until reboot on shm. A secret whose notification never posted is unstaged on the way out, since nothing could ever collect it

### Waiting for the click

`--block` polls until the relay disappears, which is the collection signal - the server reads the file and unlinks it in the same breath. Use it to sequence work after the secret has actually landed, and to leave nothing behind when it has not: on a timeout the secret is deleted and the command exits `1`, so an abandoned notification cannot hand a live button to whoever clicks next.

It means **collected, not pasted**. The page fetches the value and only then calls `navigator.clipboard.writeText`, so a browser that refuses the clipboard does so after `--block` has already returned `0`. Nothing is reported back from the page, and this is as close to "the secret arrived" as the terminal can get - but a refused write is not a lost secret; see below.

```bash
# out of the vault, into the clipboard, ready to paste into a web form
pass-cli get github/api --field password --quiet --no-clipboard | jupyterlab-passkey copy

# block until it lands - and leave nothing staged if it never does
pass-cli get db/prod --field password --quiet --no-clipboard \
  | jupyterlab-passkey copy --label "DB password" --block || exit 1

# or straight from a file
jupyterlab-passkey copy ~/.config/some-service/token

# with two secrets in flight, name them - the notifications are otherwise identical
pass-cli get github/api --field password --quiet --no-clipboard | jupyterlab-passkey copy --label "GitHub token"
pass-cli get db/prod --field password --quiet --no-clipboard | jupyterlab-passkey copy --label "DB password"
```

Nothing is reported back to the terminal. In the browser, a click that copies cleanly closes the notification and says nothing - but a clipboard write the browser refuses (the window was not focused, or the click's user activation had expired) is retried quietly for 15 seconds, and if it still cannot land, a second notification appears: "The clipboard needs another click". Its button finishes the copy under a fresh click, with the value held in the page's memory - never re-staged anywhere - until then. A secret is lost when the tab closes or reloads before that click, or when the page's fetch of it fails.

Once it is on the clipboard it is an OS-wide value - any application, and any page you grant clipboard read to, can read it until you overwrite it. That is inherent to wanting to paste it somewhere.

## `show`

Reads a code from `FILE` or stdin and raises a notification whose button shows it in a dialog **as a distorted image**. For a value the user must read off the screen and type somewhere else - a one-time authenticator code, a pairing code - rather than paste. The mirror of `copy` for the eyes rather than the clipboard.

| Argument / flag | Required | Meaning                                            |
| --------------- | -------- | -------------------------------------------------- |
| `FILE`          | no       | file to read the code from; omit or `-` for stdin  |
| `--label`       | no       | name shown in the notification and above the image |

- **Never as text** - the code is staged in a one-shot relay and the notification carries only a nonce; the click fetches a PNG the server renders from the relay and consumes in the same breath. The code is absent from the notification broadcast, the page DOM, and the accessibility tree
- **Scraper-resistant** - a screen scraper sees only an image, and CAPTCHA-style distortion (per-character jitter and rotation, colour variation, overlaid noise) means an OCR pass on a screenshot still has to work for it
- **Fire and forget** - it posts and returns; nothing is reported back, the click is what shows it. The relay is one-shot, so a dismissed dialog cannot be reopened
- **Trailing newline** - exactly one is stripped. **No terminal input** - a stdin that is a terminal is refused

```bash
# show a TOTP enrolment code the user must type into their authenticator app
printf '%s' "$totp_secret" | jupyterlab-passkey show --label "Authenticator code"

# from a file
jupyterlab-passkey show ~/pairing-code.txt
```

The dialog's image has empty `alt` text on purpose: the code must not re-enter the accessibility tree the image exists to keep it out of. That closes the channel to a screen reader as well - inherent to the goal, not an oversight.

## `vault`

The password vault the Jupyter server keeps - see the [README](../README.md#vault) for the file, the encryption and where the unlocked key is held. Every vault subcommand calls the server's authenticated API. The two passkey steps - a passkey unlock and a passkey registration - raise a notification whose click runs the step in the tab, and the page sends the PRF straight to the server; only `ok` or the error comes back to the CLI.

| Subcommand                                                                                               | Does                                                                                                    |
| -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `init [--in-browser] [--label L] [--no-passkey]`                                                         | creates the vault: the recovery passphrase (entered twice), then a passkey                              |
| `unlock [--recovery] [--in-browser]`                                                                     | unlocks with a passkey for the tab's hostname, or with the recovery passphrase                          |
| `lock`                                                                                                   | clears the key from its holder now                                                                      |
| `status`                                                                                                 | state, time left, key holder, protection level and each capability explained, passkeys, unlock duration |
| `list [--category C] [--json]`                                                                           | names and metadata, never passwords                                                                     |
| `get NAME [--field F]`                                                                                   | prints one value to stdout                                                                              |
| `add NAME [-u U] [--url URL] [-c C] [--notes N] [--generate [--length N]] [--in-browser]`                | adds an entry                                                                                           |
| `edit NAME [-u U] [--url URL] [-c C] [--notes N] [--password \| --generate [--length N]] [--in-browser]` | changes only the fields given                                                                           |
| `rm NAME`                                                                                                | removes an entry                                                                                        |
| `generate [--length N] [--no-symbols]`                                                                   | prints a random password, 24 characters by default                                                      |
| `copy NAME [--field F]`                                                                                  | puts a value on the browser clipboard                                                                   |
| `show NAME [--field F]`                                                                                  | shows a value in the browser as a distorted image                                                       |
| `exec --env VAR=NAME[:FIELD] -- CMD`                                                                     | becomes CMD (exec) with vault values in its environment - its signals and exit status are CMD's own     |
| `import [FILE]`                                                                                          | adds entries from a JSON list; skips names that exist                                                   |
| `passkey add [--label L]`, `passkey list`, `passkey rm --cred-id ID`                                     | registers, lists or removes passkeys                                                                    |
| `recovery [--in-browser]`                                                                                | replaces the recovery passphrase: the current one, then the new one twice; a terminal or `--in-browser` |

- **Secrets never on argv** - a new password or passphrase is typed at a hidden prompt (twice for a new one), piped on stdin, typed in a JupyterLab dialog with `--in-browser`, or generated. No option takes one as its value
- **Unlock on demand** - on a locked vault, `get`, `copy`, `show`, `exec`, `list`, `import` and the entry changes run the passkey unlock first, then carry on. A vault with no passkey stops there instead and names `vault unlock --recovery`. `passkey rm` needs an unlocked vault and says so. `passkey add` and `recovery` need a proof instead - an unlocked vault is not enough. `passkey add` gets it in the browser after the notification click - a passkey for the tab's hostname, or the recovery passphrase when it has none, that request gets no answer or the passkey gives no PRF (on a tab at an IP address it asks for nothing and says where to open JupyterLab) - so no secret passes through a relay; `init` with a passkey therefore asks for the passphrase there once more. `recovery` asks for the current recovery passphrase
- **Waits** - a vault command waits 120 s for its click in the tab; `init` and `passkey add` wait 600 s, because a registration takes a proof - a passkey, or a recovery passphrase kept offline - two more passkey prompts and a name. `--timeout SECONDS` sets either; the vault commands that never wait (`lock`, `status`, `generate`, `passkey list`, `passkey rm`) take none
- **Fields** - `password` (the default), `username`, `url`, `category`, `notes` and `name`
- **Generated passwords** - leave out characters that look alike on the Show image or a phone keyboard (`l I 1 | O 0`), and quotes, backslash, backtick and space
- **Server environment** - `JLAB_PASSKEY_VAULT` (the file) and `JLAB_PASSKEY_VAULT_HOLDER` (the key holder) are read by the Jupyter server, not by the CLI; set them where the server starts
- **Copy and show** - the server stages the value in the one-shot relay the `copy` and `show` flows already use, so the value never enters the CLI process. Nothing is reported back: the click is what copies or shows it. An unclicked one stays in the relay - until its TTL on keyctl, until reboot on shm - and a `vault lock` does not remove it
- **Import** - a JSON list of objects with `name` (or pass-cli's `service`), `username`, `password`, `url`, `category` and `notes`; a `notes` object is stored as JSON text
- **Errors** - one line on stderr and exit `1` for a locked vault, a missing entry, a missing vault or an unreachable server
- **Debug** - `--debug` adds the server's key-holder decision: the holder chosen, its capabilities, and why each earlier holder was skipped

```bash
jupyterlab-passkey vault init
jupyterlab-passkey vault add github/api -u me --url https://github.com -c infrastructure
printf '%s' "$token" | jupyterlab-passkey vault add gitlab/api          # piped, never typed on the command line
jupyterlab-passkey vault add db/prod --generate --length 32
jupyterlab-passkey vault get github/api --field username
jupyterlab-passkey vault copy github/api
jupyterlab-passkey vault exec --env GITHUB_TOKEN=github/api --env GH_USER=github/api:username -- gh repo list
jupyterlab-passkey vault import export.json
jupyterlab-passkey vault passkey add --label "Work laptop"
jupyterlab-passkey vault status --debug
```

## Detached use

A subcommand that raises a browser notification and waits for its click does work that outlives the shell that launched it. The CLI ignores `SIGHUP`, so a command backgrounded with `&` keeps waiting even after its terminal closes; notifications, popups and queries all land the same whether the process is attached, backgrounded, or launched under `nohup`/`setsid`. A detached `copy` or `show` that reads stdin still needs its input piped or a `FILE`, since a detached process has no terminal to type into. The command that `vault exec` runs gets the `SIGHUP` handling the CLI was started with, so under `nohup` or `setsid` it outlives the terminal. A hangup that arrived while `vault exec` still waited for the unlock click does not stop it: the command runs after the click, with no terminal for its output.

## Relay backend

Every secret this bridge moves lives briefly in a relay between the browser and a local client. There are two backends, chosen once per process:

- **keyctl** (preferred) - a uid-scoped kernel `user` key the kernel destroys at a TTL. The value never swaps to disk and nothing survives a crash
- **shm** (fallback) - the `0600` file under `/dev/shm/jlab-passkey-$(id -u)`, guarded against a co-tenant squatting the path

The choice is automatic: if a `keyctl` add/search/read round-trip works, keyctl is used; otherwise the CLI falls back to shm and prints one line to **stderr** naming why keyctl was refused (`--debug` shows the full decision). Force it with `JLAB_PASSKEY_RELAY_BACKEND=keyctl|shm|auto` (default `auto`); `keyctl` fails loud if the keyring is not functional.

keyctl is a durability improvement, not an access-control one: `--alswrv` grants your uid, so any process of yours can read the key - the same exposure as the `0600` file. What it buys is no swap, self-destruct at a TTL, and no disk artifact. The server and CLI must share a uid (both do on a normal single-user server); a server running as another user must use `shm`.

## Keystore use

The two secret sources a passkey-backed keystore needs, each one command:

- **Passkey slot** - `get --prf-salt` yields the PRF; the keystore derives its key from it
- **Recovery slot** - `passphrase` yields a reference (`keyctl:` or `file:`) the keystore reads its passphrase from
- **Division of labour** - this CLI only moves secrets between the browser and a local client; wrapping, slots and key derivation belong to the keystore

```bash
salt=$(head -c32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')
prf=$(jupyterlab-passkey get --rp-id lab.example.com --cred-id "$cred_id" --prf-salt "$salt")
```

See [example-secret-unlock.md](example-secret-unlock.md) for a worked end-to-end example.
