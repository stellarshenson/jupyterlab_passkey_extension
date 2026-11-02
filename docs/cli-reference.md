# CLI reference

`jupyterlab-passkey` turns a browser ceremony into a blocking local call. It is a thin proxy to the [JupyterLab commands](commands-reference.md): it posts the notification that carries the command, waits for the relay the server writes, and prints the result. It deletes the ceremony relay after reading it; the passphrase relay is left for its consumer (on shm, to shred). A consumer never learns the relay contract.

- **Ships with the package** - `pip install jupyterlab_passkey_extension` puts it on `PATH`
- **Subcommands** - `create`, `get`, `passphrase`, `copy`, `show`, mirroring the commands (`create` and `get` both run `passkey:run`), and the [`vault`](#vault) group
- **Transport** - HTTP only; it finds the server and token via `jupyter server list --json`, and posts only to the server the environment names, see [How the server is found](#how-the-server-is-found)
- **Where to run it** - a terminal on the same Jupyter server, with a JupyterLab tab open
- **Blocking** - `create`, `get` and `passphrase` wait for you to click the button and approve the prompt; `copy` and `show` return at once (`copy` unless given `--block`); a [`vault`](#vault) subcommand waits only for its browser steps
- **Timeout** - `--timeout` seconds, default `120` (`600` for `vault init` and `vault passkey add`); exit `1` if no relay arrives. On `copy` it applies only with `--block`, and is rejected without it; `show`, `vault lock`, `vault status`, `vault generate`, `vault passkey list`, `vault passkey rm`, `vault git install` and `vault git uninstall` never wait and take none
- **Failure** - a failed ceremony exits `1` with the error on stderr, nothing on stdout
- **Who asks** - every notification starts with `Asked by <name>:`, so the person who clicks knows which project raised it. State the name with `--caller NAME`, which every subcommand takes after its own name: `jupyterlab-passkey vault copy github/api --caller invoice-processing`. On `vault exec` it goes before `--`: everything after `--` is the command's own arguments. A caller with no command line, such as the Python `Vault` class, sets the environment variable `JLAB_PASSKEY_CALLER`; `--caller` outranks it, and the command that `vault exec` runs inherits the name. With neither, the name is the project the command runs in: the name of the nearest directory, from the working directory upwards, that holds `.git`, or of the working directory when none does. The name is one line of at most 60 characters. It is the caller's own statement and proves nothing: any process of your user can state any name
- **Debug** - `--debug` on any subcommand reports the relay backend decision on stderr before running: which backend was chosen, where `keyctl` was found, and, when keyctl was rejected, the step that failed with the kernel's own message

The click is not incidental - WebAuthn requires a user gesture, and a terminal has none. The notification button is the gesture.

### How the server is found

The CLI does not guess which running server is the lab. When it cannot tell, it stops with an error that lists the running servers.

- **Named by the environment** - the first of these that is set names the lab: `JUPYTER_SERVER_URL`'s port and base URL path (a JupyterLab terminal sets it), `JUPYTERHUB_SERVICE_PREFIX`, `JUPYTER_PORT`. The CLI uses the entry of `jupyter server list --json` that matches it, and stops when none matches
- **The terminal's root** - with `JUPYTER_SERVER_URL`, the entry's `root_dir` must also be the terminal's `JUPYTER_SERVER_ROOT` when that is set. The URL keeps the port the lab was set to, so a lab that found that port taken by a test server and moved to the next one would otherwise name the test server
- **Named by nothing** - the CLI uses the one running server that carries a token, and stops when there are none or several; set `JUPYTER_PORT` to the lab's port
- **When that list is empty** - the CLI uses `JUPYTER_PORT` (8888 when only `JUPYTERHUB_SERVICE_PREFIX` is set) with `JUPYTERHUB_SERVICE_PREFIX`, authenticating with `JUPYTERHUB_API_TOKEN`, `JPY_API_TOKEN` or `JUPYTER_TOKEN`; with neither variable set it stops

A server that asks for no token, as every Galata test server does, therefore receives a request only when a variable names it.

The hub variables take priority over the server list's own token, because under JupyterHub a server rejects its own listed token and accepts only the hub-issued one.

Pointing `JUPYTER_RUNTIME_DIR` at a specific runtime folder narrows discovery only if that folder holds the server's record. Point it somewhere empty and the list is empty, so the CLI uses the empty-list rule above.

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

| Flag       | Required | Meaning                                                       |
| ---------- | -------- | ------------------------------------------------------------- |
| `--prompt` | no       | dialog prompt text; defaults per mode                         |
| `--twice`  | no       | ask for the value twice, with a confirm field that must match |
| `--once`   | no       | accepted for compatibility; one entry is the default          |

By default the dialog takes one entry. A "Type it twice" checkbox adds a confirm field, and Submit stays disabled until the two match, so a mismatch cannot be submitted. `--twice` asks twice with no checkbox. Either way Cancel and Submit are the only ways out, and Escape cancels; cancelling stages no secret and tells the CLI so, which exits `1` at once rather than waiting out its timeout.

The reference is **scheme-prefixed** (see [Relay backend](#relay-backend)), so one consumer handles both backends:

- `keyctl:jlab-passkey:<nonce>.pass` - the value is a kernel key; read it with `keyctl pipe $(keyctl search @u user <desc>)`
- `file:<path>` - the value is a `0600` file; read the path, and shred it when done

The value never passes through this CLI on the way out - a keyctl-aware consumer resolves the reference and reads the secret itself.

A `keyctl:` reference is **time-bounded**: the kernel key self-destructs at its TTL (300s), so the consumer must resolve it promptly - a resolve more than five minutes after entry reads nothing where the same flow succeeds on shm. A `file:` reference persists until reboot (shred it when done).

```bash
# a passphrase you are setting - tick "Type it twice", or pass --twice to force it:
pass_ref=$(jupyterlab-passkey passphrase --prompt "Recovery passphrase") || exit 1
PASS_RECOVERY_REF="$pass_ref" pass-cli-open --ensure

# a token you are pasting - one field, nothing to confirm
tok_ref=$(jupyterlab-passkey passphrase --prompt "GitHub token") || exit 1
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
- **No terminal input** - it refuses a stdin that is a terminal, which would echo the secret into your scrollback. Pipe it in, pass a `FILE`, or use `passphrase` to type one
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

The password vault the Jupyter server keeps - see the [usage notes](usage.md#vault) for the file, the encryption and where the unlocked key is held. Every vault subcommand calls the server's authenticated API. The browser steps - an unlock (a passkey, or the chooser of a passkey, the unlock password and a code, and the recovery passphrase) and a new passkey - raise a notification whose click runs the step in the tab; only `ok` or the error comes back to the CLI.

| Subcommand                                                                                               | Does                                                                                                                    |
| -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `init [--in-browser] [--label L] [--no-passkey]`                                                         | creates the vault: the recovery passphrase, then a passkey                                                              |
| `unlock [--password \| --recovery] [--in-browser]`                                                       | unlocks with a passkey for the tab's hostname, with the unlock password and a code, or with the recovery passphrase     |
| `lock`                                                                                                   | clears the key from its holder now                                                                                      |
| `status`                                                                                                 | state, time left, key holder, protection and each capability, passkeys, password and authenticator app, unlock duration |
| `list [--category C] [--json]`                                                                           | names and metadata, never passwords                                                                                     |
| `get NAME [--field F]`                                                                                   | prints one value to stdout                                                                                              |
| `add NAME [-u U] [--url URL] [-c C] [--notes N] [--generate [--length N]] [--in-browser]`                | adds an entry                                                                                                           |
| `edit NAME [-u U] [--url URL] [-c C] [--notes N] [--password \| --generate [--length N]] [--in-browser]` | changes only the fields given                                                                                           |
| `rm NAME`                                                                                                | removes an entry                                                                                                        |
| `generate [--length N] [--no-symbols]`                                                                   | prints a random password, 24 characters by default                                                                      |
| `copy NAME [--field F]`                                                                                  | puts a value on the browser clipboard                                                                                   |
| `show NAME [--field F]`                                                                                  | shows a value in the browser as a distorted image                                                                       |
| `exec --env VAR=NAME[:FIELD] -- CMD`                                                                     | becomes CMD (exec) with vault values in its environment - its signals and exit status are CMD's own                     |
| `import [FILE]`, `import --pass-cli [--in-browser]`                                                      | adds entries from a JSON list, or from a pass-cli vault; skips names that exist                                         |
| `git install [--local]`, `git uninstall [--local]`                                                       | points git's `credential.helper` at `git-credential-jupyterlab-passkey`, or removes it                                  |
| `git migrate [--dry-run] [--no-install] [--remove-source]`                                               | imports git's plaintext credential store into the vault, then installs the helper                                       |
| `passkey add [--label L]`, `passkey list`, `passkey rm --cred-id ID`                                     | adds, lists or removes passkeys                                                                                         |
| `recovery [--in-browser]`                                                                                | replaces the recovery passphrase: the current one, then the new one (twice at a terminal)                               |

- **Missing vault** - a vault command that finds no vault at its path offers to create one at a terminal, runs the same steps as `vault init`, then runs the command. Answering no exits with the no-vault error, and a run without a terminal on stdin and stdout asks nothing and fails the same way
- **Secrets never on argv** - a new password or passphrase is typed at a hidden prompt (twice at a terminal for a new one), piped on stdin, typed in a JupyterLab dialog with `--in-browser` (one field, with a "Type it twice" checkbox), or generated. No option takes one as its value
- **Unlock on demand** - on a locked vault, `get`, `copy`, `show`, `exec`, `list`, `import` and the entry changes unlock first in the same call, then carry on. The notification's passkey click unlocks it; when no passkey can open the tab's hostname, the same click opens a chooser of the passkey when it can be used, the unlock password and a code, and the recovery passphrase. `passkey rm` needs an unlocked vault and says so. `passkey add` and `recovery` need a proof instead - an unlocked vault is not enough. `passkey add` gets it in the browser after the notification click - a passkey for the tab's hostname; when it has none, that request gets no answer or the passkey gives no PRF, a code of the authenticator app while the vault is unlocked, or the recovery passphrase (on a tab at an IP address it asks for nothing and says where to open JupyterLab) - so no secret passes through a relay; `init` with a passkey therefore asks for the passphrase there once more. `recovery` asks for the current recovery passphrase
- **Waits** - a vault command waits 120 s for its click in the tab; `init` and `passkey add` wait 600 s, because a new passkey takes a proof - a passkey, a code of the authenticator app, or a recovery passphrase kept offline - two more passkey prompts and a name. `--timeout SECONDS` sets either; the vault commands that never wait (`lock`, `status`, `generate`, `passkey list`, `passkey rm`, `git install`, `git uninstall`) take none. `git migrate` takes one for the unlock
- **Password and code** - `unlock --password` asks the unlock password, then a code of the authenticator app; the server unlocks only for both. Two values are typed, so it runs at a terminal or with `--in-browser`, not from a pipe. The two are added and removed together in the panel's cog view, and `status` reports them on one line
- **Fields** - `password` (the default), `username`, `url`, `category`, `notes` and `name`
- **Generated passwords** - leave out characters that look alike on the Show image or a phone keyboard (`l I 1 | O 0`), and quotes, backslash, backtick and space
- **Server environment** - `JLAB_PASSKEY_VAULT` (the file) and `JLAB_PASSKEY_VAULT_HOLDER` (the key holder) are read by the Jupyter server, not by the CLI; set them where the server starts
- **Copy and show** - the server stages the value in the one-shot relay the `copy` and `show` flows already use, so the value never enters the CLI process. Nothing is reported back: the click is what copies or shows it. An unclicked one stays in the relay - until its TTL on keyctl, until reboot on shm - and a `vault lock` does not remove it
- **Import** - a JSON list of objects with `name` (or `service`), `username`, `password`, `url`, `category`, `notes`, `created` and `updated`; a `notes` object is stored as JSON text. `created` and `updated` are dates such as `2026-03-23T20:37:13Z`; an entry without them gets the time of the import. Any other field is refused by name and nothing is imported
- **Import from pass-cli** - `import --pass-cli` runs `pass-cli list --format json` and one `pass-cli get` per entry, about a second each, and takes the pass-cli master password from a hidden prompt, from stdin or, with `--in-browser`, from a JupyterLab dialog. It changes nothing in the pass-cli vault but its usage counters. An entry with a TOTP secret is named and not imported, because the vault has no field for it
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
jupyterlab-passkey vault import --pass-cli --in-browser                 # every entry of a pass-cli vault
jupyterlab-passkey vault passkey add --label "Work laptop"
jupyterlab-passkey vault status --debug
```

### Git credentials

`git-credential-jupyterlab-passkey` is installed with the package as git's credential helper. It follows [gitcredentials(7)](https://git-scm.com/docs/gitcredentials): git runs it with `get`, `store` or `erase` and writes the request on stdin, and `get` answers `username=` and `password=` on stdout. The vault is the only writer, so `store` and `erase` exit `1` and write nothing.

- **Matching** - the entry's url must carry the request's host, the port included, and its scheme when the entry names one. A request with `path` - which git sends only under `credential.useHttpPath` - keeps the entries whose url path is a segment prefix of it and takes the longest; without `path`, entry paths are ignored. A `username` in the request narrows the match to that name when an entry has it
- **One answer or none** - exactly one entry answers. No match, or several that the username does not narrow to one, exits `1` and names the candidates on stderr, never a password
- **Install and remove** - `vault git install` puts `credential.helper = jupyterlab-passkey` first in the global git config and keeps the other helpers behind it; `--local` writes the repository config. `vault git uninstall` removes every copy of that value and keeps the others. Running either command twice changes nothing
- **Migrate** - `vault git migrate` reads the files git's `store` helper reads - `credential.helper = store --file <path>` (or `--file=<path>`), else `~/.git-credentials` and `$XDG_CONFIG_HOME/git/credentials` - and adds one entry per line, named `git/<username>@<host>[:<port>][/<path>]`, or `git/<host>[:<port>][/<path>]` when the line has no username, with url, username, password and category `git`. An existing name is skipped, never overwritten. `--dry-run` prints the names and hosts and writes nothing and needs no vault; `--no-install` skips the helper; `--remove-source` asks at a terminal and removes the plaintext files only when nothing was skipped - with a skipped line the files stay and the command says so - and retires the global `store` helper that reads them; a store value in another git config keeps the files and is named. Without `--remove-source`, or without a terminal, the files stay. No password is printed
- **A git command can block** - a locked vault unlocks from the same notification and click as the other commands, so `git fetch` waits for the click; nobody answers within the CLI's fixed 120 s click timeout and the helper exits `1` with the wait on stderr

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
