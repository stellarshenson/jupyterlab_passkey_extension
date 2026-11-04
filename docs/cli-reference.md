# CLI reference

`jupyterlab-passkey` turns a browser ceremony into a blocking local call. It is a thin proxy to the [JupyterLab commands](commands-reference.md): it posts the notification that carries the command, waits for the relay the server writes, and prints the result. It deletes the ceremony relay after reading it; the passphrase relay is left for its consumer (on shm, to shred). A consumer never learns the relay contract.

- **Ships with the package** - `pip install jupyterlab_passkey_extension` puts it on `PATH`
- **Subcommands** - `create`, `get`, `passphrase`, `copy`, `show`, mirroring the commands (`create` and `get` both run `passkey:run`), and the [`vault`](#vault) group
- **Transport** - HTTP only; it finds the server and token via `jupyter server list --json`, and posts only to the server the environment names, see [How the server is found](#how-the-server-is-found)
- **Where to run it** - a terminal on the same Jupyter server, with a JupyterLab tab open
- **Blocking** - `create`, `get` and `passphrase` wait for you to click the button and approve the prompt; `copy` and `show` return at once (`copy` unless given `--block`); a [`vault`](#vault) subcommand waits only for its browser steps
- **Timeout** - `--timeout` seconds, default `120` (`600` for `vault init` and `vault passkey add`); exit `1` if no relay arrives. On `copy` it applies only with `--block`, and is rejected without it; `show`, `vault lock`, `vault status`, `vault generate`, `vault passkey list`, `vault passkey rm`, `vault git install`, `vault git uninstall`, `vault aws install` and `vault aws uninstall` never wait and take none
- **Failure** - a failed command exits `1` with the error on stderr, nothing on stdout; with `--json`, stdout carries the failure object instead
- **`--json`** - after any subcommand's name, and before `--` on `vault exec`: stdout is one object, `{"ok": true, "command", "result"}` with exit `0`, or `{"ok": false, "command", "error", "code"}` with exit `1`, and stderr stays empty. `result` holds every value the text output shows (`vault list` nests its names in `result.entries`); `code` is the server's code or the local `no-vault`, `no-server`, `relay` or `usage`. A command's question still goes to stderr, and an argument error keeps its text and exit `2`
- **Who asks** - every notification starts `**<caller>**:`, entry name bold, so whoever clicks knows which project asked. State the name with `--caller NAME`, which every subcommand takes after its own name: `jupyterlab-passkey vault copy github/api --caller invoice-processing`. On `vault exec` it goes before `--`: everything after `--` is the command's own arguments. A caller with no command line, such as the Python `Vault` class, sets the environment variable `JLAB_PASSKEY_CALLER`; `--caller` outranks it, and the command that `vault exec` runs inherits the name. With neither, the name is the project the command runs in: the name of the nearest directory, from the working directory upwards, that holds `.git`, or of the working directory when none does. The name is one line of at most 60 characters. It is the caller's own statement and proves nothing: any process of your user can state any name
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

By default the dialog takes one entry. The calling agent decides on `--twice`, for a value being set: the dialog has two fields, and Submit stays disabled until they match, so a mismatch cannot be submitted. The dialog gives the user no control over this. Either way Cancel and Submit are the only ways out, and Escape cancels; cancelling stages no secret and tells the CLI so, which exits `1` at once rather than waiting out its timeout.

The reference is **scheme-prefixed** (see [Relay backend](#relay-backend)), so one consumer handles both backends:

- `keyctl:jlab-passkey:<nonce>.pass` - the value is a kernel key; read it with `keyctl pipe $(keyctl search @u user <desc>)`
- `file:<path>` - the value is a `0600` file; read the path, and shred it when done

The value never passes through this CLI on the way out - a keyctl-aware consumer resolves the reference and reads the secret itself.

A `keyctl:` reference is **time-bounded**: the kernel key self-destructs at its TTL (300s), so the consumer must resolve it promptly - a resolve more than five minutes after entry reads nothing where the same flow succeeds on shm. A `file:` reference persists until reboot (shred it when done).

```bash
# a passphrase you are setting - two fields that must match:
pass_ref=$(jupyterlab-passkey passphrase --twice --prompt "Recovery passphrase") || exit 1
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
| `--label`       | yes      | name of the secret; shown in the notification and its recovery offer              |
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
pass-cli get github/api --field password --quiet --no-clipboard | jupyterlab-passkey copy --label "GitHub token"

# block until it lands - and leave nothing staged if it never does
pass-cli get db/prod --field password --quiet --no-clipboard \
  | jupyterlab-passkey copy --label "DB password" --block || exit 1

# or straight from a file
jupyterlab-passkey copy ~/.config/some-service/token --label "some-service token"

# with two secrets in flight, name them - the notifications are otherwise identical
pass-cli get github/api --field password --quiet --no-clipboard | jupyterlab-passkey copy --label "GitHub token"
pass-cli get db/prod --field password --quiet --no-clipboard | jupyterlab-passkey copy --label "DB password"
```

Nothing is reported back to the terminal. In the browser, a click that copies cleanly closes the notification and says nothing - but a clipboard write the browser refuses (the window was not focused, or the click's user activation had expired) is retried quietly for 15 seconds, and if it still cannot land, a second notification appears: "Clipboard refused - copy <name> again", naming the secret from `--label`. Its button finishes the copy under a fresh click, with the value held in the page's memory - never re-staged anywhere - until then. A secret is lost when the tab closes or reloads before that click, or when the page's fetch of it fails.

Once it is on the clipboard it is an OS-wide value - any application, and any page you grant clipboard read to, can read it until you overwrite it. That is inherent to wanting to paste it somewhere.

## `show`

Reads a code from `FILE` or stdin and raises a notification whose button shows it in a dialog **as a distorted image**. For a value the user must read off the screen and type somewhere else - a one-time authenticator code, a pairing code - rather than paste. The mirror of `copy` for the eyes rather than the clipboard.

| Argument / flag | Required | Meaning                                                         |
| --------------- | -------- | --------------------------------------------------------------- |
| `FILE`          | no       | file to read the code from; omit or `-` for stdin               |
| `--label`       | yes      | name of the code; shown in the notification and above the image |

- **Never as text** - the code is staged in a one-shot relay and the notification carries only a nonce; the click fetches a PNG the server renders from the relay and consumes in the same breath. The code is absent from the notification broadcast, the page DOM, and the accessibility tree
- **Scraper-resistant** - a screen scraper sees only an image, and CAPTCHA-style distortion (per-character jitter and rotation, colour variation, overlaid noise) means an OCR pass on a screenshot still has to work for it
- **Fire and forget** - it posts and returns; nothing is reported back, the click is what shows it. The relay is one-shot, so a dismissed dialog cannot be reopened
- **Trailing newline** - exactly one is stripped. **No terminal input** - a stdin that is a terminal is refused

```bash
# show a TOTP enrolment code the user must type into their authenticator app
printf '%s' "$totp_secret" | jupyterlab-passkey show --label "Authenticator code"

# from a file
jupyterlab-passkey show --label "Pairing code" ~/pairing-code.txt
```

The dialog's image has empty `alt` text on purpose: the code must not re-enter the accessibility tree the image exists to keep it out of. That closes the channel to a screen reader as well - inherent to the goal, not an oversight.

## `vault`

The password vault the Jupyter server keeps - see the [usage notes](usage.md#vault) for the file, the encryption and where the unlocked key is held. Every vault subcommand calls the server's authenticated API. The browser steps - an unlock (a passkey, or the chooser of a passkey, the unlock password and a code, the unlock password and a passkey with no PRF, and the recovery passphrase) and a new passkey - raise a notification whose click runs the step in the tab; only `ok` or the error comes back to the CLI.

| Subcommand                                                                                               | Does                                                                                                                                           |
| -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `init [--in-browser] [--label L] [--no-passkey]`                                                         | creates the vault: the recovery passphrase, then a passkey                                                                                     |
| `unlock [--password \| --recovery] [--in-browser]`                                                       | unlocks with a passkey for the tab's hostname, with the unlock password and a code, with Password and passkey, or with the recovery passphrase |
| `lock`                                                                                                   | clears the key from its holder now                                                                                                             |
| `status`                                                                                                 | state, time left, key holder, protection and each capability, passkeys, password and authenticator app, password and passkey, unlock duration  |
| `list [--category C] [--recovery \| --password] [--in-browser]`                                          | names and metadata, never passwords                                                                                                            |
| `get NAME [--field F] [--recovery \| --password] [--in-browser]`                                         | prints one value to stdout                                                                                                                     |
| `add NAME [-u U] [--url URL] [-c C] [--notes N] [--generate [--length N]] [--in-browser]`                | adds an entry                                                                                                                                  |
| `edit NAME [-u U] [--url URL] [-c C] [--notes N] [--password \| --generate [--length N]] [--in-browser]` | changes only the fields given                                                                                                                  |
| `rm NAME`                                                                                                | removes an entry                                                                                                                               |
| `generate [--length N] [--no-symbols]`                                                                   | prints a random password, 24 characters by default                                                                                             |
| `copy NAME [--field F] [--recovery \| --password] [--in-browser]`                                        | puts a value on the browser clipboard                                                                                                          |
| `show NAME [--field F] [--recovery \| --password] [--in-browser]`                                        | shows a value in the browser as a distorted image                                                                                              |
| `exec [--recovery \| --password] [--in-browser] --env VAR=NAME[:FIELD] -- CMD`                           | becomes CMD (exec) with vault values in its environment - its signals and exit status are CMD's own                                            |
| `import [FILE]`, `import --pass-cli [--in-browser]`                                                      | adds entries from a JSON list, or from a pass-cli vault; skips names that exist                                                                |
| `git install [--local]`, `git uninstall [--local]`                                                       | points git's `credential.helper` at `git-credential-jupyterlab-passkey`, or removes it                                                         |
| `git migrate [--dry-run] [--no-install] [--remove-source]`                                               | imports git's plaintext credential store into the vault, then installs the helper                                                              |
| `aws install PROFILE`, `aws uninstall PROFILE`                                                           | writes or removes the profile's `credential_process` line, which runs `aws-credential-jupyterlab-passkey`                                      |
| `passkey add [--label L]`, `passkey list`, `passkey rm --cred-id ID`                                     | adds, lists or removes passkeys; `list` prints the passkey of Password and passkey too, and `rm` with its `cred_id` removes that method        |
| `recovery [--in-browser]`                                                                                | replaces the recovery passphrase: the current one, then the new one (typed twice)                                                              |

- **Missing vault** - `list`, `get`, `add`, `edit`, `rm`, `copy`, `show`, `exec`, `import` of a file, `passkey rm` and `git migrate` offer to create a vault they find missing at a terminal, run the same steps as `vault init`, its 600 s wait for the passkey step included, then run the command. Answering no exits with the no-vault error, and a run without a terminal on stdin and stdout asks nothing and fails the same way. `unlock`, `lock`, `import --pass-cli`, `passkey add`, `recovery` and `rotate` offer nothing and exit with the no-vault error
- **After a failed passkey step** - `vault init` and the missing-vault offer exit `1` with the vault created, and name `vault passkey add` and Password and authenticator app under Vault settings and security (the cog), because the CLI has no command that adds that method
- **Secrets never on argv** - a new password or passphrase is typed at a hidden prompt (twice at a terminal for a new one), piped on stdin, typed in a JupyterLab dialog with `--in-browser`, or generated. No option takes one as its value. The dialog has two fields that must match for a recovery passphrase being set, and one field for an entry value, an unlock and a proof
- **Unlock on demand** - on a locked vault, `get`, `copy`, `show`, `exec`, `list`, `import` and the entry changes unlock first in the same call, then carry on. `list`, `get`, `copy`, `show` and `exec` also take `--recovery` or `--password` with `--in-browser`: a locked vault unlocks by that method in the same call, the secret typed at the terminal or in a dialog, and an unlocked vault ignores the flags and asks nothing. The notification's passkey click unlocks it; when no passkey can open the tab's hostname, the same click opens a chooser of the passkey when it can be used, the unlock password and a code, Password and passkey when the vault has it, and the recovery passphrase. `passkey rm` needs an unlocked vault and says so. `passkey add` and `recovery` need a proof instead - an unlocked vault is not enough. `passkey add` gets it in the browser after the notification click - a passkey for the tab's hostname; when it has none, that request gets no answer or the passkey gives no PRF, the passkey of Password and passkey added at the tab's address while the vault is unlocked, then a code of the authenticator app while the vault is unlocked, or the recovery passphrase (on a tab at an IP address it asks for nothing and says where to open JupyterLab) - so no secret passes through a relay; `init` with a passkey therefore asks for the passphrase there once more. `recovery` asks for the current recovery passphrase
- **One shared unlock** - an unlocked vault raises no notification. Processes of one user share an unlock: the first raises the notification, the others raise none and wait on vault status, and one press lets all go on. An unlock from the panel, another tab or a terminal ends the wait too, with no click. A cancelled or failed unlock ends every wait with its line; a status read that fails ends none. A process stopped by Ctrl-C or a kill leaves no claim and ends no other wait: the next process, or one of those waiting, raises the notification in its place, and the others share it. On the keyctl relay backend a relay directory that cannot be used fails no unlock: each process raises its own notification
- **After an unanswered wait** - the command exits `1` with `the vault is locked`, the time it waited and `jupyterlab-passkey vault unlock`. For the next 10 minutes a command that needs the unlocked vault fails at once with the same line and raises nothing, so a batch does not wait process by process. `vault unlock` still raises the notification, and any unlock ends the refusal
- **Waits** - a vault command waits 120 s for its click in the tab; `init`, the passkey step of the missing-vault offer and `passkey add` wait 600 s, because a new passkey takes a proof - a passkey, a code of the authenticator app, or a recovery passphrase kept offline - two more passkey prompts and a name. The set-up a git request raises waits 600 s too, until the vault exists. `--timeout SECONDS` sets the wait of the command it is given to; the passkey step of the missing-vault offer always waits 600 s. The vault commands that wait for no click (`lock`, `status`, `generate`, `passkey list`, `passkey rm`, `git install`, `git uninstall`, `aws install`, `aws uninstall`) take no `--timeout`, and `passkey rm` waits only in that passkey step. `git migrate` takes one for the unlock
- **Password and code** - `unlock --password` asks the unlock password, then a code of the authenticator app; the server unlocks only for both. Two values are typed, so it runs at a terminal or with `--in-browser`, not from a pipe. The two are added and removed together in the panel's cog view, and `status` reports them on one line
- **Password and passkey** - a passkey with no PRF, added in the panel through Passkey, works with an unlock password of its own; the server unlocks only for the password and a verified signature of that passkey. On a vault whose only unlock password is this one, `unlock --password` raises the notification, as `unlock` with no option does: a tab that can use another passkey of the vault asks for that passkey first and opens the chooser on a cancel, and any other tab opens the chooser at once. The chooser offers Password and passkey in a tab at the address where it was added, and its password is typed in the tab; no secret is read at the terminal. `status` prints `password and passkey: added <date> at <address>` or `none`
- **Fields** - `password` (the default), `username`, `url`, `category`, `notes` and `name`
- **Generated passwords** - leave out characters that look alike on the Show image or a phone keyboard (`l I 1 | O 0`), and quotes, backslash, backtick and space
- **Server environment** - `JLAB_PASSKEY_VAULT` (the file) and `JLAB_PASSKEY_VAULT_HOLDER` (the key holder) are read by the Jupyter server, not by the CLI; set them where the server starts
- **Copy and show** - the server stages the value in the one-shot relay the `copy` and `show` flows already use, so the value never enters the CLI process. Nothing is reported back: the click is what copies or shows it. An unclicked one stays in the relay - until its TTL on keyctl, until reboot on shm - and a `vault lock` does not remove it
- **Import** - a JSON list of objects with `name` (or `service`), `username`, `password`, `url`, `category`, `notes`, `created` and `updated`; a `notes` object is stored as JSON text. `created` and `updated` are dates such as `2026-03-23T20:37:13Z`; an entry without them gets the time of the import. Any other field is refused by name and nothing is imported
- **Import from pass-cli** - `import --pass-cli` runs `pass-cli list --format json` and one `pass-cli get` per entry, about a second each, and takes the pass-cli master password from a hidden prompt, from stdin or, with `--in-browser`, from a JupyterLab dialog. It changes nothing in the pass-cli vault but its usage counters. An entry with a TOTP secret is named and not imported, because the vault has no field for it
- **Errors** - one line on stderr and exit `1` for a locked vault, a missing entry, a missing vault or an unreachable server. When the server's answer carries a stable code, the line ends with it in brackets, such as `[entry-not-found]`; the codes are listed in the [usage notes](usage.md#vault)
- **Debug** - `--debug` adds the server's key-holder decision: the holder chosen, its capabilities, and why each earlier holder was skipped

```bash
jupyterlab-passkey vault init
jupyterlab-passkey vault add github/api -u me --url https://github.com -c infrastructure
printf '%s' "$token" | jupyterlab-passkey vault add gitlab/api          # piped, never typed on the command line
jupyterlab-passkey vault add db/prod --generate --length 32
jupyterlab-passkey vault get github/api --field username
jupyterlab-passkey vault get github/api --recovery --in-browser          # a locked vault, one call
jupyterlab-passkey vault copy github/api
jupyterlab-passkey vault exec --env GITHUB_TOKEN=github/api --env GH_USER=github/api:username -- gh repo list
jupyterlab-passkey vault import export.json
jupyterlab-passkey vault import --pass-cli --in-browser                 # every entry of a pass-cli vault
jupyterlab-passkey vault passkey add --label "Work laptop"
jupyterlab-passkey vault status --debug
```

### Git credentials

`git-credential-jupyterlab-passkey` is installed with the package as git's credential helper. It follows [gitcredentials(7)](https://git-scm.com/docs/gitcredentials): git runs it with `get`, `store` or `erase` and writes the request on stdin, and `get` answers `username=` and `password=` on stdout. The vault is the only writer, so `store` and `erase` exit `1` and write nothing.

- **First set-up** - with no vault, git's first request raises one `Set up vault` notification, however many processes ask at once: the first raises it and the others wait. The tab asks the recovery passphrase in two fields, then offers Passkey, Password and authenticator app, and Later. The lookup runs as soon as the vault exists, made in the tab or in the panel, while the tab still offers the methods. A cancelled or failed passphrase step exits `1` naming that step, and the next request starts again. With nobody answering, the request exits `1` after 600 s with `no vault yet` and `jupyterlab-passkey vault init`, and for the next 10 minutes a request fails at once with the same line
- **Existing vault** - any vault that exists, with a passkey, the unlock password and app, or the recovery passphrase alone, unlocks the normal way and raises no set-up
- **Matching** - the entry's url must carry the request's host, the port included, and its scheme when the entry names one. Percent-encoding in the url is decoded first, and `<name>:<port>` with no scheme is a host and a port. A `username` in the request must match, as `git credential-store` requires: the entry with that username answers, or else an entry with no username, and any other entry gives no answer. A request with `path` - which git sends only under `credential.useHttpPath` - keeps the entries whose url path is a segment prefix of it and takes the longest; without `path`, entry paths are ignored. A path byte that is not UTF-8 matches the same byte in the entry's url. A request with no host, as git sends for a client certificate's passphrase, gets no answer and reads no entry
- **Several entries** - when several entries are left after the username and the path narrow them, with or without a username in the request, the newest changed entry answers, as `store` answers its first line and writes a new line first. No match exits `1` and names the candidates on stderr, never a password
- **No username** - an entry with no username answers the password only, so git keeps the username it has. With no username in the request either, the helper invents none: it exits `1` and names the entry
- **Install and remove** - `vault git install` puts `credential.helper = jupyterlab-passkey` first in the global git config and keeps the other helpers behind it. It removes every `store` helper there, `credential.<url>.helper` values included, and prints each value and its file, because git would write every credential it accepts back in plaintext; the plaintext file stays until `vault git migrate --remove-source`. A `store` helper is `store`, a full path to `git-credential-store`, or a `!git credential-store` shell snippet; a helper whose name only starts with `store` is another helper. `--local` does the same in the repository config and in the files it includes. When a git config write fails after a value was removed, the command exits `1` and prints each removed `store` value with the `git config` command that restores it. `vault git uninstall` removes every copy of that value and keeps the others. The global config is two files, `~/.gitconfig` and `$XDG_CONFIG_HOME/git/config`, and git runs the XDG file's helpers first: both commands read both files and name the file they changed, and `install` writes the file that makes ours run first. Running either command twice changes nothing. A `credential.<url>.helper` value of another helper stays. Both commands, and `migrate`, need git 2.26 or later
- **Migrate** - `vault git migrate` reads the files git's `store` helper reads - `credential.helper` or `credential.<url>.helper` `= store --file <path>` (or `--file=<path>`, the last one when there are several), with a `~` that starts the word and a set variable outside single quotes expanded, as git's shell expands them, and `~/.git-credentials` and `$XDG_CONFIG_HOME/git/credentials` unless a store value for every URL names other files. A `~` after `--file=` or in quotes, and a `$` after a backslash, stay as written, as they do for git. It checks each line before it adds, by what the helper would match for that line. The same host, username and value adds nothing, counts as held and does not block `--remove-source`. The same host and username with another value adds nothing and is named, and the source stays. Another username gets its own entry, named `git/<username>@<host>[:<port>][/<path>]`, or `git/<host>[:<port>][/<path>]` when the line has no username, with the host and path decoded from git's percent-encoding, a `?` or `#` in the path kept as part of it, a path with an unprintable character staying encoded in the name, and url, username, password and category `git`. An entry with the line's name and username counts the same way, whatever url it holds, so the http and https lines of one account are one entry with the url of the first line, and a request the entry's url does not match gets no answer once the source is gone. An entry of that name with another username is never overwritten: the line is skipped and the source stays. Entries get dates one second apart in line order, so a host answers a request with no username as `store` did. A line the vault already holds adds no entry, and the entry that holds it keeps its own date: when a host's first line was held, a request with no username gets the newest changed entry of that host, which can be another line's. The check reads the value of each entry on the same account, so those entries read as used. One line names each host left with several entries. `--dry-run` prints the names and hosts, and that line, and writes nothing and needs no vault: it reads no value, it counts the entries of an unlocked vault, and with a locked vault or none it counts the store's lines alone. `--no-install` skips the helper; `--remove-source` asks at a terminal and removes the plaintext files only when nothing was skipped - with a skipped line the files stay and the command says so - and retires the global `store` helpers that read them, `credential.<url>.helper` values included; a store value in another git config keeps the files and is named. Without `--remove-source`, or without a terminal, the files stay. A file `--remove-source` cannot remove exits `1` with one line naming it, after the lines that restore the values the run removed. A line with a client certificate's passphrase (`cert://`) is named by its file and number, not imported, and keeps the files on `--remove-source`; the other lines are imported. A bad line exits `1` with one line naming the file and the line number, never the text of the line; a host, username or password that is not UTF-8 text and a name the vault refuses are bad lines. No password is printed
- **A `--file` store** - `install` and every `migrate` that removes a `store --file <path>` value leave no helper naming that file, so a later `migrate` cannot find it. Both print every removed `--file` value as written, with the exact `git config` command that restores it to the file that held it, whether or not a line was left out, unless the run removed the file. Run that command, then `vault git migrate --remove-source`; after a `migrate` that skipped lines, the line names the entries to change or remove in the vault first. A bare `store` gets the line only while a file it reads exists and `migrate` reads that file no more. A value that holds bytes which are not UTF-8 is printed as those bytes, so the command restores it exactly. When `migrate` read the value and the file stays, both also print the file's path. A `migrate` that left no line out also prints an `rm` line for it
- **A value `migrate` can read** - `migrate` reads only a plain path, `~` and a set variable. Any other spelling, such as a value only a shell can evaluate, gets the line with the value and the command and no path. To import such a file, restore the value, then change it to a plain path. The code does not parse further shell syntax
- **A git command can block** - a locked vault unlocks from the same notification and click as the other commands, so `git fetch` waits for the click. Parallel git commands [share one unlock](#vault). When nobody answers within the CLI's fixed 120 s click timeout, the helper exits `1` with the wait and `jupyterlab-passkey vault unlock` on stderr, and later helpers fail at once for 10 minutes

### AWS credentials

`aws-credential-jupyterlab-passkey` is installed with the package as an AWS profile's credential process.

- **Entry** - `vault add aws/<profile> -u <access-key-id>`: `username` is the access key id and `password` the secret access key. Static keys only: no session token, no expiry, and an SSO or session profile bypasses the helper
- **Install** - `vault aws install <profile>` writes `credential_process = "<absolute helper path> <profile>"` through `aws configure set --profile <profile>`, so the line does not depend on `PATH` at AWS time. It names the entry the helper reads and exits `1` naming the way forward when the helper or `aws` is not on `PATH`; with no `aws` it prints the line to add by hand
- **Helper** - the AWS CLI runs it with the profile on the line; it prints `{"Version": 1, "AccessKeyId": ..., "SecretAccessKey": ...}` on stdout and nothing else there
- **Locked vault** - the helper raises the same unlock notification and waits; the `aws` command blocks until the click, and the message on an unanswered wait names `jupyterlab-passkey vault unlock`
- **Set-up** - with no vault, the helper offers the set-up at a terminal; the AWS CLI pipes stdout, so it runs the browser set-up, as the git helper does
- **Remove** - `vault aws uninstall <profile>` removes only the `credential_process` lines of that profile that name this helper, from `$AWS_CONFIG_FILE` or `~/.aws/config`, and keeps every other line and the file mode as they are. A line naming another helper stays and the command exits `1` naming its value; with no such line it succeeds and says so; with no config file it says there is none. It prints no key

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
