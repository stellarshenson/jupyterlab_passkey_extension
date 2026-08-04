# Changelog

<!-- <START NEW CHANGELOG ENTRY> -->

## [1.0.44] - 2026-08-04

Turns a passkey ceremony that fails because the RP ID does not match the tab's URL into an error the caller can act on, instead of a dead-end `error` code.

### Fixed

- A ceremony that fails because `--rp-id` is not the JupyterLab tab's hostname (nor a parent domain of it) now exits with a message that says exactly that, instead of the opaque `ceremony failed: error`. WebAuthn throws this synchronously as a `SecurityError`, distinct from the privacy-conflated `NotAllowedError` it uses for a cancel or a missing credential, so it is safe to name. Any other unexpected ceremony exception now carries its name through (`error: <name>`) rather than collapsing to a bare `error`

<!-- <END NEW CHANGELOG ENTRY> -->

## [1.0.43] - 2026-07-24

Makes the kernel-keyring relay actually available inside a container, tells the truth when it is not, and ends the wait as soon as a passphrase dialog is dismissed.

### Added

- `--debug` on every subcommand, reporting the relay backend decision on stderr - which backend was chosen, where `keyctl` was found, and, when keyctl was rejected, the exact step that failed with the kernel's own message. stdout still carries only the result

### Fixed

- The keyctl relay is no longer silently downgraded to the `/dev/shm` file inside a container. A kernel `user` key grants read to the key's **possessor**, and a process possesses a key only when it is reachable from its session keyring - which container-spawned processes (a `docker exec`, a JupyterHub spawner, a JupyterLab terminal) never get, because `pam_keyinit` does not run for them. Staging and searching both succeeded and only the read was refused, so the probe rejected a keyctl that was installed and working. It now links the user keyring into the session before testing, establishing possession for the server and the CLI alike
- The fallback warning named the wrong cause. It said "install keyutils" whatever went wrong - useless advice on a host where keyutils is installed and the kernel is refusing the syscall. It now distinguishes a sandbox refusal (a rootless or user-namespaced container, where no package helps), a possession failure, and a genuinely missing binary, which is the only case that still asks for keyutils
- Dismissing the passphrase dialog no longer leaves the CLI waiting out its full timeout. Cancel and Escape relayed nothing, which is indistinguishable from a button nobody has clicked, so `passphrase` polled for 120s before reporting a refusal made instantly. The dialog now signals the cancel through a marker that carries no secret, and the command exits at once

## [1.0.41] - 2026-07-24

Adds `show`, a command that displays a code in a popup rendered so a screen scraper cannot read it, and makes every command keep working when the calling process is detached from its terminal.

### Added

- `show` command, `passkey:show` frontend command, and an authenticated one-shot `render` endpoint: a local client stages a code (an authenticator enrolment code, a pairing code) and the browser shows it as a server-rendered, distorted image. The code never reaches the page as text - it is absent from the notification broadcast, the page DOM, and the accessibility tree - and CAPTCHA-style distortion means an OCR pass on a screenshot still has to beat it. The dialog image carries empty `alt` text by design
- `Pillow>=10.1` as a dependency, used by the `render` endpoint to draw the code (no font file ships - it uses Pillow's scalable default)
- Every subcommand now ignores `SIGHUP`, so a notification, popup or query raised by a backgrounded process keeps waiting for its click after the terminal that launched it has closed - notifications, popups and queries work the same detached as attached

## [1.0.38] - 2026-07-23

Makes the copy-recovery integration test deterministic so the Build workflow's Galata job is no longer flaky. No runtime behaviour changes.

### Fixed

- The `copy re-offers the click when even the recovery write is refused` Galata test no longer fails intermittently under slow CI. It now waits for the dismissed recovery toast to fully detach from the DOM before clicking the re-offer, instead of relying on toast ordering or a settle count, so exactly one clipboard button exists at click time

## [1.0.37] - 2026-07-21

Makes the relay handoff survive a backend split between the writer and the reader, so a Jupyter server still running an older build (which stages the secret as a `/dev/shm` file) can hand off to a newer keyctl-preferring client without the secret stranding uncollected.

### Fixed

- A keyctl-preferring reader now also checks the `/dev/shm` file relay when its kernel key is empty, so a secret staged by a writer on the other backend is still collected instead of stranding under the same nonce in a store the reader never looked at. Covers the ceremony result, the copy secret, the passphrase reference, and cleanup
- The `passphrase` reference now names the file when the value actually landed in `/dev/shm` under that split, instead of printing a `keyctl:` handle that resolves to an empty keyring
- A relay directory found to be squatted during the fallback read is surfaced once to stderr rather than silently swallowed

## [1.0.36] - 2026-07-19

Hardens the keyctl relay backend against seven defects found in a five-round adversarial review, so a key that cannot self-destruct is never left staged and no failure path leaks a secret or masks an error.

### Fixed

- A keyctl key that cannot be given a TTL (its self-destruct) is no longer left staged: the failure removes the key and reports an error, instead of holding the secret with no expiry - most sharply for the passphrase key, which the extension never unlinks itself
- `copy --block` no longer reports success after the kernel key self-expires during a long wait: the key is now given a TTL that outlives the wait
- A forced-but-broken `JLAB_PASSKEY_RELAY_BACKEND=keyctl` now surfaces as a clean 500 (server) or a one-line message (CLI) rather than a traceback
- A relay failure on an unwind path no longer masks the error actually propagating: relay teardown is best-effort and never raises
- `copy --block --timeout` rejects a non-positive, non-finite, or out-of-range value instead of minting a no-expiry key or wrapping the kernel's 32-bit timeout
- The keyctl backend probe no longer leaks the probe key it stages

## [1.0.35] - 2026-07-19

Stages every relayed secret in a kernel keyring key when available, so the value never swaps to disk and self-destructs at a TTL, with the `/dev/shm` file relay as a fallback.

### Added

- keyctl relay backend: the ceremony PRF, the passphrase, and the copy secret are staged in a uid-scoped kernel `user` key that never swaps to disk and the kernel destroys at a TTL, chosen automatically when a `keyctl` add/search/read round-trip works. It closes two gaps the file relay left: the value could swap to disk, and a crashed consumer orphaned a plaintext file
- `JLAB_PASSKEY_RELAY_BACKEND=auto|keyctl|shm` forces the backend; `auto` (default) prefers keyctl and falls back to the `/dev/shm` `0600` file with a one-line stderr warning advising `keyutils`

### Changed

- `passphrase` now prints a scheme-prefixed reference (`keyctl:jlab-passkey:<nonce>.pass` or `file:<path>`) instead of a bare file path, so one keyctl-aware consumer resolves it whichever backend is live and the value never transits the CLI. This is a breaking change for consumers that read the printed value as a path
- Server handlers answer a relay-backend failure (a keyctl quota, a missing binary, a squatted directory) with a clean 500 rather than a traceback in the Jupyter log

### Fixed

- The keyctl payload rides stdin, never a process argument, so a secret is not exposed in the process list

## [1.0.32] - 2026-07-17

Adds copy-to-clipboard for local secrets, makes it survive Chrome's clipboard gating in every tested condition, and hardens the `/dev/shm` relay directory against squatting.

### Added

- `copy` subcommand and `passkey:copy` command: the CLI stages a secret from a file or stdin as a one-shot `0600` relay, the notification carries only the nonce, and the browser fetches the value (read and unlink in the same breath) and writes it to the clipboard. Flags: `--label` names the secret, `--block` waits for collection and deletes the relay on timeout; a tty is refused as the secret source
- Recovery notification: a clipboard write still refused once the click's user activation has expired (Chrome honours writes only ~5s past the last gesture) raises a "clipboard needs another click" toast whose button finishes the copy under a fresh gesture. The value lives only in page memory and dies with the tab; no refusal loses a secret short of closing the tab first
- `passphrase --once` drops the confirm field, for pasting existing secrets rather than typing new ones
- Three Galata tests reproduce Chrome's focus-refusal conditions (transient blip, expired activation plus recovery click, refused recovery re-offer) against the real command, relay, and clipboard

### Changed

- A refused clipboard write retries on every return of window focus and on a 2s tick for 15s before offering the recovery click; refusal reasons go to the console, never the value

### Fixed

- The relay directory under the world-writable `/dev/shm` is now guarded against squatting: symlink, ownership, and mode are checked before every relay read and write, a foreign-owned or loose-permissioned directory is refused, and a self-owned loose one is tightened to `0700`
- A ceremony relay missing `cred_id` exits with a one-line message instead of a `KeyError` traceback
- Relay reads pin `utf-8` regardless of locale

## [1.0.15] - 2026-07-16

Hardens the passphrase dialog: Submit is impossible until the two entries match, Cancel and Submit are the only ways out, and the status line no longer resizes the dialog.

### Changed

- Submit is disabled until both entries match, from the moment the dialog opens rather than only on the caller's after-the-fact check. The confirm field carries a custom validity message, which is the signal JupyterLab's own `Dialog` already reads to gate its accept buttons
- Cancel and Submit are the only exits. The close button and dismiss-on-outside-click are gone - a passphrase prompt that vanishes on a stray click leaves the waiting CLI blocked on a relay that never arrives, which reads as a hang rather than a cancel. Escape still cancels
- The status line reports both states - `Passphrases match` as well as `Passphrases do not match` - and reserves its row at all times, so revealing it no longer walks the dialog's bottom edge up and down under the pointer as you type

### Fixed

- The mismatch indicator no longer collapses the dialog's height when hidden

## [1.0.12] - 2026-07-16

Fixes a credential id or PRF salt that begins with `-` aborting the CLI before the ceremony runs.

### Fixed

- A `cred_id` or `prf_salt` beginning with `-` no longer aborts `jupyterlab-passkey get` before any ceremony runs. base64url's alphabet includes `-`, so roughly one value in 64 starts with one, and argparse reads such a value as an option rather than an argument - failing the documented `--cred-id "$cred"` with `expected one argument`, deterministically for that credential rather than intermittently, which is how it survived a release. Values now reach argparse attached with `=`, the form it cannot misread. Every existing CLI test called the subcommand with a ready-made namespace, so argv parsing had no coverage at all; the regression tests drive `main()`

## [1.0.10] - 2026-07-16

Adds `jupyterlab-passkey`, a shipped console script that turns a browser ceremony into a blocking local call, and `passkey:passphrase` for the secret a passkey cannot supply. Everything since 1.0.4 lands here.

### Added

- `jupyterlab-passkey` console script - `create`, `get`, `passphrase`, mirroring the frontend commands one-to-one. It posts the notification carrying the command, waits for the relay, and prints the result, so a consumer never learns the relay contract. `passphrase` prints the file's path, never the value
- `passkey:passphrase` frontend command capturing a passphrase in a dialog that takes it twice and relays it only when both entries match, plus an authenticated `POST .../passphrase` endpoint writing it raw to a `0600` `<nonce>.pass` file
- `docs/commands-reference.md` (JupyterLab commands, relay contract, endpoints) and `docs/cli-reference.md` (the CLI), including a "How the server is found" section documenting the CLI's silent environment fallback
- Functional Galata tier spawning the real console script against a CDP virtual authenticator - the only tier that fails when the packaging is wrong rather than the code
- `JUPYTER_TEST_PORT` for the integration suite, so it can run beside a JupyterLab already holding port 8888

### Changed

- `jupyterlab_notifications_extension>=1.2` is now a hard dependency, not an optional trigger - the CLI posts to its `ingest` endpoint to raise the button that supplies WebAuthn's required user gesture
- `relay_dir` is public in `routes` and shared with the CLI, so the writer and the reader cannot disagree on the path
- Relays are documented as atomic rather than one-shot - `os.replace` guarantees no partial read, but deleting after reading is the consumer's job

### Fixed

- A timed-out ceremony no longer strands its PRF on disk: a relay landing in the final poll window is now consumed rather than declared missing and left behind
- Server token precedence follows the hub variables first, since under JupyterHub a server rejects its own listed token and accepts only the hub-issued one
- `--timeout` is accepted after the subcommand, where it is natural to type
- Removed `scripts/passkey_selftest.py`, which was never packaged and so unreachable for anyone installing from PyPI

## [1.0.4] - 2026-07-15

First published release of `jupyterlab_passkey_extension` - a JupyterLab 4 extension that bridges the browser/OS passkey (WebAuthn) capability to local clients that have no browser of their own.

### Added

- `passkey:run` frontend command running the WebAuthn `get`/`create` ceremony with optional PRF (hmac-secret) evaluation and POSTing the result to the server
- Authenticated Tornado `POST .../result` handler writing a one-shot `0600` `/dev/shm/jlab-passkey-<uid>/<nonce>.json` relay via `mkstemp`-then-`os.replace`, plus a `GET .../health` endpoint
- On-demand self-test (`scripts/passkey_selftest.py`) driving the real authenticator through `jupyterlab-notify`
- Developer-facing README with architecture diagram, `passkey:run` argument table, result shapes, and security notes
- Full test coverage: jest 27, pytest 21, Galata 6

### Changed

- `create` no longer rejects when `prf.enabled` is false at registration, so Windows Hello (which reports `enabled:false` yet yields a PRF at assertion) is supported

### Fixed

- `package.json` `repository.url` corrected so `jupyter-releaser check-npm` resolves the repository owner and name
