# Changelog

<!-- <START NEW CHANGELOG ENTRY> -->

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

<!-- <END NEW CHANGELOG ENTRY> -->

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
