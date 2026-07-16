# Changelog

<!-- <START NEW CHANGELOG ENTRY> -->

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

<!-- <END NEW CHANGELOG ENTRY> -->

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
