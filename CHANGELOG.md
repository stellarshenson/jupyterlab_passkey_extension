# Changelog

<!-- <START NEW CHANGELOG ENTRY> -->

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

<!-- <END NEW CHANGELOG ENTRY> -->
