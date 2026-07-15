# Logs

Progress logs for background jobs in this project.

- `make-install.log` - output of `make install` (clean, version bump, prod labextension build via `python -m build`, wheel install)
- `ui-tests-install.log` - output of `jlpm install` + `jlpm playwright install chromium` in `ui-tests/` (Galata + Playwright deps and browser for the integration suite)
- `jlpm-build.log` - output of `jlpm build` (dev tsc + labextension rebuild; no version bump)
- `galata.log` - output of the Galata integration run (`playwright test`) for the passkey E2E suite
