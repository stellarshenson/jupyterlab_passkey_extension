# Recovery State - jupyterlab_passkey_extension

## BRACE 2026-07-15 - SESSION-ONLY (Opus usage limit, resets 5am)

**Horizon: SESSION-ONLY.** The CLI/session may terminate at the usage cap; the host
and disk SURVIVE. No detached compute is running (both `make install` and the build
workflow completed). Nothing to reattach - resume from disk + this board.

### FIRST ACTION on resume
The Star Colonel typed `make install` right before the limit hit. **Do NOT auto-run it
blind** - the previous `make install` already SUCCEEDED this session (built, installed,
registered OK) and left the version at **0.1.1**. Re-running `make install` will bump
**0.1.1 -> 0.1.2** (the Makefile `build` target always runs `increment_version`).
-> Confirm with the Star Colonel: re-run `make install` (accept the 0.1.2 bump) or is the
existing 0.1.1 install sufficient? Then they **restart the Jupyter server + hard-reload
the browser tab**.

### DONE and valid on disk
- **Build verified GREEN** (re-verified after the hardening edits): `jlpm build:lib` (tsc,
  clean) exit 0 · `jlpm lint:check` 0 errors (3 pre-existing warnings) · jest 8 passed ·
  pytest 8 passed.
- **Installed**: `jupyterlab_passkey_extension 0.1.1`; `jupyter labextension list` and
  `jupyter server extension list` both show **OK**.
- **Version**: package.json = `0.1.1` (bumped by the approved `make install`).

### The build - generic passkey (WebAuthn) bridge
- **Frontend** `src/index.ts` - registers command `passkey:run` (+ command palette), keeps
  the verbatim activation log line; delegates to:
  - `src/passkey.ts` - `runPasskey(op, args, serverSettings)`: random 32-byte challenge,
    `op:"get"`/`"create"` per contract, error codes `no-prf`/`prf-unsupported`/`not-allowed`/
    `error`, POSTs result via `requestAPI`, never logs prf.
  - `src/passkey-util.ts` - pure `b64urlEncode` / `b64urlToBuf` / `mapCeremonyError`.
- **Server** `jupyterlab_passkey_extension/routes.py` - `PasskeyResultHandler`
  (POST `/jupyterlab-passkey-extension/result`, `@authenticated`, nonce `re.fullmatch`
  guard, per-uid relay `/dev/shm/jlab-passkey-<uid>/<nonce>.json`, `mkstemp` 0600 +
  `os.replace`, best-effort chmod, never logs body, 204) + `PasskeyHealthHandler`
  (GET `/health`, 200 `{ok:true}`).
- **Contract**: command args `{op, nonce, rp_id, cred_id?, prf_salt?, user?}`; relay JSON
  `{nonce, ok, cred_id?, prf?, prf_enabled?, error?}`. RP id target
  `jupyterhub.lab.stellars-tech.eu`. Caller supplies all params; the extension does no crypto.
- **Tests**: `tests/test_routes.py` (8: valid write, traversal x2, short nonce, trailing
  newline, health, prf-not-logged, 403) · `src/__tests__/...` (8 jest) · `ui-tests/...`
  (Galata: activation message + CDP virtual-authenticator relay round-trip, tolerant assert).
- **Toolchain pins** (`package.json`): webpack `5.106.0` + chalk `4.1.2` in
  `resolutions`+`overrides`; typescript `~5.8.0`; `tsconfig.json` `skipLibCheck: true`.
  Removed the redundant `src/webauthn-prf.d.ts` (TS 5.8 stock lib ships PRF types).
- **Dependency added**: `@jupyterlab/apputils` (for the command palette).

### Committed in this brace
Full build was uncommitted; this brace commits it. Local repo, **no git remote** -> commit
only, no push. Paired lockfiles staged together: `package.json` + `package-lock.json` +
`yarn.lock`.

### PENDING (next-session work)
- **Journal entry** for the build not yet written -> `/journal:update` (modus secundis;
  versioned project, tag `v0.1.1`).
- **Vault consumer** (`pass-cli`, SEPARATE repo) NOT built - it is what actually drives
  `passkey:run` (pushes the jupyterlab-notify action button, polls the relay, derives the
  key). Spec: `/home/lab/workspace/acc-crit-vault-passkey-unlock.md`.
- Offered, not done: a throwaway **proof-of-life demo** (see the Windows Hello prompt + the
  relay round-trip end to end).
- Noted: passkey *listing* is not this extension's job (WebAuthn forbids enumeration) -
  device passkeys via the OS/browser manager or `ykman fido credentials list`; enrolled-slot
  listing belongs in the future vault CLI.

### Smoke test after restart
`curl -s -H "Authorization: token $JUPYTER_TOKEN" \
  http://localhost:8888/jupyterlab-passkey-extension/health` -> `{"ok": true}`;
browser console shows the activation line; `passkey:run` appears in the command palette.
