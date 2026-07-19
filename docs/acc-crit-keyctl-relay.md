# Acceptance Criteria - keyctl relay backend

A kernel-keyring relay backend for the secrets this extension moves, chosen automatically when `keyctl` works and falling back to the current `/dev/shm` file relay (with a warning) when it does not. keyctl closes two gaps the file relay leaves open - the value can swap to disk, and a crashed consumer orphans a plaintext file - by holding the value in a uid-scoped kernel `user` key the kernel destroys at a TTL. It buys no isolation from the user's own processes; same-uid exposure is identical to the `0600` file.

## Contents

- [Scope and non-goals](#scope-and-non-goals)
- [Backend selection](#backend-selection)
- [Per-flow behaviour](#per-flow-behaviour)
- [Passphrase consumer contract](#passphrase-consumer-contract)
- [Security properties](#security-properties)
- [Edge cases](#edge-cases)
- [Tests](#tests)
- [API](#api)
- [Resolved defaults](#resolved-defaults)

## Scope and non-goals

- [x] **In scope** - all three relays: ceremony `<nonce>.json`, passphrase `<nonce>.pass`, copy `<nonce>.secret`
  - log: 2026-07-18 criterion added
- [x] **Non-goal: isolation** - keyctl does not restrict same-uid reads; the win is no-swap, kernel-TTL self-destruct, no disk artifact - stated, never implied as access control
  - log: 2026-07-18 criterion added
- [x] **Non-goal: cross-uid** - server and CLI must share a uid (both uid 1000 here); a server running as another user is out of scope and must use the file backend
  - log: 2026-07-18 criterion added

## Backend selection

- [x] **Probe, not presence** - keyctl is chosen only when a full add -> search -> pipe -> unlink round-trip on `@u` succeeds, not merely when the binary is on PATH (the session-keyring linking caveat can make a present binary non-functional)
  - log: 2026-07-18 criterion added
  - log: 2026-07-19 probe key now unlinked in a `finally` keyed off padd's id, so a post-padd failure cannot leak it (review finding)
- [x] **Cross-session reach** - every keyctl op names `@u` explicitly, which resolves across sessions on its own; no `keyctl link @u @s` is needed and none is done. The probe proves the round-trip end to end, so a host where `@u` were unreachable falls back to shm rather than staging into a key the reader cannot find
  - log: 2026-07-18 criterion added
  - log: 2026-07-19 implemented as explicit `@u` naming, not session linking - simpler and probe-verified; cross-process handoff tested
- [x] **Independent, converging** - server and CLI probe independently; availability is environmental and uid-scoped, so they agree in practice, and a reader that guesses wrong resolves to not-found rather than silent-wrong (see Edge)
  - log: 2026-07-18 criterion added
- [x] **Override** - `JLAB_PASSKEY_RELAY_BACKEND` = `auto` (default) / `keyctl` / `shm`; `keyctl` fails loud if the probe fails, `shm` forces the file relay, `auto` prefers keyctl and falls back
  - log: 2026-07-18 criterion added
  - log: 2026-07-19 forced-but-broken `keyctl` raises `OSError` (not `RuntimeError`), so the handlers' `except OSError` guards answer with a clean 500 / one line, never a traceback (review finding); passphrase's wait/reference now guarded too
  - log: 2026-07-19 `unstage` made best-effort (never raises): `_run`'s `finally: unstage` re-enters `backend()`, and a raise in a `finally` would MASK the clean `SystemExit` with an `OSError` traceback on `create`/`get` (review finding); `test_ceremony_under_forced_broken_keyctl_exits_one_line_not_a_traceback`, `test_unstage_is_best_effort_when_the_backend_is_unavailable`
- [x] **Fallback warning** - on fallback to shm, one warning on **stderr** (never stdout - it carries the result): "keyctl unavailable; using /dev/shm relay (swappable, orphaned on crash) - install keyutils for kernel-keyring relays"
  - log: 2026-07-18 criterion added
- [x] **Warning once** - the warning fires once per process, not once per relay
  - log: 2026-07-18 criterion added

## Per-flow behaviour

Writer and reader per relay, and whether keyctl is transparent to the caller.

| Flow               | Writer | Reader                   | keyctl transparent?                   |
| ------------------ | ------ | ------------------------ | ------------------------------------- |
| Ceremony `.json`   | server | CLI (`_run`)             | yes - CLI reads it internally         |
| Ceremony raw-shell | server | external shell (docs)    | no - documented shell must use keyctl |
| Copy `.secret`     | CLI    | browser via `secret` API | yes - both ends are our code          |
| Passphrase `.pass` | server | external consumer        | no - consumer contract changes        |

- [x] **Copy: transparent** - CLI stages `jlab-passkey:<nonce>.secret`, notification carries the nonce only, `secret` handler searches + pipes + unlinks (one-shot); browser side unchanged
  - log: 2026-07-18 criterion added
- [x] **Copy: --block collection** - `--block` polls until the key is gone (search fails), same signal as the file disappearing today
  - log: 2026-07-18 criterion added
- [x] **Ceremony: CLI read** - server stages `jlab-passkey:<nonce>.json`; `_wait` polls `keyctl search`, reads via pipe, unlinks; PRF still printed to stdout, never logged
  - log: 2026-07-18 criterion added
- [x] **Ceremony: raw-shell doc** - the raw `jupyterlab-notify` example in commands-reference.md gains the keyctl equivalent (`keyctl pipe $(keyctl search @u user ...)`), and states the file form applies only under the shm backend
  - log: 2026-07-18 criterion added
- [x] **Passphrase: keyctl stage** - server stages `jlab-passkey:<nonce>.pass`; CLI prints a scheme-prefixed reference (see contract), not a path
  - log: 2026-07-18 criterion added
- [x] **TTL** - ceremony `json` and passphrase `pass` keys expire at 300s; copy `secret` at 900s, since the user may not click its notification at once; all via `keyctl timeout`
  - log: 2026-07-18 criterion added
  - log: 2026-07-19 TTLs set to json/pass 300s, secret 900s (was proposed 120/300); copy widened for the click-whenever window
- [x] **TTL set is checked** - the `keyctl timeout` return code is checked; a key that cannot be given an expiry is unlinked and the stage fails loud, never left holding a secret with no self-destruct (the padd->timeout window is non-atomic and accepted as no-worse-than-shm)
  - log: 2026-07-19 criterion added + implemented (review finding); `test_keyctl_stage_unlinks_and_raises_when_the_ttl_cannot_be_set`
- [x] **Copy `--block` outlives the wait** - in `--block` the copy key's TTL is set past the wait deadline (`ceil(timeout)` + margin), so a key vanishing during the wait can only mean collection, never expiry - otherwise `--block` would report a secret delivered that TTL-expired uncollected (keyctl only; shm files never expire)
  - log: 2026-07-19 criterion added + implemented (review finding); `test_copy_block_gives_the_key_a_ttl_that_outlives_the_wait`
  - log: 2026-07-19 `--block --timeout` must be positive and finite - inf/nan would crash `ceil()`, and `<= -60` would drive the TTL to 0/negative (`keyctl timeout 0` clears the expiry); rejected before staging (review finding); `test_copy_rejects_a_non_positive_or_non_finite_block_timeout`
  - log: 2026-07-19 also capped at 1e8s - keyctl stores the TTL in a 32-bit unsigned int, so a value at/beyond 2^32 wraps below the wait, re-opening the mid-wait self-destruct (review finding); one range test `0 < timeout <= 1e8` subsumes non-finite/non-positive/oversized

## Passphrase consumer contract

The passphrase value must reach a tool outside this extension. The CLI prints a **reference**, scheme-prefixed so one consumer handles both backends and the value never transits the bridge CLI or an agent.

- [x] **Reference form** - keyctl: `keyctl:jlab-passkey:<nonce>.pass`; shm fallback: `file:<relay_dir>/<nonce>.pass`
  - log: 2026-07-18 criterion added
- [x] **Consumer resolves** - a keyctl-aware consumer branches on the scheme: `keyctl:` -> `keyctl pipe $(keyctl search @u user <desc>)`; `file:` -> read the path
  - log: 2026-07-18 criterion added
- [x] **No bridge-side read helper** - the extension never pipes the value to its own stdout; the consumer reads the key itself, keeping the value out of the bridge CLI and any agent transcript
  - log: 2026-07-18 criterion added
- [x] **Consumer stays one-shot-optional** - keyctl passphrase is not unlinked on read (mirrors the file the consumer shreds today); the kernel TTL is the backstop, and the consumer may unlink after use
  - log: 2026-07-18 criterion added
- [x] **Reference is time-bounded on keyctl** - a `keyctl:` reference resolves only until its 300s TTL; the consumer must resolve promptly, where the `file:` form persists until reboot - documented in cli-reference.md as a backend asymmetry, not silently different
  - log: 2026-07-19 criterion added (review finding); documented, TTL unchanged (deliberate)
- [x] **Docs: worked example** - cli-reference.md passphrase examples show the keyctl consumer form beside the file form, and the `pass-cli` integration the vault side must match
  - log: 2026-07-18 criterion added

## Security properties

- [x] **No value on argv** - `keyctl padd` takes the payload on stdin; only the nonce/description is ever an argument
  - log: 2026-07-18 criterion added
- [x] **No value in logs** - no handler or CLI path logs the value or the pipe output, same bar as the file relay
  - log: 2026-07-18 criterion added
- [x] **One-shot preserved** - copy and ceremony unlink the key on read; a second reader finds nothing, exactly as the file relay unlinks
  - log: 2026-07-18 criterion added
- [x] **Squat guard scope** - the keyctl path has no filesystem to squat; `ensure_relay_dir` and the `0600` model are retained and exercised only on the shm fallback
  - log: 2026-07-18 criterion added
- [x] **Same-uid caveat documented** - README security section states keyctl protects against swap and disk residue, not against the user's own processes
  - log: 2026-07-18 criterion added

## Edge cases

- [x] **Edge: backend mismatch** - writer keyctl, reader probes shm-only -> reader finds nothing and times out with the normal not-found message, never a wrong value
  - log: 2026-07-18 criterion added
- [x] **Edge: quota exhausted** - `keyctl padd` fails on the per-uid key quota -> CLI/server answer with a one-line error (as a full /dev/shm does today), never a traceback
  - log: 2026-07-18 criterion added
- [x] **Edge: TTL expiry mid-wait** - a key that expires before collection -> the waiter reports the same timeout as an uncollected file, nothing stranded
  - log: 2026-07-18 criterion added
- [x] **Edge: keyctl present, linking broken** - probe round-trip fails -> auto falls back to shm with the warning; `JLAB_PASSKEY_RELAY_BACKEND=keyctl` fails loud instead
  - log: 2026-07-18 criterion added
- [x] **Edge: empty / non-text payload** - same boundary rules as today (empty rejected, utf-8 strict at the stdin boundary)
  - log: 2026-07-18 criterion added

## Tests

- [x] **Probe test** - selection returns keyctl when the round-trip works, shm when it is forced off, discriminating against a stubbed-broken keyctl
  - log: 2026-07-18 criterion added
- [x] **Cross-process handoff** - a key staged in one process is read byte-exact in another (mirrors the empirical check already run)
  - log: 2026-07-18 criterion added
- [x] **TTL destroys** - a key is gone after its timeout, no reaper
  - log: 2026-07-18 criterion added
- [x] **One-shot** - copy/ceremony read unlinks; a second read finds nothing
  - log: 2026-07-18 criterion added
- [x] **No argv leak** - the value never appears in a staged process command line (payload on stdin)
  - log: 2026-07-18 criterion added
- [x] **Fallback + warning** - forcing shm emits exactly one stderr warning and uses the file relay; nothing on stdout
  - log: 2026-07-18 criterion added
- [x] **Both backends per flow** - copy, ceremony and passphrase each pass on keyctl and on shm
  - log: 2026-07-18 criterion added
- [x] **Adversarial review** - survives the same review bar as the relay work (architect + bug-hunter), on a snapshot of the working tree
  - log: 2026-07-18 criterion added

## API

- Kernel key: type `user`, description `jlab-passkey:<nonce>.<kind>`, keyring `@u`, payload = the raw value, TTL per flow
- Backend selection env: `JLAB_PASSKEY_RELAY_BACKEND` = `auto` | `keyctl` | `shm`
- Passphrase reference (stdout): `keyctl:jlab-passkey:<nonce>.pass` or `file:<relay_dir>/<nonce>.pass`
- No new HTTP endpoints; the `secret` / `result` / `passphrase` handlers gain a backend indirection, wire contract unchanged

## Resolved defaults

- [x] **TTLs** - set to ceremony/passphrase 300s, copy 900s (copy widened for the click-whenever window)
  - log: 2026-07-18 criterion added
  - log: 2026-07-19 resolved
- [x] **Reference scheme** - `keyctl:` / `file:` prefixes (confirmed); the consumer branches on the scheme
  - log: 2026-07-18 criterion added
  - log: 2026-07-19 resolved
- [x] **pass-cli side** - the vault consumer that reads the `keyctl:` reference is updated separately, outside this extension, which only prints the reference
  - log: 2026-07-18 criterion added
  - log: 2026-07-19 resolved - out of this repo's scope per the project boundary
