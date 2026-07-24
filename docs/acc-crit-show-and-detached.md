# Acceptance Criteria - Show Code and Detached Commands

Two features delivered together. `show` displays a code a local client staged (a one-time authenticator code, a pairing code) as a server-rendered distorted image, so the code never reaches the page as text and a screen scraper cannot lift it. Separately, every CLI command now survives its terminal closing, so a notification, popup or query raised by a detached process still lands.

## Contents

- [Show code - CLI](#show-code---cli)
- [Show code - render endpoint](#show-code---render-endpoint)
- [Show code - frontend command](#show-code---frontend-command)
- [Show code - renderer](#show-code---renderer)
- [Detached commands](#detached-commands)
- [API](#api)

## Show code - CLI

`jupyterlab-passkey show` reads a code from FILE or stdin, stages it in a one-shot relay under kind `code`, and raises a notification whose button runs `passkey:show`. Fire and forget, mirroring `copy` without `--block`.

- [x] **Stages the code** - reads FILE or stdin and stages it as relay kind `code` (`0600` on shm), value never on argv
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Notification carries only the nonce** - the payload holds `nonce` (and `label` if given), never the code; `commandId` is `passkey:show`, button label `Show the code`
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Fire and forget** - posts and returns `0`; no `--block`/`--timeout`, nothing waited on, a stderr note says the click is what shows it
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Strips one trailing newline** - exactly one, so a multi-line value survives intact
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Never echoes the code** - the value is absent from stdout
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Edge: empty input** - refuses with `nothing to show - the input was empty`, stages nothing
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Edge: stdin is a terminal** - refused with `refusing to read a code from a terminal`, stages nothing
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Edge: non-text stdin** - strict utf-8 decode, refused with `is not text`
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Edge: trigger fails** - a failed/interrupted trigger unstages the code, since the nonce dies with the process and no button was raised (BaseException-guarded)
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Edge: relay stage fails** - an `OSError` (full shm, keyctl quota, squatted dir) exits one line, not a traceback
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Edge: code too long** - a code over `relay.MAX_CODE_CHARS` (256) is refused before staging, so a mistaken `show` of a file cannot tie up the server rendering it; the limit boundary is accepted
  - log: 2026-07-24 implemented (v1.0.39), length cap added after bug-hunter review

## Show code - render endpoint

`POST <base>/jupyterlab-passkey-extension/render` reads the `code` relay once, renders it to a PNG, and returns only image bytes. Authenticated, one-shot.

- [x] **Returns a PNG** - `{"png": "<base64>"}` whose decode starts with the PNG magic
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **One-shot** - the relay is consumed on render; a second call `404`s
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Never returns the code as text** - the value appears nowhere in the response body, only as image bytes
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Never logged** - the code is absent from server logs at every level
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Authenticated** - a tokenless caller gets `403` and does not consume the relay
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Edge: nothing staged** - `404` when the nonce was never staged, already rendered, or expired
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Edge: bad / traversal nonce** - `400` on a nonce failing `^[A-Za-z0-9_-]{16,128}$`, reading and unlinking no outside file
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Edge: code too long** - a staged code over `relay.MAX_CODE_CHARS` (256) gets a clean `400` before any render, defending the event loop against a value staged by any other writer; the relay is consumed one-shot regardless
  - log: 2026-07-24 implemented (v1.0.39), length cap added after bug-hunter review
- [x] **Edge: relay backend failure** - a clean `500` (`relay backend unavailable`), never a traceback
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Edge: renderer failure** - Pillow imported inside the handler, so a render-time Pillow failure gives this one endpoint a clean `500`, not a traceback or a server-extension load failure; the relay is already consumed
  - log: 2026-07-24 implemented (v1.0.39)

## Show code - frontend command

`passkey:show` POSTs the nonce to `render` and shows the returned image in a dialog.

- [x] **Fetches the render** - POSTs `{nonce}` to `render` and reads `{png}`
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Shows the image** - sets an `<img>` `src` to `data:image/png;base64,<png>` inside a dialog with a Close button
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Label only, never the code** - a caller `label` is shown as text; the code is only ever the image
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Accessibility channel closed** - the image `alt` is empty by design, so the code does not re-enter the accessibility tree
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Edge: render fails** - a rejected fetch (e.g. `404` on a spent relay) propagates; no dialog is opened
  - log: 2026-07-24 implemented (v1.0.39)
- [ ] **End to end** - a real `passkey:show` shows an `<img>` and the code string is absent from the page DOM; the relay is consumed (Galata)
  - log: 2026-07-24 criterion added, verifying

## Show code - renderer

`render_code_png(text)` draws the code as a distorted, scraper-resistant PNG.

- [x] **Valid PNG** - returns bytes Pillow opens as a PNG with non-zero dimensions
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **No embedded text** - the code appears nowhere as literal bytes in the file (no text/metadata chunk)
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Distortion** - per-character jitter and rotation, colour variation, overlaid line and dot noise
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **No font file shipped** - `ImageFont.load_default(size=...)` (Pillow >= 10.1), with a fallback for older Pillow
  - log: 2026-07-24 implemented (v1.0.39)

## Detached commands

Every subcommand ignores `SIGHUP`, so a backgrounded command keeps waiting for its click after its terminal closes - notifications, popups and queries land the same attached or detached.

- [x] **SIGHUP ignored** - `_ignore_hangup()` sets `SIG_IGN` for `SIGHUP`; a delivered `SIGHUP` no longer terminates the process
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Installed before dispatch** - `main()` calls `_ignore_hangup()` before parsing/dispatching any command
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Std streams tolerant** - a closed or redirected stderr never crashes the command (`_say` drops a poisoned stream, pre-existing)
  - log: 2026-07-24 implemented (v1.0.39)
- [x] **Edge: non-POSIX / no SIGHUP** - best-effort; a platform without `SIGHUP` (Windows) or a non-main thread is a no-op, the command still works under `nohup`/`setsid`
  - log: 2026-07-24 implemented (v1.0.39)

## API

- `POST <base>/jupyterlab-passkey-extension/render` body `{nonce}` -> `{"png": "<base64 PNG>"}`; `400` bad nonce, `404` nothing staged / already rendered, `403` unauthenticated, `500` relay or renderer failure
- Relay kind `code`, keyctl TTL 900s; staged by `jupyterlab-passkey show`, consumed by the `render` endpoint
- Frontend command `passkey:show` args `{nonce, label?}`
