<!-- Project overlay - imports BOTH configuration layers without duplicating their content -->
<!-- User-level (global, every project on this machine): /home/lab/.claude/CLAUDE.md -->
<!-- @import /home/lab/.claude/CLAUDE.md -->
<!-- Workspace-level (everything under /home/lab/workspace): /home/lab/workspace/.claude/CLAUDE.md -->
<!-- @import /home/lab/workspace/.claude/CLAUDE.md -->

# Project-Specific Configuration - jupyterlab_passkey_extension

This file is a thin overlay. It imports the two configuration layers above and does not
duplicate their content:

- **User-level** (`/home/lab/.claude/CLAUDE.md`) - global rules for every project on this machine
- **Workspace-level** (`/home/lab/workspace/.claude/CLAUDE.md`) - rules for everything under `/home/lab/workspace`

All rules from both layers apply. Those `.claude/` directories carry additional instruction
files and skills referenced by their CLAUDE.md - consult them to discover every applicable
standard. Project-specific rules below strengthen or extend those layers.

## Mandatory Bans (Reinforced)

The following workspace rules are STRICTLY ENFORCED for this project:

- **No automatic git tags** - only create tags when user explicitly requests
- **No automatic version changes** - only modify version in package.json/pyproject.toml/etc. when user explicitly requests
- **No automatic publishing** - never run `make publish`, `npm publish`, `twine upload`, or similar without explicit user request
- **No manual package installs if Makefile exists** - use `make install` or equivalent Makefile targets, not direct `pip install`/`uv install`/`npm install`
- **No automatic git commits or pushes** - only when user explicitly requests

## Project Context

`jupyterlab_passkey_extension` is a JupyterLab 4 extension that bridges the passkey
(WebAuthn) capability of the user's browser or operating system to local clients with no
browser of their own - the JupyterLab terminal and the CLI or API clients running on the
Jupyter server. It runs the browser-side passkey ceremony and hands the result back to the
requesting local process. It is purpose-agnostic and performs no cryptography; callers
supply every parameter. It ships as a Python server extension plus an NPM frontend, both
named `jupyterlab_passkey_extension`.

- **Frontend** - TypeScript, `@jupyterlab/application`; one command `passkey:run` with args `{op:"get"|"create", nonce, rp_id, cred_id?, prf_salt?, user?}` runs the ceremony (optional PRF eval) and POSTs the result
- **Server** - `jupyter_server` Tornado handlers: one authenticated `POST <base>/jupyterlab-passkey/result` that writes a one-shot `0600` `/dev/shm/jlab-passkey/<nonce>.json` relay (never logged), plus `GET <base>/jupyterlab-passkey/health`
- **Trigger** - consumers invoke `passkey:run` via jupyterlab-notify (the notification button click supplies the required WebAuthn user gesture); this extension builds no request-submission surface of its own
- **Build/release** - versioned Makefile (currently v1.34), jupyter-releaser CI/CD workflows
- **Tests** - Jest (frontend), pytest (server), Playwright (`ui-tests/`)

## Mandatory Project Rules

- **Install with `make install`** - never run manual `pip install` / `jlpm install` / `yarn install` / `npm install`; use the Makefile targets (`make install`, `make build`, `make test`)
- **Repository initialised locally** - this project is its own git repository (`git init -b main`), created with an initial import of all artefacts
- **Commit `package.json` and `package-lock.json` together** - always stage and commit both lockfiles in the same commit; never split them across commits
- **Keep the Makefile current** - always check the local `Makefile` version against `/home/lab/workspace/private/jupyterlab/@utils/jupyterlab-extensions/Makefile` and update the local copy as soon as a newer version is found

## Required Global Skills

These global skills (at `/home/lab/.claude/skills/`) MUST be used when working on this project:

- **jupyterlab-extension** - extension development guidelines, CI/CD, jupyter-releaser, common caveats
- **my-browser** - browser automation for screenshots and UI verification

## Journal Rules (Project-Specific)

- **APPEND ONLY**: New journal entries MUST be appended at the end of the file, never inserted between existing entries
- Entries maintain strict chronological order by position - the last entry in the file is always the most recent work
- Never reorder, move, or insert entries out of sequence
- The Stellars **journal plugin** is the canonical tool for this file: create via `/journal:create`, append via `/journal:update`, archive via `/journal:archive`. The `journal:journal` skill auto-triggers on any mention of "journal" and runs `journal-tools check` after every write
- Direct edits to `JOURNAL.md` are a last resort - prefer the plugin so modus secundis format, continuous numbering and append-only order are enforced automatically

## Strengthened Rules

- **Makefile-first** - all install/build/test/clean operations go through the versioned Makefile; the Makefile stays in sync with the canonical `@utils/jupyterlab-extensions/Makefile`
- **Lockfiles paired** - `package.json` and `package-lock.json` are always committed together
- **jupyterlab-extension skill governs CI/CD** - follow it for jupyter-releaser, testing strategy, and TypeScript compatibility caveats
