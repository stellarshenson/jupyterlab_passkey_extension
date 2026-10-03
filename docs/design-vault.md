# jupyterlab_passkey_extension - Password vault design v1

Status: current for release 1.1.2, 2026-09-29.

## Contents

- [1. Overview](#1.-Overview)
- [2. Components](#2.-Components)
- [3. Vault file](#3.-Vault-file)
  - [3.1 File format](#3.1-File-format)
  - [3.2 Encryption and slots](#3.2-Encryption-and-slots)
  - [3.3 Writes](#3.3-Writes)
- [4. Unlock and lock](#4.-Unlock-and-lock)
  - [4.1 Unlock paths](#4.1-Unlock-paths)
  - [4.2 Key holders](#4.2-Key-holders)
  - [4.3 Unlock duration and lock](#4.3-Unlock-duration-and-lock)
- [5. Passkeys and hostnames](#5.-Passkeys-and-hostnames)
- [6. Proof requirements](#6.-Proof-requirements)
- [7. Reading values](#7.-Reading-values)
- [8. REST API](#8.-REST-API)
- [9. Clients](#9.-Clients)
  - [9.1 CLI](#9.1-CLI)
  - [9.2 Python API](#9.2-Python-API)
  - [9.3 Panel](#9.3-Panel)
- [10. Security limits](#10.-Security-limits)
- [11. Configuration](#11.-Configuration)

## 1. Overview

This section states what the vault is and which parts take part in it. The vault is one encrypted file of passwords per user. The Jupyter server keeps it, and a passkey, the unlock password with a code of the authenticator app, or the recovery passphrase opens it.

- **One owner of the file** - only the Jupyter server process reads and writes the vault file; every client calls its REST API
- **Three clients** - the `jupyterlab-passkey vault` CLI, the Python `Vault` class and the sidebar panel
- **Three ways in** - a passkey added for the hostname of the browser tab, the unlock password together with a code of the authenticator app, or the recovery passphrase
- **One unlock for all clients** - an unlock keeps the data key for the unlock duration (default 240 minutes), and the CLI, the Python class and the panel all use that one unlock
- **Passkey steps run in the tab** - WebAuthn runs only in a browser tab after a click, so the CLI and the Python class raise a notification, and its button starts the passkey step in the tab. The notification starts with the name of the project that asked (`Asked by <name>:`, see the [CLI reference](cli-reference.md)); the name is the caller's statement, not a proof

```mermaid
%%{init: {'themeCSS': '.cluster-label span, .cluster-label text, .edgeLabel span {color:var(--jp-ui-font-color1, var(--vscode-editor-foreground, var(--fgColor-default, #1f2937))); fill:var(--jp-ui-font-color1, var(--vscode-editor-foreground, var(--fgColor-default, #1f2937)))} @media (prefers-color-scheme: dark){.cluster-label span, .cluster-label text, .edgeLabel span {color:var(--jp-ui-font-color1, var(--vscode-editor-foreground, var(--fgColor-default, #e5e7eb))); fill:var(--jp-ui-font-color1, var(--vscode-editor-foreground, var(--fgColor-default, #e5e7eb)))}}'}}%%
flowchart LR
    subgraph TERM["Terminal or notebook"]
        direction TB
        CLI[jupyterlab-passkey vault]:::act
        PY[Python Vault class]:::act
    end
    subgraph TAB["Browser tab"]
        direction TB
        PANEL[Vault panel]:::act
        CMD[Vault commands<br/>passkey:vault-unlock<br/>passkey:vault-register]:::act
    end
    subgraph SRV["Jupyter server"]
        direction TB
        NOTIF[Notifications extension]:::data
        REST[REST handlers<br/>vault/action]:::model
        SVC[VaultService]:::model
        HOLD[(Key holder<br/>keyctl, gpg-agent or memory)]:::data
    end
    FILE[(vault.json)]:::data
    CLI -->|REST| REST
    PY -->|REST| REST
    CLI -->|notification| NOTIF
    NOTIF -->|button click| CMD
    CMD -->|PRF| REST
    PANEL -->|REST| REST
    REST --> SVC
    SVC --> HOLD
    SVC --> FILE
    classDef data fill:#FFFFFF,stroke:#6B7280,color:#111,font-size:9px
    classDef model fill:#3B82F6,stroke:#2563EB,color:#fff,font-size:9px
    classDef act fill:#10B981,stroke:#047857,color:#fff,font-size:9px
    style TERM fill:none,stroke:#6b7280,stroke-width:3px
    style TAB fill:none,stroke:#6b7280,stroke-width:3px
    style SRV fill:none,stroke:#6b7280,stroke-width:3px
    linkStyle default stroke-width:2.3px
```

_Fig 1 - Vault components and the calls between them_

## 2. Components

This section lists the modules of the vault and the job of each. Paths are relative to the repository root.

| Component                  | Location                                         | Description                                                                       |
| -------------------------- | ------------------------------------------------ | --------------------------------------------------------------------------------- |
| File format and encryption | `jupyterlab_passkey_extension/vault/store.py`    | reads, encrypts and writes `vault.json`                                           |
| Authenticator codes        | `jupyterlab_passkey_extension/vault/totp.py`     | computes and checks the codes of the authenticator app                            |
| Key holders                | `jupyterlab_passkey_extension/vault/holders.py`  | keep the data key while the vault is unlocked                                     |
| Vault service              | `jupyterlab_passkey_extension/vault/service.py`  | unlock, lock, entries, slots and proofs; the only code that opens the file        |
| REST handlers              | `jupyterlab_passkey_extension/vault/handlers.py` | map each `vault/<action>` request to the service                                  |
| Client                     | `jupyterlab_passkey_extension/vault/client.py`   | REST calls and the notification step, shared by the CLI and the Python class      |
| CLI                        | `jupyterlab_passkey_extension/vault/cli.py`      | the `jupyterlab-passkey vault` subcommands                                        |
| Panel                      | `src/vault/panel.ts`, `src/vault/dialogs.ts`     | entry list, entry forms, and the settings and security view (the cog)             |
| Passkey steps              | `src/vault/webauthn.ts`                          | new passkey, unlock and proof requests to the authenticator                       |
| Authenticator setup        | `src/vault/totp.ts`                              | the setup key of a new authenticator app and its QR code                          |
| Commands                   | `src/vault/plugin.ts`                            | `passkey:vault-unlock` and `passkey:vault-register`, run by a notification button |

## 3. Vault file

This section describes the file on disk, how its contents are encrypted, and how a change is written. The file is `$XDG_DATA_HOME/jupyterlab-passkey/vault.json` (`~/.local/share/jupyterlab-passkey/vault.json` by default), or the path in `JLAB_PASSKEY_VAULT`.

### 3.1 File format

The file is one JSON document with format version 1.

```json
{
  "format": "jupyterlab-passkey-vault",
  "version": 1,
  "id": "<16 hex characters>",
  "slots": [
    {
      "type": "recovery",
      "kdf": "scrypt",
      "n": 131072,
      "r": 8,
      "p": 1,
      "salt": "<base64>",
      "wrapped": "<base64>"
    },
    {
      "type": "passkey",
      "cred_id": "<base64url>",
      "rp_id": "<hostname>",
      "prf_salt": "<base64url>",
      "hkdf_salt": "<base64>",
      "created": "<ISO 8601 UTC>",
      "wrapped": "<base64>",
      "label": "<text>"
    },
    {
      "type": "password",
      "kdf": "scrypt",
      "n": 131072,
      "r": 8,
      "p": 1,
      "salt": "<base64>",
      "created": "<ISO 8601 UTC>",
      "wrapped": "<base64>"
    }
  ],
  "entries": "<base64: 12-byte nonce + AES-256-GCM ciphertext>",
  "authenticator": {
    "created": "<ISO 8601 UTC>",
    "secret": "<base64: 12-byte nonce + AES-256-GCM ciphertext>"
  }
}
```

- **`id`** - random per vault; it names the data key in the key holder, so two vaults of one user never read each other's key
- **`slots`** - one recovery slot, zero or more passkey slots, and at most one unlock password slot, which is added and removed together with `authenticator`
- **`entries`** - all entries, names included, encrypted as one JSON list
- **`authenticator`** - present only while the vault has an authenticator app; its secret is encrypted, so a locked vault tells that an app exists and since when, nothing more
- **Entry fields** - `name`, `username`, `password`, `url`, `category`, `notes`, `created`, `updated`
- **Limits** - a name is at most 200 printable characters; a field is at most 65,536 characters

### 3.2 Encryption and slots

The data key is 32 random bytes that encrypt the entries. Each slot holds one copy of the data key, encrypted under a key derived from one secret.

| Item          | Encrypted under               | Algorithm                                                                                                |
| ------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------- |
| Entries       | the data key                  | AES-256-GCM, 12-byte nonce                                                                               |
| Recovery slot | the recovery passphrase       | scrypt with n = 131,072, r = 8, p = 1 and a 16-byte salt (128 MiB of memory per guess), then AES-256-GCM |
| Passkey slot  | the PRF output of the passkey | HKDF-SHA256 with a 16-byte salt, then AES-256-GCM                                                        |
| Password slot | the unlock password           | scrypt with the same parameters as the recovery slot, then AES-256-GCM                                   |
| App secret    | the data key                  | AES-256-GCM, 12-byte nonce, with associated data of its own                                              |

- **PRF** - the WebAuthn PRF extension: the authenticator returns 32 bytes computed from the passkey and the slot's `prf_salt`; the same passkey and salt always return the same bytes
- **Any slot decrypts the data key** - every slot holds the same one
- **The authenticator app is no slot** - its secret is data inside the vault, not a key to it. A code takes no part in the encryption: the password slot decrypts the data key, and the server keeps that key only for a right code
- **Slot changes leave the entries as they are** - adding or removing a slot never re-encrypts the entries
- **Slot fields are authenticated** - every slot field except `wrapped` and `label` is bound to the encryption as associated data, so a changed salt, cost, credential id or hostname fails to open
- **Cost per slot** - each recovery slot stores its own scrypt parameters, so a higher cost for new slots leaves existing slots readable

### 3.3 Writes

Every change is a read, a change and a write under one exclusive lock.

- **Lock** - `flock` on `<vault>.lock` beside the file
- **Write** - a temporary file in the same directory, `fsync`, mode `0600`, rename over the vault, `fsync` of the directory
- **Wrong key** - a write first decrypts the current entries with the data key it holds, so a wrong key never overwrites the file
- **Directory** - created with mode `0700` when it does not exist

## 4. Unlock and lock

This section describes how the server takes the data key out of a slot, where it keeps the key, and how the key is removed.

### 4.1 Unlock paths

The server decrypts the data key from one slot and puts it in the key holder for the unlock duration. Four requests do this.

- **Passkey** - the tab sends one WebAuthn request that offers the passkeys added for its hostname (section 5), each with its own `prf_salt`; it then sends the `cred_id` and the PRF to `POST vault/unlock`
- **Recovery passphrase** - `POST vault/unlock` with the passphrase; the CLI reads it from a hidden prompt, from stdin, or from a browser dialog with `--in-browser`
- **Unlock password and code** - `POST vault/unlock` with the password and a code of the authenticator app. The server decrypts the data key with the password, reads the app's secret with that key, and puts the key in the holder only for a right code that was not used before. The CLI asks both with `vault unlock --password`, at a terminal or with `--in-browser`
- **Create** - `POST vault/init` creates the vault and leaves it unlocked

When the CLI or the Python class starts a passkey unlock, the PRF goes from the tab to the vault endpoint. The result relay (a kernel key, or a `0600` file in `/dev/shm`) carries only `ok` or the error line back to the CLI.

```mermaid
%%{init: {'themeVariables': {'fontSize': '8px'}}}%%
sequenceDiagram
    participant C as CLI or Python Vault
    participant S as Jupyter server
    participant T as Browser tab
    participant A as Authenticator
    C->>S: GET vault/status
    C->>S: POST notification: button runs passkey:vault-unlock with a nonce
    S-->>T: notification shown
    T->>T: user clicks the button
    T->>A: WebAuthn get with the PRF salt of each matching slot
    A-->>T: cred_id and PRF, after the user approves
    T->>S: POST vault/unlock with cred_id and PRF
    S->>S: decrypt the data key, put it in the key holder
    T->>S: POST result with the nonce and ok
    S-->>C: result relay with ok
    C->>S: GET vault/status
```

_Fig 2 - A passkey unlock started from the CLI_

### 4.2 Key holders

The server keeps the data key in the first key holder that works on the host, tried in the order keyctl, gpg-agent, memory. Hosts differ: a seccomp profile can forbid the kernel keyring, and GnuPG can be missing.

| Capability               | keyctl              | gpg-agent                                                                 | memory                                     |
| ------------------------ | ------------------- | ------------------------------------------------------------------------- | ------------------------------------------ |
| Where the key is         | kernel keyring `@u` | a gpg-agent with its own GnuPG home                                       | Jupyter server process memory              |
| Never in swap            | yes                 | measured on the agent process                                             | yes with `memfd_secret` or `mlock`         |
| Never in crash dumps     | yes                 | measured on the agent process                                             | yes with `memfd_secret` or `MADV_DONTDUMP` |
| Expires on its own       | yes, kernel timeout | yes, agent `max-cache-ttl`                                                | no, a timer in the server removes it       |
| Locks on server restart  | no                  | no                                                                        | yes                                        |
| Isolated from containers | no                  | yes when the agent socket is outside `$XDG_STATE_HOME/jupyterlab-passkey` | yes                                        |

- **Choice** - `JLAB_PASSKEY_VAULT_HOLDER` pins `keyctl`, `gpg-agent` or `memory`; a pinned holder that does not work is an error
- **keyctl test** - keyctl is chosen only after a real add, search and read of a test key succeeds
- **gpg-agent** - a separate agent under `$XDG_STATE_HOME/jupyterlab-passkey/gnupg`, never the user's `~/.gnupg` one, because its `max-cache-ttl` would change the user's own gpg and ssh caching
- **Protection level** - `strong` when the key is kept out of swap and out of crash dumps, `reduced` with one of the two, `basic` with neither
- **Shown to the user** - `vault status` and the cog view show the chosen holder and each capability; when the memory holder is chosen, the server logs why gpg-agent was skipped and the panel shows the same line

### 4.3 Unlock duration and lock

This subsection covers how long a key stays and what removes it earlier.

- **Duration** - the `unlockMinutes` setting, 1 to 1,440 minutes, default 240
- **Storage** - the panel sends the setting to `POST vault/config`, together with `passwordMinLength`, and the server stores both in `$XDG_STATE_HOME/jupyterlab-passkey/vault-config.json`
- **When it applies** - at the next unlock from any client; a key already held keeps its expiry
- **Lock** - `vault lock`, `Vault.lock()` or the panel's Lock button removes the key from the holder
- **Server restart** - with keyctl or gpg-agent the key can stay held after a restart until the duration ends; with the memory holder a restart locks the vault

## 5. Passkeys and hostnames

This section describes which hostname a passkey belongs to. WebAuthn binds each passkey to one relying-party id (RP ID), and the vault uses the hostname of the browser tab as that id.

- **Source of the hostname** - the tab reads `location.hostname` for a new passkey, unlock, reveal and proof; the server stores the `rp_id` the tab sends
- **Proxies** - the server reads no `Host` or `X-Forwarded-Host` header, so a server on localhost behind a chain of proxies records the hostname in the user's address bar
- **Scope** - a passkey opens the vault from its hostname or from a subdomain of it
- **Most specific hostname** - WebAuthn takes one RP ID per request, so the tab offers the passkeys of the longest hostname that has a passkey and matches
- **One passkey per hostname** - JupyterLab opened at two hostnames needs a passkey added at each
- **IP address** - a tab at an IP address such as `127.0.0.1` cannot use a passkey; the tab refuses and names the hostnames that have passkeys
- **Two requests to add a passkey** - a WebAuthn `create` makes the passkey, then a `get` with a new random `prf_salt` returns the PRF, because some authenticators, Windows Hello among them, return a PRF only at `get`
- **Two dialogs to add a passkey** - the user names the passkey in a dialog before the `create`, and confirms it in a second dialog before the `get`; each button is the click the browser needs for its request
- **Name in the passkey manager** - `JupyterLab vault - <UTC time> - <hostname>`, so two passkeys of one vault can be told apart
- **No PRF** - an authenticator that returns no PRF cannot hold a vault key; adding it fails and the panel names the passkey the browser created, so the user can delete it

## 6. Proof requirements

This section lists which requests need a proof. A proof is sent with the request and is one of three: a passkey answer (`cred_id` and PRF), the current recovery passphrase, or a code of the authenticator app. From the first two the server decrypts the data key itself instead of taking it from the holder. A code holds no key, so it is a proof only while the vault is unlocked: the server checks it against the app's secret and takes the data key from the holder. The unlock password alone is a fourth proof for one request only, showing a password in the panel. For 60 seconds after a browser tab unlocked the vault or had a proof accepted, that tab's panel shows a password with no proof. A locked vault shows no password, whatever the proof. Every request also needs the Jupyter server token.

| Request                                   | Needs                                                                                                              |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Add a passkey                             | a proof                                                                                                            |
| Replace the recovery passphrase           | a proof                                                                                                            |
| Show a password in the panel              | an unlocked vault, and a proof or the unlock password; neither in the minute after an unlock or a proof in the tab |
| Add the password and authenticator app    | a proof, the new password, and the code the app shows for its secret                                               |
| Remove a passkey                          | an unlocked vault                                                                                                  |
| Remove the password and authenticator app | an unlocked vault                                                                                                  |
| Read, add, edit or delete an entry        | an unlocked vault                                                                                                  |
| Change the unlock duration                | nothing more                                                                                                       |

The vault's unlock methods, and what each may do:

| Unlock method                  | How many                      | Unlocks the vault                     | Shows a password in the panel, vault unlocked | Adds an unlock method, changes the recovery passphrase           |
| ------------------------------ | ----------------------------- | ------------------------------------- | --------------------------------------------- | ---------------------------------------------------------------- |
| Recovery passphrase            | exactly one, never removed    | yes                                   | yes                                           | yes                                                              |
| Passkey                        | any number, one hostname each | yes                                   | yes                                           | yes                                                              |
| Password and authenticator app | at most one pair              | yes, the password and a code together | yes, a code alone or the password alone       | a code alone, while the vault is unlocked; the password alone no |

- **One rule on the server** - `PROOFS` in `service.py` names the kinds of proof and the one that proves a reveal only; the REST handler and the two refusals that list the proofs read it
- **Why a proof** - a new passkey and a new recovery passphrase each open the vault later, an authenticator app proves both, and an unlocked vault proves nothing about who asks now
- **Order in the tab** - a passkey added for the tab's hostname first. With none, or when the passkey request gets no answer or returns no PRF: a code when the vault has an app and is unlocked, with a button for the recovery passphrase; otherwise the recovery passphrase
- **Order in the entry dialog** - a passkey added for the tab's hostname first. With none, or no answer: a row under the password asks a code when the vault has an app, with a link to the unlock password, then to the recovery passphrase, and from the last of them back to the first
- **No second proof for a minute** - for 60 seconds after a tab unlocked the vault or had a proof accepted (a password shown, a passkey or the pair added, the recovery passphrase changed), the eye in that tab shows a password and asks nothing: the person at the screen has just proven. A new unlock method and a recovery passphrase change ask their proof in that minute too. The minute ends after 60 seconds, when the tab locks the vault and when the page is reloaded. An unlock that this tab did not send - one the CLI sends itself (`--password`, `--recovery`) or one in another tab - starts no minute in this tab; a passkey unlock or a new passkey that the CLI raises is done by this tab and starts one
- **The tab counts the minute** - the eye's proof is asked by the tab, so the tab keeps the time of its last unlock or proof (`VaultApi.proven`). In the minute the eye sends the plain read that `vault get` sends. The server answers that read for every request on an unlocked vault, so a count kept on the server would refuse nothing
- **The pair's flow** - the panel asks the new unlock password twice, then the proof, then shows the app's QR code and asks its code. The code is typed last, because the server checks it with the request and a code stays right for less than a minute. The proof is checked with that same request, after the app took the setup key: when the server refuses the request for another reason than a wrong code (a wrong recovery passphrase, a pair added elsewhere meanwhile), the panel's line says that the entry the app added is unused, so the user can delete it. A lost answer and a 5xx answer get no such sentence, because the pair may have been added
- **A code can expire where the proof comes first** - a new passkey and a recovery passphrase change ask the proof before their other steps (a name and two passkey prompts; the new passphrase typed twice). A code typed there is refused as `wrong code` when those steps take longer than the code stays right, and that refusal counts as a wrong code. The code dialog's Use recovery passphrase button gives the proof that does not expire; after a refused new passkey the panel names the passkey the browser created, so the user can delete it
- **No relay** - the tab asks for the proof itself, so no secret reaches the page through a relay
- **Unlock password** - it opens the vault only together with a code. Alone it shows a password on an unlocked vault, and it is refused as a proof for a new passkey, a new pair and a recovery passphrase change
- **A code is a check, not encryption** - a code has six digits and changes every 30 s, so it cannot be key material. The password slot alone decrypts the data key; the server refuses to keep that key without a right code. What that leaves open is in [10. Security limits](#10.-Security-limits)
- **One pair** - the vault holds at most one unlock password and one authenticator app, added in one request and removed in one. The tab creates the app's secret (160 bits), shows it as a QR code and as a setup key, and the server stores the two only for a right code and a proof. A new password or a new phone means Remove, then add again
- **Vaults of 1.1.28 to 1.1.31** - those builds added the password and the app apart from each other. A password with no app still unlocks alone; the panel's row and `vault status` say which half is there, and Remove removes it
- **Codes** - RFC 6238 with HMAC-SHA-1, 6 digits and a 30 s time step, the parameters every authenticator app supports. The step before and the step after the current one are accepted
- **A code is accepted once** - the server refuses a code of a time step at or before the last one it accepted, so the code that unlocked the vault or added the pair is refused as a proof until the app shows its next code. The minute with no second proof keeps the eye clear of this in the tab that unlocked or proved: when that tab asks a proof again, the app shows a later code. After an unlock from the CLI or in another tab the eye can get this refusal; its line says to wait for the next code, and the unlock password shows the password without a wait
- **Five wrong codes** - after five wrong codes in a row the server refuses every code, at unlock too, until the vault is unlocked with a passkey or the recovery passphrase; a passkey and the recovery passphrase still prove, and the unlock password alone still shows a password. Both counts are in the server's memory and start again when the server does

## 7. Reading values

This section describes the path each value takes out of the vault. A listing never carries passwords.

| Request                     | Path of the value                                                                                                        | Where it ends                                                       |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- |
| `vault get`, `Vault.get()`  | REST answer to the client process                                                                                        | stdout of the CLI, or a Python string                               |
| `vault exec --env VAR=NAME` | REST answer to the CLI process                                                                                           | the environment of the command; the CLI process becomes the command |
| `vault copy`                | server stages it in the relay; the tab collects it on the click                                                          | the browser clipboard                                               |
| `vault show`                | server stages it in the relay; the tab collects it on the click                                                          | a distorted image in the tab                                        |
| Panel eye button            | a proof asked in the entry dialog, or none in the minute after an unlock or a proof in the tab; then `POST vault/reveal` | the entry dialog                                                    |
| `vault list`, panel list    | REST answer                                                                                                              | names and fields without passwords                                  |

- **copy and show** - the value never enters the CLI process
- **Staged value lifetime** - 900 s as a kernel key, or until the next reboot as a file in `/dev/shm` when keyctl does not work; `vault lock` does not remove a staged value
- **Relay** - the same one-shot relay as the bridge commands `copy`, `show` and `passphrase` (`jupyterlab_passkey_extension/relay.py`)

## 8. REST API

This section lists the endpoints. Each is `<base_url>/jupyterlab-passkey-extension/vault/<action>`, requires the Jupyter server token, and never logs a body, a value or a result.

| Method | Action            | Body or query                                                | Answer                    |
| ------ | ----------------- | ------------------------------------------------------------ | ------------------------- |
| GET    | `status`          | -                                                            | state, see below          |
| GET    | `entries`         | -                                                            | entries without passwords |
| GET    | `generate`        | `length` (8 to 256, default 24), `symbols` (`0` for none)    | a new password            |
| POST   | `config`          | `unlock_minutes`, `password_min_length`                      | 204                       |
| POST   | `init`            | `recovery`                                                   | 204                       |
| POST   | `unlock`          | `recovery`, or `password` and `code`, or `cred_id` and `prf` | state                     |
| POST   | `lock`            | -                                                            | 204                       |
| POST   | `entries`         | `name`, `fields`                                             | 204                       |
| PATCH  | `entries`         | `name`, `fields`; only the fields given change               | 204                       |
| POST   | `delete`          | `name`                                                       | 204                       |
| POST   | `reveal`          | `name` and `field`, or `name` and a proof's keys             | `value`                   |
| POST   | `stage`           | `name`, `field`, `kind` (`secret` or `code`)                 | `nonce`                   |
| POST   | `import`          | `entries`, a list of entry objects                           | `added`, `skipped`        |
| POST   | `passkeys`        | `cred_id`, `rp_id`, `prf_salt`, `prf`, `label`, `proof`      | 204                       |
| POST   | `passkeys-remove` | `cred_id`                                                    | 204                       |
| POST   | `recovery`        | `recovery`, `proof`                                          | 204                       |
| POST   | `mfa`             | `password`, `secret` (the setup key), `code`, `proof`        | 204                       |
| POST   | `mfa-remove`      | -                                                            | 204                       |

- **State** - `initialized`, `unlocked`, `remaining` seconds, `holder` with its capabilities, slot fields without the wrapped keys and salts, `authenticator` with the date the app was added or null, `settings`, `path`, `revision`
- **A proof's keys** - `cred_id` and `prf`, or `current` (the recovery passphrase), or `code`, or for a `reveal` only `password` (the unlock password); `proof` is an object of the same keys. A `reveal` with none of them is the plain read: the CLI's `vault get`, and the panel's eye in the minute after an unlock or a proof. A `reveal` on a locked vault answers 423, whatever the proof
- **`revision`** - the first 16 hex characters of a SHA-256 of the encrypted entries; it changes with every entry change, and it tells nothing about the entries
- **Generated password** - leaves out `l I 1 | O 0`, quotes, backslash, backtick and space, because a user reads it off an image or types it on a phone
- **Errors** - the body is `{"error": "<one line>"}` with the status below

| Status | Meaning                                                                                                |
| ------ | ------------------------------------------------------------------------------------------------------ |
| 400    | refused: wrong passphrase, password or passkey at unlock, invalid input, no vault file                 |
| 403    | the proof did not open the vault, or the code is wrong, used, refused, or missing at a password unlock |
| 404    | no entry with that name, or no such action                                                             |
| 409    | an entry with that name exists, or the vault already has a password and authenticator app              |
| 423    | the vault is locked                                                                                    |
| 500    | a key holder or file failure; the log line names the action and the exception type only                |

## 9. Clients

This section describes what each client adds to the REST API.

### 9.1 CLI

The CLI is `jupyterlab-passkey vault <command>`. Its full reference is [cli-reference.md](cli-reference.md).

- **Server** - the first server that `jupyter server list` reports, with that server's token
- **No secret on the command line** - a new secret comes from a hidden prompt typed twice, from stdin, from a browser dialog with `--in-browser`, or from `--generate`
- **Locked vault** - a read raises the unlock notification, then runs once more
- **Waiting** - a browser step waits 120 s for the click by default, 600 s for `vault init` and `vault passkey add`
- **Agent skill** - `.agents/skills/jupyterlab-passkey-extension/SKILL.md`, also installed with the wheel, points an agent at `--help` and states which commands keep a value out of its output

### 9.2 Python API

The `Vault` class in `jupyterlab_passkey_extension.vault` uses the same REST calls as the CLI.

- **Methods** - `status()`, `list()`, `get(name, field="password")`, `unlock(recovery=None, password=None, code=None)`, `lock()`
- **Locked vault** - `get()` and `list()` raise the unlock notification, then run once more
- **Refusal** - raises `VaultClientError` with the one-line reason

### 9.3 Panel

The panel sits in the right sidebar by default; the `sidebar` setting moves it to the left.

- **Refresh** - while visible, it reads the state and, when unlocked, the entry list every 15 s, and at once when it is shown again
- **Changes from elsewhere** - a new `revision` or a changed slot list redraws the panel, so changes made from the CLI or another tab appear
- **Eye button** - for 60 seconds after an unlock or a proof in the tab, the eye shows the password at once. After that a password shows only after a proof, even when the vault is unlocked. The eye asks a passkey; while that request runs it shows a spinner and the line under the field reads `Waiting for your passkey`. With no passkey for the hostname, or no answer, a row under the field asks a code of the authenticator app, the unlock password or the recovery passphrase
- **Locked view** - Unlock with passkey when the hostname has one, Unlock with password when the vault has the pair (the password's dialog, then the code's), and a link for the recovery passphrase. A locked vault shows no entry
- **Cog view** - three sections: Security (the key holder and its capabilities), Unlock methods, and Settings (the unlock duration, the vault file and a button that opens the settings)
- **Unlock methods** - one row for each passkey (its name, date and hostname), one for the password and authenticator app, and one for the recovery passphrase. The first two have Remove, in two clicks; the recovery passphrase has Change. Add unlock method opens a dialog with one button for a passkey and one for a password and authenticator app, each with one short line under its name; a press on a button chooses that method, and the dialog's only other button is Cancel. The button of a second pair is disabled
- **Layout** - the geometry of the AI assistants panels (`jupyterlab_ai_code_assistants_extension`): fields and buttons 4 px from the panel border, text 18 px from it, header buttons and rows 24 px high, section headers as bands
- **Measured** - on 2026-10-02 in Chromium at a 250 px sidebar, in the Claude Code panel and the Codex panel of that extension, version 1.2.56 (one widget class, the same values in both): the title, a section label and a row's name start 18 px from the panel's left border; the header, a section header and a row have 4 px of padding on both sides (its variable `--aica-inset`, which its stylesheet also gives the search field as its margin); a row is 24 px high (`--aica-row-height`); a header button is 24 px wide and high; a section header is a band in the header's colour. The vault panel's Galata test reads the same values from the vault panel
- **Filter** - the header's filter button shows the filter field and puts the typing in it; pressing it again hides the field and clears the filter

## 10. Security limits

This section states what the vault does not protect against.

- **Jupyter token** - any process that has the token can read every entry while the vault is unlocked; `jupyter server list` shows the token to every process of the same user
- **Copied file** - a copy of `vault.json` can be attacked offline through the recovery slot and through the unlock password slot; scrypt makes each guess cost 128 MiB of memory, and a weak passphrase or password can still be guessed. The file is as strong as the weaker of the two secrets, which is why the unlock password has a minimum length. The authenticator code does not protect a copied file: whoever has the file and the unlock password decrypts it without a code
- **Authenticator code** - the server checks a code at a password unlock, and as a proof for a person at the panel on an unlocked vault. A code takes no part in the encryption and protects nothing at rest: it stops a person who has the unlock password and reaches the vault through the panel, the CLI or the REST API, and it does not stop one who has the password and a copy of the file. A process that has the Jupyter token reads entries with `vault get` without any proof, while the vault is unlocked
- **The minute with no second proof** - for 60 seconds after an unlock or a proof in a tab, a person at that tab shows any password with one click and no proof. Locking the vault in the tab ends the minute. The eye's proof checks the person at the screen and is no boundary against a process that has the Jupyter token, with or without the minute
- **Shared keyring** - with the keyctl holder, other containers that run as the same user id in the same user namespace can read the held key
- **Staged values** - an uncollected `copy` or `show` value outlives `vault lock`, see [7. Reading values](#7.-Reading-values)
- **Restart** - with keyctl or gpg-agent a key can outlive a server restart until the unlock duration ends
- **Two servers** - the CLI uses the first server; with two servers the notification can appear in a tab nobody watches, and the command times out

## 11. Configuration

This section lists the settings and environment variables of the vault. The server reads the environment variables, so they are set where the server starts.

| Setting                     | Default                                        | Effect                                                  |
| --------------------------- | ---------------------------------------------- | ------------------------------------------------------- |
| `JLAB_PASSKEY_VAULT`        | `$XDG_DATA_HOME/jupyterlab-passkey/vault.json` | path of the vault file                                  |
| `JLAB_PASSKEY_VAULT_HOLDER` | `auto`                                         | pins the key holder                                     |
| `XDG_STATE_HOME`            | `~/.local/state`                               | parent of the gpg-agent home and of `vault-config.json` |
| `unlockMinutes`             | 240                                            | unlock duration in minutes, 1 to 1,440                  |
| `passwordMinLength`         | 12                                             | fewest characters of an unlock password, 8 to 128       |
| `sidebar`                   | `right`                                        | sidebar that holds the panel                            |
