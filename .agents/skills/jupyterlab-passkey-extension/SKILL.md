---
name: jupyterlab-passkey-extension
description: Passwords, API keys, passkeys and git credentials on a Jupyter server, through the `jupyterlab-passkey` CLI and the Python `Vault` class of jupyterlab_passkey_extension. Use when reading, storing or handing over a credential or token without printing it, taking a secret from the user in the browser, giving one to the user, when a local tool needs a passkey PRF or a passphrase typed in the browser, when installing the git credential helper, or when a user asks for a git credential, a git password, or to migrate git credentials into the vault.
---

# jupyterlab-passkey

Runs on Jupyter server machine. `vault`: encrypted passwords server keeps, unlocked by passkey, unlock password with authenticator code, unlock password with passkey that has no PRF (Password and passkey: password decrypts, server checks passkey), or recovery passphrase; read by git's credential helper. Bridge (`passphrase`, `copy`, `show`, `create`, `get`): one secret between browser and local process. Commands, flags, output, waits, errors, environment: `jupyterlab-passkey --help`, `jupyterlab-passkey vault <command> --help`. Read first.

## Rules

- Command output goes into transcript. Never `vault get` to screen. Value to command: `vault exec`. Value to user: `vault copy` or `vault show`
- Python keeps value in process: `from jupyterlab_passkey_extension.vault import Vault; Vault().get("github/api")`. Refusal raises `VaultClientError` from `jupyterlab_passkey_extension.vault.client`
- Never secret on command line. `--in-browser`: vault decides fields by kind of secret, two matching for a recovery passphrase being set, else one. `passphrase` asks once; you decide on `--twice` for a value being set. Agent shell has no terminal for hidden prompt
- Tell user before command that waits. Locked vault, passkey step or dialog raises notification; command blocks until user clicks. Parallel commands share one unlock notification, one click lets all go on. After an unlock notification nobody answered, a command needing the unlocked vault fails at once for 10 minutes, naming `jupyterlab-passkey vault unlock`; that command still asks. Notification starts `Asked by <name>:`: always pass `--caller "<your project>"` after the subcommand, every subcommand takes it, before `--` on `vault exec`, else it goes to the command; Python sets `JLAB_PASSKEY_CALLER` before `Vault()`; default project directory, never another project's name
- CLI posts only to the lab its environment names: `JUPYTER_SERVER_URL` (with `JUPYTER_SERVER_ROOT`) or `JUPYTERHUB_SERVICE_PREFIX`, which JupyterLab terminal sets, else `JUPYTER_PORT`. Keep them; never unset them or point `JUPYTER_PORT` at another server. On `no running Jupyter server matches` or `cannot tell which running Jupyter server is the lab`: tell user, ask which lab; never pick a port yourself
- No vault at the path: `list`, `get`, `add`, `edit`, `rm`, `copy`, `show`, `exec`, `import` of a file, `passkey rm` and `git migrate` offer set-up when stdin and stdout are a terminal, then run; declining, or no terminal, fails with the no-vault error
- Never ask user for recovery passphrase in chat. Use `vault unlock --recovery --in-browser`

## Git credentials

- Set up: `jupyterlab-passkey vault git migrate` imports git's plaintext store into the vault, prints no secret, and puts `jupyterlab-passkey` first in the global `credential.helper`, which git runs as `git-credential-jupyterlab-passkey`; with nothing to import, `vault git install`; undo with `vault git uninstall`
- Check: `git config --get-all credential.helper` lists `jupyterlab-passkey` first, and `printf 'protocol=https\nhost=github.com\n' | git credential fill` answers with the matching entry's `username=` and `password=`
- Matching is by url host, path only under `credential.useHttpPath`; the helper follows gitcredentials(7); `vault git migrate --dry-run` lists without writing, and `--remove-source` asks at a terminal before deleting the plaintext file, which stays without it
- A git command can block on the user the same way; tell them before it runs
<!-- improved 2026-11-01 | body 333w / 18L -> 476w / 20L | benchmark n/a (not-requested) | via improve-skill -->
<!-- improved 2026-11-01 | body 476w / 20L -> 513w / 25L | benchmark n/a (not-requested) | via improve-skill -->
<!-- improved 2026-11-01 | body 513w / 25L -> 511w / 25L | benchmark n/a (not-requested) | via improve-skill -->
