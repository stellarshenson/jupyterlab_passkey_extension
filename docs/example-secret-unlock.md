# Example: seal a secret with a passkey (toy)

Bare-minimum end-to-end - register a passkey, seal a file with its WebAuthn PRF, read it back. All shell: the CLI raises each notification and reads the relay (a kernel key or a `0600` file), the bridge only relays the ceremony, `openssl` does the crypto.

```bash
RP=your.jupyterlab.host

# 1. enroll: register a passkey, keep its cred_id and a fixed 32-byte prf_salt
CRED=$(jupyterlab-passkey create --rp-id "$RP") || exit 1
SALT=$(head -c32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')

# 2. seal: get the PRF, encrypt secret-key.txt with it
echo "s3cr3t-api-key-42" > secret-key.txt
PRF=$(jupyterlab-passkey get --rp-id "$RP" --cred-id "$CRED" --prf-salt "$SALT") || exit 1
printf '%s\n' "$PRF" | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in secret-key.txt -out secret-key.enc

# 3. open: get the PRF again (one Hello), decrypt
PRF=$(jupyterlab-passkey get --rp-id "$RP" --cred-id "$CRED" --prf-salt "$SALT") || exit 1
printf '%s\n' "$PRF" | openssl enc -d -aes-256-cbc -pbkdf2 -pass stdin -in secret-key.enc   # -> s3cr3t-api-key-42
```

Each `get` returns the same 32-byte PRF for a fixed credential and salt, so the key re-derives on demand and is never stored.

- **Enroll** - `create` registers the passkey; `cred_id` and a fixed `prf_salt` are the pair that reproduces the PRF
- **Seal** - one `get` yields the PRF; `openssl -pbkdf2 -pass stdin` reads it from the pipe, stretches it to an AES-256 key and encrypts `secret-key.txt`; `printf` is a shell builtin, so the PRF is on no process's argv
- **Open** - a second `get` with the same `cred_id` and `prf_salt` yields the identical PRF, so the same passphrase decrypts

- `cred_id` and `prf_salt` are not secret - store them beside `secret-key.enc`; both are useless without the passkey

## Recovery

The toy uses the PRF directly as the key, so a lost or reset passkey means `secret-key.enc` is unrecoverable. A real consumer keeps more than one way in - envelope encryption with independent keyslots:

```
secret ──sealed under──▶ random DEK (one key)
                            ▲
             wrapped per slot (either opens it):
             ├─ passkey slot:   AES( HKDF(PRF) )        ── daily
             └─ recovery slot:  AES( Scrypt(passphrase) ) ── offline break-glass
```

- **Envelope** - seal the secret under a random 32-byte DEK; wrap the DEK per slot, so adding or revoking a slot never re-seals the secret
- **Slots are OR, not AND** - passkey `HKDF(PRF)` for daily use, passphrase `Scrypt(...)` as break-glass; a lost passkey falls back to the passphrase, then re-enrol a new one
- **Store the recovery passphrase offline** - it is the single point of recovery if the authenticator dies
