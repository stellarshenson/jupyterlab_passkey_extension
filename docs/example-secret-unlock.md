# Example: seal a secret with a passkey (toy)

Bare-minimum end-to-end - register a passkey, seal a file with its WebAuthn PRF, read it back. All shell: the bridge only relays the ceremony, `openssl` does the crypto.

```bash
RP=your.jupyterlab.host

# helpers: run one passkey:run ceremony -> echo the relay JSON; make a nonce; pull a JSON field
pk()    { n=$(echo "$1" | sed -n 's/.*"nonce":"\([^"]*\)".*/\1/p'); r="/dev/shm/jlab-passkey-$(id -u)/$n.json"; rm -f "$r"
          jupyterlab-notify --now --no-auto-close --action Approve --cmd passkey:run --command-args "$1" >/dev/null
          echo "click the 'Approve' notification and approve the prompt..." >&2
          until [ -f "$r" ]; do sleep 0.4; done; cat "$r"; rm -f "$r"; }
non()   { head -c18 /dev/urandom | base64 | tr '+/' '-_' | tr -d '='; }
jget()  { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }

# 1. enroll: register a passkey, keep its cred_id and a fixed prf_salt
CRED=$(pk "{\"op\":\"create\",\"nonce\":\"$(non)\",\"rp_id\":\"$RP\",\"user\":{\"id\":\"$(non)\",\"name\":\"toy\",\"displayName\":\"Toy\"}}" | jget cred_id)
SALT=$(non)

# 2. seal: get the PRF, encrypt secret-key.txt with it
echo "s3cr3t-api-key-42" > secret-key.txt
PRF=$(pk "{\"op\":\"get\",\"nonce\":\"$(non)\",\"rp_id\":\"$RP\",\"cred_id\":\"$CRED\",\"prf_salt\":\"$SALT\"}" | jget prf)
openssl enc -aes-256-cbc -pbkdf2 -pass "pass:$PRF" -in secret-key.txt -out secret-key.enc

# 3. open: get the PRF again (one Hello), decrypt
PRF=$(pk "{\"op\":\"get\",\"nonce\":\"$(non)\",\"rp_id\":\"$RP\",\"cred_id\":\"$CRED\",\"prf_salt\":\"$SALT\"}" | jget prf)
openssl enc -d -aes-256-cbc -pbkdf2 -pass "pass:$PRF" -in secret-key.enc   # -> s3cr3t-api-key-42
```

Each `get` returns the same 32-byte PRF for a fixed credential and salt, so the key re-derives on demand and is never stored.

- **Enroll** - `create` registers the passkey; `cred_id` and a fixed `prf_salt` are the pair that reproduces the PRF
- **Seal** - one `get` yields the PRF; `openssl -pbkdf2 -pass pass:$PRF` stretches it to an AES-256 key and encrypts `secret-key.txt`
- **Open** - a second `get` with the same `cred_id` and `prf_salt` yields the identical PRF, so the same passphrase decrypts

- `cred_id` and `prf_salt` are not secret - store them beside `secret-key.enc`; both are useless without the passkey
- Windows Hello reports `prf_enabled:false` at step 1 (`create`) but returns the PRF at `get` - expected, so `get` is the real test

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
