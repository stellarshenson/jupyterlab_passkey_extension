# Example: unlock a secret with a passkey

A local CLI seals a secret under a key derived from a WebAuthn PRF and recovers it through the bridge, with no browser of its own. Four steps below; the consumer does all crypto, the bridge only relays the ceremony result.

- **Consumer holds** - the sealed secret, the credential `cred_id`, a 32-byte `prf_salt` (both base64url)
- **Bridge holds** - nothing; it runs the ceremony and writes a one-shot relay file
- **PRF** - the 32-byte `HMAC(secret, prf_salt)` the authenticator returns; the secret never leaves the TPM / security element

## Steps

1. Generate a nonce and trigger the `get` ceremony via a notify button (the click supplies the WebAuthn gesture):

```bash
NONCE=$(python3 -c "import secrets,base64;print(base64.urlsafe_b64encode(secrets.token_bytes(18)).decode().rstrip('='))")
jupyterlab-notify --now --no-auto-close \
  --action "Unlock" --cmd "passkey:run" \
  --command-args "{\"op\":\"get\",\"nonce\":\"$NONCE\",\"rp_id\":\"your.host\",\"cred_id\":\"<b64url>\",\"prf_salt\":\"<b64url>\"}"
```

2. User clicks the button -> Windows Hello / security key prompt -> PRF evaluated in the page

3. Read the one-shot relay the server wrote (then delete it):

```bash
RELAY="/dev/shm/jlab-passkey-$(id -u)/$NONCE.json"
prf=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['prf'])" "$RELAY")
shred -u "$RELAY"
```

4. Derive the wrapping key and unwrap - `HKDF-SHA256(prf, salt=<store>)` -> AES-256 key -> decrypt the sealed secret, all in the consumer

> [!NOTE]
> To enrol, run `op: "create"` once for a `cred_id`, then one `op: "get"` with a fresh `prf_salt` to confirm PRF and derive the key. Windows Hello reports `prf_enabled: false` at create but yields the PRF at `get`, so the follow-up `get` is the authoritative test.
