import { b64urlEncode, b64urlToBuf, mapCeremonyError } from '../passkey-util';

import { ISlot, IStatus, Proof, VaultApi, VaultError } from './api';

/**
 * The passkey ceremonies of the vault. The page runs them and sends the PRF
 * straight to the server, so the PRF never passes through the CLI or any relay.
 */

function random(bytes: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bytes);
  crypto.getRandomValues(out);
  return out;
}

/**
 * The passkey slots a request from `host` can use: WebAuthn takes one RP ID per
 * request, so only the slots registered for the most specific RP ID that is
 * `host` itself or a parent domain of it.
 */
export function matchingSlots(slots: ISlot[], host: string): ISlot[] {
  const usable = slots.filter(
    s =>
      s.type === 'passkey' &&
      s.rp_id &&
      s.cred_id &&
      s.prf_salt &&
      (host === s.rp_id || host.endsWith(`.${s.rp_id}`))
  );
  if (usable.length === 0) {
    return [];
  }
  const best = usable
    .map(s => s.rp_id as string)
    .sort((a, b) => b.length - a.length)[0];
  return usable.filter(s => s.rp_id === best);
}

/**
 * A registration that stopped after the browser created the passkey: that passkey
 * sits in the user's passkey manager with no slot. The message names it by the user
 * name it was created with, so a same-day retry is not deleted in its place.
 */
export class Unused extends VaultError {
  constructor(cause: unknown, user: string) {
    super(
      0,
      `${describeFailure(cause)}; the passkey your browser created ("${user}") is unused - you can delete it in your passkey manager`
    );
  }
}

/**
 * Said where a passkey is offered on a tab opened at an IP address, which cannot
 * hold one: where to open JupyterLab instead - at the hostnames the vault's passkeys
 * belong to, when it has any.
 */
export function ipAddressAdvice(slots: ISlot[] = []): string {
  const names = Array.from(
    new Set(
      slots
        .filter(s => s.type === 'passkey' && s.rp_id)
        .map(s => s.rp_id as string)
    )
  );
  // localhost is another place on another machine: say where it applies.
  const places = names.map(n =>
    n === 'localhost' ? 'localhost (when it runs on this computer)' : n
  );
  return names.length > 0
    ? `an IP address cannot hold a passkey - open JupyterLab at ${places.join(' or ')}, where your ${names.length > 1 ? 'passkeys are' : 'passkey is'} registered, or by its hostname over HTTPS`
    : 'an IP address cannot hold a passkey - open JupyterLab by its hostname over HTTPS, or at localhost when it runs on this computer';
}

/** A passkey belongs to a domain name: IPv4, or IPv6 as `location.hostname` gives it. */
export function isIpAddress(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[');
}

/** A ceremony failure as a sentence for the panel or the CLI. */
export function describeFailure(e: unknown): string {
  if (e instanceof VaultError) {
    return e.message;
  }
  const code = mapCeremonyError(e);
  if (code === 'not-allowed') {
    return 'the passkey request was cancelled or not allowed';
  }
  return `the passkey request failed (${code})`;
}

/**
 * A passkey request for any passkey registered for this hostname: the credential it
 * used and the PRF it returned, both base64url, for the server to check.
 */
export async function passkeyPrf(
  status: IStatus,
  host: string
): Promise<{ credId: string; prf: string }> {
  const slots = matchingSlots(status.slots, host);
  if (slots.length === 0) {
    throw new VaultError(
      0,
      isIpAddress(host)
        ? ipAddressAdvice(status.slots)
        : `no passkey is registered for ${host} - register one under Vault settings and security (the cog)`
    );
  }
  // Each slot has its own PRF salt, so the salt is chosen per credential.
  const evalByCredential: Record<string, { first: Uint8Array<ArrayBuffer> }> =
    {};
  for (const s of slots) {
    evalByCredential[s.cred_id as string] = {
      first: new Uint8Array(b64urlToBuf(s.prf_salt as string))
    };
  }
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: random(32),
      rpId: slots[0].rp_id,
      allowCredentials: slots.map(s => ({
        id: b64urlToBuf(s.cred_id as string),
        type: 'public-key' as const
      })),
      userVerification: 'required',
      extensions: { prf: { evalByCredential } }
    }
  })) as PublicKeyCredential;
  const first = cred.getClientExtensionResults().prf?.results?.first;
  if (!first) {
    throw new VaultError(
      0,
      'the authenticator returned no PRF - this passkey cannot unlock the vault'
    );
  }
  return {
    credId: b64urlEncode(cred.rawId),
    prf: b64urlEncode(first as ArrayBuffer)
  };
}

/** Unlock with any passkey registered for this hostname. */
export async function unlockWithPasskey(
  api: VaultApi,
  status: IStatus,
  host: string = location.hostname
): Promise<IStatus> {
  const { credId, prf } = await passkeyPrf(status, host);
  return api.unlockPasskey(credId, prf);
}

/** The password of `name`, read with a fresh passkey request for this hostname. */
export async function revealWithPasskey(
  api: VaultApi,
  status: IStatus,
  name: string,
  host: string
): Promise<string> {
  const { credId, prf } = await passkeyPrf(status, host);
  return api.revealPassword(name, credId, prf);
}

/**
 * Register a passkey with the vault, in two steps.
 *
 * `create` makes the credential; a `get` then evaluates a fresh PRF salt, because
 * several authenticators (Windows Hello among them) return a PRF only at `get`.
 * `confirm` runs between the two and must come from a click: some browsers accept
 * one WebAuthn request per user gesture. It is offered `label` as the passkey's name
 * (empty when none was given, so the user is asked rather than handed the hostname)
 * and returns the name chosen, or null when the user backs out; an empty name falls
 * back to the hostname. `proof` is what the server asks for a new slot.
 */
export async function registerPasskey(
  api: VaultApi,
  label: string,
  confirm: (suggested: string) => Promise<string | null>,
  proof: Proof,
  host: string
): Promise<void> {
  // Host and time in the user name, so the passkeys the OS manager lists for this
  // vault can be told apart - to the second, so can a retry and the unused passkey
  // a failed attempt left.
  const createdAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
  // The time first: an authenticator may cut the name at 64 bytes, and a long
  // hostname then loses its end, not the seconds.
  const user = `JupyterLab vault - ${createdAt} UTC - ${host}`;
  const created = (await navigator.credentials.create({
    publicKey: {
      challenge: random(32),
      rp: { id: host, name: 'JupyterLab vault' },
      user: { id: random(16), name: user, displayName: user },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },
        { alg: -257, type: 'public-key' }
      ],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required'
      },
      extensions: { prf: {} }
    }
  })) as PublicKeyCredential;

  try {
    const name = await confirm(label);
    if (name === null) {
      throw new VaultError(0, 'passkey registration cancelled');
    }

    const salt = random(32);
    const cred = (await navigator.credentials.get({
      publicKey: {
        challenge: random(32),
        rpId: host,
        allowCredentials: [{ id: created.rawId, type: 'public-key' }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: salt } } }
      }
    })) as PublicKeyCredential;
    const first = cred.getClientExtensionResults().prf?.results?.first;
    if (!first) {
      throw new VaultError(
        0,
        'the authenticator returned no PRF - it cannot hold a vault key; use another passkey'
      );
    }
    await api.addPasskey(
      {
        cred_id: b64urlEncode(created.rawId),
        rp_id: host,
        prf_salt: b64urlEncode(salt.buffer),
        prf: b64urlEncode(first as ArrayBuffer),
        label: name || host
      },
      proof
    );
  } catch (e) {
    throw new Unused(e, user);
  }
}
