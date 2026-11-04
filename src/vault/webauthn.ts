import { b64urlEncode, b64urlToBuf, mapCeremonyError } from '../passkey-util';

import {
  IAssertion,
  IRegistration,
  ISlot,
  IStatus,
  Proof,
  VaultApi,
  VaultError
} from './api';

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

/** The slot of Password and passkey this tab can use: one added at its exact origin. */
export function pairSlot(
  slots: ISlot[],
  origin: string = location.origin
): ISlot | undefined {
  return slots.find(s => s.type === 'password-passkey' && s.origin === origin);
}

/** The fields of a passkey's answer that the server checks, base64url. */
function assertionOf(cred: PublicKeyCredential): IAssertion {
  const response = cred.response as AuthenticatorAssertionResponse;
  return {
    cred_id: b64urlEncode(cred.rawId),
    client_data: b64urlEncode(response.clientDataJSON),
    authenticator_data: b64urlEncode(response.authenticatorData),
    signature: b64urlEncode(response.signature)
  };
}

/**
 * A signature of the passkey of Password and passkey over `challenge`, which the
 * server gave. No PRF is asked: this passkey has none.
 */
export async function passkeyAssertion(
  slot: ISlot,
  challenge: string
): Promise<IAssertion> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: new Uint8Array(b64urlToBuf(challenge)),
      rpId: slot.rp_id,
      allowCredentials: [
        { id: b64urlToBuf(slot.cred_id as string), type: 'public-key' }
      ],
      userVerification: 'required'
    }
  })) as PublicKeyCredential;
  return assertionOf(cred);
}

/**
 * The last request of a new unlock method got no answer, or a 5xx: the server may
 * have stored it, so the passkey is not called unused.
 */
class MaybeAdded extends VaultError {
  constructor() {
    super(
      0,
      'the server did not confirm the new unlock method - it may have been added; check under Vault settings and security (the cog)'
    );
  }
}

/** Only a 4xx answer proves that the request stored nothing. */
export async function stored(request: Promise<void>): Promise<void> {
  try {
    await request;
  } catch (e) {
    throw e instanceof VaultError && e.status >= 400 && e.status < 500
      ? e
      : new MaybeAdded();
  }
}

/** A new passkey with no PRF, for Password and passkey: its fields base64url. */
export interface INewPair {
  credId: string;
  registration: IRegistration;
  label: string;
  assertion: IAssertion;
}

/**
 * A registration that stopped after the browser created the passkey: that passkey
 * sits in the user's passkey manager with no slot. Unless the browser took the request
 * to remove it (`removed`), the message names it by the time in its name, to the
 * second, so a same-day retry is not deleted in its place. The notification never
 * loses the time (`fit`); the CLI gets the whole `message`.
 */
export class Unused extends VaultError {
  constructor(cause: unknown, createdAt: string, removed: boolean) {
    const reason = describeFailure(cause);
    const clause = removed
      ? ''
      : `; delete the unused passkey dated ${createdAt}`;
    super(0, reason + clause, fit(reason, clause));
  }
}

/**
 * `reason` then `clause` as a notification shows them: 140 characters, the panel's
 * full stop one of them. A reason too long for both is cut and ends in `…`; the
 * clause, which names what the user must delete, stays whole.
 */
export function fit(reason: string, clause: string): string {
  const room = 139 - clause.length;
  return reason.length > room
    ? `${reason.slice(0, room - 1)}…${clause}`
    : reason + clause;
}

/**
 * Ask the browser to remove a passkey no slot holds, where it has
 * `PublicKeyCredential.signalUnknownCredential`. True when the browser took the
 * request, which does not prove the passkey is gone.
 */
async function forget(
  rpId: string,
  credentialId: ArrayBuffer
): Promise<boolean> {
  const api = (
    globalThis as {
      PublicKeyCredential?: {
        signalUnknownCredential?: (options: {
          rpId: string;
          credentialId: string;
        }) => Promise<void>;
      };
    }
  ).PublicKeyCredential;
  if (typeof api?.signalUnknownCredential !== 'function') {
    return false;
  }
  try {
    await api.signalUnknownCredential({
      rpId,
      credentialId: b64urlEncode(credentialId)
    });
    return true;
  } catch {
    return false;
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
    ? `an IP address cannot hold a passkey - open JupyterLab at ${places.join(' or ')}, where your ${names.length > 1 ? 'passkeys were' : 'passkey was'} added, or by its hostname over HTTPS`
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
        : `no passkey was added for ${host} - add one under Vault settings and security (the cog)`
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

/** The unlock this tab is running, whichever button started it. */
let unlocking: Promise<unknown> | null = null;

/**
 * Run `unlock`, or join the one this tab is running: a click during an unlock must not
 * open a second passkey prompt.
 */
export function shareUnlock(unlock: () => Promise<unknown>): Promise<unknown> {
  unlocking ??= unlock().finally(() => {
    unlocking = null;
  });
  return unlocking;
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

/**
 * Register a passkey with the vault, in two steps.
 *
 * `create` makes the credential; a `get` then evaluates a fresh PRF salt, because
 * several authenticators (Windows Hello among them) return a PRF only at `get`.
 * `confirm` runs between the two and must come from a click: some browsers accept
 * one WebAuthn request per user gesture. It is shown the passkey's name and returns
 * false when the user backs out. `label` is the name the user chose before this
 * call; an empty one falls back to the hostname. `proof` is what the server asks
 * for a new slot. The `create` and the `get` sign `challenge`, which the server gave:
 * for a passkey with no PRF the server runs the WebAuthn registration steps on the
 * `create` and checks the signature of the `get`, and `noPrf` takes the flow on to
 * Password and passkey, with no further passkey prompt. `challenge` is undefined with
 * an assertion proof, which holds the one live challenge until the request uses it,
 * on a vault that has Password and passkey already. Resolves to the type of the slot
 * stored: `passkey`, or `password-passkey` when `noPrf` stored Password and passkey.
 */
export async function registerPasskey(
  api: VaultApi,
  label: string,
  confirm: (name: string) => Promise<boolean>,
  proof: Proof,
  host: string,
  noPrf: (pair: INewPair) => Promise<void>,
  challenge: string | undefined
): Promise<ISlot['type']> {
  const signed =
    challenge === undefined
      ? random(32)
      : new Uint8Array(b64urlToBuf(challenge));
  const name = label || host;
  // Host and time in the user name, so the passkeys the OS manager lists for this
  // vault can be told apart - to the second, so can a retry and the unused passkey
  // a failed attempt left.
  const createdAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
  // The time first: an authenticator may cut the name at 64 bytes, and a long
  // hostname then loses its end, not the seconds.
  const user = `JupyterLab vault - ${createdAt} UTC - ${host}`;
  const created = (await navigator.credentials.create({
    publicKey: {
      challenge: signed,
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
    if (!(await confirm(name))) {
      throw new VaultError(0, 'adding the passkey was cancelled');
    }

    const salt = random(32);
    const cred = (await navigator.credentials.get({
      publicKey: {
        challenge: signed,
        rpId: host,
        allowCredentials: [{ id: created.rawId, type: 'public-key' }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: salt } } }
      }
    })) as PublicKeyCredential;
    const first = cred.getClientExtensionResults().prf?.results?.first;
    if (!first) {
      const response = created.response as AuthenticatorAttestationResponse;
      await noPrf({
        credId: b64urlEncode(created.rawId),
        registration: {
          client_data: b64urlEncode(response.clientDataJSON),
          attestation_object: b64urlEncode(response.attestationObject)
        },
        label: name,
        assertion: assertionOf(cred)
      });
      return 'password-passkey';
    }
    await stored(
      api.addPasskey(
        {
          cred_id: b64urlEncode(created.rawId),
          rp_id: host,
          prf_salt: b64urlEncode(salt.buffer),
          prf: b64urlEncode(first as ArrayBuffer),
          label: name
        },
        proof
      )
    );
    return 'passkey';
  } catch (e) {
    if (e instanceof MaybeAdded) {
      // The server may hold this passkey's slot: removing the passkey could take
      // away a working unlock method.
      throw e;
    }
    // No request stored it: no slot request was sent, or a 4xx answer refused it.
    throw new Unused(e, `${createdAt} UTC`, await forget(host, created.rawId));
  }
}
