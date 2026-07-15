import { ServerConnection } from '@jupyterlab/services';

import { requestAPI } from './request';

import { b64urlEncode, b64urlToBuf, mapCeremonyError } from './passkey-util';

export type PasskeyOp = 'get' | 'create';

export interface IPasskeyArgs {
  nonce: string;
  rp_id: string;
  cred_id?: string;
  prf_salt?: string;
  user?: { id: string; name: string; displayName: string };
}

/**
 * Run a WebAuthn passkey ceremony and relay the result to the server.
 *
 * Autogenerates a random 32-byte challenge (required-but-unused for our PRF
 * flow), runs navigator.credentials.get/create per `op`, maps the result and
 * any error per the bridge contract, and POSTs the JSON to the "result"
 * endpoint. The prf value is never logged.
 */
export async function runPasskey(
  op: PasskeyOp,
  args: IPasskeyArgs,
  serverSettings: ServerConnection.ISettings
): Promise<void> {
  const { nonce } = args;

  const post = (body: Record<string, unknown>): Promise<void> =>
    requestAPI<void>('result', serverSettings, {
      method: 'POST',
      body: JSON.stringify(body)
    });

  try {
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    if (op === 'get') {
      const publicKey: PublicKeyCredentialRequestOptions = {
        challenge,
        rpId: args.rp_id,
        allowCredentials: [
          { id: b64urlToBuf(args.cred_id!), type: 'public-key' }
        ],
        userVerification: 'required',
        extensions: args.prf_salt
          ? { prf: { eval: { first: b64urlToBuf(args.prf_salt) } } }
          : undefined
      };

      const cred = (await navigator.credentials.get({
        publicKey
      })) as PublicKeyCredential;

      const results = cred.getClientExtensionResults().prf?.results?.first;
      if (args.prf_salt && !results) {
        await post({ nonce, ok: false, error: 'no-prf' });
        return;
      }

      const cred_id = b64urlEncode(cred.rawId);
      // The DOM lib types PRF results.first as BufferSource; the WebAuthn spec
      // guarantees an ArrayBuffer here.
      const prf = results ? b64urlEncode(results as ArrayBuffer) : undefined;
      await post({ nonce, ok: true, cred_id, prf });
      return;
    }

    // op === 'create'
    const publicKey: PublicKeyCredentialCreationOptions = {
      challenge,
      rp: { id: args.rp_id, name: args.rp_id },
      user: {
        id: b64urlToBuf(args.user!.id),
        name: args.user!.name,
        displayName: args.user!.displayName
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },
        { alg: -257, type: 'public-key' }
      ],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required'
      },
      extensions: { prf: {} }
    };

    const cred = (await navigator.credentials.create({
      publicKey
    })) as PublicKeyCredential;

    const prf_enabled = cred.getClientExtensionResults().prf?.enabled === true;
    if (!prf_enabled) {
      await post({ nonce, ok: false, error: 'prf-unsupported' });
      return;
    }

    const cred_id = b64urlEncode(cred.rawId);
    await post({ nonce, ok: true, cred_id, prf_enabled });
  } catch (e) {
    await post({ nonce, ok: false, error: mapCeremonyError(e) });
  }
}
