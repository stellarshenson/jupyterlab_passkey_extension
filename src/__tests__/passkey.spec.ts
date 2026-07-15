/**
 * Unit tests for runPasskey (src/passkey). navigator.credentials and the server
 * POST are mocked, so every branch - get/create, PRF present/absent, and error
 * mapping - is exercised without a browser or network.
 */

import { ServerConnection } from '@jupyterlab/services';

import { b64urlEncode } from '../passkey-util';

// Mock the server POST so the relayed body can be captured, and stub
// @jupyterlab/services so passkey.ts loads without its ESM graph.
jest.mock('../request');
jest.mock('@jupyterlab/services', () => ({ ServerConnection: {} }));
import { requestAPI } from '../request';
import { runPasskey } from '../passkey';

const mockRequestAPI = requestAPI as jest.MockedFunction<typeof requestAPI>;

const serverSettings = {} as ServerConnection.ISettings;
const NONCE = 'unit_nonce_0123456789';
const RP = 'example.com';

function buf(bytes: number[]): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

/** The single JSON body posted to the "result" endpoint. */
function postedBody(): any {
  expect(mockRequestAPI).toHaveBeenCalledTimes(1);
  const [endpoint, settings, init] = mockRequestAPI.mock.calls[0];
  expect(endpoint).toBe('result');
  expect(settings).toBe(serverSettings);
  expect(init?.method).toBe('POST');
  return JSON.parse(init!.body as string);
}

let credGet: jest.Mock;
let credCreate: jest.Mock;

beforeAll(() => {
  const w: any = window;
  if (typeof w.crypto?.getRandomValues !== 'function') {
    Object.defineProperty(w, 'crypto', {
      value: { getRandomValues: (a: Uint8Array) => a },
      configurable: true
    });
  }
});

beforeEach(() => {
  mockRequestAPI.mockReset();
  mockRequestAPI.mockResolvedValue(undefined as any);
  credGet = jest.fn();
  credCreate = jest.fn();
  Object.defineProperty(window.navigator, 'credentials', {
    value: { get: credGet, create: credCreate },
    configurable: true
  });
});

describe('runPasskey get', () => {
  it('relays cred_id and a PRF value when prf_salt yields a result', async () => {
    const rawId = buf([9, 8, 7]);
    const prfBytes = buf([1, 2, 3, 4]);
    const saltBytes = new Array(32).fill(1);
    credGet.mockResolvedValue({
      rawId,
      getClientExtensionResults: () => ({
        prf: { results: { first: prfBytes } }
      })
    });

    await runPasskey(
      'get',
      {
        nonce: NONCE,
        rp_id: RP,
        cred_id: b64urlEncode(buf([5, 5, 5])),
        prf_salt: b64urlEncode(buf(saltBytes))
      },
      serverSettings
    );

    expect(postedBody()).toEqual({
      nonce: NONCE,
      ok: true,
      cred_id: b64urlEncode(rawId),
      prf: b64urlEncode(prfBytes)
    });

    const pk = credGet.mock.calls[0][0].publicKey;
    expect(pk.rpId).toBe(RP);
    expect(pk.userVerification).toBe('required');
    expect(new Uint8Array(pk.challenge).length).toBe(32);
    expect(pk.allowCredentials[0].type).toBe('public-key');
    expect(Array.from(new Uint8Array(pk.allowCredentials[0].id))).toEqual([
      5, 5, 5
    ]);
    // The salt fed to the authenticator must be exactly the caller's decoded
    // prf_salt - not a constant, the challenge, or the wrong buffer.
    expect(Array.from(new Uint8Array(pk.extensions.prf.eval.first))).toEqual(
      saltBytes
    );
  });

  it('relays no-prf when prf_salt is given but no result comes back', async () => {
    credGet.mockResolvedValue({
      rawId: buf([1]),
      getClientExtensionResults: () => ({})
    });

    await runPasskey(
      'get',
      {
        nonce: NONCE,
        rp_id: RP,
        cred_id: b64urlEncode(buf([5])),
        prf_salt: b64urlEncode(buf(new Array(32).fill(2)))
      },
      serverSettings
    );

    expect(postedBody()).toEqual({ nonce: NONCE, ok: false, error: 'no-prf' });
  });

  it('relays cred_id and no PRF (and no prf extension) when prf_salt is omitted', async () => {
    credGet.mockResolvedValue({
      rawId: buf([2, 2]),
      getClientExtensionResults: () => ({})
    });

    await runPasskey(
      'get',
      { nonce: NONCE, rp_id: RP, cred_id: b64urlEncode(buf([6, 6])) },
      serverSettings
    );

    expect(postedBody()).toEqual({
      nonce: NONCE,
      ok: true,
      cred_id: b64urlEncode(buf([2, 2]))
    });
    expect(credGet.mock.calls[0][0].publicKey.extensions).toBeUndefined();
  });

  it('relays not-allowed when the ceremony throws a NotAllowedError', async () => {
    credGet.mockRejectedValue(new DOMException('cancelled', 'NotAllowedError'));

    await runPasskey(
      'get',
      { nonce: NONCE, rp_id: RP, cred_id: b64urlEncode(buf([7])) },
      serverSettings
    );

    expect(postedBody()).toEqual({
      nonce: NONCE,
      ok: false,
      error: 'not-allowed'
    });
  });
});

describe('runPasskey create', () => {
  const user = { id: b64urlEncode(buf([1, 2])), name: 'n', displayName: 'd' };

  it('relays cred_id and prf_enabled:true and builds the create options', async () => {
    credCreate.mockResolvedValue({
      rawId: buf([3, 3, 3]),
      getClientExtensionResults: () => ({ prf: { enabled: true } })
    });

    await runPasskey(
      'create',
      { nonce: NONCE, rp_id: RP, user },
      serverSettings
    );

    expect(postedBody()).toEqual({
      nonce: NONCE,
      ok: true,
      cred_id: b64urlEncode(buf([3, 3, 3])),
      prf_enabled: true
    });

    const pk = credCreate.mock.calls[0][0].publicKey;
    // challenge, rp.name and the user fields are all required members of
    // PublicKeyCredentialCreationOptions - dropping any yields a spec-invalid
    // request that real authenticators reject, so assert them too.
    expect(new Uint8Array(pk.challenge).length).toBe(32);
    expect(pk.rp.id).toBe(RP);
    expect(pk.rp.name).toBe(RP);
    expect(Array.from(new Uint8Array(pk.user.id))).toEqual([1, 2]);
    expect(pk.user.name).toBe('n');
    expect(pk.user.displayName).toBe('d');
    expect(pk.pubKeyCredParams).toEqual([
      { alg: -7, type: 'public-key' },
      { alg: -257, type: 'public-key' }
    ]);
    expect(pk.authenticatorSelection).toEqual({
      residentKey: 'preferred',
      userVerification: 'required'
    });
    expect(pk.extensions).toEqual({ prf: {} });
  });

  it('reports prf_enabled:false without rejecting when the flag is false', async () => {
    credCreate.mockResolvedValue({
      rawId: buf([4]),
      getClientExtensionResults: () => ({ prf: { enabled: false } })
    });

    await runPasskey(
      'create',
      { nonce: NONCE, rp_id: RP, user },
      serverSettings
    );

    expect(postedBody()).toEqual({
      nonce: NONCE,
      ok: true,
      cred_id: b64urlEncode(buf([4])),
      prf_enabled: false
    });
  });

  it('reports prf_enabled:false when the authenticator returns no prf extension', async () => {
    credCreate.mockResolvedValue({
      rawId: buf([4]),
      getClientExtensionResults: () => ({})
    });

    await runPasskey(
      'create',
      { nonce: NONCE, rp_id: RP, user },
      serverSettings
    );

    expect(postedBody()).toEqual({
      nonce: NONCE,
      ok: true,
      cred_id: b64urlEncode(buf([4])),
      prf_enabled: false
    });
  });

  it('relays error for a non-DOMException failure', async () => {
    credCreate.mockRejectedValue(new Error('boom'));

    await runPasskey(
      'create',
      { nonce: NONCE, rp_id: RP, user },
      serverSettings
    );

    expect(postedBody()).toEqual({ nonce: NONCE, ok: false, error: 'error' });
  });

  it('relays not-allowed when create throws a NotAllowedError', async () => {
    credCreate.mockRejectedValue(
      new DOMException('cancelled', 'NotAllowedError')
    );

    await runPasskey(
      'create',
      { nonce: NONCE, rp_id: RP, user },
      serverSettings
    );

    expect(postedBody()).toEqual({
      nonce: NONCE,
      ok: false,
      error: 'not-allowed'
    });
  });
});
