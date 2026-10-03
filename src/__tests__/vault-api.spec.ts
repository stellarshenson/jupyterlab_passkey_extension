/**
 * The vault's REST wrapper (src/vault/api) against answers that are not the vault's:
 * JupyterHub's for a stopped server, the Jupyter server's Forbidden after a hub
 * logout or its 404 without the vault, and an answer that breaks off; and the minute
 * after an unlock or a proof in which the eye asks no proof.
 * ServerConnection is stubbed.
 */

jest.mock('@jupyterlab/coreutils', () => ({
  URLExt: { join: (...parts: string[]) => parts.join('/') }
}));

const mockMakeRequest = jest.fn();
jest.mock('@jupyterlab/services', () => ({
  ServerConnection: { makeRequest: mockMakeRequest }
}));

import { NoAnswer, PROVEN_MS, VaultApi, VaultError } from '../vault/api';

beforeEach(() => mockMakeRequest.mockReset());

const STOPPED =
  'JupyterHub server no longer running at /user/kj/jupyterlab-passkey-extension/vault/status.' +
  ' Restart the server at https://hub.example/hub/spawn/kj';

it('asks for JSON, so JupyterHub answers a stopped server with JSON, not a page', async () => {
  mockMakeRequest.mockResolvedValue({
    ok: false,
    status: 424,
    text: async () => JSON.stringify({ message: STOPPED })
  });
  const err = await new VaultApi({ baseUrl: 'http://host/' } as any)
    .status()
    .catch(e => e);
  expect(mockMakeRequest.mock.calls[0][1].headers).toEqual({
    Accept: 'application/json'
  });
  expect(err).toBeInstanceOf(VaultError);
  expect(err.status).toBe(424);
  expect(err.message).toBe(STOPPED);
});

it('says the vault did not answer when something in front of it answers with a page', async () => {
  mockMakeRequest.mockResolvedValue({
    ok: false,
    status: 403,
    text: async () => '<html><title>403: Forbidden</title></html>'
  });
  const err = await new VaultApi({ baseUrl: 'http://host/' } as any)
    .lock()
    .catch(e => e);
  expect(err.message).toBe(
    'the vault did not answer (HTTP 403) - reload the page to sign in again or start the server'
  );
});

it('fails on a page in place of JSON, such as the hub sign-in page answered with 200', async () => {
  mockMakeRequest.mockResolvedValue({
    ok: true,
    status: 200,
    text: async () => '<html><title>Sign in</title></html>'
  });
  const err = await new VaultApi({ baseUrl: 'http://host/' } as any)
    .status()
    .catch(e => e);
  expect(err).toBeInstanceOf(VaultError);
  expect(err.message).toBe(
    'the vault did not answer (HTTP 200) - reload the page to sign in again or start the server'
  );
});

it('says the server cannot be reached when the answer breaks off before its body', async () => {
  mockMakeRequest.mockResolvedValue({
    ok: true,
    status: 200,
    text: () => Promise.reject(new TypeError('network error'))
  });
  const err = await new VaultApi({ baseUrl: 'http://host/' } as any)
    .status()
    .catch(e => e);
  expect(err).toBeInstanceOf(NoAnswer);
  expect(err.message).toBe('cannot reach the Jupyter server');
});

it("does not show the Jupyter server's Forbidden as the vault's answer", async () => {
  // After a hub logout the server refuses the lab's revoked token with its own JSON.
  mockMakeRequest.mockResolvedValue({
    ok: false,
    status: 403,
    text: async () => JSON.stringify({ message: 'Forbidden', reason: null })
  });
  const err = await new VaultApi({ baseUrl: 'http://host/' } as any)
    .lock()
    .catch(e => e);
  expect(err.message).toBe(
    'the vault did not answer (HTTP 403) - reload the page to sign in again or start the server'
  );
});

it('says to restart the server when it runs without the vault', async () => {
  // Installed into a running server: the page has the panel, the server no routes.
  mockMakeRequest.mockResolvedValue({
    ok: false,
    status: 404,
    text: async () => '<html><title>404: Not Found</title></html>'
  });
  const err = await new VaultApi({ baseUrl: 'http://host/' } as any)
    .status()
    .catch(e => e);
  expect(err.message).toBe(
    'the vault is not loaded on this Jupyter server - restart the server'
  );
});

describe('the minute after an unlock or a proof', () => {
  const PROOF = { current: 'the passphrase' };
  const SLOT = {
    cred_id: 'AAEC',
    rp_id: 'host',
    prf_salt: 'AAAA',
    prf: 'CQkJ',
    label: 'Work laptop'
  };
  const answer = (status: number, body: unknown) => ({
    ok: status < 400,
    status,
    text: async () => JSON.stringify(body)
  });
  const vault = () => new VaultApi({ baseUrl: 'http://host/' } as any);
  const sent = () => JSON.parse(mockMakeRequest.mock.calls[0][1].body);

  afterEach(() => jest.restoreAllMocks());

  it('asks a proof before any unlock or proof in this tab', () => {
    expect(vault().proven).toBe(false);
  });

  it.each<[string, (api: VaultApi) => Promise<unknown>]>([
    ['a new vault', api => api.init('the passphrase')],
    ['a recovery unlock', api => api.unlockRecovery('the passphrase')],
    ['a password unlock', api => api.unlockPassword('a password', '123456')],
    ['a passkey unlock', api => api.unlockPasskey('AAEC', 'CQkJ')],
    ['a password shown for a proof', api => api.revealPassword('nas', PROOF)],
    ['a new passkey', api => api.addPasskey(SLOT, PROOF)],
    ['a new pair', api => api.addMfa('a password', 'KEY', '123456', PROOF)],
    ['a new recovery passphrase', api => api.replaceRecovery('new', PROOF)]
  ])('asks none after %s', async (_what, request) => {
    mockMakeRequest.mockResolvedValue(answer(200, { value: 's3cret' }));
    const api = vault();
    await request(api);
    expect(api.proven).toBe(true);
  });

  it('asks a proof again once the minute is over', async () => {
    mockMakeRequest.mockResolvedValue(answer(200, {}));
    const api = vault();
    const start = Date.now();
    const now = jest.spyOn(Date, 'now').mockReturnValue(start);
    await api.unlockRecovery('the passphrase');
    now.mockReturnValue(start + PROVEN_MS - 1);
    expect(api.proven).toBe(true);
    now.mockReturnValue(start + PROVEN_MS);
    expect(api.proven).toBe(false);
    // A system clock set back does not keep the minute open until it catches up.
    now.mockReturnValue(start - 1);
    expect(api.proven).toBe(false);
  });

  it('asks a proof again after a lock in this tab', async () => {
    mockMakeRequest.mockResolvedValue(answer(200, {}));
    const api = vault();
    await api.unlockRecovery('the passphrase');
    await api.lock();
    expect(api.proven).toBe(false);
  });

  it('is not started by a refused unlock or proof', async () => {
    mockMakeRequest.mockResolvedValue(answer(403, { error: 'wrong code' }));
    const api = vault();
    await expect(api.unlockPassword('a password', '000000')).rejects.toThrow(
      'wrong code'
    );
    await expect(api.revealPassword('nas', { code: '000000' })).rejects.toThrow(
      'wrong code'
    );
    expect(api.proven).toBe(false);
  });

  it('reads a password plainly with no proof, which starts nothing', async () => {
    mockMakeRequest.mockResolvedValue(answer(200, { value: 's3cret' }));
    const api = vault();
    expect(await api.revealPassword('nas')).toBe('s3cret');
    expect(sent()).toEqual({ name: 'nas' });
    expect(api.proven).toBe(false);
  });

  it('sends the proof with the name when it has one', async () => {
    mockMakeRequest.mockResolvedValue(answer(200, { value: 's3cret' }));
    expect(await vault().revealPassword('nas', PROOF)).toBe('s3cret');
    expect(sent()).toEqual({ name: 'nas', current: 'the passphrase' });
  });
});
