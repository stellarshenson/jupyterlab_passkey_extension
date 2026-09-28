/**
 * The vault's REST wrapper (src/vault/api) against answers that are not the vault's:
 * JupyterHub's for a stopped server, the Jupyter server's Forbidden after a hub
 * logout or its 404 without the vault, and an answer that breaks off.
 * ServerConnection is stubbed.
 */

jest.mock('@jupyterlab/coreutils', () => ({
  URLExt: { join: (...parts: string[]) => parts.join('/') }
}));

const mockMakeRequest = jest.fn();
jest.mock('@jupyterlab/services', () => ({
  ServerConnection: { makeRequest: mockMakeRequest }
}));

import { NoAnswer, VaultApi, VaultError } from '../vault/api';

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
