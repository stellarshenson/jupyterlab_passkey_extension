/**
 * Unit tests for requestAPI (src/request). URLExt and ServerConnection are
 * stubbed so the thin fetch wrapper is exercised without a server: JSON parsing,
 * empty and non-JSON bodies, transport failure, and non-ok responses.
 */

jest.mock('@jupyterlab/coreutils', () => ({
  URLExt: { join: (...parts: string[]) => parts.join('/') }
}));

const mockMakeRequest = jest.fn();
jest.mock('@jupyterlab/services', () => {
  class NetworkError extends Error {}
  class ResponseError extends Error {
    constructor(
      public response: unknown,
      message?: string
    ) {
      super(message);
    }
  }
  return {
    ServerConnection: {
      makeRequest: mockMakeRequest,
      NetworkError,
      ResponseError
    }
  };
});

import { ServerConnection } from '@jupyterlab/services';
import { requestAPI } from '../request';

const settings = { baseUrl: 'http://host/' } as any;

function res(body: string, ok = true): any {
  return { ok, text: async () => body };
}

beforeEach(() => mockMakeRequest.mockReset());

describe('requestAPI', () => {
  it('parses a JSON response body', async () => {
    mockMakeRequest.mockResolvedValue(res(JSON.stringify({ ok: true, a: 1 })));
    await expect(requestAPI('result', settings)).resolves.toEqual({
      ok: true,
      a: 1
    });
    // The wrapper must target the extension's namespaced endpoint.
    expect(mockMakeRequest.mock.calls[0][0]).toContain(
      'jupyterlab-passkey-extension/result'
    );
  });

  it('returns an empty string for an empty body', async () => {
    mockMakeRequest.mockResolvedValue(res(''));
    await expect(requestAPI('health', settings)).resolves.toBe('');
  });

  it('returns the raw text when the body is not JSON', async () => {
    const spy = jest.spyOn(console, 'log').mockImplementation(() => undefined);
    mockMakeRequest.mockResolvedValue(res('not json'));
    await expect(requestAPI('x', settings)).resolves.toBe('not json');
    spy.mockRestore();
  });

  it('wraps a transport failure in a NetworkError', async () => {
    mockMakeRequest.mockRejectedValue(new Error('down'));
    await expect(requestAPI('x', settings)).rejects.toBeInstanceOf(
      ServerConnection.NetworkError
    );
  });

  it('throws a ResponseError carrying the payload message on a non-ok response', async () => {
    mockMakeRequest.mockResolvedValue(
      res(JSON.stringify({ message: 'bad' }), false)
    );
    const err: any = await requestAPI('x', settings).catch(e => e);
    expect(err).toBeInstanceOf(ServerConnection.ResponseError);
    expect(err.message).toBe('bad');
  });
});
