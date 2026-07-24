/**
 * Unit tests for runShow (src/show). The Dialog and the server POST are mocked, so
 * the render fetch, the image-only body, and the closed accessibility channel are
 * exercised without a browser. The code must never appear as text - only as the
 * rendered image's data URL.
 */

import { ServerConnection } from '@jupyterlab/services';

const mockLaunch = jest.fn();
const mockCtor = jest.fn();
jest.mock('@jupyterlab/apputils', () => ({
  Dialog: class {
    options: any;
    static okButton(opts: any): any {
      return { accept: true, ...opts };
    }
    constructor(options: any) {
      this.options = options;
      mockCtor(options);
    }
    launch(): any {
      return mockLaunch(this.options);
    }
  }
}));
jest.mock('@jupyterlab/services', () => ({ ServerConnection: {} }));
jest.mock('../request');

import { requestAPI } from '../request';
import { runShow } from '../show';

const mockRequestAPI = requestAPI as jest.MockedFunction<typeof requestAPI>;

const serverSettings = {} as ServerConnection.ISettings;
const NONCE = 'unit_nonce_0123456789';
const PNG = 'aGVsbG8tcG5nLWJ5dGVz'; // stand-in base64, opaque to this test

/** The body widget node handed to the Dialog constructor on the last call. */
function dialogBodyNode(): HTMLElement {
  return mockCtor.mock.calls[0][0].body.node;
}

beforeEach(() => {
  jest.clearAllMocks();
  mockLaunch.mockResolvedValue({ button: { accept: true } });
  mockRequestAPI.mockResolvedValue({ png: PNG } as any);
});

describe('runShow', () => {
  it('fetches the render for the nonce and never receives the code as text', async () => {
    await runShow(
      { nonce: NONCE, label: 'Authenticator code' },
      serverSettings
    );

    expect(mockRequestAPI).toHaveBeenCalledTimes(1);
    const [endpoint, , init] = mockRequestAPI.mock.calls[0] as any;
    expect(endpoint).toBe('render');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body)).toEqual({ nonce: NONCE });
  });

  it('shows the rendered image as a data URL and launches the dialog', async () => {
    await runShow(
      { nonce: NONCE, label: 'Authenticator code' },
      serverSettings
    );

    const img = dialogBodyNode().querySelector('img') as HTMLImageElement;
    expect(img).not.toBeNull();
    expect(img.getAttribute('src')).toBe(`data:image/png;base64,${PNG}`);
    expect(mockLaunch).toHaveBeenCalledTimes(1);
  });

  it('closes the accessibility channel - the image carries no alt text', async () => {
    // The code must not re-enter the accessibility tree the image exists to keep it
    // out of, so the alt is deliberately empty.
    await runShow({ nonce: NONCE }, serverSettings);

    const img = dialogBodyNode().querySelector('img') as HTMLImageElement;
    expect(img.getAttribute('alt')).toBe('');
  });

  it('shows the caller-chosen label but only the label, never the code', async () => {
    await runShow(
      { nonce: NONCE, label: 'Authenticator code' },
      serverSettings
    );

    const label = dialogBodyNode().querySelector('.jp-PasskeyCode-label');
    expect(label?.textContent).toBe('Authenticator code');
  });

  it('omits the label element when no label is given', async () => {
    await runShow({ nonce: NONCE }, serverSettings);

    expect(dialogBodyNode().querySelector('.jp-PasskeyCode-label')).toBeNull();
  });

  it('propagates a failed render, e.g. a relay already consumed (404)', async () => {
    mockRequestAPI.mockRejectedValue(new Error('404'));

    await expect(runShow({ nonce: NONCE }, serverSettings)).rejects.toThrow(
      '404'
    );
    expect(mockCtor).not.toHaveBeenCalled();
  });
});
