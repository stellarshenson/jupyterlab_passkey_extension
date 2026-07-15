/**
 * Unit tests for runPassphrase (src/passphrase). showDialog and the server POST
 * are mocked, so the confirm-match rule, the cancel path and the relayed body
 * are exercised without a browser.
 */

import { ServerConnection } from '@jupyterlab/services';

// Capture the dialog options so the body widget can be driven directly, and
// stub the heavy @jupyterlab/* modules so ts-jest loads the source without
// their untransformed ESM graph.
const mockShowDialog = jest.fn();
jest.mock('@jupyterlab/apputils', () => ({
  showDialog: (...args: any[]) => mockShowDialog(...args),
  Dialog: {
    cancelButton: () => ({ accept: false }),
    okButton: (opts: any) => ({ accept: true, ...opts })
  }
}));
jest.mock('@jupyterlab/services', () => ({ ServerConnection: {} }));
jest.mock('../request');

import { requestAPI } from '../request';
import { runPassphrase } from '../passphrase';

const mockRequestAPI = requestAPI as jest.MockedFunction<typeof requestAPI>;

const serverSettings = {} as ServerConnection.ISettings;
const NONCE = 'unit_nonce_0123456789';

/** The body widget handed to showDialog on the last call. */
function dialogBody(): any {
  return mockShowDialog.mock.calls[0][0].body;
}

/** Type into both password fields, firing the input listeners. */
function fill(body: any, first: string, second: string): void {
  body.first.value = first;
  body.second.value = second;
  body.first.dispatchEvent(new Event('input'));
  body.second.dispatchEvent(new Event('input'));
}

beforeEach(() => {
  mockRequestAPI.mockReset();
  mockRequestAPI.mockResolvedValue(undefined as any);
  mockShowDialog.mockReset();
});

/** Accept the dialog after filling the fields with the given values. */
function acceptWith(first: string, second: string): void {
  mockShowDialog.mockImplementation(async (opts: any) => {
    fill(opts.body, first, second);
    return { button: { accept: true } };
  });
}

describe('runPassphrase', () => {
  it('relays the passphrase when both fields match', async () => {
    acceptWith('hunter2-correct', 'hunter2-correct');

    await expect(runPassphrase({ nonce: NONCE }, serverSettings)).resolves.toBe(
      true
    );

    expect(mockRequestAPI).toHaveBeenCalledTimes(1);
    const [endpoint, settings, init] = mockRequestAPI.mock.calls[0];
    expect(endpoint).toBe('passphrase');
    expect(settings).toBe(serverSettings);
    expect(init?.method).toBe('POST');
    expect(JSON.parse(init!.body as string)).toEqual({
      nonce: NONCE,
      passphrase: 'hunter2-correct'
    });
  });

  it('relays nothing when the two fields differ', async () => {
    acceptWith('hunter2-correct', 'hunter2-typo');

    await expect(runPassphrase({ nonce: NONCE }, serverSettings)).resolves.toBe(
      false
    );
    expect(mockRequestAPI).not.toHaveBeenCalled();
  });

  it('relays nothing when the passphrase is empty', async () => {
    acceptWith('', '');

    await expect(runPassphrase({ nonce: NONCE }, serverSettings)).resolves.toBe(
      false
    );
    expect(mockRequestAPI).not.toHaveBeenCalled();
  });

  it('relays nothing when the user cancels', async () => {
    mockShowDialog.mockImplementation(async (opts: any) => {
      fill(opts.body, 'hunter2-correct', 'hunter2-correct');
      return { button: { accept: false } };
    });

    await expect(runPassphrase({ nonce: NONCE }, serverSettings)).resolves.toBe(
      false
    );
    expect(mockRequestAPI).not.toHaveBeenCalled();
  });

  it('uses password inputs that never autofill, and the given prompt', async () => {
    acceptWith('a-passphrase', 'a-passphrase');

    await runPassphrase(
      { nonce: NONCE, prompt: 'Recovery passphrase' },
      serverSettings
    );

    const body = dialogBody();
    // A visible field or a retained autofill would leak the passphrase.
    expect(body.first.type).toBe('password');
    expect(body.second.type).toBe('password');
    expect(body.first.autocomplete).toBe('new-password');
    expect(body.second.autocomplete).toBe('new-password');
    expect(body.node.textContent).toContain('Recovery passphrase');
  });

  it('shows the mismatch banner only once the confirm field has content', async () => {
    mockShowDialog.mockImplementation(async (opts: any) => {
      const body = opts.body;
      const error = body.node.querySelector('.jp-PassphraseDialog-error');

      // Mid-typing: first field only - must stay quiet.
      fill(body, 'hunter2-correct', '');
      expect(error.hidden).toBe(true);

      // Confirm diverges - banner shows.
      fill(body, 'hunter2-correct', 'hunter2-typo');
      expect(error.hidden).toBe(false);

      // Corrected - banner hides again.
      fill(body, 'hunter2-correct', 'hunter2-correct');
      expect(error.hidden).toBe(true);

      return { button: { accept: false } };
    });

    await runPassphrase({ nonce: NONCE }, serverSettings);
    expect(mockShowDialog).toHaveBeenCalledTimes(1);
  });
});
