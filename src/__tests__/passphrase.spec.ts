/**
 * Unit tests for runPassphrase (src/passphrase). The Dialog and the server POST
 * are mocked, so the confirm-match rule, the Submit gate, the cancel and Escape
 * paths and the relayed body are exercised without a browser.
 */

import { ServerConnection } from '@jupyterlab/services';

// Model Dialog as the class runPassphrase now constructs, capturing its options
// so the body widget can be driven directly, and stub the heavy @jupyterlab/*
// modules so ts-jest loads the source without their untransformed ESM graph.
const mockLaunch = jest.fn();
const mockReject = jest.fn();
const mockCtor = jest.fn();
jest.mock('@jupyterlab/apputils', () => ({
  Dialog: class {
    options: any;
    static cancelButton(): any {
      return { accept: false };
    }
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
    reject(): void {
      mockReject();
    }
  }
}));
jest.mock('@jupyterlab/services', () => ({ ServerConnection: {} }));
jest.mock('../request');

import { requestAPI } from '../request';
import { runPassphrase } from '../passphrase';

const mockRequestAPI = requestAPI as jest.MockedFunction<typeof requestAPI>;

const serverSettings = {} as ServerConnection.ISettings;
const NONCE = 'unit_nonce_0123456789';

/** The options handed to the Dialog constructor on the last call. */
function dialogOptions(): any {
  return mockCtor.mock.calls[0][0];
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
  mockLaunch.mockReset();
  mockReject.mockReset();
  mockCtor.mockReset();
});

/** Accept the dialog after filling the fields with the given values. */
function acceptWith(first: string, second: string): void {
  mockLaunch.mockImplementation(async (opts: any) => {
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
    mockLaunch.mockImplementation(async (opts: any) => {
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

    const body = dialogOptions().body;
    // A visible field or a retained autofill would leak the passphrase.
    expect(body.first.type).toBe('password');
    expect(body.second.type).toBe('password');
    expect(body.first.autocomplete).toBe('new-password');
    expect(body.second.autocomplete).toBe('new-password');
    expect(body.node.textContent).toContain('Recovery passphrase');
  });

  it('offers no exit but Cancel and Submit', async () => {
    acceptWith('a-passphrase', 'a-passphrase');
    await runPassphrase({ nonce: NONCE }, serverSettings);

    const opts = dialogOptions();
    // hasClose would add a close button AND dismiss on an outside click, which
    // strands the CLI on a relay that never arrives.
    expect(opts.hasClose).toBe(false);
    expect(opts.buttons).toHaveLength(2);
    expect(opts.buttons[0].accept).toBe(false);
    expect(opts.buttons[1]).toMatchObject({ accept: true, label: 'Submit' });
  });

  it('cancels on Escape, which hasClose:false would otherwise switch off', async () => {
    mockLaunch.mockImplementation(
      async () =>
        new Promise(resolve => {
          document.dispatchEvent(
            new KeyboardEvent('keydown', { key: 'Escape' })
          );
          resolve({ button: { accept: false } });
        })
    );

    await expect(runPassphrase({ nonce: NONCE }, serverSettings)).resolves.toBe(
      false
    );
    expect(mockReject).toHaveBeenCalledTimes(1);
  });

  it('stops listening for Escape once the dialog is done', async () => {
    acceptWith('a-passphrase', 'a-passphrase');
    await runPassphrase({ nonce: NONCE }, serverSettings);

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    // A leaked listener would reject a dialog that is no longer on screen.
    expect(mockReject).not.toHaveBeenCalled();
  });

  it('gates Submit on a match via the validity Dialog actually reads', async () => {
    mockLaunch.mockImplementation(async (opts: any) => {
      const body = opts.body;

      // Empty: Submit must not be clickable before anything is typed.
      expect(body.second.checkValidity()).toBe(false);

      fill(body, 'hunter2-correct', 'hunter2-typo');
      expect(body.second.checkValidity()).toBe(false);

      fill(body, 'hunter2-correct', 'hunter2-correct');
      expect(body.second.checkValidity()).toBe(true);

      return { button: { accept: false } };
    });

    await runPassphrase({ nonce: NONCE }, serverSettings);
  });

  it('reports match state only once the confirm field has content, without resizing', async () => {
    mockLaunch.mockImplementation(async (opts: any) => {
      const body = opts.body;
      const status = body.node.querySelector('.jp-PassphraseDialog-status');

      // Mid-typing: first field only - must stay quiet, but keep its row.
      fill(body, 'hunter2-correct', '');
      expect(body.state).toBe('pending');
      // Never `hidden`: that collapses the box and jumps the dialog's edge.
      expect(status.hidden).toBe(false);

      fill(body, 'hunter2-correct', 'hunter2-typo');
      expect(body.state).toBe('mismatch');

      fill(body, 'hunter2-correct', 'hunter2-correct');
      expect(body.state).toBe('match');

      return { button: { accept: false } };
    });

    await runPassphrase({ nonce: NONCE }, serverSettings);
  });
});
