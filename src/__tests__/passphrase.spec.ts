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

  it('titles the dialog and prompts for a passphrase by default', async () => {
    acceptWith('a-passphrase', 'a-passphrase');
    await runPassphrase({ nonce: NONCE }, serverSettings);

    expect(dialogOptions().title).toBe('Passphrase');
    expect(dialogOptions().body.node.textContent).toContain(
      'Enter the passphrase twice'
    );
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

  it('announces match state through a live region that is always in the a11y tree', async () => {
    mockLaunch.mockImplementation(async (opts: any) => {
      const body = opts.body;
      const status = body.node.querySelector('.jp-PassphraseDialog-status');
      const announce = body.node.querySelector('.jp-PassphraseDialog-announce');

      // The visible row is presentational only. It keeps its text at every state so
      // its line box - and the dialog's height - never collapses, which is exactly
      // why it must not be the thing that gets read out.
      expect(status.getAttribute('aria-hidden')).toBe('true');

      // The announced row is a separate node that never leaves the tree: a live
      // region inserted with its text already in place is not reliably announced,
      // and `visibility: hidden` removes a node from the tree altogether.
      expect(announce.getAttribute('role')).toBe('status');
      expect(announce.textContent).toBe('');

      fill(body, 'hunter2-correct', 'hunter2-typo');
      expect(announce.textContent).toBe('Passphrases do not match');

      fill(body, 'hunter2-correct', 'hunter2-correct');
      expect(announce.textContent).toBe('Passphrases match');

      return { button: { accept: false } };
    });

    await runPassphrase({ nonce: NONCE }, serverSettings);
  });

  it('rewrites the live region only on a real transition, not once per keystroke', async () => {
    mockLaunch.mockImplementation(async (opts: any) => {
      const body = opts.body;
      const announce = body.node.querySelector('.jp-PassphraseDialog-announce');

      // Assigning textContent replaces the text node even when the string is
      // identical, and a live region announces that. _validate runs twice per
      // keystroke (bubble listeners plus the capture one), so an unguarded write
      // would queue "Passphrases do not match" ~40 times over a 20-character
      // field. Count real mutations, not calls.
      let mutations = 0;
      const observer = new MutationObserver(m => (mutations += m.length));
      observer.observe(announce, {
        childList: true,
        characterData: true,
        subtree: true
      });
      // MutationObserver delivers on a microtask, so the count is only true after
      // a flush - reading it straight after a fill reads zero and proves nothing.
      const flush = () => new Promise(resolve => setTimeout(resolve, 0));

      fill(body, 'hunter2-correct', 'x');
      await flush();
      const afterTransition = mutations;
      // The transition itself must speak, or the guard has silenced everything.
      expect(afterTransition).toBeGreaterThan(0);

      // Still mismatched, so there is nothing new to say - and saying it again
      // is what a screen-reader user would hear on every keystroke.
      fill(body, 'hunter2-correct', 'xy');
      fill(body, 'hunter2-correct', 'xyz');
      await flush();

      expect(mutations).toBe(afterTransition);
      observer.disconnect();

      return { button: { accept: false } };
    });

    await runPassphrase({ nonce: NONCE }, serverSettings);
  });
});

/** Type into the single field of a `once` dialog, firing the input listeners. */
function fillOnce(body: any, value: string): void {
  body.first.value = value;
  body.first.dispatchEvent(new Event('input'));
}

describe('runPassphrase with once', () => {
  it('relays a single entry, with no confirm field to match against', async () => {
    mockLaunch.mockImplementation(async (opts: any) => {
      // The whole point: a secret pasted from a password manager is not typed
      // twice, so there is nothing to confirm it against.
      expect(opts.body.second).toBeNull();
      fillOnce(opts.body, 'ghp_pasted_token');
      return { button: { accept: true } };
    });

    await expect(
      runPassphrase({ nonce: NONCE, once: true }, serverSettings)
    ).resolves.toBe(true);

    expect(JSON.parse(mockRequestAPI.mock.calls[0][2]!.body as string)).toEqual(
      {
        nonce: NONCE,
        passphrase: 'ghp_pasted_token'
      }
    );
  });

  it('gates Submit on the one field being non-empty', async () => {
    mockLaunch.mockImplementation(async (opts: any) => {
      const body = opts.body;

      // With no confirm field the gate moves onto the only field there is.
      expect(body.first.checkValidity()).toBe(false);

      fillOnce(body, 'ghp_pasted_token');
      expect(body.first.checkValidity()).toBe(true);

      fillOnce(body, '');
      expect(body.first.checkValidity()).toBe(false);

      return { button: { accept: false } };
    });

    await runPassphrase({ nonce: NONCE, once: true }, serverSettings);
  });

  it('shows no match status, having nothing to report a match about', async () => {
    mockLaunch.mockImplementation(async (opts: any) => {
      fillOnce(opts.body, 'ghp_pasted_token');
      expect(
        opts.body.node.querySelector('.jp-PassphraseDialog-status')
      ).toBeNull();
      return { button: { accept: false } };
    });

    await runPassphrase({ nonce: NONCE, once: true }, serverSettings);
  });

  it('titles the dialog and prompts for a secret, not a passphrase', async () => {
    mockLaunch.mockImplementation(async (opts: any) => {
      fillOnce(opts.body, 'x');
      return { button: { accept: false } };
    });

    await runPassphrase({ nonce: NONCE, once: true }, serverSettings);

    expect(dialogOptions().title).toBe('Secret');
    expect(dialogOptions().body.node.textContent).toContain('Enter the secret');
  });

  it('still takes an explicit prompt', async () => {
    mockLaunch.mockImplementation(async (opts: any) => {
      fillOnce(opts.body, 'x');
      return { button: { accept: false } };
    });

    await runPassphrase(
      { nonce: NONCE, once: true, prompt: 'GitHub token' },
      serverSettings
    );

    expect(dialogOptions().body.node.textContent).toContain('GitHub token');
  });

  it('keeps the single field a password input that never autofills', async () => {
    mockLaunch.mockImplementation(async (opts: any) => {
      fillOnce(opts.body, 'x');
      return { button: { accept: false } };
    });

    await runPassphrase({ nonce: NONCE, once: true }, serverSettings);

    const body = dialogOptions().body;
    expect(body.first.type).toBe('password');
    expect(body.first.autocomplete).toBe('new-password');
  });
});
