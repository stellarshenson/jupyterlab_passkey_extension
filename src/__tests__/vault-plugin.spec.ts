/**
 * The vault plugin's commands a CLI raises: `passkey:vault-register` runs in the page,
 * gets the proof there and answers the CLI through the result relay. The REST API,
 * the relay, the dialogs and WebAuthn are faked.
 */

const mockApi: any = {};
const mockAskSecret = jest.fn();
const mockLaunch = jest.fn();
const mockRequest = jest.fn();
const mockError: jest.Mock = jest.fn(() => 'failure-1');
const mockEmit = jest.fn();
const mockDismiss = jest.fn();
/** The notifications in this tab, and who listens for a change to them. */
const mockNotices: any[] = [];
const mockChanged: ((sender: any, change: any) => void)[] = [];
jest.mock('@jupyterlab/apputils', () => ({
  Notification: {
    emit: (...a: any[]) => mockEmit(...a),
    error: (...a: any[]) => mockError(...a),
    dismiss: (id: string) => {
      mockDismiss(id);
      const i = mockNotices.findIndex(n => n.id === id);
      if (i >= 0) {
        mockNotices.splice(i, 1);
      }
    },
    manager: {
      get notifications() {
        return mockNotices.slice();
      },
      changed: { connect: (fn: any) => mockChanged.push(fn) }
    }
  },
  Dialog: class {
    static cancelButton(o: any = {}): any {
      return { accept: false, ...o };
    }
    static okButton(o: any = {}): any {
      return { accept: true, ...o };
    }
    constructor(readonly options: any) {}
    reject(): void {
      // A press on a method closes the dialog; `mockLaunch` has already returned.
    }
  }
}));
jest.mock('@jupyterlab/ui-components', () => {
  const icon = { element: () => document.createElement('span') };
  return {
    addIcon: icon,
    filterIcon: icon,
    lockIcon: icon,
    refreshIcon: icon,
    settingsIcon: icon,
    LabIcon: class {
      element() {
        return document.createElement('span');
      }
    }
  };
});
jest.mock('../passphrase', () => ({
  askSecret: (...a: any[]) => mockAskSecret(...a),
  launchWithEscape: (...a: any[]) => mockLaunch(...a)
}));
jest.mock('../request', () => ({
  requestAPI: (...a: any[]) => mockRequest(...a)
}));
jest.mock('../vault/api', () => ({
  ...jest.requireActual('../vault/api'),
  VaultApi: jest.fn().mockImplementation(() => mockApi)
}));

import schema from '../../schema/vault.json';
import { NoAnswer, VaultError } from '../vault/api';
import { setupVault } from '../vault/dialogs';
import { REFRESH_MS } from '../vault/panel';
import {
  dismissStale,
  REGISTER_COMMAND,
  SETUP_COMMAND,
  vaultPlugin
} from '../vault/plugin';

/** A vault whose one passkey belongs to this tab's hostname (jsdom: localhost). */
function vaultStatus(): any {
  return {
    initialized: true,
    unlocked: false,
    remaining: null,
    holder: {
      name: 'memory',
      about: '',
      summary: 'strong',
      protection: '',
      capabilities: {},
      details: [],
      notice: null
    },
    slots: [
      { type: 'recovery' },
      {
        type: 'passkey',
        cred_id: 'AAEC',
        rp_id: location.hostname,
        prf_salt: 'c2FsdA',
        label: 'desktop',
        created: '2026-09-26T10:00:00Z'
      }
    ],
    settings: {
      unlock_minutes: 240,
      password_min_length: 12,
      reveal_seconds: 60,
      rotate_days: 365
    },
    rotation: {
      created: '2026-10-11T10:00:00Z',
      age_days: 10,
      period_days: 365,
      due: false
    },
    path: '~/.local/share/jupyterlab-passkey/vault.json'
  };
}

let mockPanel: any;
let mockApp: any;

async function activate(
  settingRegistry: any = null,
  translator: any = null
): Promise<Map<string, any>> {
  Object.assign(mockApi, {
    status: jest.fn().mockResolvedValue(vaultStatus()),
    addPasskey: jest.fn().mockResolvedValue(undefined),
    checkRecovery: jest.fn().mockResolvedValue(undefined),
    challenge: jest
      .fn()
      .mockResolvedValue('Y2hhbGxlbmdlLWNoYWxsZW5nZS1jaGFsbGVuZ2UtMzI')
  });
  const commands = new Map<string, any>();
  mockApp = {
    commands: {
      addCommand: (id: string, options: any) => commands.set(id, options),
      execute: jest.fn()
    },
    serviceManager: { serverSettings: {} },
    shell: {
      add: jest.fn((widget: any) => {
        mockPanel = widget;
      })
    }
  };
  await vaultPlugin.activate(mockApp, settingRegistry, translator);
  return commands;
}

it('labels its commands and the panel through the lab translator, and describes the arguments', async () => {
  const translator = { load: () => ({ __: (s: string) => `<${s}>` }) };
  const commands = await activate(null, translator);
  const unlock = commands.get('passkey:vault-unlock');
  const register = commands.get(REGISTER_COMMAND);
  expect(unlock.label).toBe('<Unlock Vault With Passkey>');
  expect(register.label).toBe('<Add Vault Passkey>');
  expect(Object.keys(unlock.describedBy.args.properties)).toEqual([
    'nonce',
    'method'
  ]);
  expect(Object.keys(register.describedBy.args.properties)).toEqual([
    'nonce',
    'label'
  ]);
  // The sidebar caption of the panel reads the same bundle.
  expect(mockPanel.title.caption).toBe('<Vault>');

  // A lab with no translator: each string is returned as written.
  const plain = await activate();
  expect(plain.get(REGISTER_COMMAND).label).toBe('Add Vault Passkey');
  expect(mockPanel.title.caption).toBe('Vault');
});

/** The passkey on another device: the proof request fails, the rest succeeds. */
function browser(): { create: jest.Mock } {
  const get = jest
    .fn()
    .mockRejectedValueOnce(new DOMException('x', 'NotAllowedError'))
    .mockResolvedValue({
      rawId: new Uint8Array([9]).buffer,
      getClientExtensionResults: () => ({
        prf: { results: { first: new Uint8Array([1]).buffer } }
      })
    });
  const create = jest
    .fn()
    .mockResolvedValue({ rawId: new Uint8Array([9]).buffer });
  Object.defineProperty(navigator, 'credentials', {
    value: { get, create },
    configurable: true
  });
  return { create };
}

/** The proof's passkey is on another device; the new one signs and gives no PRF. */
function noPrfBrowser(): void {
  const get = jest
    .fn()
    .mockRejectedValueOnce(new DOMException('x', 'NotAllowedError'))
    .mockResolvedValue({
      rawId: new Uint8Array([9]).buffer,
      response: {
        clientDataJSON: new Uint8Array([1]).buffer,
        authenticatorData: new Uint8Array([2]).buffer,
        signature: new Uint8Array([3]).buffer
      },
      getClientExtensionResults: () => ({})
    });
  const create = jest.fn().mockResolvedValue({
    rawId: new Uint8Array([9]).buffer,
    response: {
      clientDataJSON: new Uint8Array([4]).buffer,
      attestationObject: new Uint8Array([5]).buffer
    }
  });
  Object.defineProperty(navigator, 'credentials', {
    value: { get, create },
    configurable: true
  });
}

/** What the page posted to the CLI's result relay. */
function answered(): any {
  const call = mockRequest.mock.calls.find(c => c[0] === 'result');
  return JSON.parse(call[2].body);
}

/**
 * Every post to the result relay. An unlock and a set-up post only a failure: the CLI
 * reads a success in vault status, and a post after its wait ended would stay there.
 */
function posted(): any[] {
  return mockRequest.mock.calls
    .filter(c => c[0] === 'result')
    .map(c => JSON.parse(c[2].body));
}

afterEach(() => {
  jest.clearAllMocks();
});

it('registers with the recovery passphrase when this host passkey does not answer, and answers ok', async () => {
  const commands = await activate();
  browser();
  mockAskSecret.mockResolvedValue({ accepted: true, value: 'recovery words' });
  mockLaunch.mockImplementation(async (dialog: any) => ({
    button: {
      accept: ['Name the new passkey', 'Confirm the new passkey'].includes(
        dialog.options.title
      )
    }
  }));
  await commands.get(REGISTER_COMMAND).execute({ nonce: 'n1', label: 'CLI' });
  expect(mockAskSecret.mock.calls[0][0]).toBe(
    'No passkey answered - enter the current recovery passphrase instead'
  );
  expect(mockApi.addPasskey.mock.calls[0][1]).toEqual({
    current: 'recovery words'
  });
  expect(answered()).toEqual({ nonce: 'n1', ok: true, method: 'passkey' });
});

it('answers the CLI that the registration was cancelled, and creates nothing', async () => {
  const commands = await activate();
  const { create } = browser();
  mockAskSecret.mockResolvedValue({ accepted: false, value: null });
  await commands.get(REGISTER_COMMAND).execute({ nonce: 'n2' });
  expect(create).not.toHaveBeenCalled();
  expect(answered()).toEqual({
    nonce: 'n2',
    ok: false,
    error: 'adding the passkey was cancelled'
  });
});

const WRONG_PASSPHRASE = new VaultError(403, 'wrong recovery passphrase');

it('asks a wrong passphrase again before the browser creates anything for the CLI', async () => {
  const commands = await activate();
  const { create } = browser();
  mockApi.checkRecovery.mockRejectedValueOnce(WRONG_PASSPHRASE);
  mockAskSecret
    .mockResolvedValueOnce({ accepted: true, value: 'wrong' })
    .mockResolvedValueOnce({ accepted: false, value: null });
  await commands.get(REGISTER_COMMAND).execute({ nonce: 'n20' });
  expect(mockAskSecret.mock.calls[1].slice(2)).toEqual([
    'Add passkey',
    undefined,
    'Wrong recovery passphrase'
  ]);
  expect(create).not.toHaveBeenCalled();
  expect(answered()).toEqual({
    nonce: 'n20',
    ok: false,
    error: 'adding the passkey was cancelled'
  });
});

it("dismisses the panel's failure notification through a CLI step, as the next action does", async () => {
  // A failed action in the panel, then the CLI's step succeeds here.
  const commands = await activate();
  await mockPanel._act(() =>
    Promise.reject(new VaultError(400, 'the vault refused'))
  );
  expect(mockError).toHaveBeenCalledWith('The vault refused.', {
    autoClose: false
  });
  expect(mockDismiss).not.toHaveBeenCalled();
  browser();
  mockAskSecret.mockResolvedValue({ accepted: true, value: 'recovery words' });
  mockLaunch.mockImplementation(async (dialog: any) => ({
    button: {
      accept: ['Name the new passkey', 'Confirm the new passkey'].includes(
        dialog.options.title
      )
    }
  }));
  await commands.get(REGISTER_COMMAND).execute({ nonce: 'n4', label: 'CLI' });
  expect(answered()).toEqual({ nonce: 'n4', ok: true, method: 'passkey' });
  expect(mockDismiss).toHaveBeenCalledWith('failure-1');
});

it('answers the CLI for a declined passkey with no PRF with the ways in, not a retry of the command', async () => {
  const commands = await activate();
  noPrfBrowser();
  mockAskSecret.mockResolvedValue({ accepted: true, value: 'recovery words' });
  // Name and confirm the passkey, then decline Password and passkey.
  mockLaunch.mockImplementation(async (dialog: any) => ({
    button: {
      accept: ['Name the new passkey', 'Confirm the new passkey'].includes(
        dialog.options.title
      )
    }
  }));
  await commands.get(REGISTER_COMMAND).execute({ nonce: 'n5' });
  expect(mockLaunch.mock.calls.map(([d]) => d.options.title)).toContain(
    'Add password and passkey'
  );
  const { ok, error } = answered();
  expect(ok).toBe(false);
  // A retry on the same authenticator fails again, so the line names what works.
  expect(error).toMatch(
    /^no PRF - passkey not added; use another passkey or Password and authenticator app; delete the unused passkey dated \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$/
  );
  expect(mockApi.addPasskey).not.toHaveBeenCalled();
});

it('answers the CLI with the method stored: Password and passkey for a passkey with no PRF', async () => {
  const commands = await activate();
  mockApi.addPair = jest.fn().mockResolvedValue(undefined);
  noPrfBrowser();
  // The recovery passphrase as the proof, then the new unlock password.
  mockAskSecret
    .mockResolvedValueOnce({ accepted: true, value: 'recovery words' })
    .mockResolvedValueOnce({ accepted: true, value: 'a long password' });
  // Name and confirm the passkey, then continue to Password and passkey.
  mockLaunch.mockImplementation(async (dialog: any) => ({
    button: {
      accept: [
        'Name the new passkey',
        'Confirm the new passkey',
        'Add password and passkey'
      ].includes(dialog.options.title)
    }
  }));
  await commands.get(REGISTER_COMMAND).execute({ nonce: 'n6' });
  expect(mockApi.addPair).toHaveBeenCalledTimes(1);
  expect(mockApi.addPasskey).not.toHaveBeenCalled();
  expect(answered()).toEqual({
    nonce: 'n6',
    ok: true,
    method: 'password-passkey'
  });
});

it('proves a registration against the vault the server serves now, not the one this tab read', async () => {
  // Re-created since this tab read it: the old vault's passkey must not be offered.
  const commands = await activate();
  await mockPanel.refresh();
  const get = jest.fn().mockResolvedValue({
    rawId: new Uint8Array([9]).buffer,
    getClientExtensionResults: () => ({
      prf: { results: { first: new Uint8Array([1]).buffer } }
    })
  });
  const create = jest
    .fn()
    .mockResolvedValue({ rawId: new Uint8Array([9]).buffer });
  Object.defineProperty(navigator, 'credentials', {
    value: { get, create },
    configurable: true
  });
  mockApi.status.mockResolvedValue({
    ...vaultStatus(),
    slots: [{ type: 'recovery' }]
  });
  mockAskSecret.mockResolvedValue({ accepted: true, value: 'recovery words' });
  mockLaunch.mockImplementation(async (dialog: any) => ({
    button: {
      accept: ['Name the new passkey', 'Confirm the new passkey'].includes(
        dialog.options.title
      )
    }
  }));
  await commands.get(REGISTER_COMMAND).execute({ nonce: 'n5', label: 'CLI' });
  expect(mockAskSecret.mock.calls[0][0]).toBe(
    'Enter the current recovery passphrase'
  );
  // The one request before the new passkey exists is the create, not a proof.
  expect(create.mock.invocationCallOrder[0]).toBeLessThan(
    get.mock.invocationCallOrder[0]
  );
  expect(mockApi.addPasskey.mock.calls[0][1]).toEqual({
    current: 'recovery words'
  });
  expect(answered()).toEqual({ nonce: 'n5', ok: true, method: 'passkey' });
});

it('reads the vault again for an unlock when this tab read no passkey for its host', async () => {
  // A passkey registered since this tab read the vault.
  const commands = await activate();
  mockApi.status.mockResolvedValue({
    ...vaultStatus(),
    slots: [{ type: 'recovery' }]
  });
  await mockPanel.refresh();
  mockApi.status.mockResolvedValue(vaultStatus());
  mockApi.unlockPasskey = jest
    .fn()
    .mockResolvedValue({ ...vaultStatus(), unlocked: true });
  Object.defineProperty(navigator, 'credentials', {
    value: {
      get: jest.fn().mockResolvedValue({
        rawId: new Uint8Array([0, 1, 2]).buffer,
        getClientExtensionResults: () => ({
          prf: { results: { first: new Uint8Array([1]).buffer } }
        })
      })
    },
    configurable: true
  });
  await commands.get('passkey:vault-unlock').execute({ nonce: 'n6' });
  expect(mockApi.unlockPasskey.mock.calls[0][0]).toBe('AAEC');
  expect(posted()).toEqual([]);
});

it('runs the chooser for method choose, and the passkey with no method', async () => {
  const commands = await activate();
  mockApi.unlockRecovery = jest.fn().mockResolvedValue(vaultStatus());
  mockAskSecret.mockResolvedValue({ accepted: true, value: 'recovery words' });
  mockLaunch.mockImplementation(async (dialog: any) => {
    expect(dialog.options.title).toBe('Unlock vault');
    // The chooser offers the passkey, the pair and the passphrase; pick the last.
    dialog.options.body.chosen = 'recovery';
    return { button: { accept: false } };
  });
  await commands
    .get('passkey:vault-unlock')
    .execute({ nonce: 'n7', method: 'choose' });
  expect(mockAskSecret.mock.calls[0][1]).toBe(1);
  expect(mockApi.unlockRecovery).toHaveBeenCalledWith('recovery words');
  expect(posted()).toEqual([]);

  // No method: a passkey for this hostname is asked for directly.
  mockApi.unlockPasskey = jest.fn().mockResolvedValue(vaultStatus());
  Object.defineProperty(navigator, 'credentials', {
    value: {
      get: jest.fn().mockResolvedValue({
        rawId: new Uint8Array([0, 1, 2]).buffer,
        getClientExtensionResults: () => ({
          prf: { results: { first: new Uint8Array([1]).buffer } }
        })
      })
    },
    configurable: true
  });
  await commands.get('passkey:vault-unlock').execute({ nonce: 'n8' });
  expect(mockApi.unlockPasskey).toHaveBeenCalled();
  expect(posted()).toEqual([]);
});

it('posts the refusal of a Password and passkey unlock whose challenge expired while the password dialog was open', async () => {
  const commands = await activate();
  const pair = {
    type: 'password-passkey',
    cred_id: 'CQ',
    rp_id: location.hostname,
    origin: location.origin,
    label: 'Phone',
    created: '2026-11-02T10:00:00Z'
  };
  mockApi.status.mockResolvedValue({
    ...vaultStatus(),
    slots: [{ type: 'recovery' }, pair]
  });
  const refusal = 'the passkey check failed or expired - try again';
  mockApi.unlockPair = jest
    .fn()
    .mockRejectedValue(new VaultError(403, refusal));
  mockAskSecret.mockResolvedValue({ accepted: true, value: 'pw' });
  mockLaunch.mockImplementation(async (dialog: any) => {
    dialog.options.body.chosen = 'pair';
    return { button: { accept: false } };
  });
  const bytes = new Uint8Array([1]).buffer;
  const get = jest.fn().mockResolvedValue({
    rawId: new Uint8Array([9]).buffer,
    response: {
      clientDataJSON: bytes,
      authenticatorData: bytes,
      signature: bytes
    }
  });
  Object.defineProperty(navigator, 'credentials', {
    value: { get },
    configurable: true
  });
  await commands
    .get('passkey:vault-unlock')
    .execute({ nonce: 'n9', method: 'choose' });
  // The chooser is the one dialog; the password's Submit leads to the passkey.
  expect(mockLaunch).toHaveBeenCalledTimes(1);
  expect(get).toHaveBeenCalledTimes(1);
  expect(mockApi.unlockPair).toHaveBeenCalledWith('pw', expect.any(Object));
  // The CLI prints the refusal, which names the way forward.
  expect(posted()).toEqual([{ nonce: 'n9', ok: false, error: refusal }]);
  // The page says it too: the CLI has stopped waiting by the time a challenge expires.
  expect(mockError).toHaveBeenCalledWith(
    'The passkey check failed or expired - try again.',
    { autoClose: false }
  );
  // It is the panel's failure notification: a new refusal replaces it, and a CLI
  // step done in this tab dismisses it, as the next action in the panel does.
  expect(mockDismiss).not.toHaveBeenCalled();
  mockError.mockReturnValueOnce('failure-2');
  mockApi.unlockPair.mockRejectedValueOnce(
    new VaultError(400, 'wrong unlock password')
  );
  await commands
    .get('passkey:vault-unlock')
    .execute({ nonce: 'n10', method: 'choose' });
  expect(mockError).toHaveBeenLastCalledWith('Wrong unlock password.', {
    autoClose: false
  });
  expect(mockDismiss.mock.calls).toEqual([['failure-1']]);
  mockApi.unlockPair.mockResolvedValueOnce(vaultStatus());
  await commands
    .get('passkey:vault-unlock')
    .execute({ nonce: 'n11', method: 'choose' });
  expect(mockDismiss.mock.calls).toEqual([['failure-1'], ['failure-2']]);
  expect(mockError).toHaveBeenCalledTimes(2);
});

it('opens a vault with the recovery slot alone from the Recovery passphrase button of the chooser', async () => {
  const commands = await activate();
  const recoveryOnly = { ...vaultStatus(), slots: [{ type: 'recovery' }] };
  mockApi.status.mockResolvedValue(recoveryOnly);
  mockApi.unlockRecovery = jest.fn().mockResolvedValue(recoveryOnly);
  mockAskSecret.mockResolvedValue({ accepted: true, value: 'recovery words' });
  mockLaunch.mockImplementation(async (dialog: any) => {
    (
      dialog.options.body.node.querySelector(
        'button[data-method="recovery"]'
      ) as HTMLButtonElement
    ).click();
    return { button: { accept: false } };
  });

  await commands
    .get('passkey:vault-unlock')
    .execute({ nonce: 'n21', method: 'choose' });

  const { title, buttons, body } = mockLaunch.mock.calls[0][0].options;
  expect(title).toBe('Unlock vault');
  // Cancel is the dialog's only button of its own.
  expect(buttons).toEqual([{ accept: false }]);
  expect(
    Array.from(body.node.querySelectorAll('button') as HTMLButtonElement[]).map(
      button => [
        (button.firstChild as HTMLElement).textContent,
        (button.lastChild as HTMLElement).textContent,
        button.disabled
      ]
    )
  ).toEqual([
    ['Passkey', `No passkey was added for ${location.hostname}.`, true],
    ['Password and authenticator app', 'No unlock password was set.', true],
    ['Recovery passphrase', 'The passphrase you stored offline.', false]
  ]);
  expect(mockApi.unlockRecovery).toHaveBeenCalledWith('recovery words');
  expect(posted()).toEqual([]);
});

it('offers the chooser when the passkey for this hostname does not answer', async () => {
  // The slot matches, but the passkey lives on another machine or was deleted:
  // the ceremony fails and the chooser offers every way in.
  const commands = await activate();
  await mockPanel.refresh();
  Object.defineProperty(navigator, 'credentials', {
    value: {
      get: jest.fn().mockRejectedValue(new DOMException('x', 'NotAllowedError'))
    },
    configurable: true
  });
  mockApi.unlockRecovery = jest.fn().mockResolvedValue(vaultStatus());
  mockAskSecret.mockResolvedValue({ accepted: true, value: 'recovery words' });
  mockLaunch.mockImplementation(async (dialog: any) => {
    dialog.options.body.chosen = 'recovery';
    return { button: { accept: false } };
  });
  await commands.get('passkey:vault-unlock').execute({ nonce: 'n9' });
  expect(mockApi.unlockRecovery).toHaveBeenCalledWith('recovery words');
  expect(posted()).toEqual([]);
});

const UNLOCK = 'passkey:vault-unlock';
const open = () => ({ ...vaultStatus(), unlocked: true, remaining: 600 });

describe('one unlock asks for the passkey once', () => {
  /** What a passkey answers; with `prf` false, an authenticator with no PRF. */
  const answer = (prf = true) => ({
    rawId: new Uint8Array([0, 1, 2]).buffer,
    getClientExtensionResults: () =>
      prf ? { prf: { results: { first: new Uint8Array([1]).buffer } } } : {}
  });

  function credentials(get: jest.Mock): jest.Mock {
    Object.defineProperty(navigator, 'credentials', {
      value: { get },
      configurable: true
    });
    return get;
  }

  beforeEach(() => {
    mockApi.unlockPasskey = jest.fn().mockResolvedValue(open());
    mockApi.entries = jest.fn().mockResolvedValue([]);
  });

  it('asks nothing on a vault that is unlocked, and posts nothing', async () => {
    const commands = await activate();
    mockApi.status.mockResolvedValue(open());
    await mockPanel.refresh();
    const get = credentials(jest.fn());
    await commands.get(UNLOCK).execute({ nonce: 'n10' });
    expect(get).not.toHaveBeenCalled();
    expect(mockLaunch).not.toHaveBeenCalled();
    expect(posted()).toEqual([]);
  });

  it('opens no chooser on a vault that is unlocked', async () => {
    const commands = await activate();
    mockApi.status.mockResolvedValue(open());
    await commands.get(UNLOCK).execute({ nonce: 'n11', method: 'choose' });
    expect(mockLaunch).not.toHaveBeenCalled();
    expect(posted()).toEqual([]);
  });

  it('runs the passkey when this tab still reads unlocked and the vault is locked', async () => {
    // A hidden panel reads nothing, so what it read last can be a lock ago.
    const commands = await activate();
    mockApi.status.mockResolvedValue(open());
    await mockPanel.refresh();
    mockApi.status.mockResolvedValue(vaultStatus());
    const get = credentials(jest.fn().mockResolvedValue(answer()));
    await commands.get(UNLOCK).execute({ nonce: 'n12' });
    expect(get).toHaveBeenCalledTimes(1);
    expect(mockApi.unlockPasskey).toHaveBeenCalledTimes(1);
    expect(posted()).toEqual([]);
  });

  it('reads the vault once, then goes on to the passkey request on a locked vault', async () => {
    // The tab has just read it locked: the press reads all the same.
    const commands = await activate();
    await mockPanel.refresh();
    mockApi.status.mockClear();
    let reads = -1;
    const get = credentials(
      jest.fn().mockImplementation(async () => {
        reads = mockApi.status.mock.calls.length;
        return answer();
      })
    );
    await commands.get(UNLOCK).execute({ nonce: 'n13' });
    expect(reads).toBe(1);
    expect(get).toHaveBeenCalledTimes(1);
    expect(mockApi.unlockPasskey).toHaveBeenCalledTimes(1);
  });

  it('shares one passkey request between two clicks during an unlock', async () => {
    const commands = await activate();
    await mockPanel.refresh();
    let release: (value: unknown) => void = () => undefined;
    const get = credentials(
      jest.fn().mockImplementation(
        () =>
          new Promise(resolve => {
            release = resolve;
          })
      )
    );
    const clicks = [
      commands.get(UNLOCK).execute({ nonce: 'n14' }),
      commands.get(UNLOCK).execute({ nonce: 'n15' })
    ];
    await new Promise(resolve => setTimeout(resolve));
    release(answer());
    await Promise.all(clicks);
    expect(get).toHaveBeenCalledTimes(1);
    expect(mockApi.unlockPasskey).toHaveBeenCalledTimes(1);
    expect(posted()).toEqual([]);
  });

  it('shares it with a click on the panel button', async () => {
    const commands = await activate();
    await mockPanel.refresh();
    let release: (value: unknown) => void = () => undefined;
    const get = credentials(
      jest.fn().mockImplementation(
        () =>
          new Promise(resolve => {
            release = resolve;
          })
      )
    );
    const click = commands.get(UNLOCK).execute({ nonce: 'n16' });
    await new Promise(resolve => setTimeout(resolve));
    const label = 'Unlock with passkey';
    (
      Array.from<HTMLButtonElement>(
        mockPanel.node.querySelectorAll('button')
      ).find(b => b.textContent === label) as HTMLButtonElement
    ).click();
    await new Promise(resolve => setTimeout(resolve));
    release(answer());
    await click;
    expect(get).toHaveBeenCalledTimes(1);
    expect(mockApi.unlockPasskey).toHaveBeenCalledTimes(1);
  });

  it('runs a click of its own once the unlock before it has ended', async () => {
    const commands = await activate();
    await mockPanel.refresh();
    const get = credentials(jest.fn().mockResolvedValue(answer()));
    await commands.get(UNLOCK).execute({ nonce: 'n17' });
    await commands.get(UNLOCK).execute({ nonce: 'n18' });
    expect(get).toHaveBeenCalledTimes(2);
  });

  it('sends a refusal after the passkey answered to the CLI, with no chooser', async () => {
    const commands = await activate();
    await mockPanel.refresh();
    const get = credentials(jest.fn().mockResolvedValue(answer()));
    mockApi.unlockPasskey = jest
      .fn()
      .mockRejectedValue(new VaultError(500, 'the key holder refused'));
    await commands.get(UNLOCK).execute({ nonce: 'n19' });
    expect(get).toHaveBeenCalledTimes(1);
    expect(mockLaunch).not.toHaveBeenCalled();
    expect(answered()).toEqual({
      nonce: 'n19',
      ok: false,
      error: 'the key holder refused'
    });
  });

  it('sends a passkey with no PRF to the CLI as its line, with no chooser', async () => {
    const commands = await activate();
    await mockPanel.refresh();
    const get = credentials(jest.fn().mockResolvedValue(answer(false)));
    await commands.get(UNLOCK).execute({ nonce: 'n20' });
    expect(get).toHaveBeenCalledTimes(1);
    expect(mockLaunch).not.toHaveBeenCalled();
    expect(answered()).toEqual({
      nonce: 'n20',
      ok: false,
      error: 'no PRF - this passkey cannot unlock the vault'
    });
  });
});

describe('a vault notification nothing waits for', () => {
  let seq = 0;

  /** A notification the notifications extension adds in this tab, as a CLI raised it. */
  function notice(data: unknown): any {
    const n = {
      id: `notice-${++seq}`,
      createdAt: Date.now(),
      message: '**the tests**: Unlock the vault',
      type: 'info',
      options: { data, actions: [] }
    };
    mockNotices.push(n);
    mockChanged.forEach(fn => fn(null, { type: 'added', notification: n }));
    return n;
  }

  /** Let the reads in flight finish. */
  async function settled(): Promise<void> {
    await jest.advanceTimersByTimeAsync(0);
  }

  beforeEach(() => {
    mockNotices.length = 0;
    mockChanged.length = 0;
    mockApi.entries = jest.fn().mockResolvedValue([]);
    jest.useFakeTimers();
  });

  afterEach(async () => {
    // With none left, each poll of this test stops and drops its listener.
    mockNotices.length = 0;
    await jest.advanceTimersByTimeAsync(REFRESH_MS);
    jest.useRealTimers();
  });

  it('drops an unlock notification on a read begun after it that shows the vault open', () => {
    const n = notice({ command: UNLOCK, seconds: 120 });
    expect(dismissStale(open(), n.createdAt)).toBe(true);
    expect(dismissStale(vaultStatus(), n.createdAt + 1)).toBe(true);
    expect(mockDismiss).not.toHaveBeenCalled();
    expect(dismissStale(open(), n.createdAt + 1)).toBe(false);
    expect(mockDismiss).toHaveBeenCalledWith(n.id);
  });

  it('leaves every other notification alone', () => {
    const others = [
      notice(undefined),
      notice(null),
      notice(UNLOCK),
      notice({ command: 'passkey:copy', seconds: 0 }),
      notice({ command: REGISTER_COMMAND, seconds: 0 })
    ];
    expect(dismissStale(open(), Date.now() + 1)).toBe(false);
    expect(mockNotices).toEqual(others);
    expect(mockDismiss).not.toHaveBeenCalled();
  });

  it('reads nothing while no vault notification is in the tab', async () => {
    await activate();
    await settled();
    notice({ command: 'passkey:copy', seconds: 120 });
    await jest.advanceTimersByTimeAsync(3 * REFRESH_MS);
    // The one read at start-up.
    expect(mockApi.status).toHaveBeenCalledTimes(1);
  });

  it('removes an unlock notification within one poll once the vault opens elsewhere, and a press then asks nothing', async () => {
    // The panel is never shown: a hidden panel reads nothing of its own.
    const commands = await activate();
    await settled();
    const n = notice({ command: UNLOCK, seconds: 120 });
    // Opened by a terminal or another tab.
    mockApi.status.mockResolvedValue(open());
    await jest.advanceTimersByTimeAsync(REFRESH_MS - 1);
    expect(mockNotices).toEqual([n]);
    await jest.advanceTimersByTimeAsync(1);
    expect(mockNotices).toEqual([]);
    expect(mockDismiss).toHaveBeenCalledWith(n.id);

    const get = jest.fn();
    Object.defineProperty(navigator, 'credentials', {
      value: { get },
      configurable: true
    });
    await commands.get(UNLOCK).execute({ nonce: 'n40' });
    expect(get).not.toHaveBeenCalled();
    expect(mockLaunch).not.toHaveBeenCalled();
    expect(posted()).toEqual([]);

    // The poll stops with the last one gone.
    const reads = mockApi.status.mock.calls.length;
    await jest.advanceTimersByTimeAsync(3 * REFRESH_MS);
    expect(mockApi.status).toHaveBeenCalledTimes(reads);
  });

  it('keeps it while the vault stays locked, until the wait of its CLI has run out', async () => {
    await activate();
    await settled();
    const n = notice({ command: UNLOCK, seconds: (2 * REFRESH_MS) / 1000 });
    await jest.advanceTimersByTimeAsync(REFRESH_MS);
    expect(mockNotices).toEqual([n]);
    await jest.advanceTimersByTimeAsync(REFRESH_MS);
    expect(mockNotices).toEqual([]);
  });

  it('removes a set-up notification once the vault exists', async () => {
    await activate();
    await settled();
    mockApi.status.mockResolvedValue(NEW_VAULT());
    notice({ command: SETUP_COMMAND, seconds: 600 });
    await jest.advanceTimersByTimeAsync(REFRESH_MS);
    expect(mockNotices).toHaveLength(1);
    // Created in the panel of another tab, and locked since.
    mockApi.status.mockResolvedValue(vaultStatus());
    await jest.advanceTimersByTimeAsync(REFRESH_MS);
    expect(mockNotices).toEqual([]);
  });

  it('takes no read begun before it came for a sign the vault is open', async () => {
    // A read begun while the vault was open answers after a CLI met the lock.
    await activate();
    await settled();
    let answer: (status: unknown) => void = () => undefined;
    mockApi.status.mockImplementationOnce(
      () =>
        new Promise(resolve => {
          answer = resolve;
        })
    );
    const reading = mockPanel.refresh();
    jest.setSystemTime(Date.now() + 1);
    const n = notice({ command: UNLOCK, seconds: 120 });
    // The answer comes after the notification: the read's start time decides.
    jest.setSystemTime(Date.now() + 1);
    answer(open());
    await reading;
    expect(
      mockPanel.node.querySelector('.jp-PasskeyVaultPanel-stateText')
        .textContent
    ).toContain('Unlocked');
    expect(mockNotices).toEqual([n]);
    // The next poll reads the lock.
    await jest.advanceTimersByTimeAsync(REFRESH_MS);
    expect(mockNotices).toEqual([n]);

    // The same for a read of the poll: it began after n and before m.
    mockApi.status.mockImplementationOnce(
      () =>
        new Promise(resolve => {
          answer = resolve;
        })
    );
    await jest.advanceTimersByTimeAsync(REFRESH_MS);
    jest.setSystemTime(Date.now() + 1);
    const m = notice({ command: UNLOCK, seconds: 120 });
    jest.setSystemTime(Date.now() + 1);
    answer(open());
    await settled();
    expect(mockNotices).toEqual([m]);
  });

  it('removes it on a poll that reads the vault open, as the tab read it before', async () => {
    // Locked and opened again between two reads of this tab: what it reads is unchanged.
    await activate();
    await settled();
    mockApi.status.mockResolvedValue(open());
    await mockPanel.refresh();
    const n = notice({ command: UNLOCK, seconds: 120 });
    await jest.advanceTimersByTimeAsync(REFRESH_MS - 1);
    expect(mockNotices).toEqual([n]);
    await jest.advanceTimersByTimeAsync(1);
    expect(mockNotices).toEqual([]);
  });

  it('stops reading once the last one is dismissed in the notification list', async () => {
    await activate();
    await settled();
    const n = notice({ command: UNLOCK, seconds: 600 });
    await jest.advanceTimersByTimeAsync(REFRESH_MS);
    const reads = mockApi.status.mock.calls.length;
    // The user's dismissal, not a press, which reads again by itself.
    mockNotices.splice(mockNotices.indexOf(n), 1);
    mockChanged.forEach(fn => fn(null, { type: 'removed', notification: n }));
    await jest.advanceTimersByTimeAsync(3 * REFRESH_MS);
    expect(mockApi.status).toHaveBeenCalledTimes(reads);
  });

  it('reads nothing in a hidden tab, and reads at once when it is shown again', async () => {
    await activate();
    await settled();
    const n = notice({ command: UNLOCK, seconds: 600 });
    mockApi.status.mockResolvedValue(open());
    const reads = mockApi.status.mock.calls.length;
    Object.defineProperty(document, 'hidden', {
      value: true,
      configurable: true
    });
    try {
      await jest.advanceTimersByTimeAsync(2 * REFRESH_MS);
      expect(mockApi.status).toHaveBeenCalledTimes(reads);
      expect(mockNotices).toEqual([n]);
    } finally {
      delete (document as any).hidden;
    }
    document.dispatchEvent(new Event('visibilitychange'));
    await settled();
    expect(mockNotices).toEqual([]);
  });

  // The notifications extension fetches the pending ones before this plugin starts,
  // as when a tab opens or reloads while a CLI waits. activate() sets the API double
  // at once and reads only after its lazy imports, so a change to it right after the
  // call reaches the start-up read.
  it('reads for one that came before the plugin started, its start-up read failed', async () => {
    const n = notice({ command: UNLOCK, seconds: 120 });
    const starting = activate();
    mockApi.status.mockRejectedValueOnce(new Error('offline'));
    await starting;
    await settled();
    mockApi.status.mockResolvedValue(open());
    await jest.advanceTimersByTimeAsync(REFRESH_MS - 1);
    expect(mockNotices).toEqual([n]);
    await jest.advanceTimersByTimeAsync(1);
    expect(mockNotices).toEqual([]);
  });

  it('removes one that came before the plugin started on its start-up read of an open vault', async () => {
    const n = notice({ command: UNLOCK, seconds: 120 });
    jest.setSystemTime(Date.now() + 1);
    const starting = activate();
    mockApi.status.mockResolvedValue(open());
    await starting;
    await settled();
    expect(mockNotices).toEqual([]);
    expect(mockDismiss).toHaveBeenCalledWith(n.id);
    expect(mockApi.status).toHaveBeenCalledTimes(1);
  });

  // Owner decision 41. The locked unlock is 'reads the vault once, then goes on to the
  // passkey request on a locked vault' above.
  describe('a press reads the vault state before it asks anything', () => {
    const FAILED =
      'Vault state unreadable (cannot reach the Jupyter server) - rerun the command';

    /**
     * A tab whose start-up read gave `before`, then a notification of `command`, and
     * the press a second later, before the tab's next read.
     */
    async function pressing(
      command: string,
      before: unknown
    ): Promise<{ commands: Map<string, any>; n: any; get: jest.Mock }> {
      const starting = activate();
      mockApi.status.mockResolvedValue(before);
      const commands = await starting;
      await settled();
      const n = notice({ command, seconds: 600 });
      jest.setSystemTime(Date.now() + 1000);
      const get = jest.fn();
      Object.defineProperty(navigator, 'credentials', {
        value: { get },
        configurable: true
      });
      return { commands, n, get };
    }

    it('asks nothing on an unlock notification once the vault was opened another way, and the notification leaves', async () => {
      const { commands, n, get } = await pressing(UNLOCK, vaultStatus());
      mockApi.status.mockResolvedValue(open());
      await commands.get(UNLOCK).execute({ nonce: 'p1' });
      expect(get).not.toHaveBeenCalled();
      expect(mockLaunch).not.toHaveBeenCalled();
      expect(posted()).toEqual([]);
      expect(mockNotices).toEqual([]);
      expect(mockDismiss).toHaveBeenCalledWith(n.id);
    });

    it('asks nothing on an unlock notification when the read fails, and raises a failure notification', async () => {
      const { commands, get } = await pressing(UNLOCK, vaultStatus());
      mockApi.status.mockRejectedValueOnce(new NoAnswer());
      await commands.get(UNLOCK).execute({ nonce: 'p2' });
      expect(get).not.toHaveBeenCalled();
      expect(mockLaunch).not.toHaveBeenCalled();
      expect(mockError).toHaveBeenCalledWith(
        'Vault state unreadable (cannot reach the Jupyter server) - rerun the command.',
        { autoClose: false }
      );
      expect(posted()).toEqual([{ nonce: 'p2', ok: false, error: FAILED }]);
    });

    it('asks nothing on a set-up notification once a vault exists, and the notification leaves', async () => {
      const { commands, n } = await pressing(SETUP_COMMAND, NEW_VAULT());
      // Created in the panel of another tab.
      mockApi.status.mockResolvedValue(vaultStatus());
      await commands.get(SETUP_COMMAND).execute({ nonce: 'p3' });
      expect(mockAskSecret).not.toHaveBeenCalled();
      expect(mockLaunch).not.toHaveBeenCalled();
      expect(posted()).toEqual([]);
      expect(mockNotices).toEqual([]);
      expect(mockDismiss).toHaveBeenCalledWith(n.id);
    });

    it('reads, then asks the recovery passphrase on a set-up notification while there is no vault', async () => {
      const { commands } = await pressing(SETUP_COMMAND, NEW_VAULT());
      mockApi.status.mockClear();
      let reads = -1;
      mockAskSecret.mockImplementationOnce(async () => {
        reads = mockApi.status.mock.calls.length;
        return { accepted: false, value: null };
      });
      await commands.get(SETUP_COMMAND).execute({ nonce: 'p4' });
      expect(reads).toBe(1);
      expect(answered().ok).toBe(false);
    });

    it('asks nothing on a set-up notification when the read fails, and raises a failure notification', async () => {
      const { commands } = await pressing(SETUP_COMMAND, NEW_VAULT());
      mockApi.status.mockRejectedValueOnce(new NoAnswer());
      await commands.get(SETUP_COMMAND).execute({ nonce: 'p5' });
      expect(mockAskSecret).not.toHaveBeenCalled();
      expect(mockError).toHaveBeenCalledWith(
        'Vault state unreadable (cannot reach the Jupyter server) - rerun the command.',
        { autoClose: false }
      );
      expect(posted()).toEqual([{ nonce: 'p5', ok: false, error: FAILED }]);
    });
  });
});

it('unlocks from the chooser with the passkey', async () => {
  const commands = await activate();
  mockApi.unlockPasskey = jest.fn().mockResolvedValue(vaultStatus());
  Object.defineProperty(navigator, 'credentials', {
    value: {
      get: jest.fn().mockResolvedValue({
        rawId: new Uint8Array([0, 1, 2]).buffer,
        getClientExtensionResults: () => ({
          prf: { results: { first: new Uint8Array([1]).buffer } }
        })
      })
    },
    configurable: true
  });
  mockLaunch.mockImplementation(async (dialog: any) => {
    dialog.options.body.chosen = 'passkey';
    return { button: { accept: false } };
  });
  await commands
    .get('passkey:vault-unlock')
    .execute({ nonce: 'n10', method: 'choose' });
  expect(mockApi.unlockPasskey).toHaveBeenCalledWith('AAEC', 'AQ');
  expect(posted()).toEqual([]);
});

it('unlocks from the chooser with the unlock password and a code', async () => {
  const commands = await activate();
  const withMfa = {
    ...vaultStatus(),
    slots: [...vaultStatus().slots, { type: 'password' }],
    authenticator: { created: '2026-10-02T10:00:00Z' }
  };
  mockApi.status.mockResolvedValue(withMfa);
  mockApi.unlockPassword = jest.fn().mockResolvedValue(withMfa);
  mockAskSecret.mockResolvedValue({ accepted: true, value: 'everyday' });
  mockLaunch.mockImplementation(async (dialog: any) => {
    const body = dialog.options.body;
    if ('chosen' in body) {
      body.chosen = 'mfa';
      return { button: { accept: false } };
    }
    body.code.value = '123456';
    return { button: { accept: true } };
  });
  await commands
    .get('passkey:vault-unlock')
    .execute({ nonce: 'n11', method: 'choose' });
  expect(mockAskSecret.mock.calls[0][1]).toBe(1);
  expect(mockApi.unlockPassword).toHaveBeenCalledWith('everyday', '123456');
  expect(posted()).toEqual([]);
});

/** A browser that creates a passkey and answers the PRF request for it. */
function creatingBrowser(): void {
  Object.defineProperty(navigator, 'credentials', {
    value: {
      get: jest.fn().mockResolvedValue({
        rawId: new Uint8Array([9]).buffer,
        getClientExtensionResults: () => ({
          prf: { results: { first: new Uint8Array([1]).buffer } }
        })
      }),
      create: jest.fn().mockResolvedValue({ rawId: new Uint8Array([9]).buffer })
    },
    configurable: true
  });
}

const NAMING = async (dialog: any): Promise<any> => ({
  button: {
    accept: ['Name the new passkey', 'Confirm the new passkey'].includes(
      dialog.options.title
    )
  }
});

/** A press on each of `choices` in turn at the set-up's choice; then Escape. */
function choosing(...choices: string[]): void {
  mockLaunch.mockImplementation(async (dialog: any) => {
    const body = dialog.options.body;
    if (typeof body === 'object' && 'chosen' in body) {
      body.chosen = choices.shift() ?? null;
      return { button: { accept: false } };
    }
    return NAMING(dialog);
  });
}

/** The body of the choice dialog opened `index`-th. */
function chooser(index = 0): any {
  return mockLaunch.mock.calls
    .map(call => call[0].options.body)
    .filter(body => typeof body === 'object' && 'chosen' in body)[index];
}

/** The button names of that dialog. */
function choices(index = 0): string[] {
  return Array.from(
    chooser(index).node.querySelectorAll('button') as NodeListOf<HTMLElement>
  ).map(button => (button.firstChild as HTMLElement).textContent as string);
}

const NEW_VAULT = (): any => ({
  ...vaultStatus(),
  initialized: false,
  slots: []
});

describe('the set-up a command raises', () => {
  beforeEach(() => {
    mockApi.init = jest.fn().mockResolvedValue(undefined);
    mockApi.addMfa = jest.fn().mockResolvedValue(undefined);
    mockAskSecret.mockResolvedValue({
      accepted: true,
      value: 'recovery words'
    });
  });

  afterEach(() => {
    mockAskSecret.mockReset();
    mockLaunch.mockReset();
  });

  it('asks the passphrase, then offers the choice, and adds a passkey with that proof', async () => {
    const commands = await activate();
    creatingBrowser();
    mockApi.status.mockResolvedValue(NEW_VAULT());
    choosing('passkey');

    await commands.get(SETUP_COMMAND).execute({ nonce: 's1' });
    expect(mockAskSecret.mock.calls[0][0]).toBe(
      'Choose a recovery passphrase and store it offline - it opens the vault when no other method can'
    );
    expect(mockAskSecret.mock.calls[0][1]).toBe(2);
    expect(mockApi.init).toHaveBeenCalledWith('recovery words');
    expect(choices()).toEqual([
      'Passkey',
      'Password and authenticator app',
      'Later'
    ]);
    // The passphrase just chosen is the proof: no second prompt for it.
    expect(mockAskSecret).toHaveBeenCalledTimes(1);
    expect(mockApi.checkRecovery).not.toHaveBeenCalled();
    expect(mockApi.addPasskey.mock.calls[0][1]).toEqual({
      current: 'recovery words'
    });
    expect(posted()).toEqual([]);
  });

  it('adds the password and authenticator app with that proof', async () => {
    const commands = await activate();
    mockApi.status.mockResolvedValue(NEW_VAULT());
    mockAskSecret
      .mockResolvedValueOnce({ accepted: true, value: 'recovery words' })
      .mockResolvedValueOnce({ accepted: true, value: 'a long password' });
    mockLaunch.mockImplementation(async (dialog: any) => {
      const body = dialog.options.body;
      if ('chosen' in body) {
        body.chosen = 'mfa';
        return { button: { accept: false } };
      }
      body.code.value = '123456';
      return { button: { accept: true } };
    });

    await commands.get(SETUP_COMMAND).execute({ nonce: 's8' });
    expect(mockAskSecret).toHaveBeenCalledTimes(2);
    expect(mockAskSecret.mock.calls[1]).toEqual([
      'Enter the new unlock password, at least 12 characters',
      2,
      'Add password and authenticator app',
      { minLength: 12 }
    ]);
    expect(mockApi.addMfa).toHaveBeenCalledWith(
      'a long password',
      expect.any(String),
      '123456',
      { current: 'recovery words' }
    );
    expect(mockApi.addPasskey).not.toHaveBeenCalled();
    expect(posted()).toEqual([]);
  });

  it('offers no Passkey at an IP address, and leaves the other choices', async () => {
    await activate();
    mockApi.status.mockResolvedValue(NEW_VAULT());
    choosing('later');
    await setupVault(mockApi, NEW_VAULT(), '192.168.1.10');
    expect(mockApi.init).toHaveBeenCalledWith('recovery words');
    expect(choices()).toEqual(['Password and authenticator app', 'Later']);
  });

  it.each([
    ['with no passkey', [{ type: 'recovery' }]],
    ['with a passkey', undefined]
  ])(
    'asks nothing when a vault exists %s by the time of the click',
    async (_, slots) => {
      const commands = await activate();
      mockApi.status.mockResolvedValue({
        ...vaultStatus(),
        ...(slots ? { slots } : {})
      });
      await commands.get(SETUP_COMMAND).execute({ nonce: 's3' });
      expect(mockAskSecret).not.toHaveBeenCalled();
      expect(mockLaunch).not.toHaveBeenCalled();
      expect(mockApi.init).not.toHaveBeenCalled();
      expect(mockApi.addPasskey).not.toHaveBeenCalled();
      expect(posted()).toEqual([]);
    }
  );

  it('posts a cancelled passphrase step to the command, naming the step', async () => {
    const commands = await activate();
    mockApi.status.mockResolvedValue(NEW_VAULT());
    mockAskSecret.mockResolvedValue({ accepted: false, value: null });
    await commands.get(SETUP_COMMAND).execute({ nonce: 's4' });
    expect(mockApi.init).not.toHaveBeenCalled();
    expect(answered()).toEqual({
      nonce: 's4',
      ok: false,
      error:
        'recovery passphrase step was cancelled - rerun the command to continue'
    });
  });

  it('posts a refused passphrase step to the command, with no choice opened', async () => {
    const commands = await activate();
    mockApi.status.mockResolvedValue(NEW_VAULT());
    mockApi.init.mockRejectedValue(new VaultError(400, 'disk full'));
    await commands.get(SETUP_COMMAND).execute({ nonce: 's10' });
    expect(mockLaunch).not.toHaveBeenCalled();
    expect(answered()).toEqual({
      nonce: 's10',
      ok: false,
      error:
        'recovery passphrase step failed (disk full) - rerun the command to continue'
    });
  });
});

it('opens the Settings Editor at the vault settings, searched by the schema title', async () => {
  await activate();
  mockPanel._openSettings();
  expect(mockApp.commands.execute).toHaveBeenCalledWith('settingeditor:open', {
    query: 'Passkey Vault'
  });
  expect(schema.title).toBe('Passkey Vault');
  // The sidebar is the page's only setting: the vault's policy lives on the server.
  expect(Object.keys(schema.properties)).toEqual(['sidebar']);
});

describe('one success notification per unlock', () => {
  it('emits once on the locked -> unlocked edge, and not on a repeated read', async () => {
    await activate();
    await mockPanel.refresh();
    expect(mockEmit).not.toHaveBeenCalled();
    mockApi.status.mockResolvedValue(open());
    await mockPanel.refresh();
    expect(mockEmit).toHaveBeenCalledTimes(1);
    expect(mockEmit).toHaveBeenCalledWith('Vault unlocked', 'success', {
      autoClose: 4000
    });
    // The timer's read shares the last value: no second toast.
    await mockPanel.poll();
    expect(mockEmit).toHaveBeenCalledTimes(1);
  });

  it('emits none when the first read is already unlocked', async () => {
    const starting = activate();
    mockApi.status.mockResolvedValue(open());
    await starting;
    await mockPanel.refresh();
    expect(mockEmit).not.toHaveBeenCalled();
  });

  it('emits none on repeated unlocked reads', async () => {
    const starting = activate();
    mockApi.status.mockResolvedValue(open());
    await starting;
    await mockPanel.refresh();
    await mockPanel.refresh();
    expect(mockEmit).not.toHaveBeenCalled();
  });
});

it('docks the panel on the side the setting names, and moves it when the setting changes', async () => {
  let side = 'left';
  let onChange = (): void => undefined;
  const get = jest.fn((key: string) => ({
    composite: key === 'sidebar' ? side : 240
  }));
  const settings = {
    get,
    changed: { connect: (fn: () => void) => (onChange = fn) }
  };
  await activate({ load: jest.fn().mockResolvedValue(settings) });
  expect(mockApp.shell.add).toHaveBeenLastCalledWith(
    mockPanel,
    'left',
    expect.anything()
  );
  side = 'right';
  onChange();
  expect(mockApp.shell.add).toHaveBeenLastCalledWith(
    mockPanel,
    'right',
    expect.anything()
  );
  expect(mockApp.shell.add).toHaveBeenCalledTimes(2);
  // Only the sidebar is read, and nothing is posted to the server.
  expect(get.mock.calls.every(call => call[0] === 'sidebar')).toBe(true);
  expect((mockApi as any).setConfig).toBeUndefined();
});
