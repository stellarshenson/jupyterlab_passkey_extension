/**
 * The vault plugin's commands a CLI raises: `passkey:vault-register` runs in the page,
 * gets the proof there and answers the CLI through the result relay. The REST API,
 * the relay, the dialogs and WebAuthn are faked.
 */

const mockApi: any = {};
const mockAskSecret = jest.fn();
const mockLaunch = jest.fn();
const mockRequest = jest.fn();
jest.mock('@jupyterlab/apputils', () => ({
  Dialog: class {
    static cancelButton(o: any = {}): any {
      return { accept: false, ...o };
    }
    static okButton(o: any = {}): any {
      return { accept: true, ...o };
    }
    constructor(readonly options: any) {}
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
import { REGISTER_COMMAND, SETUP_COMMAND, vaultPlugin } from '../vault/plugin';

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
    addPasskey: jest.fn().mockResolvedValue(undefined)
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

/** What the page posted to the CLI's result relay. */
function answered(): any {
  const call = mockRequest.mock.calls.find(c => c[0] === 'result');
  return JSON.parse(call[2].body);
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
  expect(answered()).toEqual({ nonce: 'n1', ok: true });
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

it('clears a kept line through a CLI step, as the next action does', async () => {
  // A lost answer to the panel's own unlock, then the CLI's step succeeds here.
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
  mockPanel._message = {
    kind: 'error',
    text: 'Not confirmed by the vault',
    at: 0,
    keep: true
  };
  await commands.get(REGISTER_COMMAND).execute({ nonce: 'n4', label: 'CLI' });
  expect(answered()).toEqual({ nonce: 'n4', ok: true });
  expect(mockPanel.node.textContent).not.toContain('Not confirmed');
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
  expect(answered()).toEqual({ nonce: 'n5', ok: true });
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
  expect(answered()).toEqual({ nonce: 'n6', ok: true });
});

it('runs the chooser for method choose, and the passkey with no method', async () => {
  const commands = await activate();
  const answers = (): any[] =>
    mockRequest.mock.calls
      .filter(c => c[0] === 'result')
      .map(c => JSON.parse(c[2].body));
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
  expect(mockApi.unlockRecovery).toHaveBeenCalledWith('recovery words');
  expect(answers()).toEqual([{ nonce: 'n7', ok: true }]);

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
  expect(answers()).toEqual([
    { nonce: 'n7', ok: true },
    { nonce: 'n8', ok: true }
  ]);
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
  expect(answered()).toEqual({ nonce: 'n9', ok: true });
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
  expect(answered()).toEqual({ nonce: 'n10', ok: true });
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
  expect(mockApi.unlockPassword).toHaveBeenCalledWith('everyday', '123456');
  expect(answered()).toEqual({ nonce: 'n11', ok: true });
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

it('sets the vault up from a command: the passphrase, then a passkey, and answers ok', async () => {
  const commands = await activate();
  creatingBrowser();
  mockApi.status.mockResolvedValue({
    ...vaultStatus(),
    initialized: false,
    slots: []
  });
  mockApi.init = jest.fn().mockResolvedValue(undefined);
  mockAskSecret.mockResolvedValue({ accepted: true, value: 'recovery words' });
  mockLaunch.mockImplementation(NAMING);

  await commands.get(SETUP_COMMAND).execute({ nonce: 's1' });
  expect(mockAskSecret.mock.calls[0][0]).toBe(
    'Choose a recovery passphrase and store it offline - it is the only way in without a passkey.'
  );
  expect(mockApi.init).toHaveBeenCalledWith('recovery words');
  expect(mockApi.addPasskey.mock.calls[0][1]).toEqual({
    current: 'recovery words'
  });
  expect(answered()).toEqual({ nonce: 's1', ok: true });
});

it('adds only the passkey when the vault already exists without one', async () => {
  const commands = await activate();
  creatingBrowser();
  mockApi.status.mockResolvedValue({
    ...vaultStatus(),
    slots: [{ type: 'recovery' }]
  });
  mockApi.init = jest.fn();
  mockAskSecret.mockResolvedValue({ accepted: true, value: 'recovery words' });
  mockLaunch.mockImplementation(NAMING);

  await commands.get(SETUP_COMMAND).execute({ nonce: 's2' });
  expect(mockApi.init).not.toHaveBeenCalled();
  expect(mockAskSecret.mock.calls[0][0]).toBe(
    'Enter the current recovery passphrase'
  );
  expect(mockApi.addPasskey.mock.calls[0][1]).toEqual({
    current: 'recovery words'
  });
  expect(answered()).toEqual({ nonce: 's2', ok: true });
});

it('answers without a dialog when the vault and its passkey are already there', async () => {
  const commands = await activate();
  mockApi.init = jest.fn();
  await commands.get(SETUP_COMMAND).execute({ nonce: 's3' });
  expect(mockAskSecret).not.toHaveBeenCalled();
  expect(mockApi.init).not.toHaveBeenCalled();
  expect(mockApi.addPasskey).not.toHaveBeenCalled();
  expect(answered()).toEqual({ nonce: 's3', ok: true });
});

it('posts a cancelled set-up step to the command, naming the step', async () => {
  const commands = await activate();
  mockApi.status.mockResolvedValue({
    ...vaultStatus(),
    initialized: false,
    slots: []
  });
  mockAskSecret.mockResolvedValue({ accepted: false, value: null });
  await commands.get(SETUP_COMMAND).execute({ nonce: 's4' });
  expect(answered()).toEqual({
    nonce: 's4',
    ok: false,
    error:
      'the recovery passphrase step was cancelled - run the command again to continue the vault set-up'
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
