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
import { REGISTER_COMMAND, vaultPlugin } from '../vault/plugin';

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
  expect(Object.keys(unlock.describedBy.args.properties)).toEqual(['nonce']);
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
