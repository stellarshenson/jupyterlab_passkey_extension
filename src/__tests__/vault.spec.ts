/**
 * Unit tests for the vault frontend: passkey slot matching and the two ceremonies,
 * the panel's views, the entry form and the settings wiring. The REST
 * API, the dialogs and WebAuthn are faked; the panel renders into jsdom.
 */

import { MessageLoop } from '@lumino/messaging';
import { Widget } from '@lumino/widgets';

const mockAskSecret = jest.fn();
const mockEditEntry = jest.fn();
const mockViewEntry = jest.fn();
const mockConfirmDelete = jest.fn();
const mockLaunch = jest.fn();
jest.mock('../passphrase', () => ({
  askSecret: (...a: any[]) => mockAskSecret(...a),
  launchWithEscape: (...a: any[]) => mockLaunch(...a)
}));
jest.mock('../vault/dialogs', () => {
  const actual = jest.requireActual('../vault/dialogs');
  return {
    ...actual,
    editEntry: (...a: any[]) => mockEditEntry(...a),
    viewEntry: (...a: any[]) => mockViewEntry(...a),
    confirmDelete: (...a: any[]) => mockConfirmDelete(...a)
  };
});
jest.mock('@jupyterlab/apputils', () => ({
  Dialog: class {
    static cancelButton(o: any = {}): any {
      return { accept: false, ...o };
    }
    static okButton(o: any = {}): any {
      return { accept: true, ...o };
    }
    static warnButton(o: any = {}): any {
      return { accept: true, ...o };
    }
    constructor(readonly options: any) {}
    addClass(): void {}
  }
}));

/** Answer the dialogs the code under test opens itself, by title: accept or not. */
function answerDialogs(accept: Record<string, boolean>): void {
  mockLaunch.mockImplementation(async (dialog: any) => ({
    button: { accept: accept[dialog.options.title] ?? false }
  }));
}
// Only the icons are used; the real module drags in untransformed ESM React code.
jest.mock('@jupyterlab/ui-components', () => {
  const icon = { element: () => document.createElement('span') };
  return {
    addIcon: icon,
    lockIcon: icon,
    refreshIcon: icon,
    settingsIcon: icon,
    LabIcon: class {
      constructor(private readonly _options: { name: string }) {}
      element() {
        const span = document.createElement('span');
        span.dataset.icon = this._options.name;
        return span;
      }
    }
  };
});

import { IStatus, NoAnswer, VaultError } from '../vault/api';
import { EntryForm, EntryView } from '../vault/dialogs';
import {
  ARM_DELAY_MS,
  formatMinutes,
  formatRemaining,
  REFRESH_MS,
  VaultPanel
} from '../vault/panel';
import { connectSettings } from '../vault/plugin';
import {
  describeFailure,
  ipAddressAdvice,
  matchingSlots,
  registerPasskey,
  unlockWithPasskey
} from '../vault/webauthn';

const HOST = 'lab.example.com';

function status(over: Partial<IStatus> = {}): IStatus {
  return {
    initialized: true,
    unlocked: true,
    remaining: 4 * 3600,
    holder: {
      name: 'gpg-agent',
      about: 'a GnuPG agent of its own',
      summary: 'reduced',
      protection: 'not kept out of swap',
      capabilities: {
        locked_memory: false,
        no_core_dump: true,
        holder_ttl: true,
        locks_on_restart: false,
        container_isolated: true
      },
      details: [
        {
          key: 'locked_memory',
          label: 'Never in swap',
          text: "the holder's copy of the key can be written to swap"
        },
        {
          key: 'no_core_dump',
          label: 'Never in crash dumps',
          text: "a crash dump never contains the holder's copy of the key"
        },
        {
          key: 'holder_ttl',
          label: 'Expires on its own',
          text: 'the key is deleted at expiry even if the server stops'
        },
        {
          key: 'locks_on_restart',
          label: 'Locks on server restart',
          text: 'the key can outlive a Jupyter server restart, so the vault can stay unlocked until the unlock duration ends'
        },
        {
          key: 'container_isolated',
          label: 'Isolated from containers',
          text: 'other containers cannot read the key'
        }
      ],
      notice: null
    },
    slots: [
      { type: 'recovery' },
      {
        type: 'passkey',
        cred_id: 'AAEC',
        rp_id: HOST,
        prf_salt: 'c2FsdA',
        label: 'laptop',
        created: '2026-09-26T10:00:00Z'
      }
    ],
    settings: { unlock_minutes: 240 },
    path: '~/.local/share/jupyterlab-passkey/vault.json',
    ...over
  };
}

const ENTRIES = [
  {
    name: 'github/api',
    username: 'me',
    url: 'https://github.com',
    category: 'infra',
    notes: '',
    created: '',
    updated: ''
  },
  {
    name: 'gitlab/api',
    username: 'kj',
    url: 'https://gitlab.example',
    category: 'infra',
    notes: '',
    created: '',
    updated: ''
  },
  {
    name: 'nas/ugos',
    username: 'konrad',
    url: 'https://nas',
    category: 'home',
    notes: '{"ip": "1"}',
    created: '',
    updated: ''
  }
];

function fakeApi(over: Record<string, any> = {}): any {
  return {
    status: jest.fn().mockResolvedValue(status()),
    entries: jest.fn().mockResolvedValue(ENTRIES),
    lock: jest.fn().mockResolvedValue(undefined),
    init: jest.fn().mockResolvedValue(undefined),
    unlockRecovery: jest.fn().mockResolvedValue(status()),
    unlockPasskey: jest.fn().mockResolvedValue(status()),
    add: jest.fn().mockResolvedValue(undefined),
    edit: jest.fn().mockResolvedValue(undefined),
    remove: jest.fn().mockResolvedValue(undefined),
    revealPassword: jest.fn().mockResolvedValue('s3cret-value'),
    generate: jest.fn().mockResolvedValue('generated-pw'),
    addPasskey: jest.fn().mockResolvedValue(undefined),
    removePasskey: jest.fn().mockResolvedValue(undefined),
    replaceRecovery: jest.fn().mockResolvedValue(undefined),
    setConfig: jest.fn().mockResolvedValue(undefined),
    ...over
  };
}

async function panelWith(
  api: any,
  extra: Record<string, any> = {}
): Promise<VaultPanel> {
  const panel = new VaultPanel({
    api,
    openSettings: jest.fn(),
    host: HOST,
    ...extra
  });
  Widget.attach(panel, document.body);
  await panel.refresh();
  return panel;
}

function text(panel: VaultPanel): string {
  return panel.node.textContent ?? '';
}

function button(panel: VaultPanel, label: string): HTMLButtonElement {
  const found = Array.from(panel.node.querySelectorAll('button')).find(
    b => b.textContent === label
  );
  if (!found) {
    throw new Error(`no button "${label}" in: ${text(panel)}`);
  }
  return found;
}

const flush = () => new Promise(r => setTimeout(r, 0));

/** The banner's lines, each as its colour and its text. */
function lines(panel: VaultPanel): [string | undefined, string | null][] {
  return Array.from(
    panel.node.querySelectorAll<HTMLElement>('.jp-PasskeyVaultPanel-message')
  ).map(l => [l.dataset.kind, l.textContent]);
}

/** A passkey that answers with credential AAEC and PRF CQkJ (both base64url). */
function fakePasskey(): jest.Mock {
  const get = jest.fn().mockResolvedValue({
    rawId: new Uint8Array([0, 1, 2]).buffer,
    getClientExtensionResults: () => ({
      prf: { results: { first: new Uint8Array([9, 9, 9]).buffer } }
    })
  });
  Object.defineProperty(navigator, 'credentials', {
    value: { get },
    configurable: true
  });
  return get;
}

afterEach(() => {
  document.body.innerHTML = '';
  jest.clearAllMocks();
});

// --------------------------------------------------------------------------- //
// slots and ceremonies
// --------------------------------------------------------------------------- //

describe('matchingSlots', () => {
  const slots = [
    { type: 'recovery' as const },
    {
      type: 'passkey' as const,
      cred_id: 'a',
      rp_id: 'example.com',
      prf_salt: 's'
    },
    { type: 'passkey' as const, cred_id: 'b', rp_id: HOST, prf_salt: 's' },
    {
      type: 'passkey' as const,
      cred_id: 'c',
      rp_id: 'other.org',
      prf_salt: 's'
    }
  ];

  it('takes only the most specific RP ID that covers the host', () => {
    expect(matchingSlots(slots, HOST).map(s => s.cred_id)).toEqual(['b']);
  });

  it('accepts a parent domain when that is all there is', () => {
    expect(
      matchingSlots(slots, 'other.example.com').map(s => s.cred_id)
    ).toEqual(['a']);
  });

  it('offers nothing for an unrelated host', () => {
    expect(matchingSlots(slots, 'localhost')).toEqual([]);
  });
});

describe('unlockWithPasskey', () => {
  const get = jest.fn();
  beforeAll(() => {
    Object.defineProperty(navigator, 'credentials', {
      value: { get, create: jest.fn() },
      configurable: true
    });
  });

  it("asks only for this host's credentials, each with its own salt, and sends the PRF to the server", async () => {
    get.mockResolvedValue({
      rawId: new Uint8Array([0, 1, 2]).buffer,
      getClientExtensionResults: () => ({
        prf: { results: { first: new Uint8Array([7, 7]).buffer } }
      })
    });
    const api = fakeApi();
    const s = status();
    s.slots.push({
      type: 'passkey',
      cred_id: 'ZZZZ',
      rp_id: 'elsewhere.org',
      prf_salt: 'eA'
    });
    await unlockWithPasskey(api, s, HOST);
    const options = get.mock.calls[0][0].publicKey;
    expect(options.rpId).toBe(HOST);
    expect(options.allowCredentials).toHaveLength(1);
    expect(Object.keys(options.extensions.prf.evalByCredential)).toEqual([
      'AAEC'
    ]);
    expect(api.unlockPasskey).toHaveBeenCalledWith('AAEC', 'Bwc');
  });

  it('refuses when no passkey is registered for the host', async () => {
    await expect(
      unlockWithPasskey(fakeApi(), status(), 'localhost')
    ).rejects.toThrow('no passkey is registered for localhost');
  });

  it('refuses an authenticator that returns no PRF', async () => {
    get.mockResolvedValue({
      rawId: new ArrayBuffer(1),
      getClientExtensionResults: () => ({})
    });
    await expect(unlockWithPasskey(fakeApi(), status(), HOST)).rejects.toThrow(
      'no PRF'
    );
  });
});

describe('registerPasskey', () => {
  const create = jest.fn();
  const get = jest.fn();
  beforeAll(() => {
    Object.defineProperty(navigator, 'credentials', {
      value: { get, create },
      configurable: true
    });
  });

  it('creates, waits for the confirm click, then evaluates a PRF and registers the slot', async () => {
    const order: string[] = [];
    create.mockImplementation(async () => {
      order.push('create');
      return { rawId: new Uint8Array([9]).buffer };
    });
    get.mockImplementation(async () => {
      order.push('get');
      return {
        rawId: new Uint8Array([9]).buffer,
        getClientExtensionResults: () => ({
          prf: { results: { first: new Uint8Array([1]).buffer } }
        })
      };
    });
    const api = fakeApi();
    const offered: string[] = [];
    await registerPasskey(
      api,
      '',
      async suggested => {
        order.push('confirm');
        offered.push(suggested);
        return '';
      },
      { current: 'recovery words' },
      HOST
    );
    expect(order).toEqual(['create', 'confirm', 'get']);
    // Offered no name (so two passkeys do not both default to the hostname); an
    // empty answer falls back to the hostname.
    expect(offered).toEqual(['']);
    const slot = api.addPasskey.mock.calls[0][0];
    expect(slot).toMatchObject({
      cred_id: 'CQ',
      rp_id: HOST,
      label: HOST,
      prf: 'AQ'
    });
    expect(slot.prf_salt).toHaveLength(43);
    // The proof goes with the slot.
    expect(api.addPasskey.mock.calls[0][1]).toEqual({
      current: 'recovery words'
    });
  });

  it('stores the name chosen in the confirm step', async () => {
    create.mockResolvedValue({ rawId: new Uint8Array([9]).buffer });
    get.mockResolvedValue({
      rawId: new Uint8Array([9]).buffer,
      getClientExtensionResults: () => ({
        prf: { results: { first: new Uint8Array([1]).buffer } }
      })
    });
    const api = fakeApi();
    await registerPasskey(
      api,
      'cli label',
      async () => 'Work laptop',
      { current: 'pw' },
      HOST
    );
    expect(api.addPasskey.mock.calls[0][0].label).toBe('Work laptop');
    // The OS passkey manager can tell the credentials apart by host and date.
    const user = create.mock.calls[0][0].publicKey.user;
    expect(user.name).toMatch(
      new RegExp(
        `^JupyterLab vault - \\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} UTC - ${HOST}$`
      )
    );
  });

  it('says the created passkey is unused when any step after create stops', async () => {
    create.mockResolvedValue({ rawId: new Uint8Array([9]).buffer });
    const api = fakeApi();
    // Named by the user name it was created with, which the passkey manager lists.
    const unused = (why: string) =>
      new RegExp(
        `^${why}; the passkey your browser created \\("JupyterLab vault - [0-9: -]+ UTC - ${HOST}"\\) is unused - you can delete it in your passkey manager$`
      );
    // Declined at the confirm step ...
    await expect(
      registerPasskey(api, 'x', async () => null, { current: 'pw' }, HOST)
    ).rejects.toThrow(unused('passkey registration cancelled'));
    // ... or the second passkey prompt dismissed.
    get.mockRejectedValue(new DOMException('x', 'NotAllowedError'));
    await expect(
      registerPasskey(api, 'x', async () => '', { current: 'pw' }, HOST)
    ).rejects.toThrow(
      unused('the passkey request was cancelled or not allowed')
    );
    expect(api.addPasskey).not.toHaveBeenCalled();
  });
});

it('names localhost as a place on the computer that runs JupyterLab, and every passkey hostname', () => {
  const slot = (rp: string) => ({
    type: 'passkey' as const,
    cred_id: rp,
    rp_id: rp,
    prf_salt: 'c2FsdA'
  });
  expect(
    ipAddressAdvice([
      { type: 'recovery' },
      slot('localhost'),
      slot('lab.example.com'),
      slot('localhost')
    ])
  ).toBe(
    'an IP address cannot hold a passkey - open JupyterLab at localhost (when it runs on this computer) or lab.example.com, where your passkeys are registered, or by its hostname over HTTPS'
  );
});

it('describes a cancelled WebAuthn request in words', () => {
  expect(describeFailure(new DOMException('x', 'NotAllowedError'))).toBe(
    'the passkey request was cancelled or not allowed'
  );
  expect(describeFailure(new VaultError(423, 'the vault is locked'))).toBe(
    'the vault is locked'
  );
});

// --------------------------------------------------------------------------- //
// the panel
// --------------------------------------------------------------------------- //

describe('VaultPanel', () => {
  it('offers Create vault when there is none', async () => {
    const panel = await panelWith(
      fakeApi({
        status: jest.fn().mockResolvedValue(
          status({
            initialized: false,
            unlocked: false,
            remaining: null,
            slots: []
          })
        )
      })
    );
    expect(text(panel)).toContain(
      'No vault at ~/.local/share/jupyterlab-passkey/vault.json yet.'
    );
    // Drawn as the cog view draws it: one element per part.
    expect(
      Array.from(
        panel.node.querySelectorAll(
          '.jp-PasskeyVaultPanel-hint .jp-PasskeyVaultPanel-pathValue > span'
        )
      ).map(part => part.textContent)
    ).toEqual(['~/', '.local/', 'share/', 'jupyterlab-passkey/', 'vault.json']);
    expect(button(panel, 'Create vault')).toBeTruthy();
  });

  it('creates a vault: recovery passphrase twice, then a passkey', async () => {
    mockAskSecret.mockResolvedValue({
      accepted: true,
      value: 'recovery words'
    });
    const create = jest
      .fn()
      .mockResolvedValue({ rawId: new Uint8Array([9]).buffer });
    const get = jest.fn().mockResolvedValue({
      rawId: new Uint8Array([9]).buffer,
      getClientExtensionResults: () => ({
        prf: { results: { first: new Uint8Array([1]).buffer } }
      })
    });
    Object.defineProperty(navigator, 'credentials', {
      value: { get, create },
      configurable: true
    });
    answerDialogs({ 'Confirm the new passkey': true });
    const api = fakeApi({
      status: jest.fn().mockResolvedValue(
        status({
          initialized: false,
          unlocked: false,
          remaining: null,
          slots: []
        })
      )
    });
    const panel = await panelWith(api);
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    expect(mockAskSecret).toHaveBeenCalledWith(
      expect.any(String),
      false,
      'Create vault'
    );
    expect(api.init).toHaveBeenCalledWith('recovery words');
    // The passphrase just chosen is the proof: no second prompt for it.
    expect(mockAskSecret).toHaveBeenCalledTimes(1);
    expect(api.addPasskey.mock.calls[0][1]).toEqual({
      current: 'recovery words'
    });
  });

  it('says an IP address cannot hold a passkey, and where to open JupyterLab instead', async () => {
    // Jupyter prints http://127.0.0.1:8888 at start; a passkey needs a domain name.
    const ip = '127.0.0.1';
    // The vault has a passkey for HOST: that is where to go.
    const there = `an IP address cannot hold a passkey - open JupyterLab at ${HOST}, where your passkey is registered, or by its hostname over HTTPS`;
    await expect(unlockWithPasskey(fakeApi(), status(), ip)).rejects.toThrow(
      there
    );
    const locked = await panelWith(
      fakeApi({
        status: jest
          .fn()
          .mockResolvedValue(status({ unlocked: false, remaining: null }))
      }),
      { host: ip }
    );
    expect(text(locked)).toContain(
      `An IP address cannot hold a passkey - open JupyterLab at ${HOST}, where your passkey is registered, or by its hostname over HTTPS.`
    );
    locked.dispose();
    const panel = await panelWith(fakeApi(), { host: ip });
    (
      panel.node.querySelector(
        'button[title="Vault settings and security"]'
      ) as HTMLElement
    ).click();
    expect(text(panel)).toContain(`open JupyterLab at ${HOST}`);
    expect(
      Array.from(panel.node.querySelectorAll('button')).some(
        b => b.textContent === 'Register new passkey'
      )
    ).toBe(false);
  });

  it('creates a vault at an IP address without a passkey step, saying so first', async () => {
    const create = jest.fn();
    Object.defineProperty(navigator, 'credentials', {
      value: { create, get: jest.fn() },
      configurable: true
    });
    mockAskSecret.mockResolvedValue({
      accepted: true,
      value: 'recovery words'
    });
    const api = fakeApi({
      status: jest.fn().mockResolvedValue(
        status({
          initialized: false,
          unlocked: false,
          remaining: null,
          slots: []
        })
      )
    });
    const panel = await panelWith(api, { host: '192.168.1.10' });
    // No passkey anywhere yet: the hostname, or localhost on this computer.
    expect(text(panel)).toContain(
      'An IP address cannot hold a passkey - open JupyterLab by its hostname over HTTPS, or at localhost when it runs on this computer.'
    );
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    expect(api.init).toHaveBeenCalledWith('recovery words');
    expect(create).not.toHaveBeenCalled();
    expect(text(panel)).toContain('Vault created');
  });

  it('keeps the unused-passkey line when the read after the action fails', async () => {
    // The server goes away between the browser's create and the registration.
    Object.defineProperty(navigator, 'credentials', {
      value: {
        create: jest
          .fn()
          .mockResolvedValue({ rawId: new Uint8Array([9]).buffer }),
        get: jest.fn().mockResolvedValue({
          rawId: new Uint8Array([9]).buffer,
          getClientExtensionResults: () => ({
            prf: { results: { first: new Uint8Array([1]).buffer } }
          })
        })
      },
      configurable: true
    });
    answerDialogs({ 'Confirm the new passkey': true });
    mockAskSecret.mockResolvedValue({
      accepted: true,
      value: 'recovery words'
    });
    const gone = new NoAnswer();
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValueOnce(
          status({
            initialized: false,
            unlocked: false,
            remaining: null,
            slots: []
          })
        )
        .mockRejectedValue(gone),
      addPasskey: jest.fn().mockRejectedValue(gone)
    });
    const panel = await panelWith(api);
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    await flush();
    const line = panel.node.querySelector(
      '.jp-PasskeyVaultPanel-message'
    ) as HTMLElement;
    expect(line.dataset.kind).toBe('warn');
    expect(line.textContent).toContain(
      'Vault created, but no passkey was registered'
    );
    expect(line.textContent).toContain('is unused');
    // The failed read is its own line, under the action's.
    expect(lines(panel)[1]).toEqual([
      'error',
      'cannot reach the Jupyter server'
    ]);
    mockAskSecret.mockReset();
  });

  it('keeps the success line beside a read that fails after the action', async () => {
    mockViewEntry.mockResolvedValue('delete');
    mockConfirmDelete.mockResolvedValue(true);
    const api = fakeApi();
    const panel = await panelWith(api);
    api.status.mockRejectedValue(new NoAnswer());
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    await flush();
    expect(lines(panel)).toEqual([
      ['info', 'Deleted nas/ugos'],
      ['error', 'cannot reach the Jupyter server']
    ]);
  });

  it('shows why a passkey without a PRF cannot unlock, not a lost answer', async () => {
    // Refused in the page before any request: the reason is the useful line.
    Object.defineProperty(navigator, 'credentials', {
      value: {
        get: jest.fn().mockResolvedValue({
          rawId: new Uint8Array([0, 1, 2]).buffer,
          getClientExtensionResults: () => ({})
        }),
        create: jest.fn()
      },
      configurable: true
    });
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValue(status({ unlocked: false, remaining: null }))
    });
    const panel = await panelWith(api);
    button(panel, 'Unlock with passkey').click();
    await flush();
    await flush();
    expect(api.unlockPasskey).not.toHaveBeenCalled();
    expect(lines(panel)).toEqual([
      [
        'error',
        'the authenticator returned no PRF - this passkey cannot unlock the vault'
      ]
    ]);
  });

  it('says an action answered by a proxy page is not confirmed while the server cannot be read', async () => {
    // JupyterHub answers an action for a stopped server with a page, a read with JSON.
    const api = fakeApi({
      lock: jest
        .fn()
        .mockRejectedValue(
          new VaultError(
            403,
            'the vault did not answer (HTTP 403) - reload the page to sign in again or start the server'
          )
        )
    });
    const panel = await panelWith(api);
    const stopped =
      'JupyterHub server no longer running at /user/kj/. Restart the server at https://hub.example/hub/spawn/kj';
    api.status.mockRejectedValue(new VaultError(424, stopped));
    (
      panel.node.querySelector('button[title="Lock the vault"]') as HTMLElement
    ).click();
    await flush();
    await flush();
    expect(lines(panel)).toEqual([
      ['error', 'Not confirmed by the vault'],
      ['error', stopped]
    ]);
  });

  it('keeps the reason of a refusal made in the page while the server cannot be read', async () => {
    Object.defineProperty(navigator, 'credentials', {
      value: {
        get: jest.fn().mockResolvedValue({
          rawId: new Uint8Array([0, 1, 2]).buffer,
          getClientExtensionResults: () => ({})
        }),
        create: jest.fn()
      },
      configurable: true
    });
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValue(status({ unlocked: false, remaining: null }))
    });
    const panel = await panelWith(api);
    api.status.mockRejectedValue(new NoAnswer());
    button(panel, 'Unlock with passkey').click();
    await flush();
    await flush();
    expect(api.unlockPasskey).not.toHaveBeenCalled();
    expect(lines(panel)).toEqual([
      [
        'error',
        'the authenticator returned no PRF - this passkey cannot unlock the vault'
      ],
      ['error', 'cannot reach the Jupyter server']
    ]);
  });

  it('keeps the reason of a browser error while the server cannot be read', async () => {
    Object.defineProperty(navigator, 'credentials', {
      value: {
        get: jest
          .fn()
          .mockRejectedValue(new DOMException('x', 'SecurityError')),
        create: jest.fn()
      },
      configurable: true
    });
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValue(status({ unlocked: false, remaining: null }))
    });
    const panel = await panelWith(api);
    api.status.mockRejectedValue(new NoAnswer());
    button(panel, 'Unlock with passkey').click();
    await flush();
    await flush();
    const [line] = lines(panel);
    expect(line[0]).toBe('error');
    expect(line[1]).toMatch(/^the passkey request failed/);
  });

  it('shows a failed Refresh under an older warning', async () => {
    Object.defineProperty(navigator, 'credentials', {
      value: {
        get: jest
          .fn()
          .mockRejectedValue(new DOMException('x', 'NotAllowedError')),
        create: jest.fn()
      },
      configurable: true
    });
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValue(status({ unlocked: false, remaining: null }))
    });
    const panel = await panelWith(api);
    button(panel, 'Unlock with passkey').click();
    await flush();
    await flush();
    // Later, the server stops answering and Refresh is clicked.
    api.status.mockRejectedValue(new NoAnswer());
    await panel.refresh();
    expect(lines(panel)).toEqual([
      ['warn', 'the passkey request was cancelled or not allowed'],
      ['error', 'cannot reach the Jupyter server']
    ]);
  });

  it('says an action was not confirmed when it fails while the server cannot be read, and keeps that once the server answers', async () => {
    const gone = new NoAnswer();
    const api = fakeApi({ lock: jest.fn().mockRejectedValue(gone) });
    const panel = await panelWith(api);
    api.status.mockRejectedValue(gone);
    (
      panel.node.querySelector('button[title="Lock the vault"]') as HTMLElement
    ).click();
    await flush();
    await flush();
    const notDone = ['error', 'Not confirmed by the vault'];
    expect(lines(panel)).toEqual([
      notDone,
      ['error', 'cannot reach the Jupyter server']
    ]);
    api.status.mockResolvedValue(status());
    await panel.refresh();
    expect(lines(panel)).toEqual([notDone]);
  });

  it('shows the locked view with passkey and recovery unlock', async () => {
    const panel = await panelWith(
      fakeApi({
        status: jest
          .fn()
          .mockResolvedValue(status({ unlocked: false, remaining: null }))
      })
    );
    expect(text(panel)).toContain('Locked');
    expect(button(panel, 'Unlock with passkey').classList).toContain(
      'jp-mod-accept'
    );
    // The fallback is a link: a button element without the button look.
    expect(button(panel, 'Use recovery passphrase').className).toBe(
      'jp-PasskeyVaultPanel-link'
    );
  });

  it('offers only the recovery passphrase link when no passkey matches this host', async () => {
    const panel = await panelWith(
      fakeApi({
        status: jest.fn().mockResolvedValue(
          status({
            unlocked: false,
            remaining: null,
            slots: [{ type: 'recovery' }]
          })
        )
      })
    );
    expect(() => button(panel, 'Unlock with passkey')).toThrow();
    expect(button(panel, 'Use recovery passphrase').className).toBe(
      'jp-PasskeyVaultPanel-link'
    );
    expect(text(panel)).toContain(`No passkey is registered for ${HOST}`);
  });

  it('shows a dismissed passkey prompt as a warning, not an error', async () => {
    Object.defineProperty(navigator, 'credentials', {
      value: {
        get: jest
          .fn()
          .mockRejectedValue(new DOMException('x', 'NotAllowedError')),
        create: jest.fn()
      },
      configurable: true
    });
    const panel = await panelWith(
      fakeApi({
        status: jest
          .fn()
          .mockResolvedValue(status({ unlocked: false, remaining: null }))
      })
    );
    button(panel, 'Unlock with passkey').click();
    await flush();
    await flush();
    const line = panel.node.querySelector(
      '.jp-PasskeyVaultPanel-message'
    ) as HTMLElement;
    expect(line.dataset.kind).toBe('warn');
  });

  it('unlocks with the recovery passphrase', async () => {
    mockAskSecret.mockResolvedValue({
      accepted: true,
      value: 'recovery words'
    });
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValue(status({ unlocked: false, remaining: null }))
    });
    const panel = await panelWith(api);
    button(panel, 'Use recovery passphrase').click();
    await flush();
    expect(api.unlockRecovery).toHaveBeenCalledWith('recovery words');
  });

  it('keeps a refusal as a red line when the read after it succeeds', async () => {
    mockAskSecret.mockResolvedValue({ accepted: true, value: 'wrong words' });
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValue(status({ unlocked: false, remaining: null })),
      unlockRecovery: jest
        .fn()
        .mockRejectedValue(new VaultError(403, 'wrong recovery passphrase'))
    });
    const panel = await panelWith(api);
    button(panel, 'Use recovery passphrase').click();
    await flush();
    await flush();
    expect(lines(panel)).toEqual([['error', 'wrong recovery passphrase']]);
  });

  it('shows state, time left and the holder in the status line', async () => {
    const panel = await panelWith(fakeApi());
    const line = panel.node.querySelector('.jp-PasskeyVaultPanel-status')!;
    expect(line.textContent).toContain('Unlocked, 4h 0m left');
    expect(line.textContent).toContain('gpg-agent');
    expect(
      line.querySelector('.jp-PasskeyVaultPanel-diode')!.classList
    ).toContain('jp-mod-active');
  });

  it("says when the extension's own code holds the key, and why, in the banner and the Key holder tooltip", async () => {
    const s = status();
    s.holder = {
      ...s.holder,
      name: 'memory/memfd_secret',
      about: "this extension's own code, in the server's memory",
      notice:
        'gpg-agent unavailable (not found); install GnuPG (apt install gnupg)'
    };
    const panel = await panelWith(
      fakeApi({ status: jest.fn().mockResolvedValue(s) })
    );
    const line = panel.node.querySelector('.jp-PasskeyVaultPanel-notice')!;
    expect(line.textContent).toBe(
      'gpg-agent unavailable (not found); install GnuPG (apt install gnupg)'
    );
    (
      panel.node.querySelector(
        'button[title="Vault settings and security"]'
      ) as HTMLElement
    ).click();
    const holder = panel.node.querySelector(
      '.jp-PasskeyVaultPanel-pair'
    ) as HTMLElement;
    expect(holder.textContent).toBe('Key holdermemory');
    expect(holder.title).toBe(
      "memory/memfd_secret - this extension's own code, in the server's memory. gpg-agent unavailable (not found); install GnuPG (apt install gnupg)"
    );
  });

  it('replaces the banner notice when a restart changes its reason', async () => {
    const s = status();
    s.holder = {
      ...s.holder,
      name: 'memory/memfd_secret',
      notice:
        'gpg-agent unavailable (not found); install GnuPG (apt install gnupg)'
    };
    const read = jest.fn().mockResolvedValue(s);
    const panel = await panelWith(fakeApi({ status: read }));
    read.mockResolvedValue({
      ...s,
      holder: {
        ...s.holder,
        notice: 'gpg-agent unavailable (it did not start)'
      }
    });
    await panel.refresh();
    expect(
      panel.node.querySelector('.jp-PasskeyVaultPanel-notice')!.textContent
    ).toBe('gpg-agent unavailable (it did not start)');
  });

  it('groups entries by category and filters them as the user types', async () => {
    const panel = await panelWith(fakeApi());
    const headers = Array.from(
      panel.node.querySelectorAll('.jp-PasskeyVaultPanel-sectionHeader')
    ).map(h => h.textContent);
    expect(headers).toEqual(['home (1)', 'infra (2)']);
    const filter = panel.node.querySelector('input') as HTMLInputElement;
    filter.value = 'gitlab';
    filter.dispatchEvent(new Event('input'));
    const names = Array.from(
      panel.node.querySelectorAll('.jp-PasskeyVaultPanel-rowName')
    ).map(n => n.textContent);
    expect(names).toEqual(['gitlab/api']);
  });

  it('shows each entry as its name and username only, with no buttons', async () => {
    const panel = await panelWith(fakeApi());
    const rows = Array.from(
      panel.node.querySelectorAll('.jp-PasskeyVaultPanel-rowLine')
    );
    expect(rows.map(r => r.textContent)).toEqual([
      'nas/ugoskonrad',
      'github/apime',
      'gitlab/apikj'
    ]);
    expect(rows.every(r => r.tagName === 'BUTTON')).toBe(true);
    expect(rows.every(r => r.querySelector('button') === null)).toBe(true);
    // The panel offers no Copy or Show.
    const labels = Array.from(panel.node.querySelectorAll('button')).map(
      b => b.textContent
    );
    expect(labels.filter(l => /Copy|Show/.test(l ?? ''))).toEqual([]);
  });

  it('keeps the not-confirmed line when the server returns with the vault locked by its restart, whichever read comes first', async () => {
    for (const first of ['tick', 'refresh']) {
      const gone = new NoAnswer();
      const api = fakeApi({ lock: jest.fn().mockRejectedValue(gone) });
      const panel = await panelWith(api);
      api.status.mockRejectedValue(gone);
      (
        panel.node.querySelector(
          'button[title="Lock the vault"]'
        ) as HTMLElement
      ).click();
      await flush();
      await flush();
      api.status.mockResolvedValue(
        status({ unlocked: false, remaining: null })
      );
      if (first === 'tick') {
        await (panel as any)._tick();
      } else {
        await panel.refresh();
      }
      expect(lines(panel)).toEqual([['error', 'Not confirmed by the vault']]);
      expect(text(panel)).toContain('Locked');
      panel.dispose();
    }
  });

  it('goes on to the passkey step when a read shows the vault that a lost Create answer wrote', async () => {
    Object.defineProperty(navigator, 'credentials', {
      value: {
        create: jest
          .fn()
          .mockResolvedValue({ rawId: new Uint8Array([9]).buffer }),
        get: jest.fn().mockResolvedValue({
          rawId: new Uint8Array([9]).buffer,
          getClientExtensionResults: () => ({
            prf: { results: { first: new Uint8Array([1]).buffer } }
          })
        })
      },
      configurable: true
    });
    answerDialogs({ 'Confirm the new passkey': true });
    mockAskSecret.mockResolvedValue({
      accepted: true,
      value: 'recovery words'
    });
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValueOnce(
          status({
            initialized: false,
            unlocked: false,
            remaining: null,
            slots: []
          })
        )
        .mockResolvedValue(status({ slots: [{ type: 'recovery' }] })),
      init: jest.fn().mockRejectedValue(new NoAnswer())
    });
    const panel = await panelWith(api);
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    await flush();
    expect(api.addPasskey).toHaveBeenCalled();
    expect(lines(panel)).toEqual([['info', 'Vault created']]);
    mockAskSecret.mockReset();
  });

  it('says a Create whose answer was lost is not confirmed while the server cannot be read, with no advice to create again', async () => {
    mockAskSecret.mockResolvedValue({
      accepted: true,
      value: 'recovery words'
    });
    const api = fakeApi({
      status: jest.fn().mockResolvedValueOnce(
        status({
          initialized: false,
          unlocked: false,
          remaining: null,
          slots: []
        })
      ),
      init: jest.fn().mockRejectedValue(new NoAnswer())
    });
    const panel = await panelWith(api);
    api.status.mockRejectedValue(new NoAnswer());
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    expect(api.addPasskey).not.toHaveBeenCalled();
    expect(lines(panel)).toEqual([
      ['error', 'Vault creation not confirmed by the vault'],
      ['error', 'cannot reach the Jupyter server']
    ]);
    // The server answers with the vault: its state shows the Create landed.
    api.status.mockResolvedValue(status({ slots: [{ type: 'recovery' }] }));
    await (panel as any)._tick();
    expect(lines(panel)).toEqual([]);
    mockAskSecret.mockReset();
  });

  it('offers Create again when the read after a lost answer shows no vault', async () => {
    const create = jest.fn();
    Object.defineProperty(navigator, 'credentials', {
      value: { create, get: jest.fn() },
      configurable: true
    });
    mockAskSecret.mockResolvedValue({
      accepted: true,
      value: 'recovery words'
    });
    const none = status({
      initialized: false,
      unlocked: false,
      remaining: null,
      slots: []
    });
    const api = fakeApi({
      status: jest.fn().mockResolvedValue(none),
      init: jest.fn().mockRejectedValue(new NoAnswer())
    });
    const panel = await panelWith(api);
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    expect(create).not.toHaveBeenCalled();
    expect(lines(panel)).toEqual([
      ['error', 'Vault creation not confirmed by the vault']
    ]);
    expect(button(panel, 'Create vault')).toBeTruthy();
    mockAskSecret.mockReset();
  });

  it('reads nothing more when Create is refused with an answer', async () => {
    // A vault made from the CLI meanwhile: the refusal is an answer, not a lost one.
    const create = jest.fn();
    Object.defineProperty(navigator, 'credentials', {
      value: { create, get: jest.fn() },
      configurable: true
    });
    mockAskSecret.mockResolvedValue({
      accepted: true,
      value: 'recovery words'
    });
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValueOnce(
          status({
            initialized: false,
            unlocked: false,
            remaining: null,
            slots: []
          })
        )
        .mockResolvedValue(status({ unlocked: false, remaining: null })),
      init: jest
        .fn()
        .mockRejectedValue(
          new VaultError(400, 'a vault already exists at ~/vault.json')
        )
    });
    const panel = await panelWith(api);
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    expect(create).not.toHaveBeenCalled();
    expect(lines(panel)).toEqual([
      ['error', 'Vault creation: a vault already exists at ~/vault.json']
    ]);
    mockAskSecret.mockReset();
  });

  it('drops the line of a Create whose passkey step was dismissed once the vault changes', async () => {
    Object.defineProperty(navigator, 'credentials', {
      value: {
        create: jest
          .fn()
          .mockRejectedValue(new DOMException('x', 'NotAllowedError')),
        get: jest.fn()
      },
      configurable: true
    });
    answerDialogs({});
    mockAskSecret.mockResolvedValue({
      accepted: true,
      value: 'recovery words'
    });
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValueOnce(
          status({
            initialized: false,
            unlocked: false,
            remaining: null,
            slots: []
          })
        )
        .mockResolvedValue(status({ slots: [{ type: 'recovery' }] }))
    });
    const panel = await panelWith(api);
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    await flush();
    expect(lines(panel)).toEqual([
      ['warn', expect.stringContaining('no passkey was registered')]
    ]);
    // A passkey registered from another tab: the vault's slots show it.
    api.status.mockResolvedValue(status());
    await (panel as any)._tick();
    expect(lines(panel)).toEqual([]);
    mockAskSecret.mockReset();
  });

  it('keeps the unused-passkey line when the server returns with the vault Create made, whichever read comes first', async () => {
    for (const first of ['tick', 'refresh']) {
      Object.defineProperty(navigator, 'credentials', {
        value: {
          create: jest
            .fn()
            .mockResolvedValue({ rawId: new Uint8Array([9]).buffer }),
          get: jest.fn().mockResolvedValue({
            rawId: new Uint8Array([9]).buffer,
            getClientExtensionResults: () => ({
              prf: { results: { first: new Uint8Array([1]).buffer } }
            })
          })
        },
        configurable: true
      });
      answerDialogs({ 'Confirm the new passkey': true });
      mockAskSecret.mockResolvedValue({
        accepted: true,
        value: 'recovery words'
      });
      const gone = new NoAnswer();
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValueOnce(
            status({
              initialized: false,
              unlocked: false,
              remaining: null,
              slots: []
            })
          )
          .mockRejectedValue(gone),
        addPasskey: jest.fn().mockRejectedValue(gone)
      });
      const panel = await panelWith(api);
      button(panel, 'Create vault').click();
      await flush();
      await flush();
      await flush();
      api.status.mockResolvedValue(status());
      if (first === 'tick') {
        await (panel as any)._tick();
      } else {
        await panel.refresh();
      }
      expect(lines(panel)).toEqual([
        ['warn', expect.stringContaining('is unused')]
      ]);
      panel.dispose();
      mockAskSecret.mockReset();
    }
  });

  it('reads at once when the browser tab is shown again', async () => {
    const api = fakeApi();
    const panel = await panelWith(api);
    MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
    await flush();
    Object.defineProperty(document, 'hidden', {
      value: true,
      configurable: true
    });
    // Locked from the CLI while the tab was hidden.
    api.status.mockResolvedValue(status({ unlocked: false, remaining: null }));
    document.dispatchEvent(new Event('visibilitychange'));
    await flush();
    expect(text(panel)).toContain('Unlocked');
    Object.defineProperty(document, 'hidden', {
      value: false,
      configurable: true
    });
    document.dispatchEvent(new Event('visibilitychange'));
    await flush();
    await flush();
    expect(text(panel)).toContain('Locked');
    expect(text(panel)).not.toContain('Unlocked');
    // A hidden panel stops listening.
    MessageLoop.sendMessage(panel, Widget.Msg.BeforeHide);
    const reads = api.status.mock.calls.length;
    document.dispatchEvent(new Event('visibilitychange'));
    await flush();
    expect(api.status.mock.calls.length).toBe(reads);
    panel.dispose();
  });

  it('stops reading when it is moved to the other sidebar', async () => {
    // The sidebar detaches the panel before hiding it, so no hide message comes.
    const api = fakeApi();
    const panel = await panelWith(api);
    MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
    await flush();
    MessageLoop.sendMessage(panel, Widget.Msg.BeforeDetach);
    expect((panel as any)._timer).toBeNull();
    const reads = api.status.mock.calls.length;
    document.dispatchEvent(new Event('visibilitychange'));
    await flush();
    expect(api.status.mock.calls.length).toBe(reads);
    panel.dispose();
  });

  it('reads nothing while the browser tab is hidden', async () => {
    const api = fakeApi();
    const panel = await panelWith(api);
    const reads = api.status.mock.calls.length;
    Object.defineProperty(document, 'hidden', {
      value: true,
      configurable: true
    });
    try {
      await (panel as any)._tick();
      expect(api.status.mock.calls.length).toBe(reads);
    } finally {
      Object.defineProperty(document, 'hidden', {
        value: false,
        configurable: true
      });
    }
    await (panel as any)._tick();
    expect(api.status.mock.calls.length).toBe(reads + 1);
  });

  it('clears the filter after a saved Edit, so the edited entry shows', async () => {
    mockViewEntry.mockResolvedValue('edit');
    mockEditEntry.mockResolvedValue({ name: 'nas/ugos', username: 'k2' });
    const api = fakeApi();
    const panel = await panelWith(api);
    const filter = panel.node.querySelector(
      '.jp-PasskeyVaultPanel-filterInput'
    ) as HTMLInputElement;
    filter.value = 'konrad';
    filter.dispatchEvent(new Event('input'));
    api.entries.mockResolvedValue([
      ENTRIES[0],
      ENTRIES[1],
      { ...ENTRIES[2], username: 'k2' }
    ]);
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    await flush();
    expect(api.edit).toHaveBeenCalledWith('nas/ugos', { username: 'k2' });
    expect(filter.value).toBe('');
    expect(text(panel)).toContain('nas/ugos');
  });

  it('clears the filter after Add, so the new entry shows', async () => {
    mockEditEntry.mockResolvedValue({ name: 'new/one', username: 'x' });
    const api = fakeApi();
    const panel = await panelWith(api);
    const filter = panel.node.querySelector(
      '.jp-PasskeyVaultPanel-filterInput'
    ) as HTMLInputElement;
    filter.value = 'github';
    filter.dispatchEvent(new Event('input'));
    api.entries.mockResolvedValue([
      ...ENTRIES,
      { ...ENTRIES[0], name: 'new/one', username: 'x', url: 'https://x.org' }
    ]);
    (
      panel.node.querySelector('button[title="Add an entry"]') as HTMLElement
    ).click();
    await flush();
    await flush();
    expect(api.add).toHaveBeenCalledWith('new/one', { username: 'x' });
    expect(filter.value).toBe('');
    expect(text(panel)).toContain('new/one');
  });

  it('opens no form for an entry deleted elsewhere while its popup was open', async () => {
    mockViewEntry.mockImplementation(async () => {
      api.entries.mockResolvedValue([ENTRIES[0], ENTRIES[1]]);
      await panel.refresh();
      return 'edit';
    });
    const api = fakeApi();
    const panel = await panelWith(api);
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    await flush();
    expect(mockEditEntry).not.toHaveBeenCalled();
    expect(lines(panel)).toEqual([['warn', 'nas/ugos was deleted elsewhere']]);
  });

  it('opens Edit when the entries could not be read, not calling the entry deleted', async () => {
    mockViewEntry.mockImplementation(async () => {
      api.entries.mockRejectedValueOnce(new NoAnswer());
      await panel.refresh();
      return 'edit';
    });
    const api = fakeApi();
    const panel = await panelWith(api);
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    await flush();
    expect(mockEditEntry.mock.calls[0][1]).toEqual(ENTRIES[2]);
    expect(text(panel)).not.toContain('deleted elsewhere');
  });

  it('names the entry whose change it could not confirm', async () => {
    mockViewEntry.mockResolvedValue('edit');
    mockEditEntry.mockResolvedValue({ name: 'nas/ugos', password: 'new' });
    const gone = new NoAnswer();
    const api = fakeApi({ edit: jest.fn().mockRejectedValue(gone) });
    const panel = await panelWith(api);
    api.status.mockRejectedValue(gone);
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    await flush();
    expect(lines(panel)).toEqual([
      [
        'error',
        'Change to nas/ugos not confirmed by the vault - do it again once the server answers'
      ],
      ['error', 'cannot reach the Jupyter server']
    ]);
  });

  it('leaves the list alone when an action starts while a tick re-reads a change', async () => {
    const api = fakeApi();
    const panel = await panelWith(api);
    const row = panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine');
    let answer: (s: any) => void = () => undefined;
    api.status
      .mockResolvedValueOnce(status({ revision: 'changed-by-an-agent' }))
      .mockReturnValueOnce(new Promise(r => (answer = r)));
    const reading = (panel as any)._tick();
    await flush();
    (panel as any)._busy = true;
    answer(status({ revision: 'changed-by-an-agent' }));
    await reading;
    expect(panel.node.contains(row)).toBe(true);
  });

  it('leaves the list alone when an action starts while a tick is reading', async () => {
    const api = fakeApi();
    const panel = await panelWith(api);
    const row = panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine');
    let answer: (s: any) => void = () => undefined;
    api.status.mockReturnValueOnce(new Promise(r => (answer = r)));
    const reading = (panel as any)._tick();
    (panel as any)._busy = true;
    answer(status({ revision: 'changed-by-an-agent' }));
    await reading;
    expect(panel.node.contains(row)).toBe(true);
    expect(api.entries).toHaveBeenCalledTimes(1);
  });

  it('sends nothing when Edit is saved unchanged', async () => {
    mockViewEntry.mockResolvedValue('edit');
    mockEditEntry.mockResolvedValue({ name: 'nas/ugos' });
    const api = fakeApi();
    const panel = await panelWith(api);
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    await flush();
    expect(mockEditEntry).toHaveBeenCalled();
    expect(api.edit).not.toHaveBeenCalled();
  });

  it('edits the entry as last read and sends the fields the form answers', async () => {
    // The URL changed elsewhere while the popup was open; the form changes the notes.
    const changedUrl = { ...ENTRIES[2], url: 'https://nas.example:5001' };
    mockViewEntry.mockImplementation(async () => {
      api.entries.mockResolvedValue([ENTRIES[0], ENTRIES[1], changedUrl]);
      await panel.refresh();
      return 'edit';
    });
    mockEditEntry.mockResolvedValue({ name: 'nas/ugos', notes: 'rack 2' });
    const api = fakeApi();
    const panel = await panelWith(api);
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    await flush();
    expect(mockEditEntry.mock.calls[0][1]).toEqual(changedUrl);
    expect(api.edit).toHaveBeenCalledWith('nas/ugos', { notes: 'rack 2' });
  });

  it('opens the entry in its popup, and Edit there opens Edit entry for it', async () => {
    mockViewEntry.mockResolvedValue('edit');
    mockEditEntry.mockResolvedValue({ name: 'nas/ugos', username: 'k2' });
    const api = fakeApi();
    const panel = await panelWith(api);
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click(); // Enter and Space on a button fire click
    await flush();
    await flush();
    expect(mockViewEntry).toHaveBeenCalledWith(
      ENTRIES[2],
      expect.any(Function)
    );
    expect(mockEditEntry).toHaveBeenCalledWith(
      expect.any(Function),
      ENTRIES[2]
    );
    expect(api.edit).toHaveBeenCalledWith('nas/ugos', { username: 'k2' });
  });

  it('puts focus back on the row before Delete asks, when a redraw replaced the list', async () => {
    const api = fakeApi();
    const panel = await panelWith(api);
    // The popup had focus; a read meanwhile replaced every row.
    mockViewEntry.mockImplementation(async () => {
      (document.activeElement as HTMLElement | null)?.blur();
      await panel.refresh();
      return 'delete';
    });
    let focusAtConfirm: string | undefined;
    mockConfirmDelete.mockImplementation(async () => {
      focusAtConfirm = (document.activeElement as HTMLElement).dataset.focusKey;
      return false;
    });
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    await flush();
    expect(focusAtConfirm).toBe('row:nas/ugos');
  });

  it('opens no form when the unlock ran out behind the popup, before the next read', async () => {
    // 10 s left at the first read; the server says locked from then on.
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValueOnce(status({ remaining: 10 }))
        .mockResolvedValue(status({ unlocked: false, remaining: null }))
    });
    const panel = await panelWith(api);
    const now = jest.spyOn(Date, 'now');
    const start = Date.now();
    mockViewEntry.mockImplementation(async () => {
      // 20 s pass while the popup is open; no status read happens meanwhile.
      now.mockReturnValue(start + 20000);
      return 'edit';
    });
    try {
      (
        panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
      ).click();
      await flush();
      await flush();
      expect(mockEditEntry).not.toHaveBeenCalled();
      expect(text(panel)).toContain(
        'The vault locked - unlock it, then try again'
      );
      // The locked view, with its unlock, not the list under a stale status line.
      expect(
        panel.node.querySelector('.jp-PasskeyVaultPanel-stateText')?.textContent
      ).toBe('Locked');
      expect(button(panel, 'Unlock with passkey')).toBeTruthy();
    } finally {
      now.mockRestore();
    }
  });

  it('opens no Add form when the unlock ran out before the next read', async () => {
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValueOnce(status({ remaining: 10 }))
        .mockResolvedValue(status({ unlocked: false, remaining: null }))
    });
    const panel = await panelWith(api);
    const now = jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 20000);
    try {
      (
        panel.node.querySelector('button[title="Add an entry"]') as HTMLElement
      ).click();
      await flush();
      await flush();
      expect(mockEditEntry).not.toHaveBeenCalled();
      expect(text(panel)).toContain(
        'The vault locked - unlock it, then try again'
      );
      expect(button(panel, 'Unlock with passkey')).toBeTruthy();
    } finally {
      now.mockRestore();
    }
  });

  it('drops the lock line when a read finds the vault unlocked elsewhere', async () => {
    // 10 s left, then locked, then unlocked again from the CLI.
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValueOnce(status({ remaining: 10 }))
        .mockResolvedValueOnce(status({ unlocked: false, remaining: null }))
        .mockResolvedValue(status())
    });
    const panel = await panelWith(api);
    const now = jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 20000);
    try {
      (
        panel.node.querySelector('button[title="Add an entry"]') as HTMLElement
      ).click();
      await flush();
      expect(text(panel)).toContain('The vault locked');
      // `vault unlock` from the CLI; the notification's click reads again.
      await panel.refresh();
      expect(text(panel)).not.toContain('The vault locked');
      expect(text(panel)).toContain('nas/ugos');
    } finally {
      now.mockRestore();
    }
  });

  it('drops the lock line after a failed read, once the vault is unlocked elsewhere', async () => {
    // The 15 s read first in one run, Refresh first in the other: each drop rule.
    for (const next of ['tick', 'refresh']) {
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValueOnce(status({ remaining: 10 }))
          .mockResolvedValueOnce(status({ unlocked: false, remaining: null }))
          .mockRejectedValueOnce(new NoAnswer())
          .mockResolvedValue(status())
      });
      const panel = await panelWith(api);
      const now = jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 20000);
      try {
        (
          panel.node.querySelector(
            'button[title="Add an entry"]'
          ) as HTMLElement
        ).click();
        await flush();
        expect(text(panel)).toContain('The vault locked');
        // A Refresh while the server restarts, then `vault unlock` from the CLI.
        await panel.refresh();
        expect(text(panel)).toContain('cannot reach the Jupyter server');
        await (next === 'tick' ? (panel as any)._tick() : panel.refresh());
        expect(lines(panel)).toEqual([]);
        expect(text(panel)).toContain('nas/ugos');
      } finally {
        now.mockRestore();
        panel.dispose();
      }
    }
  });

  it('opens no form when the vault locked while the popup was open', async () => {
    const api = fakeApi();
    const panel = await panelWith(api);
    // The unlock runs out behind the popup; Edit is chosen after that.
    mockViewEntry.mockImplementation(async () => {
      api.status.mockResolvedValue(
        status({ unlocked: false, remaining: null })
      );
      await panel.refresh();
      return 'edit';
    });
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    await flush();
    expect(mockEditEntry).not.toHaveBeenCalled();
    const line = panel.node.querySelector(
      '.jp-PasskeyVaultPanel-message'
    ) as HTMLElement;
    expect(line.dataset.kind).toBe('warn');
    expect(line.textContent).toBe(
      'The vault locked - unlock it, then try again'
    );
  });

  it("reveals through a passkey request, sending the server that request's PRF", async () => {
    mockViewEntry.mockResolvedValue(null);
    fakePasskey();
    const api = fakeApi();
    const panel = await panelWith(api);
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    const reveal = mockViewEntry.mock.calls[0][1] as () => Promise<string>;
    expect(api.revealPassword).not.toHaveBeenCalled();
    expect(await reveal()).toBe('s3cret-value');
    expect(api.revealPassword).toHaveBeenCalledWith('nas/ugos', 'AAEC', 'CQkJ');
    expect(text(panel)).not.toContain('s3cret-value');
  });

  it('asks before deleting from the popup, and keeps the entry when that is declined', async () => {
    mockViewEntry.mockResolvedValue('delete');
    mockConfirmDelete.mockResolvedValueOnce(false).mockResolvedValue(true);
    const api = fakeApi();
    const panel = await panelWith(api);
    const row = () =>
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement;
    row().click();
    await flush();
    await flush();
    expect(mockConfirmDelete).toHaveBeenCalledWith('nas/ugos');
    expect(api.remove).not.toHaveBeenCalled();
    expect(text(panel)).not.toContain('Deleted');
    row().click();
    await flush();
    await flush();
    expect(api.remove).toHaveBeenCalledWith('nas/ugos');
    expect(text(panel)).toContain('Deleted nas/ugos');
  });

  it('runs one action at a time', async () => {
    let release: () => void = () => undefined;
    const api = fakeApi({
      lock: jest.fn(() => new Promise<void>(r => (release = () => r())))
    });
    const panel = await panelWith(api);
    const lock = panel.node.querySelector(
      'button[title="Lock the vault"]'
    ) as HTMLButtonElement;
    lock.click();
    lock.click();
    expect(panel.node.classList).toContain('jp-mod-busy');
    release();
    await flush();
    expect(api.lock).toHaveBeenCalledTimes(1);
    expect(panel.node.classList).not.toContain('jp-mod-busy');
  });

  it('says the vault exists when the passkey step of Create fails', async () => {
    mockAskSecret.mockResolvedValue({ accepted: true, value: 'pw' });
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValue(status({ initialized: false, unlocked: false }))
    });
    Object.defineProperty(navigator, 'credentials', {
      value: {
        get: jest.fn(),
        create: jest
          .fn()
          .mockRejectedValue(new DOMException('x', 'NotAllowedError'))
      },
      configurable: true
    });
    const panel = await panelWith(api);
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    expect(api.init).toHaveBeenCalledWith('pw');
    expect(text(panel)).toContain(
      'Vault created, but no passkey was registered'
    );
    expect(text(panel)).toContain('the cog');
    // The vault exists and is open: a warning, not an error.
    expect(
      (panel.node.querySelector('.jp-PasskeyVaultPanel-message') as HTMLElement)
        .dataset.kind
    ).toBe('warn');
  });

  it('says nothing was created when the Create dialog is cancelled', async () => {
    mockAskSecret.mockResolvedValue({ accepted: false, value: null });
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValue(status({ initialized: false, unlocked: false }))
    });
    const panel = await panelWith(api);
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    expect(api.init).not.toHaveBeenCalled();
    expect(text(panel)).not.toContain('Vault created');
  });

  it('keeps focus in the panel when the focused entry is deleted', async () => {
    mockViewEntry.mockResolvedValue('delete');
    mockConfirmDelete.mockResolvedValue(true);
    const api = fakeApi({
      entries: jest
        .fn()
        .mockResolvedValueOnce(ENTRIES)
        .mockResolvedValue(ENTRIES.filter(e => e.name !== 'nas/ugos'))
    });
    const panel = await panelWith(api);
    const row = panel.node.querySelector(
      '.jp-PasskeyVaultPanel-rowLine'
    ) as HTMLButtonElement;
    row.click();
    await flush();
    await flush();
    await flush();
    expect(document.activeElement).toBe(
      panel.node.querySelector('.jp-PasskeyVaultPanel-filterInput')
    );
    panel.dispose();
  });

  it('puts the banner below the list, so a line that comes or goes never moves the entries', async () => {
    const panel = await panelWith(fakeApi());
    expect(
      panel.node.lastElementChild?.classList.contains(
        'jp-PasskeyVaultPanel-banner'
      )
    ).toBe(true);
  });

  it('says the entries could not be read, not that there are none', async () => {
    const panel = await panelWith(
      fakeApi({
        entries: jest.fn().mockRejectedValue(new NoAnswer())
      })
    );
    expect(text(panel)).toContain('The entries could not be read.');
    expect(text(panel)).not.toContain('No entries yet.');
  });

  it('orders categories as a reader would, whatever their case', async () => {
    const panel = await panelWith(
      fakeApi({
        entries: jest.fn().mockResolvedValue([
          { ...ENTRIES[0], category: 'Work' },
          { ...ENTRIES[1], category: 'banking' },
          { ...ENTRIES[2], category: '' }
        ])
      })
    );
    const headers = Array.from(
      panel.node.querySelectorAll('.jp-PasskeyVaultPanel-sectionHeader')
    ).map(h => h.textContent);
    expect(headers).toEqual(['banking (1)', 'Uncategorised (1)', 'Work (1)']);
  });

  it('keeps focus in the panel when Lock is pressed from the keyboard', async () => {
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValueOnce(status())
        .mockResolvedValue(status({ unlocked: false, remaining: null }))
    });
    const panel = await panelWith(api);
    const lock = panel.node.querySelector(
      'button[title="Lock the vault"]'
    ) as HTMLButtonElement;
    lock.focus();
    lock.click();
    await flush();
    await flush();
    // Refresh, not Unlock with passkey: a Space pressed next must not start a prompt.
    expect(document.activeElement).toBe(
      panel.node.querySelector('button[title="Refresh"]')
    );
    panel.dispose();
  });

  it('redraws the body when a vault appears while the panel is open', async () => {
    jest.useFakeTimers();
    try {
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValueOnce(
            status({ initialized: false, unlocked: false, remaining: null })
          )
          .mockResolvedValue(status({ unlocked: false, remaining: null }))
      });
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      expect(text(panel)).toContain('Create vault');
      await jest.advanceTimersByTimeAsync(REFRESH_MS);
      expect(text(panel)).not.toContain('Create vault');
      expect(button(panel, 'Unlock with passkey')).toBeTruthy();
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('adds an entry through the form', async () => {
    mockEditEntry.mockResolvedValue({
      name: 'new/one',
      username: 'u',
      password: 'p'
    });
    const api = fakeApi();
    const panel = await panelWith(api);
    (
      panel.node.querySelector('button[title="Add an entry"]') as HTMLElement
    ).click();
    await flush();
    expect(api.add).toHaveBeenCalledWith('new/one', {
      username: 'u',
      password: 'p'
    });
  });

  describe('the cog view', () => {
    async function openCog(api = fakeApi(), openSettings = jest.fn()) {
      const panel = await panelWith(api, { openSettings });
      (
        panel.node.querySelector(
          'button[title="Vault settings and security"]'
        ) as HTMLElement
      ).click();
      return panel;
    }

    it('shows short values, with the explanations as tooltips', async () => {
      const panel = await openCog();
      const pair = (label: string) =>
        Array.from(
          panel.node.querySelectorAll('.jp-PasskeyVaultPanel-pair')
        ).find(
          r =>
            r.querySelector('.jp-PasskeyVaultPanel-pairLabel')!.textContent ===
            label
        ) as HTMLElement;
      expect(pair('Key holder').textContent).toBe('Key holdergpg-agent');
      expect(pair('Key holder').title).toBe(
        'gpg-agent - a GnuPG agent of its own'
      );
      expect(pair('Protection').textContent).toBe('Protectionreduced');
      expect(pair('Protection').title).toBe('not kept out of swap');
      const rows = Array.from(
        panel.node.querySelectorAll('.jp-PasskeyVaultPanel-capability')
      ) as HTMLElement[];
      expect(rows.map(r => r.dataset.capability)).toEqual([
        'locked_memory',
        'no_core_dump',
        'locks_on_restart'
      ]);
      // The holder's own expiry and container isolation are detail for `vault status`.
      expect(text(panel)).not.toContain('Expires on its own');
      expect(text(panel)).not.toContain('Isolated from containers');
      expect(rows[0].textContent).toBe('Never in swapno');
      expect(rows[0].title).toBe(
        "the holder's copy of the key can be written to swap"
      );
      // No line of instructions under the rows: the tooltips are the details.
      expect(text(panel)).not.toContain('vault status');
    });

    it('marks each protection present or missing, for its colour', async () => {
      const panel = await openCog();
      const state = (key: string) =>
        (panel.node.querySelector(`[data-capability="${key}"]`) as HTMLElement)
          .dataset.protection;
      expect(state('locked_memory')).toBe('missing');
      expect(state('no_core_dump')).toBe('present');
      // Yes is the safer state for every row: a key that outlives a restart is no.
      expect(state('locks_on_restart')).toBe('missing');
      expect(
        (
          panel.node.querySelector(
            '[data-capability="locks_on_restart"]'
          ) as HTMLElement
        ).textContent
      ).toBe('Locks on server restartno');
    });

    /** A browser whose passkey requests all succeed; `order` records each call. */
    function browser(order: string[] = []) {
      const get = jest.fn().mockImplementation(async () => {
        order.push('get');
        return {
          rawId: new Uint8Array([0, 1, 2]).buffer,
          getClientExtensionResults: () => ({
            prf: { results: { first: new Uint8Array([9, 9, 9]).buffer } }
          })
        };
      });
      const create = jest.fn().mockImplementation(async () => {
        order.push('create');
        return { rawId: new Uint8Array([9]).buffer };
      });
      Object.defineProperty(navigator, 'credentials', {
        value: { get, create },
        configurable: true
      });
      return { get, create };
    }

    /** A vault whose only passkey belongs to another hostname. */
    const noPasskeyHere = () =>
      fakeApi({
        status: jest.fn().mockResolvedValue(
          status({
            slots: [
              { type: 'recovery' },
              {
                type: 'passkey',
                cred_id: 'AAEC',
                rp_id: 'other.example',
                prf_salt: 'c2FsdA',
                label: 'desktop',
                created: '2026-09-26T10:00:00Z'
              }
            ]
          })
        )
      });

    it('keeps the unused-passkey line of a refused registration when the vault is changed elsewhere', async () => {
      browser([]);
      mockLaunch.mockResolvedValue({ button: { accept: true } });
      const api = fakeApi({
        addPasskey: jest
          .fn()
          .mockRejectedValue(
            new VaultError(403, 'the passkey did not open the vault')
          )
      });
      const panel = await openCog(api);
      button(panel, 'Register new passkey').click();
      await flush();
      await flush();
      const unused = ['warn', expect.stringContaining('is unused')];
      expect(lines(panel)).toEqual([unused]);
      api.status.mockResolvedValue(status({ revision: 'changed-by-an-agent' }));
      await (panel as any)._tick();
      expect(lines(panel)).toEqual([unused]);
    });

    it('names the registration a dismissed create prompt stopped, and drops that line once the passkeys change', async () => {
      const { create } = browser();
      create.mockRejectedValue(new DOMException('x', 'NotAllowedError'));
      mockLaunch.mockResolvedValue({ button: { accept: true } });
      const api = fakeApi();
      const panel = await openCog(api);
      button(panel, 'Register new passkey').click();
      await flush();
      await flush();
      const line = [
        'warn',
        'Passkey registration: the passkey request was cancelled or not allowed'
      ];
      expect(lines(panel)).toEqual([line]);
      // Registered from the CLI in another tab: the cog's list shows the passkey.
      api.status.mockResolvedValue(
        status({
          slots: [
            ...status().slots,
            {
              type: 'passkey',
              cred_id: 'BBBB',
              rp_id: HOST,
              prf_salt: 'c2FsdA',
              label: 'cli',
              created: '2026-09-27T08:00:00Z'
            }
          ]
        })
      );
      await (panel as any)._tick();
      expect(lines(panel)).toEqual([]);
    });

    it('says a recovery change whose answer was lost is not confirmed, though the server answers again', async () => {
      fakePasskey();
      mockAskSecret.mockResolvedValue({ accepted: true, value: 'new words' });
      const api = fakeApi({
        replaceRecovery: jest.fn().mockRejectedValue(new NoAnswer())
      });
      const panel = await openCog(api);
      button(panel, 'Change recovery passphrase').click();
      await flush();
      await flush();
      await flush();
      expect(lines(panel)).toEqual([
        [
          'error',
          'Recovery passphrase change not confirmed by the vault - do it again once the server answers'
        ]
      ]);
    });

    it('registers a passkey with an existing passkey as the proof', async () => {
      const order: string[] = [];
      browser(order);
      mockLaunch.mockImplementation(async (dialog: any) => {
        order.push(dialog.options.title);
        return { button: { accept: true } };
      });
      const api = fakeApi();
      const panel = await openCog(api);
      button(panel, 'Register new passkey').click();
      // The proof request runs from the click, before any dialog, and the line says
      // the browser's sign-in is that proof, not the new passkey.
      expect(order).toEqual(['get']);
      expect(text(panel)).toContain(
        'First confirm with a passkey you already have'
      );
      await flush();
      await flush();
      // A dialog gives the browser the fresh click it needs to create the passkey.
      expect(order).toEqual([
        'get',
        'Register new passkey',
        'create',
        'Confirm the new passkey',
        'get'
      ]);
      expect(mockAskSecret).not.toHaveBeenCalled();
      expect(api.addPasskey.mock.calls[0][1]).toEqual({
        cred_id: 'AAEC',
        prf: 'CQkJ'
      });
      expect(text(panel)).toContain('Passkey registered');
    });

    it('registers with the recovery passphrase on a hostname with no passkey, asked before the browser creates one', async () => {
      const order: string[] = [];
      browser(order);
      answerDialogs({ 'Confirm the new passkey': true });
      mockAskSecret.mockImplementation(async () => {
        order.push('passphrase');
        return { accepted: true, value: 'recovery words' };
      });
      const api = noPasskeyHere();
      const panel = await openCog(api);
      button(panel, 'Register new passkey').click();
      await flush();
      await flush();
      expect(order).toEqual(['passphrase', 'create', 'get']);
      expect(mockAskSecret).toHaveBeenCalledWith(
        'Enter the current recovery passphrase',
        true,
        'Register new passkey'
      );
      expect(api.addPasskey.mock.calls[0][1]).toEqual({
        current: 'recovery words'
      });
      mockAskSecret.mockReset();
    });

    it('falls back to the recovery passphrase when the passkey for this host does not answer', async () => {
      // A second machine: the hostname's passkey sits on another device.
      const order: string[] = [];
      const { get, create } = browser(order);
      get.mockImplementationOnce(async () => {
        order.push('get');
        throw new DOMException('x', 'NotAllowedError');
      });
      // The line about the passkey proof is over once the proof is in.
      let lineAtCreate: string | null | undefined;
      create.mockImplementationOnce(async () => {
        order.push('create');
        lineAtCreate = panel.node.querySelector(
          '.jp-PasskeyVaultPanel-message'
        )?.textContent;
        return { rawId: new Uint8Array([9]).buffer };
      });
      answerDialogs({ 'Confirm the new passkey': true });
      mockAskSecret.mockImplementation(async (prompt: string) => {
        order.push(prompt);
        return { accepted: true, value: 'recovery words' };
      });
      const api = fakeApi();
      const panel = await openCog(api);
      button(panel, 'Register new passkey').click();
      await flush();
      await flush();
      expect(order).toEqual([
        'get',
        'No passkey answered - enter the current recovery passphrase instead',
        'create',
        'get'
      ]);
      expect(lineAtCreate).toBeUndefined();
      expect(api.addPasskey.mock.calls[0][1]).toEqual({
        current: 'recovery words'
      });
      mockAskSecret.mockReset();
    });

    it('creates nothing when the proof is not given', async () => {
      // Cancelled at the passphrase dialog, or at the dialog after the passkey proof.
      for (const [api, cancel] of [
        [
          noPasskeyHere(),
          () =>
            mockAskSecret.mockResolvedValue({ accepted: false, value: null })
        ],
        [fakeApi(), () => answerDialogs({})]
      ] as const) {
        const { create } = browser();
        cancel();
        const panel = await openCog(api);
        button(panel, 'Register new passkey').click();
        await flush();
        await flush();
        expect(create).not.toHaveBeenCalled();
        expect(api.addPasskey).not.toHaveBeenCalled();
        expect(panel.node.querySelector('.jp-PasskeyVaultPanel-message')).toBe(
          null
        );
        panel.dispose();
      }
    });

    it('says the created passkey is unused when the registration is cancelled at the confirm step', async () => {
      browser();
      answerDialogs({ 'Register new passkey': true });
      const api = fakeApi();
      const panel = await openCog(api);
      button(panel, 'Register new passkey').click();
      await flush();
      await flush();
      expect(api.addPasskey).not.toHaveBeenCalled();
      const line = panel.node.querySelector(
        '.jp-PasskeyVaultPanel-message'
      ) as HTMLElement;
      expect(line.dataset.kind).toBe('warn');
      expect(line.textContent).toContain('unused');
    });

    it('says a refused proof left the created passkey unused', async () => {
      browser();
      answerDialogs({ 'Confirm the new passkey': true });
      mockAskSecret.mockResolvedValue({ accepted: true, value: 'wrong' });
      const api = noPasskeyHere();
      api.addPasskey = jest
        .fn()
        .mockRejectedValue(new VaultError(403, 'wrong recovery passphrase'));
      const panel = await openCog(api);
      button(panel, 'Register new passkey').click();
      await flush();
      await flush();
      const line = panel.node.querySelector(
        '.jp-PasskeyVaultPanel-message'
      ) as HTMLElement;
      expect(line.textContent).toMatch(
        /^wrong recovery passphrase; the passkey your browser created \("JupyterLab vault - .+ UTC - .+"\) is unused - you can delete it in your passkey manager$/
      );
    });

    it('lists passkeys and removes one in two steps', async () => {
      const api = fakeApi();
      const panel = await openCog(api);
      expect(text(panel)).toContain('laptop');
      // To the minute, so two passkeys added the same day differ.
      expect(text(panel)).toContain('added 2026-09-26 10:00 UTC');
      const now = jest.spyOn(Date, 'now').mockReturnValue(1000);
      button(panel, 'Remove').click();
      now.mockReturnValue(1000 + ARM_DELAY_MS);
      button(panel, 'Confirm remove').click();
      now.mockRestore();
      await flush();
      expect(api.removePasskey).toHaveBeenCalledWith('AAEC');
      expect(button(panel, 'Register new passkey')).toBeTruthy();
    });

    it('keeps a refused recovery change when the vault is changed elsewhere', async () => {
      fakePasskey();
      mockAskSecret.mockResolvedValue({ accepted: true, value: 'new words' });
      const api = fakeApi({
        replaceRecovery: jest
          .fn()
          .mockRejectedValue(
            new VaultError(403, 'the passkey did not open the vault')
          )
      });
      const panel = await openCog(api);
      button(panel, 'Change recovery passphrase').click();
      await flush();
      await flush();
      await flush();
      const refused = [
        'error',
        'Recovery passphrase change: the passkey did not open the vault'
      ];
      expect(lines(panel)).toEqual([refused]);
      // An agent edits an entry: nothing else would show the change was refused.
      api.status.mockResolvedValue(status({ revision: 'changed-by-an-agent' }));
      await (panel as any)._tick();
      expect(lines(panel)).toEqual([refused]);
    });

    it('names the recovery change it could not confirm while the server is gone', async () => {
      fakePasskey();
      mockAskSecret.mockResolvedValue({ accepted: true, value: 'new words' });
      const gone = new NoAnswer();
      const api = fakeApi({
        replaceRecovery: jest.fn().mockRejectedValue(gone)
      });
      const panel = await openCog(api);
      api.status.mockRejectedValue(gone);
      button(panel, 'Change recovery passphrase').click();
      await flush();
      await flush();
      await flush();
      expect(lines(panel)).toEqual([
        [
          'error',
          'Recovery passphrase change not confirmed by the vault - do it again once the server answers'
        ],
        ['error', 'cannot reach the Jupyter server']
      ]);
    });

    it('asks for the recovery passphrase when the proof passkey gives no PRF', async () => {
      Object.defineProperty(navigator, 'credentials', {
        value: {
          get: jest.fn().mockResolvedValue({
            rawId: new Uint8Array([0, 1, 2]).buffer,
            getClientExtensionResults: () => ({})
          }),
          create: jest.fn()
        },
        configurable: true
      });
      mockAskSecret
        .mockResolvedValueOnce({ accepted: true, value: 'current words' })
        .mockResolvedValueOnce({ accepted: true, value: 'new words' });
      const api = fakeApi();
      const panel = await openCog(api);
      button(panel, 'Change recovery passphrase').click();
      await flush();
      await flush();
      await flush();
      expect(mockAskSecret.mock.calls[0][0]).toBe(
        'This passkey cannot unlock the vault - enter the current recovery passphrase instead'
      );
      expect(api.replaceRecovery).toHaveBeenCalledWith('new words', {
        current: 'current words'
      });
    });

    it('keeps the header buttons in place in the cog view, with + hidden', async () => {
      const panel = await openCog(fakeApi());
      const add = panel.node.querySelector(
        'button[title="Add an entry"]'
      ) as HTMLElement;
      // Still laid out, so Lock stays where it was; hidden, so it cannot be clicked.
      expect(add.style.display).toBe('');
      expect(add.style.visibility).toBe('hidden');
    });

    it('does not return focus to the hidden + in the cog view', async () => {
      const panel = await openCog(fakeApi());
      const add = panel.node.querySelector(
        'button[title="Add an entry"]'
      ) as HTMLElement;
      (panel as any)._restoreFocus(add.dataset.focusKey);
      expect(document.activeElement).not.toBe(add);
    });

    it('redraws the settings view when a restart changed the key holder, its notice or the file', async () => {
      const api = fakeApi();
      const panel = await openCog(api);
      const holderRow = () =>
        Array.from(
          panel.node.querySelectorAll('.jp-PasskeyVaultPanel-pair')
        ).find(
          r =>
            r.querySelector('.jp-PasskeyVaultPanel-pairLabel')!.textContent ===
            'Key holder'
        ) as HTMLElement;
      expect(holderRow().textContent).toBe('Key holdergpg-agent');
      // Restarted with another holder.
      const memory = status();
      memory.holder = { ...memory.holder, name: 'memory/memfd_secret' };
      api.status.mockResolvedValue(memory);
      await (panel as any)._tick();
      expect(holderRow().textContent).toBe('Key holdermemory');
      // The same holder, measured with one more protection: its row follows.
      const locked = status();
      locked.holder = {
        ...memory.holder,
        capabilities: { ...memory.holder.capabilities, locked_memory: true }
      };
      api.status.mockResolvedValue(locked);
      await (panel as any)._tick();
      expect(
        (
          panel.node.querySelector(
            '[data-capability="locked_memory"]'
          ) as HTMLElement
        ).dataset.protection
      ).toBe('present');
      // The same holder, now reached by falling back: its notice appears.
      const fallback = status();
      fallback.holder = {
        ...locked.holder,
        notice: 'gpg-agent could not be used'
      };
      api.status.mockResolvedValue(fallback);
      await (panel as any)._tick();
      expect(holderRow().title).toContain('gpg-agent could not be used');
      // The same holder, with the vault file moved.
      const moved = status();
      moved.holder = fallback.holder;
      moved.path = '~/vaults/moved.json';
      api.status.mockResolvedValue(moved);
      await (panel as any)._tick();
      expect(text(panel)).toContain('~/vaults/moved.json');
    });

    it('changes the recovery passphrase with a passkey as the proof', async () => {
      const get = fakePasskey();
      // The proof line is over once the proof is in: gone when the new one is asked.
      let lineAtAsk: string | null | undefined;
      mockAskSecret.mockImplementation(async () => {
        lineAtAsk = panel.node.querySelector(
          '.jp-PasskeyVaultPanel-message'
        )?.textContent;
        return { accepted: true, value: 'new words' };
      });
      const api = fakeApi();
      const panel = await openCog(api);
      button(panel, 'Change recovery passphrase').click();
      // The passkey request runs from the click, before any dialog.
      expect(get).toHaveBeenCalled();
      expect(mockAskSecret).not.toHaveBeenCalled();
      await flush();
      await flush();
      expect(mockAskSecret).toHaveBeenCalledWith(
        expect.any(String),
        false,
        'Change recovery passphrase'
      );
      expect(api.replaceRecovery).toHaveBeenCalledWith('new words', {
        cred_id: 'AAEC',
        prf: 'CQkJ'
      });
      expect(lineAtAsk).toBeUndefined();
      expect(text(panel)).toContain('Recovery passphrase changed');
      mockAskSecret.mockReset();
    });

    it('changes the recovery passphrase with the current one when the passkey does not answer', async () => {
      const get = fakePasskey();
      get.mockRejectedValueOnce(new DOMException('x', 'NotAllowedError'));
      mockAskSecret
        .mockResolvedValueOnce({ accepted: true, value: 'old words' })
        .mockResolvedValue({ accepted: true, value: 'new words' });
      const api = fakeApi();
      const panel = await openCog(api);
      button(panel, 'Change recovery passphrase').click();
      await flush();
      await flush();
      expect(mockAskSecret.mock.calls[0][0]).toBe(
        'No passkey answered - enter the current recovery passphrase instead'
      );
      expect(api.replaceRecovery).toHaveBeenCalledWith('new words', {
        current: 'old words'
      });
      mockAskSecret.mockReset();
    });

    it('asks for the current passphrase as the proof when no passkey matches this host', async () => {
      mockAskSecret
        .mockResolvedValueOnce({ accepted: true, value: 'old words' })
        .mockResolvedValue({ accepted: true, value: 'new words' });
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValue(status({ slots: [{ type: 'recovery' }] }))
      });
      const panel = await openCog(api);
      button(panel, 'Change recovery passphrase').click();
      await flush();
      await flush();
      expect(mockAskSecret.mock.calls[0]).toEqual([
        'Enter the current recovery passphrase',
        true,
        'Change recovery passphrase'
      ]);
      expect(api.replaceRecovery).toHaveBeenCalledWith('new words', {
        current: 'old words'
      });
    });

    it('says nothing changed when the recovery dialog is cancelled', async () => {
      fakePasskey();
      mockAskSecret.mockResolvedValue({ accepted: false, value: null });
      const api = fakeApi();
      const panel = await openCog(api);
      button(panel, 'Change recovery passphrase').click();
      await flush();
      await flush();
      expect(api.replaceRecovery).not.toHaveBeenCalled();
      expect(text(panel)).not.toContain('Recovery passphrase changed');
    });

    it('shows the unlock duration and opens the Settings Editor', async () => {
      const openSettings = jest.fn();
      const panel = await openCog(fakeApi(), openSettings);
      expect(text(panel)).toContain('Unlock duration4h');
      expect(text(panel)).toContain(
        'Vault file~/.local/share/jupyterlab-passkey/vault.json'
      );
      button(panel, 'Open settings').click();
      expect(openSettings).toHaveBeenCalled();
    });

    it('asks for an unlock only to remove passkeys on a locked vault', async () => {
      const panel = await openCog(
        fakeApi({
          status: jest
            .fn()
            .mockResolvedValue(status({ unlocked: false, remaining: null }))
        })
      );
      expect(text(panel)).toContain('Unlock the vault to remove passkeys.');
      expect(
        Array.from(panel.node.querySelectorAll('button')).some(
          b => b.textContent === 'Remove'
        )
      ).toBe(false);
      // A proof, not an unlock, is what a new passkey needs.
      expect(button(panel, 'Register new passkey')).toBeTruthy();
      expect(text(panel)).toContain('Key holder');
    });
  });

  it('keeps a success line one full refresh period, and leaves an unchanged banner alone', async () => {
    jest.useFakeTimers();
    try {
      mockViewEntry.mockResolvedValue('delete');
      mockConfirmDelete.mockResolvedValue(true);
      const panel = new VaultPanel({
        api: fakeApi(),
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(REFRESH_MS - 5000);
      (
        panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
      ).click();
      await jest.advanceTimersByTimeAsync(0);
      const line = panel.node.querySelector('.jp-PasskeyVaultPanel-message');
      expect(line?.textContent).toContain('Deleted nas/ugos');
      // The tick 5 s later: the line stays, and is the same node, so a screen
      // reader does not announce it again.
      await jest.advanceTimersByTimeAsync(5000);
      expect(panel.node.querySelector('.jp-PasskeyVaultPanel-message')).toBe(
        line
      );
      await jest.advanceTimersByTimeAsync(REFRESH_MS);
      expect(text(panel)).not.toContain('Deleted nas/ugos');
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('reads nothing while an action waits on a dialog', async () => {
    jest.useFakeTimers();
    try {
      // Delete waits on its confirm dialog; the tick in the meantime reads nothing.
      let answer: (v: boolean) => void = () => undefined;
      mockViewEntry.mockResolvedValue('delete');
      mockConfirmDelete.mockReturnValue(
        new Promise<boolean>(resolve => (answer = resolve))
      );
      // The unlock also runs out meanwhile, which alone would read.
      const api = fakeApi({
        status: jest.fn().mockResolvedValue(status({ remaining: 20 }))
      });
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      const row = panel.node.querySelector(
        '.jp-PasskeyVaultPanel-rowLine'
      ) as HTMLElement;
      row.click();
      await jest.advanceTimersByTimeAsync(0);
      const reads = api.status.mock.calls.length;
      await jest.advanceTimersByTimeAsync(2 * REFRESH_MS);
      expect(api.status.mock.calls.length).toBe(reads);
      answer(false);
      await jest.advanceTimersByTimeAsync(0);
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it("keeps the outcome line when a tick lands during the action's final read", async () => {
    jest.useFakeTimers();
    try {
      mockViewEntry.mockResolvedValue('delete');
      // The confirm comes 20 ms before the tick, and each status read takes 50 ms.
      mockConfirmDelete.mockImplementation(
        () => new Promise(resolve => setTimeout(() => resolve(true), 20))
      );
      const api: any = fakeApi();
      api.status = jest.fn().mockImplementation(
        () =>
          new Promise(resolve =>
            setTimeout(
              () =>
                resolve(
                  status({
                    revision: api.remove.mock.calls.length ? 'after' : 'before'
                  })
                ),
              50
            )
          )
      );
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(100);
      await jest.advanceTimersByTimeAsync(REFRESH_MS - 100 - 40);
      (
        panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
      ).click();
      await jest.advanceTimersByTimeAsync(200);
      expect(text(panel)).toContain('Deleted nas/ugos');
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('draws the locked view when the unlock runs out during the final read', async () => {
    jest.useFakeTimers();
    try {
      mockViewEntry.mockResolvedValue('delete');
      mockConfirmDelete.mockResolvedValue(true);
      const api = fakeApi();
      // After the delete: 1 s of unlock left, and the entries take 1.5 s to arrive.
      api.status = jest
        .fn()
        .mockImplementation(async () =>
          status(api.remove.mock.calls.length ? { remaining: 1 } : {})
        );
      api.entries = jest
        .fn()
        .mockImplementation(
          () =>
            new Promise(resolve =>
              setTimeout(
                () => resolve(ENTRIES),
                api.remove.mock.calls.length ? 1500 : 0
              )
            )
        );
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      (
        panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
      ).click();
      await jest.advanceTimersByTimeAsync(2000);
      expect(
        panel.node.querySelector('.jp-PasskeyVaultPanel-stateText')?.textContent
      ).toBe('Locked');
      expect(panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine')).toBe(
        null
      );
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('reads once, not without end, when the countdown ran out and the read fails', async () => {
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValueOnce(status({ remaining: 1 }))
        .mockRejectedValue(new NoAnswer())
    });
    const now = jest.spyOn(Date, 'now').mockReturnValue(1000);
    try {
      const panel = await panelWith(api);
      now.mockReturnValue(1000 + 5000); // past the 1 s left
      await panel.refresh();
      await flush();
      await flush();
      expect(api.status.mock.calls.length).toBeLessThanOrEqual(3);
      expect(text(panel)).toContain('cannot reach the Jupyter server');
      panel.dispose();
    } finally {
      now.mockRestore();
    }
  });

  it('drops the old read failure when the status answers and the unlock ran out before the entries read', async () => {
    const api = fakeApi();
    const panel = await panelWith(api);
    api.status.mockRejectedValueOnce(new NoAnswer());
    await panel.refresh();
    expect(lines(panel)).toEqual([
      ['error', 'cannot reach the Jupyter server']
    ]);
    api.entries.mockRejectedValueOnce(new VaultError(423, 'vault is locked'));
    await panel.refresh();
    expect(lines(panel)).toEqual([]);
    expect(text(panel)).toContain('Locked');
  });

  it('reads the entries again on the next tick after a failed read', async () => {
    jest.useFakeTimers();
    try {
      const api = fakeApi({
        entries: jest
          .fn()
          .mockRejectedValueOnce(new NoAnswer())
          .mockResolvedValue(ENTRIES)
      });
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      expect(text(panel)).toContain('The entries could not be read.');
      await jest.advanceTimersByTimeAsync(REFRESH_MS);
      expect(text(panel)).toContain('github/api');
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('says on the next tick that the server stopped answering, and clears it once it answers', async () => {
    jest.useFakeTimers();
    try {
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValueOnce(status())
          .mockRejectedValueOnce(new NoAnswer())
          .mockResolvedValue(status())
      });
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      expect(lines(panel)).toEqual([]);
      await jest.advanceTimersByTimeAsync(REFRESH_MS);
      expect(lines(panel)).toEqual([
        ['error', 'cannot reach the Jupyter server']
      ]);
      // The entries on screen are still the last ones read: a filter that matches
      // none of them says so.
      const filter = panel.node.querySelector(
        '.jp-PasskeyVaultPanel-filterInput'
      ) as HTMLInputElement;
      filter.value = 'zzz';
      filter.dispatchEvent(new Event('input'));
      expect(text(panel)).toContain('No entry matches the filter.');
      filter.value = '';
      filter.dispatchEvent(new Event('input'));
      await jest.advanceTimersByTimeAsync(REFRESH_MS);
      expect(lines(panel)).toEqual([]);
      expect(text(panel)).toContain('github/api');
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('drops a line about a state that changed elsewhere', async () => {
    jest.useFakeTimers();
    try {
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValueOnce(status({ unlocked: false, remaining: null }))
          .mockResolvedValue(status())
      });
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      (panel as any)._message = {
        kind: 'error',
        text: 'the passkey request was cancelled or not allowed',
        at: Date.now()
      };
      (panel as any)._render();
      // Unlocked from the CLI: the next tick sees it, and the old failure goes.
      await jest.advanceTimersByTimeAsync(REFRESH_MS);
      expect(text(panel)).toContain('Unlocked');
      expect(text(panel)).not.toContain('cancelled or not allowed');
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('re-reads the entries when another client changes them', async () => {
    jest.useFakeTimers();
    try {
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValueOnce(status({ revision: 'r1' }))
          .mockResolvedValue(status({ revision: 'r2' })),
        entries: jest
          .fn()
          .mockResolvedValueOnce(ENTRIES.slice(0, 1))
          .mockResolvedValue(ENTRIES)
      });
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      expect(text(panel)).not.toContain('nas/ugos');
      // The CLI imported entries: the revision moves, the panel reads them.
      await jest.advanceTimersByTimeAsync(REFRESH_MS);
      expect(text(panel)).toContain('nas/ugos');
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('announces a repeated outcome again, with a new banner line', async () => {
    mockViewEntry.mockResolvedValue('delete');
    mockConfirmDelete.mockResolvedValue(true);
    const panel = await panelWith(fakeApi());
    const row = () =>
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement;
    row().click();
    await flush();
    await flush();
    const first = panel.node.querySelector('.jp-PasskeyVaultPanel-message');
    row().click();
    await flush();
    await flush();
    const second = panel.node.querySelector('.jp-PasskeyVaultPanel-message');
    expect(second?.textContent).toBe(first?.textContent);
    expect(second).not.toBe(first);
  });

  it('lets the countdown run out while the server does not answer', async () => {
    jest.useFakeTimers();
    try {
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValueOnce(status({ remaining: 20 }))
          .mockRejectedValue(new NoAnswer())
      });
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      expect(text(panel)).toContain('Unlocked');
      await jest.advanceTimersByTimeAsync(REFRESH_MS * 2);
      expect(
        panel.node.querySelector('.jp-PasskeyVaultPanel-stateText')?.textContent
      ).toBe('Locked');
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('offers the passkey unlock once a passkey for this host appears', async () => {
    jest.useFakeTimers();
    try {
      const locked = status({ unlocked: false, remaining: null });
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValueOnce({ ...locked, slots: [{ type: 'recovery' }] })
          .mockResolvedValue(locked)
      });
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      expect(() => button(panel, 'Unlock with passkey')).toThrow();
      // Registered from another tab: the next tick redraws the locked view.
      await jest.advanceTimersByTimeAsync(REFRESH_MS);
      expect(button(panel, 'Unlock with passkey')).toBeTruthy();
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('clears a read error once a later read succeeds', async () => {
    jest.useFakeTimers();
    try {
      const api = fakeApi({
        status: jest
          .fn()
          .mockRejectedValueOnce(new NoAnswer())
          .mockResolvedValue(status())
      });
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      expect(text(panel)).toContain('cannot reach the Jupyter server');
      await jest.advanceTimersByTimeAsync(REFRESH_MS);
      expect(text(panel)).not.toContain('cannot reach the Jupyter server');
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('switches to the locked view when the vault expires while shown', async () => {
    jest.useFakeTimers();
    try {
      const statuses = [status(), status({ unlocked: false, remaining: null })];
      const api = fakeApi({
        status: jest.fn(() =>
          Promise.resolve(statuses.length > 1 ? statuses.shift() : statuses[0])
        )
      });
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      expect(text(panel)).toContain('Unlocked');
      await jest.advanceTimersByTimeAsync(REFRESH_MS);
      expect(text(panel)).toContain('Locked');
      expect(button(panel, 'Unlock with passkey')).toBeTruthy();
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });
});

// --------------------------------------------------------------------------- //
// the entry form, the settings wiring
// --------------------------------------------------------------------------- //

describe('EntryForm', () => {
  it('never lets the browser autofill the password and fills it on Generate', async () => {
    const form = new EntryForm(async () => 'fresh-generated');
    expect(form.password.type).toBe('password');
    expect(form.password.autocomplete).toBe('new-password');
    form.generate.click();
    await flush();
    expect(form.password.value).toBe('fresh-generated');
  });

  it('says in Edit that a generated password replaces the current one', async () => {
    const form = new EntryForm(async () => 'fresh-generated', ENTRIES[0]);
    form.generate.click();
    await flush();
    expect(form.node.textContent).toContain(
      'Save replaces the current password'
    );
    expect(form.node.textContent).not.toContain(
      'Leave empty to keep the current password'
    );
    // Cleared again, the field keeps the current password, and the line says so.
    form.password.value = '';
    form.password.dispatchEvent(new Event('input'));
    expect(form.node.textContent).toContain(
      'Leave empty to keep the current password'
    );
    expect(form.getValue()).not.toHaveProperty('password');
    // Typed by hand, a password replaces the current one as a generated one does.
    form.password.value = 'typed by hand';
    form.password.dispatchEvent(new Event('input'));
    expect(form.node.textContent).toContain(
      'Save replaces the current password'
    );
  });

  it('keeps the replace rule beside a failed Generate that follows a successful one', async () => {
    const generate = jest
      .fn()
      .mockResolvedValueOnce('first-generated')
      .mockRejectedValue(new Error('cannot reach the Jupyter server'));
    const form = new EntryForm(generate, ENTRIES[0]);
    form.generate.click();
    await flush();
    form.generate.click();
    await flush();
    expect(form.node.textContent).toContain(
      'No password was generated: cannot reach the Jupyter server. Save replaces the current password'
    );
    expect(form.getValue().password).toBe('first-generated');
    // A second failure replaces the first; it does not stack on it.
    form.generate.click();
    await flush();
    expect(form.node.textContent).toContain(
      'No password was generated: cannot reach the Jupyter server. Save replaces the current password'
    );
    expect(form.node.textContent).not.toContain(
      'server. No password was generated'
    );
  });

  it('clears a failed Generate line in Add once a password is generated', async () => {
    const generate = jest
      .fn()
      .mockRejectedValueOnce(new Error('the vault is locked'))
      .mockResolvedValue('fresh-generated');
    const form = new EntryForm(generate);
    form.generate.click();
    await flush();
    expect(form.node.textContent).toContain('No password was generated');
    form.generate.click();
    await flush();
    expect(form.node.textContent).not.toContain('No password was generated');
  });

  it('requires a name and leaves an empty password out of an edit', () => {
    const form = new EntryForm(async () => 'x', ENTRIES[0]);
    expect(form.name.readOnly).toBe(true);
    expect(form.getValue()).not.toHaveProperty('password');
    const empty = new EntryForm(async () => 'x');
    expect(
      empty.name.validationMessage || empty.name.validity.customError
    ).toBeTruthy();
  });

  it('shows Edit with the same visible fields as Add, the name read-only, plus the keep-password help', () => {
    const shown = (form: EntryForm) =>
      Array.from(form.node.querySelectorAll('.jp-PasskeyVaultForm-field'))
        .filter(f => !(f as HTMLElement).hidden)
        .map(f => f.querySelector('.jp-PasskeyVaultForm-label')!.textContent);
    const edit = new EntryForm(async () => 'x', ENTRIES[0]);
    const add = new EntryForm(async () => 'x');
    expect(shown(edit)).toEqual([
      'Name',
      'Username',
      'Password',
      'URL',
      'Category',
      'Notes'
    ]);
    expect(shown(add)).toEqual(shown(edit));
    expect(edit.name.value).toBe(ENTRIES[0].name);
    expect(edit.node.textContent).toContain(
      'Leave empty to keep the current password'
    );
    expect(add.node.textContent).not.toContain('Leave empty');
  });

  it('refuses a name already in use before the dialog closes', () => {
    const form = new EntryForm(async () => 'x', undefined, ['github/api']);
    Widget.attach(form, document.body);
    form.name.value = 'github/api';
    form.name.dispatchEvent(new Event('input', { bubbles: true }));
    expect(form.name.validationMessage).toContain('already exists');
    expect(form.node.textContent).toContain(
      'An entry named github/api already exists'
    );
    form.dispose();
  });

  it('lets Enter type a line break in Notes', () => {
    const form = new EntryForm(async () => 'x');
    Widget.attach(form, document.body);
    const reachedDialog = jest.fn();
    form.node.addEventListener('keydown', reachedDialog, true);
    form.notes.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })
    );
    // Dialog's handler, which prevents Enter's default, never sees it.
    expect(reachedDialog).not.toHaveBeenCalled();
    // Nor Enter on Generate, which then does its click.
    form.generate.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })
    );
    expect(reachedDialog).not.toHaveBeenCalled();
    form.name.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })
    );
    expect(reachedDialog).toHaveBeenCalledTimes(1);
    form.dispose();
  });

  it('says so when Generate fails, and leaves the field as it was', async () => {
    const form = new EntryForm(async () => {
      throw new Error('the Jupyter server did not answer');
    });
    form.password.value = 'typed';
    form.generate.click();
    await flush();
    expect(form.password.value).toBe('typed');
    expect(form.node.textContent).toContain(
      'No password was generated: the Jupyter server did not answer'
    );
  });
});

describe('editEntry', () => {
  const { editEntry } = jest.requireActual('../vault/dialogs');
  // What the form's own controls do on load: CRLF to LF, line breaks dropped.
  const loaded = {
    ...ENTRIES[2],
    notes: 'rack 1\r\nshelf 2',
    url: 'https://nas.example\n'
  };

  it('answers only the name when nothing was changed, whatever the form did on load', async () => {
    mockLaunch.mockResolvedValue({ button: { accept: true } });
    const value = await editEntry(async () => 'x', loaded);
    expect(value).toEqual({ name: 'nas/ugos' });
  });

  it('answers the fields the user changed and a typed password', async () => {
    mockLaunch.mockImplementation(async (dialog: any) => {
      dialog.options.body.username.value = 'k2';
      dialog.options.body.password.value = 'new pass';
      return { button: { accept: true } };
    });
    const value = await editEntry(async () => 'x', loaded);
    expect(value).toEqual({
      name: 'nas/ugos',
      username: 'k2',
      password: 'new pass'
    });
  });
});

describe('confirmDelete', () => {
  const { confirmDelete } = jest.requireActual('../vault/dialogs');

  it('makes Cancel the button Enter presses', async () => {
    let options: any;
    mockLaunch.mockImplementation(async (dialog: any) => {
      options = dialog.options;
      return { button: { label: 'Cancel' } };
    });
    await expect(confirmDelete('nas/ugos')).resolves.toBe(false);
    // The default is the button that does not accept: Cancel.
    expect(options.buttons[options.defaultButton].accept).toBe(false);
  });
});

describe('EntryView', () => {
  const SECRET = 's3cret-value';

  function view(reveal: () => Promise<string>): EntryView {
    const v = new EntryView(ENTRIES[2], reveal);
    Widget.attach(v, document.body);
    return v;
  }

  it('shows the fields of Edit entry, every one read-only, and no copy button', () => {
    const v = view(async () => SECRET);
    const labels = Array.from(
      v.node.querySelectorAll('.jp-PasskeyVaultForm-label')
    ).map(l => l.textContent);
    expect(labels).toEqual([
      'Name',
      'Username',
      'Password',
      'URL',
      'Category',
      'Notes'
    ]);
    const controls = Array.from(
      v.node.querySelectorAll<HTMLInputElement>('input, textarea')
    );
    expect(controls.every(c => c.readOnly)).toBe(true);
    expect(controls[0].value).toBe('nas/ugos');
    expect(Array.from(v.node.querySelectorAll('button'))).toEqual([v.eye]);
    v.dispose();
  });

  it('keeps the password out of the page until a reveal returns it', () => {
    const reveal = jest.fn().mockResolvedValue(SECRET);
    const v = view(reveal);
    expect(v.password.type).toBe('password');
    expect(v.password.value).not.toContain(SECRET);
    expect(reveal).not.toHaveBeenCalled();
    v.dispose();
  });

  it('reveals once, then only hides and shows', async () => {
    const reveal = jest.fn().mockResolvedValue(SECRET);
    const v = view(reveal);
    // The icon is the state: a crossed eye while hidden, an open eye while shown.
    const icon = () =>
      (v.eye.querySelector('[data-icon]') as HTMLElement).dataset.icon;
    expect(icon()).toBe('jupyterlab-passkey-extension:eye-off');
    v.eye.click();
    await flush();
    expect(v.password.type).toBe('text');
    expect(v.password.value).toBe(SECRET);
    expect(v.eye.getAttribute('aria-label')).toBe('Hide password');
    expect(icon()).toBe('jupyterlab-passkey-extension:eye');
    v.eye.click();
    expect(v.password.type).toBe('password');
    expect(icon()).toBe('jupyterlab-passkey-extension:eye-off');
    v.eye.click();
    expect(v.password.type).toBe('text');
    expect(reveal).toHaveBeenCalledTimes(1);
    // A click selects the whole shown password, for copying.
    v.password.click();
    expect(v.password.selectionStart).toBe(0);
    expect(v.password.selectionEnd).toBe(SECRET.length);
    v.dispose();
  });

  it('says so when the entry has no password', async () => {
    const v = view(jest.fn().mockResolvedValue(''));
    v.eye.click();
    await flush();
    expect(v.node.textContent).toContain('This entry has no password');
    v.dispose();
  });

  it('keeps the dots and says nothing when the passkey prompt is cancelled', async () => {
    const v = view(
      jest.fn().mockRejectedValue(new DOMException('x', 'NotAllowedError'))
    );
    v.eye.click();
    await flush();
    expect(v.password.type).toBe('password');
    expect(v.node.querySelector('.jp-PasskeyVaultForm-help')!.textContent).toBe(
      ''
    );
    v.dispose();
  });

  it('says why when the server refuses the passkey', async () => {
    const v = view(
      jest
        .fn()
        .mockRejectedValue(
          new VaultError(403, 'the passkey did not open the vault')
        )
    );
    v.eye.click();
    await flush();
    expect(v.password.type).toBe('password');
    expect(v.node.textContent).toContain(
      'The password was not shown: the passkey did not open the vault'
    );
    v.dispose();
  });

  it('lets Enter on the eye press it instead of the default dialog button', () => {
    const v = view(async () => SECRET);
    const reachedDialog = jest.fn();
    v.node.addEventListener('keydown', reachedDialog, true);
    v.eye.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })
    );
    expect(reachedDialog).not.toHaveBeenCalled();
    v.dispose();
  });
});

describe('connectSettings', () => {
  it('sends the unlock duration and docks the panel, now and on every change', () => {
    const values: Record<string, unknown> = {
      unlockMinutes: 30,
      sidebar: 'right'
    };
    const listeners: Array<() => void> = [];
    const settings: any = {
      get: (key: string) => ({ composite: values[key] }),
      changed: { connect: (fn: () => void) => listeners.push(fn) }
    };
    const api = fakeApi();
    const dock = jest.fn();
    connectSettings(settings, api, dock);
    expect(api.setConfig).toHaveBeenLastCalledWith(30);
    expect(dock).toHaveBeenLastCalledWith('right');
    values.unlockMinutes = 90;
    values.sidebar = 'left';
    listeners.forEach(fn => fn());
    expect(api.setConfig).toHaveBeenLastCalledWith(90);
    expect(dock).toHaveBeenLastCalledWith('left');
    // A change to anything else leaves the panel where it is: docking again
    // collapses it.
    values.unlockMinutes = 45;
    listeners.forEach(fn => fn());
    expect(dock).toHaveBeenCalledTimes(2);
  });
});

it('rounds time left up to the minute, with seconds under one minute', () => {
  expect(formatRemaining(4 * 3600 - 0.5)).toBe('4h 0m');
  expect(formatRemaining(61)).toBe('2m');
  expect(formatRemaining(59.2)).toBe('60s');
});

it('shows the unlock duration in hours and minutes, a zero part left out', () => {
  expect([240, 90, 45, 1440].map(formatMinutes)).toEqual([
    '4h',
    '1h 30m',
    '45m',
    '24h'
  ]);
});
