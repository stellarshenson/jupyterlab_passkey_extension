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
const mockChoose = jest.fn();
const mockLaunch = jest.fn();
// Each notification gets its own id, as JupyterLab's do.
const mockWarning: jest.Mock = jest.fn(
  () => `warn-${mockWarning.mock.calls.length}`
);
const mockError: jest.Mock = jest.fn(
  () => `error-${mockError.mock.calls.length}`
);
const mockDismiss = jest.fn();
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
    confirmDelete: (...a: any[]) => mockConfirmDelete(...a),
    chooseUnlockMethod: (...a: any[]) => mockChoose(...a)
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
    rejected = false;
    constructor(readonly options: any) {}
    addClass(): void {}
    reject(): void {
      this.rejected = true;
    }
  },
  Notification: {
    warning: (...a: any[]) => mockWarning(...a),
    error: (...a: any[]) => mockError(...a),
    dismiss: (...a: any[]) => mockDismiss(...a)
  }
}));

/**
 * Answer the dialogs the code under test opens itself, by title: accept or not, the
 * label of the button pressed, or for the method chooser the methods pressed in turn,
 * then Escape. `code` is typed into a dialog that asks a code.
 */
function answerDialogs(
  accept: Record<string, boolean | string | string[]>,
  code = ''
): void {
  mockLaunch.mockImplementation(async (dialog: any) => {
    const answer = accept[dialog.options.title] ?? false;
    if (Array.isArray(answer)) {
      dialog.options.body.chosen = answer.shift() ?? null;
      return { button: { accept: false } };
    }
    if (dialog.options.body?.code) {
      dialog.options.body.code.value = code;
    }
    return {
      button:
        typeof answer === 'string'
          ? dialog.options.buttons.find((b: any) => b.label === answer)
          : { accept: answer }
    };
  });
}
// Only the icons are used; the real module drags in untransformed ESM React code.
jest.mock('@jupyterlab/ui-components', () => {
  const icon = { element: () => document.createElement('span') };
  return {
    addIcon: icon,
    filterIcon: icon,
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

import { ServerConnection } from '@jupyterlab/services';
import {
  ISlot,
  IStatus,
  NoAnswer,
  Proof,
  VaultApi,
  VaultError
} from '../vault/api';
import {
  askProof,
  EntryForm,
  EntryView,
  registerMfa,
  registerWithProof,
  sentence,
  unlockWithChoice,
  unlockWithPair
} from '../vault/dialogs';
import { setTranslator } from '../trans';
import {
  ARM_DELAY_MS,
  entryTooltip,
  formatMinutes,
  formatRemaining,
  REFRESH_MS,
  VaultPanel
} from '../vault/panel';
import { connectSettings } from '../vault/plugin';
import { newSetupKey, otpauthUri } from '../vault/totp';
import {
  describeFailure,
  ipAddressAdvice,
  matchingSlots,
  pairSlot,
  registerPasskey,
  unlockWithPasskey
} from '../vault/webauthn';
import { b64urlToBuf } from '../passkey-util';

const HOST = 'lab.example.com';
/** A server challenge: 32 bytes, base64url. */
const CHALLENGE = 'Y2hhbGxlbmdlLWNoYWxsZW5nZS1jaGFsbGVuZ2UtMzI';

/** What a lost answer or a 5xx of the request that adds an unlock method says. */
const MAYBE_ADDED =
  'the server did not confirm the method - it may have been added; check the cog';

/**
 * What an action the vault did not confirm says: the reason, then where its outcome
 * shows. Create's points at whether the vault exists, with no advice to create again.
 */
const NOT_CONFIRMED = 'Not confirmed - no server answer; wait for the panel.';
const CREATE_NOT_CONFIRMED =
  'Vault creation not confirmed - the server stopped answering.';

/** The line of a declined Password and passkey: what happened, then the ways in. */
const NO_PRF =
  'no PRF - passkey not added; use another passkey or Password and authenticator app';

/** A refusal of a slot request too long to fit a notification with the unused passkey. */
const TOO_MANY_CODES =
  'too many wrong codes - codes are refused until the vault is unlocked with a passkey or the recovery passphrase';

/**
 * The error the real `VaultApi` makes of an answer that is not the vault's: the
 * Jupyter server's 403 after a hub logout, or its 404 with no vault routes.
 */
async function notTheVault(code: 403 | 404): Promise<VaultError> {
  const spy = jest.spyOn(ServerConnection, 'makeRequest').mockResolvedValue({
    ok: false,
    status: code,
    text: async () => ''
  } as any);
  try {
    return await new VaultApi({ baseUrl: 'http://host/' } as any)
      .lock()
      .catch(e => e);
  } finally {
    spy.mockRestore();
  }
}

/** `text` as a regular expression that matches only itself. */
const literally = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * A failure after the browser created a passkey that no slot holds: the reason, then
 * the passkey named by its creation time, to the second.
 */
const unused = (why: string) =>
  new RegExp(
    `^${literally(why)}; delete the unused passkey dated \\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} UTC$`
  );

/** The answer of a passkey with no PRF to a `get`, and that answer as it is sent. */
const signed = () => ({
  rawId: new Uint8Array([9]).buffer,
  response: {
    clientDataJSON: new Uint8Array([1]).buffer,
    authenticatorData: new Uint8Array([2]).buffer,
    signature: new Uint8Array([3]).buffer
  },
  getClientExtensionResults: () => ({})
});
const ASSERTION = {
  cred_id: 'CQ',
  client_data: 'AQ',
  authenticator_data: 'Ag',
  signature: 'Aw'
};
/** The answer of `noPrfBrowser`'s `create` as it is sent. */
const REGISTRATION = { client_data: 'BA', attestation_object: 'BQ' };

/**
 * A browser whose passkey has no PRF: `create` gives its client data and attestation
 * object, `get` signs.
 */
function noPrfBrowser(): { create: jest.Mock; get: jest.Mock } {
  const create = jest.fn().mockResolvedValue({
    rawId: new Uint8Array([9]).buffer,
    response: {
      clientDataJSON: new Uint8Array([4]).buffer,
      attestationObject: new Uint8Array([5]).buffer
    }
  });
  const get = jest.fn().mockImplementation(async () => signed());
  Object.defineProperty(navigator, 'credentials', {
    value: { get, create },
    configurable: true
  });
  return { create, get };
}

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
      { type: 'recovery', kdf: 'argon2id' },
      {
        type: 'passkey',
        cred_id: 'AAEC',
        rp_id: HOST,
        prf_salt: 'c2FsdA',
        label: 'laptop',
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

/** The status with no vault yet. */
function NEW_VAULT(): any {
  return status({
    initialized: false,
    unlocked: false,
    remaining: null,
    slots: []
  });
}

/** The names of the buttons of a method chooser. */
function methodNames(body: HTMLElement): (string | null)[] {
  return Array.from(body.querySelectorAll('button')).map(
    choice => (choice.firstChild as HTMLElement).textContent
  );
}

function fakeApi(over: Record<string, any> = {}): any {
  return {
    status: jest.fn().mockResolvedValue(status()),
    entries: jest.fn().mockResolvedValue(ENTRIES),
    lock: jest.fn().mockResolvedValue(undefined),
    init: jest.fn().mockResolvedValue(undefined),
    unlockRecovery: jest.fn().mockResolvedValue(status()),
    unlockPasskey: jest.fn().mockResolvedValue(status()),
    unlockPassword: jest.fn().mockResolvedValue(status()),
    add: jest.fn().mockResolvedValue(undefined),
    edit: jest.fn().mockResolvedValue(undefined),
    remove: jest.fn().mockResolvedValue(undefined),
    revealPassword: jest.fn().mockResolvedValue('s3cret-value'),
    generate: jest.fn().mockResolvedValue('generated-pw'),
    addPasskey: jest.fn().mockResolvedValue(undefined),
    removePasskey: jest.fn().mockResolvedValue(undefined),
    replaceRecovery: jest.fn().mockResolvedValue(undefined),
    addMfa: jest.fn().mockResolvedValue(undefined),
    removeMfa: jest.fn().mockResolvedValue(undefined),
    rotate: jest.fn().mockResolvedValue(undefined),
    checkRecovery: jest.fn().mockResolvedValue(undefined),
    challenge: jest.fn().mockResolvedValue(CHALLENGE),
    unlockPair: jest.fn().mockResolvedValue(status()),
    addPair: jest.fn().mockResolvedValue(undefined),
    proven: false,
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

/** Press "Add unlock method" in the cog view and choose a method in its dialog. */
function addMethod(panel: VaultPanel, kind: 'passkey' | 'mfa'): void {
  mockChoose.mockResolvedValueOnce(kind);
  button(panel, 'Add unlock method').click();
}

/** Press the header's filter button, which shows the filter field, and return the field. */
function openFilter(panel: VaultPanel): HTMLInputElement {
  (
    panel.node.querySelector('button[title="Filter entries"]') as HTMLElement
  ).click();
  return panel.node.querySelector(
    '.jp-PasskeyVaultPanel-filterInput'
  ) as HTMLInputElement;
}

/** Stub the harmonica's geometry (a 200 px list, a 22 px section) and lay it out. */
function harmonica(panel: VaultPanel): void {
  const list = panel.node.querySelector(
    '.jp-PasskeyVaultPanel-list'
  ) as HTMLElement;
  Object.defineProperty(list, 'clientHeight', {
    value: 200,
    configurable: true
  });
  for (const section of Array.from(
    panel.node.querySelectorAll<HTMLElement>('.jp-PasskeyVaultPanel-section')
  )) {
    // Band 21 plus the 1 px divider; the viewport stays jsdom's 0.
    Object.defineProperty(section, 'offsetHeight', {
      value: 22,
      configurable: true
    });
  }
  MessageLoop.sendMessage(panel, Widget.ResizeMessage.UnknownSize);
}

/** The list's category bands. */
function bands(panel: VaultPanel): HTMLButtonElement[] {
  return Array.from(
    panel.node.querySelectorAll<HTMLButtonElement>(
      'button.jp-PasskeyVaultPanel-sectionHeader'
    )
  );
}

/** The list's scrolling category viewports. */
function viewports(panel: VaultPanel): HTMLElement[] {
  return Array.from(
    panel.node.querySelectorAll<HTMLElement>('.jp-PasskeyVaultPanel-viewport')
  );
}

/** A wheel event over the panel, as the harmonica's global gesture sees it. */
function wheel(
  panel: VaultPanel,
  deltaY: number,
  deltaMode: number = WheelEvent.DOM_DELTA_PIXEL
): WheelEvent {
  const event = new WheelEvent('wheel', {
    deltaY,
    deltaMode,
    cancelable: true,
    bubbles: true
  });
  panel.node.dispatchEvent(event);
  return event;
}

const flush = () => new Promise(r => setTimeout(r, 0));

/** The banner's lines, each as its colour and its text. */
function lines(panel: VaultPanel): [string | undefined, string | null][] {
  return Array.from(
    panel.node.querySelectorAll<HTMLElement>('.jp-PasskeyVaultPanel-message')
  ).map(l => [l.dataset.kind, l.textContent]);
}

/** What a JupyterLab notification shows of a message (`createContent` in jlab_core). */
const TOAST_LIMIT = 140;

/**
 * The notifications raised and not dismissed since, oldest first, each as its colour
 * and its text. Every one has no timeout, and its text shows whole.
 */
function toasts(): [string, string][] {
  const dismissed = new Set(mockDismiss.mock.calls.map(([id]) => id));
  const raised = (kind: string, mock: jest.Mock) =>
    mock.mock.calls.map(([text, options], i) => ({
      kind,
      text: text as string,
      options,
      id: mock.mock.results[i].value,
      order: mock.mock.invocationCallOrder[i]
    }));
  return [...raised('warn', mockWarning), ...raised('error', mockError)]
    .filter(t => !dismissed.has(t.id))
    .sort((a, b) => a.order - b.order)
    .map(t => {
      expect(t.options).toEqual({ autoClose: false });
      expect(t.text.length).toBeLessThanOrEqual(TOAST_LIMIT);
      return [t.kind, t.text];
    });
}

/** Forget the notifications raised so far, for a test that makes a second panel. */
function clearToasts(): void {
  [mockWarning, mockError, mockDismiss].forEach(m => m.mockClear());
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
  window.localStorage.clear();
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

  it('refuses when no passkey was added for the host', async () => {
    await expect(
      unlockWithPasskey(fakeApi(), status(), 'localhost')
    ).rejects.toThrow('no passkey for localhost - add one with the cog');
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
    const shown: string[] = [];
    await registerPasskey(
      api,
      '',
      async name => {
        order.push('confirm');
        shown.push(name);
        return true;
      },
      { current: 'recovery words' },
      HOST,
      jest.fn(),
      CHALLENGE
    );
    expect(order).toEqual(['create', 'confirm', 'get']);
    // No name chosen falls back to the hostname, which the confirm step shows.
    expect(shown).toEqual([HOST]);
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

  it('stores the name chosen before the browser created the passkey', async () => {
    create.mockResolvedValue({ rawId: new Uint8Array([9]).buffer });
    get.mockResolvedValue({
      rawId: new Uint8Array([9]).buffer,
      getClientExtensionResults: () => ({
        prf: { results: { first: new Uint8Array([1]).buffer } }
      })
    });
    const api = fakeApi();
    const shown: string[] = [];
    await registerPasskey(
      api,
      'Work laptop',
      async name => {
        shown.push(name);
        return true;
      },
      { current: 'pw' },
      HOST,
      jest.fn(),
      CHALLENGE
    );
    expect(shown).toEqual(['Work laptop']);
    expect(api.addPasskey.mock.calls[0][0].label).toBe('Work laptop');
    // The OS passkey manager can tell the credentials apart by host and date.
    const user = create.mock.calls[0][0].publicKey.user;
    expect(user.name).toMatch(
      new RegExp(
        `^JupyterLab vault - \\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} UTC - ${HOST}$`
      )
    );
  });

  it('says the created passkey is unused when any step after create stops, by the time in its name', async () => {
    create.mockResolvedValue({ rawId: new Uint8Array([9]).buffer });
    const api = fakeApi();
    // Declined at the confirm step ...
    const refused = registerPasskey(
      api,
      'x',
      async () => false,
      { current: 'pw' },
      HOST,
      jest.fn(),
      CHALLENGE
    );
    await expect(refused).rejects.toThrow(
      unused('adding the passkey was cancelled')
    );
    // The time the passkey manager lists in the name, so a same-day retry differs.
    const user = create.mock.calls[0][0].publicKey.user.name as string;
    const at = user.match(/ - (.+ UTC) - /)![1];
    await expect(refused).rejects.toThrow(
      `adding the passkey was cancelled; delete the unused passkey dated ${at}`
    );
    // ... or the second passkey prompt dismissed.
    get.mockRejectedValue(new DOMException('x', 'NotAllowedError'));
    await expect(
      registerPasskey(
        api,
        'x',
        async () => true,
        { current: 'pw' },
        HOST,
        jest.fn(),
        CHALLENGE
      )
    ).rejects.toThrow(
      unused('the passkey request was cancelled or not allowed')
    );
    expect(api.addPasskey).not.toHaveBeenCalled();
  });

  it('cuts a long reason, never the time, in the line for a notification, and gives the CLI the whole reason', async () => {
    create.mockResolvedValue({ rawId: new Uint8Array([9]).buffer });
    get.mockResolvedValue({
      rawId: new Uint8Array([9]).buffer,
      getClientExtensionResults: () => ({
        prf: { results: { first: new Uint8Array([1]).buffer } }
      })
    });
    const api = fakeApi({
      addPasskey: jest
        .fn()
        .mockRejectedValue(new VaultError(403, TOO_MANY_CODES))
    });
    const e = await registerPasskey(
      api,
      'x',
      async () => true,
      { code: '123456' },
      HOST,
      jest.fn(),
      CHALLENGE
    ).catch(x => x);
    expect(e.message).toMatch(unused(TOO_MANY_CODES));
    expect(e.short).toMatch(
      /^too many wrong codes - .+…; delete the unused passkey dated \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$/
    );
    // The panel's full stop makes it 140.
    expect(e.short).toHaveLength(139);
  });

  describe('the request to remove a passkey no slot holds', () => {
    const signal = jest.fn();
    beforeEach(() => {
      Object.defineProperty(globalThis, 'PublicKeyCredential', {
        value: { signalUnknownCredential: signal },
        configurable: true
      });
      Object.defineProperty(navigator, 'credentials', {
        value: { get, create },
        configurable: true
      });
      create.mockResolvedValue({ rawId: new Uint8Array([9]).buffer });
      get.mockResolvedValue({
        rawId: new Uint8Array([9]).buffer,
        getClientExtensionResults: () => ({
          prf: { results: { first: new Uint8Array([1]).buffer } }
        })
      });
    });
    afterEach(() => {
      delete (globalThis as any).PublicKeyCredential;
      signal.mockReset();
    });

    const register = (api: any, confirm = true) =>
      registerPasskey(
        api,
        'x',
        async () => confirm,
        { current: 'pw' },
        HOST,
        jest.fn(),
        CHALLENGE
      );

    it('is sent when no slot request went out, and the line then leaves out the passkey', async () => {
      signal.mockResolvedValue(undefined);
      const api = fakeApi();
      await expect(register(api, false)).rejects.toThrow(
        /^adding the passkey was cancelled$/
      );
      expect(signal).toHaveBeenCalledWith({ rpId: HOST, credentialId: 'CQ' });
      expect(api.addPasskey).not.toHaveBeenCalled();
    });

    it('is sent after a 4xx answer to the slot request, which stored nothing', async () => {
      signal.mockResolvedValue(undefined);
      const api = fakeApi({
        addPasskey: jest
          .fn()
          .mockRejectedValue(new VaultError(403, 'wrong recovery passphrase'))
      });
      await expect(register(api)).rejects.toThrow(
        /^wrong recovery passphrase$/
      );
      expect(signal).toHaveBeenCalledTimes(1);
    });

    it('is sent when Password and passkey is declined, and the line names the ways in', async () => {
      signal.mockResolvedValue(undefined);
      noPrfBrowser();
      answerDialogs({
        'Name the new passkey': true,
        'Confirm the new passkey': true,
        'Add password and passkey': 'Decline'
      });
      const api = fakeApi();
      await expect(
        registerWithProof(api, { current: 'pw' }, '', HOST)
      ).rejects.toThrow(new RegExp(`^${literally(NO_PRF)}$`));
      expect(signal).toHaveBeenCalledWith({ rpId: HOST, credentialId: 'CQ' });
      expect(api.addPair).not.toHaveBeenCalled();
    });

    it('keeps the passkey in the line when the browser refuses the request', async () => {
      signal.mockRejectedValue(new DOMException('x', 'SecurityError'));
      await expect(register(fakeApi(), false)).rejects.toThrow(
        unused('adding the passkey was cancelled')
      );
      expect(signal).toHaveBeenCalledTimes(1);
    });

    it.each<[string, unknown]>([
      ['a lost answer', new NoAnswer()],
      ['a 5xx answer', new VaultError(500, 'vault passkeys failed: OSError')]
    ])(
      'is never sent after %s to the slot request, which may have stored it',
      async (_what, failure) => {
        signal.mockResolvedValue(undefined);
        const api = fakeApi({
          addPasskey: jest.fn().mockRejectedValue(failure)
        });
        await expect(register(api)).rejects.toThrow(MAYBE_ADDED);
        expect(signal).not.toHaveBeenCalled();
      }
    );
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
    'an IP address cannot hold a passkey - open JupyterLab at localhost (when it runs on this computer) or lab.example.com'
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
    // The button alone: the vault file path is in the cog view.
    expect(panel.node.querySelector('.jp-PasskeyVaultPanel-hint')).toBeNull();
    expect(button(panel, 'Create vault')).toBeTruthy();
  });

  it('creates a vault: recovery passphrase twice, the choice of a method, then a passkey', async () => {
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
    answerDialogs({
      'Add unlock method': ['passkey'],
      'Name the new passkey': true,
      'Confirm the new passkey': true
    });
    const api = fakeApi({ status: jest.fn().mockResolvedValue(NEW_VAULT()) });
    const panel = await panelWith(api);
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    expect(mockAskSecret).toHaveBeenCalledWith(
      'Choose a recovery passphrase and store it offline - it opens the vault when no other method can',
      2,
      'Create vault'
    );
    expect(api.init).toHaveBeenCalledWith('recovery words');
    // The choice comes after the vault exists, and before any passkey is made.
    expect(api.init.mock.invocationCallOrder[0]).toBeLessThan(
      mockLaunch.mock.invocationCallOrder[0]
    );
    expect(methodNames(mockLaunch.mock.calls[0][0].options.body.node)).toEqual([
      'Passkey',
      'Password and authenticator app',
      'Later'
    ]);
    // The passphrase just chosen is the proof: no second prompt for it.
    expect(mockAskSecret).toHaveBeenCalledTimes(1);
    expect(api.addPasskey.mock.calls[0][1]).toEqual({
      current: 'recovery words'
    });
    expect(lines(panel)).toEqual([['info', 'Vault created']]);
  });

  it('adds the password and authenticator app at creation, with the passphrase as the proof', async () => {
    mockAskSecret
      .mockResolvedValueOnce({ accepted: true, value: 'recovery words' })
      .mockResolvedValueOnce({ accepted: true, value: 'a long password' });
    answerDialogs(
      {
        'Add unlock method': ['mfa'],
        'Add password and authenticator app': true
      },
      '123456'
    );
    const api = fakeApi({ status: jest.fn().mockResolvedValue(NEW_VAULT()) });
    const panel = await panelWith(api);
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    await flush();
    expect(mockAskSecret).toHaveBeenCalledTimes(2);
    expect(mockAskSecret.mock.calls[1]).toEqual([
      'Enter the new unlock password, at least 12 characters',
      2,
      'Add password and authenticator app',
      { minLength: 12 }
    ]);
    expect(api.addMfa).toHaveBeenCalledWith(
      'a long password',
      expect.any(String),
      '123456',
      { current: 'recovery words' }
    );
    expect(lines(panel)).toEqual([['info', 'Vault created']]);
    mockAskSecret.mockReset();
  });

  it.each([
    ['Later', ['later']],
    ['Escape', []]
  ])(
    'ends the creation on %s: the vault stays created and open, with no failure line',
    async (_, pressed) => {
      const create = jest.fn();
      Object.defineProperty(navigator, 'credentials', {
        value: { get: jest.fn(), create },
        configurable: true
      });
      mockAskSecret.mockResolvedValue({
        accepted: true,
        value: 'recovery words'
      });
      answerDialogs({ 'Add unlock method': pressed });
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValueOnce(NEW_VAULT())
          .mockResolvedValue(status({ slots: [{ type: 'recovery' }] }))
      });
      const panel = await panelWith(api);
      button(panel, 'Create vault').click();
      await flush();
      await flush();
      expect(api.init).toHaveBeenCalledTimes(1);
      expect(mockLaunch).toHaveBeenCalledTimes(1);
      expect(create).not.toHaveBeenCalled();
      expect(api.addPasskey).not.toHaveBeenCalled();
      expect(api.addMfa).not.toHaveBeenCalled();
      expect(lines(panel)).toEqual([['info', 'Vault created']]);
      mockAskSecret.mockReset();
    }
  );

  describe('a method step of Create that stops', () => {
    /**
     * Create with `dialogs` answered. `typed` answers the new unlock password. Returns
     * the line each opening of the choice showed, null for none.
     */
    const creating = async (
      dialogs: Record<string, boolean | string | string[]>,
      over: Record<string, any> = {},
      typed = { accepted: true, value: 'a long password' } as {
        accepted: boolean;
        value: string | null;
      }
    ): Promise<{ api: any; panel: VaultPanel; notes: (string | null)[] }> => {
      mockAskSecret
        .mockResolvedValueOnce({ accepted: true, value: 'recovery words' })
        .mockResolvedValueOnce(typed);
      answerDialogs(dialogs, '123456');
      const api = fakeApi({
        status: jest.fn().mockResolvedValue(NEW_VAULT()),
        ...over
      });
      const panel = await panelWith(api);
      button(panel, 'Create vault').click();
      await flush();
      await flush();
      await flush();
      const notes = mockLaunch.mock.calls
        .filter(([dialog]) => dialog.options.title === 'Add unlock method')
        .map(([dialog]) => {
          const first = dialog.options.body.node.firstChild;
          return first.tagName === 'BUTTON' ? null : first.textContent;
        });
      return { api, panel, notes };
    };

    afterEach(() => {
      mockAskSecret.mockReset();
    });

    it('opens the choice again when the naming dialog is cancelled', async () => {
      const create = jest.fn();
      Object.defineProperty(navigator, 'credentials', {
        value: { get: jest.fn(), create },
        configurable: true
      });
      const { api, panel, notes } = await creating({
        'Add unlock method': ['passkey', 'later']
      });
      expect(notes).toEqual([null, 'Adding the passkey was cancelled.']);
      expect(create).not.toHaveBeenCalled();
      expect(api.init).toHaveBeenCalledTimes(1);
      // The passphrase stays the proof: the second round asks no prompt for it.
      expect(mockAskSecret).toHaveBeenCalledTimes(1);
      expect(lines(panel)).toEqual([['info', 'Vault created']]);
    });

    it('opens the choice again when the passkey prompt is dismissed', async () => {
      Object.defineProperty(navigator, 'credentials', {
        value: {
          get: jest.fn(),
          create: jest
            .fn()
            .mockRejectedValue(new DOMException('x', 'NotAllowedError'))
        },
        configurable: true
      });
      const { notes, panel } = await creating({
        'Add unlock method': ['passkey', 'later'],
        'Name the new passkey': true
      });
      expect(notes).toEqual([
        null,
        'The passkey request was cancelled or not allowed.'
      ]);
      expect(lines(panel)).toEqual([['info', 'Vault created']]);
    });

    it('offers Password and passkey for a passkey with no PRF, names it unused when declined, and the other method works from there', async () => {
      noPrfBrowser();
      const { api, notes } = await creating({
        'Add unlock method': ['passkey', 'mfa'],
        'Name the new passkey': true,
        'Confirm the new passkey': true,
        'Add password and passkey': 'Decline',
        'Add password and authenticator app': true
      });
      expect(notes).toEqual([
        null,
        expect.stringMatching(
          /^No PRF - passkey not added; use another passkey or Password and authenticator app; delete the unused passkey dated .+ UTC\.$/
        )
      ]);
      expect(api.addPasskey).not.toHaveBeenCalled();
      expect(api.addPair).not.toHaveBeenCalled();
      expect(api.addMfa.mock.calls[0][3]).toEqual({
        current: 'recovery words'
      });
    });

    it('opens the choice again when the new unlock password is cancelled', async () => {
      const { api, notes } = await creating(
        { 'Add unlock method': ['mfa', 'later'] },
        {},
        { accepted: false, value: null }
      );
      expect(notes).toEqual([
        null,
        'Adding the password and authenticator app was cancelled.'
      ]);
      expect(api.addMfa).not.toHaveBeenCalled();
      // A cancelled password ends the step before the app dialog opens.
      expect(
        mockLaunch.mock.calls.map(([dialog]) => dialog.options.title)
      ).not.toContain('Add password and authenticator app');
    });

    it('opens the choice again when the app dialog is cancelled', async () => {
      const { api, notes } = await creating({
        'Add unlock method': ['mfa', 'later']
      });
      expect(notes).toEqual([
        null,
        'Adding the password and authenticator app was cancelled.'
      ]);
      expect(api.addMfa).not.toHaveBeenCalled();
    });

    it('opens the choice again with the reason when the server refuses the pair', async () => {
      const { notes } = await creating(
        {
          'Add unlock method': ['mfa', 'later'],
          'Add password and authenticator app': true
        },
        {
          addMfa: jest
            .fn()
            .mockRejectedValue(new VaultError(403, 'wrong recovery passphrase'))
        }
      );
      expect(notes).toEqual([
        null,
        'Wrong recovery passphrase; the authenticator entry is unused - delete it in the app.'
      ]);
    });
  });

  it('draws the sidebar icon in the colour of the other icons only while a vault exists', async () => {
    const none = await panelWith(
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
    // JupyterLab's lockIcon: one shade dimmer, which reads as inactive.
    expect((none.title.icon as any)._options).toBeUndefined();
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValue(status({ unlocked: false, remaining: null }))
    });
    const locked = await panelWith(api);
    expect((locked.title.icon as any)._options.name).toBe(
      'jupyterlab-passkey-extension:vault'
    );
    // A vault that is gone at the next read dims the icon again.
    api.status.mockResolvedValue(
      status({
        initialized: false,
        unlocked: false,
        remaining: null,
        slots: []
      })
    );
    await locked.refresh();
    expect((locked.title.icon as any)._options).toBeUndefined();
  });

  it('says an IP address cannot hold a passkey, and where to open JupyterLab instead', async () => {
    // Jupyter prints http://127.0.0.1:8888 at start; a passkey needs a domain name.
    const ip = '127.0.0.1';
    // The vault has a passkey for HOST: that is where to go.
    const there = `an IP address cannot hold a passkey - open JupyterLab at ${HOST}`;
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
      `An IP address cannot hold a passkey - open JupyterLab at ${HOST}.`
    );
    locked.dispose();
    const panel = await panelWith(fakeApi(), { host: ip });
    (
      panel.node.querySelector(
        'button[title="Vault settings and security"]'
      ) as HTMLElement
    ).click();
    // The dialog that offers the kinds says why a passkey cannot be chosen here.
    button(panel, 'Add unlock method').click();
    expect(mockChoose.mock.calls[0][0].passkey).toEqual({
      unavailable: `An IP address cannot hold a passkey - open JupyterLab at ${HOST}.`
    });
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
      'An IP address cannot hold a passkey - open by hostname over HTTPS, or at localhost.'
    );
    answerDialogs({ 'Add unlock method': ['later'] });
    button(panel, 'Create vault').click();
    await flush();
    await flush();
    expect(api.init).toHaveBeenCalledWith('recovery words');
    expect(create).not.toHaveBeenCalled();
    // Passkey is not offered: the other choices stay.
    expect(methodNames(mockLaunch.mock.calls[0][0].options.body.node)).toEqual([
      'Password and authenticator app',
      'Later'
    ]);
    expect(text(panel)).toContain('Vault created');
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
    expect(lines(panel)).toEqual([]);
    expect(toasts()).toEqual([
      ['error', 'No PRF - this passkey cannot unlock the vault.']
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
            'the vault did not answer (HTTP 403) - reload or restart'
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
    // The failed read's line stays in the panel; the action's outcome is a notification.
    expect(lines(panel)).toEqual([['error', stopped]]);
    expect(toasts()).toEqual([['error', NOT_CONFIRMED]]);
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
      ['error', 'cannot reach the Jupyter server']
    ]);
    expect(toasts()).toEqual([
      ['error', 'No PRF - this passkey cannot unlock the vault.']
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
    const [toast] = toasts();
    expect(toast[0]).toBe('error');
    expect(toast[1]).toMatch(/^The passkey request failed/);
  });

  it('shows a failed Refresh in the panel and leaves an older warning in its notification', async () => {
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
      ['error', 'cannot reach the Jupyter server']
    ]);
    expect(toasts()).toEqual([
      ['warn', 'The passkey request was cancelled or not allowed.']
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
    const notDone = ['error', NOT_CONFIRMED];
    expect(lines(panel)).toEqual([
      ['error', 'cannot reach the Jupyter server']
    ]);
    expect(toasts()).toEqual([notDone]);
    api.status.mockResolvedValue(status());
    await panel.refresh();
    expect(lines(panel)).toEqual([]);
    expect(toasts()).toEqual([notDone]);
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
    // Exactly the line, with no advice appended.
    expect(
      panel.node.querySelector('.jp-PasskeyVaultPanel-hint')?.textContent
    ).toBe('No passkey configured');
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
    expect(mockWarning).toHaveBeenCalledTimes(1);
    expect(mockError).not.toHaveBeenCalled();
    expect(lines(panel)).toEqual([]);
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
    expect(mockAskSecret.mock.calls[0][1]).toBe(1);
    expect(api.unlockRecovery).toHaveBeenCalledWith('recovery words');
  });

  it('reports a refusal as a red notification with no timeout, and no line in any view', async () => {
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
    expect(toasts()).toEqual([['error', 'Wrong recovery passphrase.']]);
    expect(lines(panel)).toEqual([]);
    // A second refusal replaces the first notification: the next action dismisses it.
    button(panel, 'Use recovery passphrase').click();
    await flush();
    await flush();
    expect(mockError).toHaveBeenCalledTimes(2);
    expect(toasts()).toEqual([['error', 'Wrong recovery passphrase.']]);
    // The cog view and Refresh show no line either: the notification is not in the panel.
    (
      panel.node.querySelector(
        'button[title="Vault settings and security"]'
      ) as HTMLElement
    ).click();
    await panel.refresh();
    expect(lines(panel)).toEqual([]);
    expect(text(panel).toLowerCase()).not.toContain(
      'wrong recovery passphrase'
    );
    expect(toasts()).toEqual([['error', 'Wrong recovery passphrase.']]);
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

  it('keeps the status row gutter in one place in every view', async () => {
    const panel = await panelWith(fakeApi());
    const width = (node: HTMLElement, offset: number, client: number) => {
      Object.defineProperty(node, 'offsetWidth', {
        value: offset,
        configurable: true
      });
      Object.defineProperty(node, 'clientWidth', {
        value: client,
        configurable: true
      });
    };
    const probe = panel.node.querySelector(
      '.jp-PasskeyVaultPanel-gutterProbe'
    ) as HTMLElement;
    const viewport = panel.node.querySelector(
      '.jp-PasskeyVaultPanel-viewport'
    ) as HTMLElement;
    // The probe always shows a classic scrollbar: 17px.
    width(probe, 447, 430);
    // The open category scrolls: its own scrollbar is not the one the row takes.
    width(viewport, 447, 430);
    MessageLoop.sendMessage(panel, Widget.ResizeMessage.UnknownSize);
    expect(panel.node.style.getPropertyValue('--jp-passkey-vault-gutter')).toBe(
      '17px'
    );
    // A category that does not scroll takes the same width.
    width(viewport, 447, 447);
    MessageLoop.sendMessage(panel, Widget.ResizeMessage.UnknownSize);
    expect(panel.node.style.getPropertyValue('--jp-passkey-vault-gutter')).toBe(
      '17px'
    );
    // The settings view takes it too: the body's scrollbar is not the row's.
    (
      panel.node.querySelector(
        'button[title="Vault settings and security"]'
      ) as HTMLElement
    ).click();
    MessageLoop.sendMessage(panel, Widget.ResizeMessage.UnknownSize);
    expect(panel.node.style.getPropertyValue('--jp-passkey-vault-gutter')).toBe(
      '17px'
    );
    // An overlay scrollbar takes no width.
    width(probe, 447, 447);
    MessageLoop.sendMessage(panel, Widget.ResizeMessage.UnknownSize);
    expect(panel.node.style.getPropertyValue('--jp-passkey-vault-gutter')).toBe(
      '0px'
    );
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
    // The first category with entries opens; the other stays as its band.
    expect(bands(panel).map(h => h.getAttribute('aria-expanded'))).toEqual([
      'true',
      'false'
    ]);
    const headers = Array.from(
      panel.node.querySelectorAll('.jp-PasskeyVaultPanel-sectionLabel')
    ).map(h => h.textContent);
    expect(headers).toEqual(['home (1)', 'infra (2)']);
    // The filter field is hidden until the header's filter button is pressed, and
    // takes the typing at once.
    const toggle = panel.node.querySelector(
      'button[title="Filter entries"]'
    ) as HTMLButtonElement;
    expect(panel.node.querySelector('input')).toBeNull();
    expect(toggle.getAttribute('aria-pressed')).toBe('false');
    const filter = openFilter(panel);
    expect(document.activeElement).toBe(filter);
    expect(filter.placeholder).toBe('Filter entries...');
    expect(toggle.getAttribute('aria-pressed')).toBe('true');
    expect(toggle.classList.contains('jp-mod-active')).toBe(true);
    filter.value = 'gitlab';
    filter.dispatchEvent(new Event('input'));
    const names = Array.from(
      panel.node.querySelectorAll('.jp-PasskeyVaultPanel-rowName')
    ).map(n => n.textContent);
    expect(names).toEqual(['gitlab/api']);
    // The open category has no match, so the category with matches opens in its place.
    expect(bands(panel).map(h => h.getAttribute('aria-expanded'))).toEqual([
      'true'
    ]);
    // Hiding the field clears the filter: no filter the user cannot see narrows the rows.
    toggle.click();
    expect(panel.node.querySelector('input')).toBeNull();
    expect(toggle.getAttribute('aria-pressed')).toBe('false');
    expect(
      panel.node.querySelectorAll('.jp-PasskeyVaultPanel-rowName')
    ).toHaveLength(3);
    // The category that stayed open keeps its place after the filter is gone.
    expect(bands(panel).map(h => h.getAttribute('aria-expanded'))).toEqual([
      'false',
      'true'
    ]);
    expect(openFilter(panel).value).toBe('');
    // The button belongs to the entry list: out of the list it stays in place, disabled.
    (
      panel.node.querySelector(
        'button[title="Vault settings and security"]'
      ) as HTMLElement
    ).click();
    expect(toggle.disabled).toBe(true);
    expect(toggle.style.visibility).toBe('');
  });

  it('shows each entry as its name, username and last-used age, with no buttons', async () => {
    const panel = await panelWith(fakeApi());
    const rows = Array.from(
      panel.node.querySelectorAll('.jp-PasskeyVaultPanel-rowLine')
    );
    expect(rows.map(r => r.textContent)).toEqual([
      'nas/ugoskonradnever',
      'github/apimenever',
      'gitlab/apikjnever'
    ]);
    expect(rows.every(r => r.tagName === 'BUTTON')).toBe(true);
    expect(rows.every(r => r.querySelector('button') === null)).toBe(true);
    // The panel offers no Copy or Show.
    const labels = Array.from(panel.node.querySelectorAll('button')).map(
      b => b.textContent
    );
    expect(labels.filter(l => /Copy|Show/.test(l ?? ''))).toEqual([]);
  });

  it('shows how long ago each entry was used in three grades: now bright, over a week or never dim, the rest plain', async () => {
    const ago = (ms: number): string => new Date(Date.now() - ms).toISOString();
    const entries = [
      { ...ENTRIES[0], name: 'recent', used: ago(30_000) },
      { ...ENTRIES[1], name: 'minutes', used: ago(5 * 60_000) },
      { ...ENTRIES[2], name: 'stale', used: ago(8 * 86_400_000) },
      { ...ENTRIES[0], name: 'unused', used: '' }
    ];
    const panel = await panelWith(
      fakeApi({ entries: jest.fn().mockResolvedValue(entries) })
    );
    const row = (name: string): HTMLElement =>
      Array.from(
        panel.node.querySelectorAll<HTMLElement>(
          '.jp-PasskeyVaultPanel-rowLine'
        )
      ).find(r => r.dataset.focusKey === `row:${name}`) as HTMLElement;
    expect(text(panel)).toContain('now');
    expect(text(panel)).toContain('5m ago');
    expect(text(panel)).toContain('8d ago');
    expect(text(panel)).toContain('never');
    expect(row('recent').classList.contains('jp-mod-recentlyActive')).toBe(
      true
    );
    expect(row('recent').classList.contains('jp-mod-stale')).toBe(false);
    expect(row('minutes').classList.contains('jp-mod-recentlyActive')).toBe(
      false
    );
    expect(row('minutes').classList.contains('jp-mod-stale')).toBe(false);
    expect(row('stale').classList.contains('jp-mod-stale')).toBe(true);
    expect(row('stale').classList.contains('jp-mod-recentlyActive')).toBe(
      false
    );
    expect(row('unused').classList.contains('jp-mod-stale')).toBe(true);
    expect(row('unused').classList.contains('jp-mod-recentlyActive')).toBe(
      false
    );
  });

  it('keeps the not-confirmed notification when the server returns with the vault locked by its restart, whichever read comes first', async () => {
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
      expect(lines(panel)).toEqual([]);
      expect(toasts()).toEqual([['error', NOT_CONFIRMED]]);
      expect(text(panel)).toContain('Locked');
      panel.dispose();
      clearToasts();
    }
  });

  it('goes on to the choice of a method when a read shows the vault that a lost Create answer wrote', async () => {
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
    answerDialogs({
      'Add unlock method': ['passkey'],
      'Name the new passkey': true,
      'Confirm the new passkey': true
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
    const notDone = ['error', CREATE_NOT_CONFIRMED];
    expect(lines(panel)).toEqual([
      ['error', 'cannot reach the Jupyter server']
    ]);
    expect(toasts()).toEqual([notDone]);
    // The server answers with the vault: its state shows the Create landed. A change
    // read from the server dismisses no notification: the user does, or the next action.
    api.status.mockResolvedValue(status({ slots: [{ type: 'recovery' }] }));
    await (panel as any)._tick();
    expect(lines(panel)).toEqual([]);
    expect(toasts()).toEqual([notDone]);
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
    expect(lines(panel)).toEqual([]);
    expect(toasts()).toEqual([['error', CREATE_NOT_CONFIRMED]]);
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
    expect(lines(panel)).toEqual([]);
    expect(toasts()).toEqual([
      ['error', 'A vault already exists at ~/vault.json.']
    ]);
    mockAskSecret.mockReset();
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
    const filter = openFilter(panel);
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
    const filter = openFilter(panel);
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
    expect(lines(panel)).toEqual([]);
    expect(toasts()).toEqual([['warn', 'nas/ugos was deleted.']]);
  });

  it('shows one failure notification at a time: a refusal outside an action replaces the last one', async () => {
    mockConfirmDelete.mockResolvedValue(true);
    const api = fakeApi({
      remove: jest
        .fn()
        .mockRejectedValue(new VaultError(500, 'vault remove failed: OSError'))
    });
    const panel = await panelWith(api);
    const row = () =>
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement;
    mockViewEntry.mockResolvedValueOnce('delete');
    row().click();
    await flush();
    await flush();
    expect(toasts()).toEqual([['error', 'Vault remove failed: OSError.']]);
    // Deleted from the CLI while its popup was open again: no action runs, and the
    // guard's notification takes the place of the last one.
    mockViewEntry.mockImplementationOnce(async () => {
      api.entries.mockResolvedValue([ENTRIES[0], ENTRIES[1]]);
      await panel.refresh();
      return 'edit';
    });
    row().click();
    await flush();
    await flush();
    expect(mockEditEntry).not.toHaveBeenCalled();
    expect(toasts()).toEqual([['warn', 'nas/ugos was deleted.']]);
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
      ['error', 'cannot reach the Jupyter server']
    ]);
    expect(toasts()).toEqual([
      [
        'error',
        'Change to nas/ugos not confirmed - retry when the server answers.'
      ]
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
    expect(mockViewEntry).toHaveBeenCalledWith(ENTRIES[2], {
      proven: expect.any(Function),
      passkey: expect.any(Function),
      reveal: expect.any(Function),
      typed: ['passphrase']
    });
    expect(mockEditEntry).toHaveBeenCalledWith(
      expect.any(Function),
      ENTRIES[2],
      [],
      ['infra', 'infra', 'home']
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
      expect(toasts()).toEqual([['warn', 'Vault locked - unlock and retry.']]);
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
      expect(toasts()).toEqual([['warn', 'Vault locked - unlock and retry.']]);
      expect(lines(panel)).toEqual([]);
      expect(button(panel, 'Unlock with passkey')).toBeTruthy();
    } finally {
      now.mockRestore();
    }
  });

  it('keeps the lock notification when a read finds the vault unlocked elsewhere, and the next action dismisses it', async () => {
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
      const locked = ['warn', 'Vault locked - unlock and retry.'];
      expect(toasts()).toEqual([locked]);
      // `vault unlock` from the CLI; the notification's click reads again.
      await panel.refresh();
      expect(text(panel)).toContain('nas/ugos');
      expect(toasts()).toEqual([locked]);
      (
        panel.node.querySelector('button[title="Add an entry"]') as HTMLElement
      ).click();
      await flush();
      expect(mockEditEntry).toHaveBeenCalledTimes(1);
      expect(toasts()).toEqual([]);
    } finally {
      now.mockRestore();
    }
  });

  it('drops a failed read after the lock notification, once the vault is unlocked elsewhere', async () => {
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
        expect(toasts()).toEqual([
          ['warn', 'Vault locked - unlock and retry.']
        ]);
        // A Refresh while the server restarts, then `vault unlock` from the CLI.
        await panel.refresh();
        expect(lines(panel)).toEqual([
          ['error', 'cannot reach the Jupyter server']
        ]);
        await (next === 'tick' ? (panel as any)._tick() : panel.refresh());
        expect(lines(panel)).toEqual([]);
        expect(text(panel)).toContain('nas/ugos');
      } finally {
        now.mockRestore();
        panel.dispose();
        clearToasts();
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
    expect(lines(panel)).toEqual([]);
    expect(toasts()).toEqual([['warn', 'Vault locked - unlock and retry.']]);
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
    const how = mockViewEntry.mock.calls[0][1];
    expect(api.revealPassword).not.toHaveBeenCalled();
    const proof = await how.passkey();
    expect(proof).toEqual({ cred_id: 'AAEC', prf: 'CQkJ' });
    expect(await how.reveal(proof)).toBe('s3cret-value');
    expect(api.revealPassword).toHaveBeenCalledWith('nas/ugos', proof);
    // No authenticator app and no unlock password in this vault.
    expect(how.typed).toEqual(['passphrase']);
    expect(text(panel)).not.toContain('s3cret-value');
  });

  it('re-reads the entries as soon as a reveal returns', async () => {
    mockViewEntry.mockResolvedValue(null);
    const api = fakeApi();
    const panel = await panelWith(api);
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    const how = mockViewEntry.mock.calls[0][1];
    const reads = api.entries.mock.calls.length;
    const value = await how.reveal();
    await flush();
    expect(value).toBe('s3cret-value');
    expect(api.entries.mock.calls.length).toBe(reads + 1);
  });

  it('tells the popup whether this tab has just unlocked or proven, and reads plainly then', async () => {
    mockViewEntry.mockResolvedValue(null);
    const api = fakeApi();
    const panel = await panelWith(api);
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    const how = mockViewEntry.mock.calls[0][1];
    // Read at each press of the eye: the minute can end while the popup is open.
    expect(how.proven()).toBe(false);
    api.proven = true;
    expect(how.proven()).toBe(true);
    expect(await how.reveal()).toBe('s3cret-value');
    expect(api.revealPassword).toHaveBeenCalledWith('nas/ugos', undefined);
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
    // On Refresh while the filter field is hidden, on the field while it is shown.
    expect(document.activeElement).toBe(
      panel.node.querySelector('button[title="Refresh"]')
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
      panel.node.querySelectorAll('.jp-PasskeyVaultPanel-sectionLabel')
    ).map(h => h.textContent);
    expect(headers).toEqual(['banking (1)', 'Uncategorised (1)', 'Work (1)']);
  });

  it('opens one category at a time from its band, at the list height', async () => {
    const panel = await panelWith(fakeApi());
    harmonica(panel);
    // The first category with entries opens; every other one is its band only.
    expect(bands(panel).map(h => h.getAttribute('aria-expanded'))).toEqual([
      'true',
      'false'
    ]);
    expect(viewports(panel).map(v => v.style.height)).toEqual(['156px', '0px']);
    // A folded category keeps its rows for the pull preview but leaves the tab order.
    expect(viewports(panel)[0].hasAttribute('inert')).toBe(false);
    expect(viewports(panel)[1].hasAttribute('inert')).toBe(true);
    bands(panel)[1].focus();
    bands(panel)[1].click();
    expect(bands(panel).map(h => h.getAttribute('aria-expanded'))).toEqual([
      'false',
      'true'
    ]);
    expect(viewports(panel).map(v => v.style.height)).toEqual(['0px', '156px']);
    expect(viewports(panel)[0].hasAttribute('inert')).toBe(true);
    expect(viewports(panel)[1].hasAttribute('inert')).toBe(false);
    // The click keeps focus on the band it opened.
    expect(document.activeElement).toBe(bands(panel)[1]);
  });

  it('re-lays out the harmonica when a banner line expires and frees the list', async () => {
    jest.useFakeTimers();
    try {
      const panel = new VaultPanel({
        api: fakeApi(),
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      harmonica(panel);
      const list = panel.node.querySelector(
        '.jp-PasskeyVaultPanel-list'
      ) as HTMLElement;
      // A line stands in the banner, which takes 26 px of the list.
      (panel as any)._message = { text: 'Data key rotated', at: Date.now() };
      Object.defineProperty(list, 'clientHeight', {
        value: 174,
        configurable: true
      });
      (panel as any)._renderBanner();
      expect(viewports(panel)[0].style.height).toBe('130px');
      // The poll drops the expired line: the list grows back to 200 px, and the
      // open category takes the new free space instead of keeping the stale height.
      Object.defineProperty(list, 'clientHeight', {
        value: 200,
        configurable: true
      });
      await jest.advanceTimersByTimeAsync(REFRESH_MS);
      expect(lines(panel)).toEqual([]);
      expect(viewports(panel)[0].style.height).toBe('156px');
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('finishes a fold a banner change lands in, and takes the new free space', async () => {
    jest.useFakeTimers();
    try {
      const panel = await panelWith(fakeApi());
      harmonica(panel);
      const list = panel.node.querySelector(
        '.jp-PasskeyVaultPanel-list'
      ) as HTMLElement;
      const [home] = viewports(panel);
      Object.defineProperty(home, 'scrollHeight', {
        value: 500,
        configurable: true
      });
      home.scrollTop = 500 - 156;
      // One event arms the switch; a fresh gesture after the gap folds.
      wheel(panel, 100);
      await jest.advanceTimersByTimeAsync(300);
      wheel(panel, 100);
      // Mid-fold a banner line takes 26 px of the list.
      await jest.advanceTimersByTimeAsync(100);
      (panel as any)._message = { text: 'Data key rotated', at: Date.now() };
      Object.defineProperty(list, 'clientHeight', {
        value: 174,
        configurable: true
      });
      (panel as any)._renderBanner();
      // One frame later both heights come from the shrunk list: the section stack
      // never stands taller than the space it has, so 156 is gone.
      await jest.advanceTimersByTimeAsync(16);
      expect(
        viewports(panel).reduce(
          (sum, v) => sum + Number.parseInt(v.style.height, 10),
          0
        )
      ).toBeLessThanOrEqual(131);
      await jest.advanceTimersByTimeAsync(400);
      // The fold completed on the entering category, which took the new space.
      expect(bands(panel).map(h => h.getAttribute('aria-expanded'))).toEqual([
        'false',
        'true'
      ]);
      expect(viewports(panel).map(v => v.style.height)).toEqual([
        '0px',
        '130px'
      ]);
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('scrolls the open category, then folds into the next one at its last entry', async () => {
    jest.useFakeTimers();
    try {
      const panel = await panelWith(fakeApi());
      harmonica(panel);
      const [home, infra] = viewports(panel);
      Object.defineProperty(home, 'scrollHeight', {
        value: 500,
        configurable: true
      });
      // The rows scroll inside the open category before anything folds.
      expect(wheel(panel, 100).defaultPrevented).toBe(true);
      expect(home.scrollTop).toBe(100);
      // At the last entry the neighbour eases in 3 px per event.
      home.scrollTop = 500 - 156;
      wheel(panel, 100);
      expect(home.style.height).toBe('153px');
      expect(infra.style.height).toBe('3px');
      // 438 ms of held pull folds: 400 ms later the next category owns the list.
      for (const wait of [100, 100, 100, 100, 40]) {
        await jest.advanceTimersByTimeAsync(wait);
        wheel(panel, 100);
      }
      await jest.advanceTimersByTimeAsync(400);
      expect(bands(panel).map(h => h.getAttribute('aria-expanded'))).toEqual([
        'false',
        'true'
      ]);
      expect(viewports(panel).map(v => v.style.height)).toEqual([
        '0px',
        '156px'
      ]);
      // The settle swallows the carried momentum: no scroll and no new pull.
      const before = infra.scrollTop;
      expect(wheel(panel, -100).defaultPrevented).toBe(true);
      expect(infra.scrollTop).toBe(before);
      expect(viewports(panel).map(v => v.style.height)).toEqual([
        '0px',
        '156px'
      ]);
      // A fresh gesture after the settle folds back up.
      await jest.advanceTimersByTimeAsync(300);
      wheel(panel, -100);
      expect(infra.style.height).toBe('153px');
      await jest.advanceTimersByTimeAsync(300);
      wheel(panel, -100);
      await jest.advanceTimersByTimeAsync(400);
      expect(bands(panel).map(h => h.getAttribute('aria-expanded'))).toEqual([
        'true',
        'false'
      ]);
      expect(viewports(panel).map(v => v.style.height)).toEqual([
        '156px',
        '0px'
      ]);
    } finally {
      jest.useRealTimers();
    }
  });

  it('moves a line-mode wheel delta as lines, not pixels', async () => {
    const panel = await panelWith(fakeApi());
    harmonica(panel);
    const [home] = viewports(panel);
    Object.defineProperty(home, 'scrollHeight', {
      value: 500,
      configurable: true
    });
    // Three lines, as a Firefox notch reports them: 3 x 16 px.
    wheel(panel, 3, WheelEvent.DOM_DELTA_LINE);
    expect(home.scrollTop).toBe(48);
  });

  it('stops the pull preview at 22 px, however far the wheel goes', async () => {
    jest.useFakeTimers();
    try {
      const panel = await panelWith(fakeApi());
      harmonica(panel);
      const [home, infra] = viewports(panel);
      Object.defineProperty(home, 'scrollHeight', {
        value: 500,
        configurable: true
      });
      home.scrollTop = 500 - 156;
      // Ten events would add 30 px; the preview stops at the 22 px cap.
      for (let n = 0; n < 10; n += 1) {
        wheel(panel, 100);
      }
      expect(infra.style.height).toBe('22px');
      // The same 22 px come off the section being left.
      expect(home.style.height).toBe('134px');
    } finally {
      jest.useRealTimers();
    }
  });

  it('pins the hold at 438 ms: 400 ms is no fold, past 438 ms folds', async () => {
    jest.useFakeTimers();
    try {
      const panel = await panelWith(fakeApi());
      harmonica(panel);
      const [home] = viewports(panel);
      Object.defineProperty(home, 'scrollHeight', {
        value: 500,
        configurable: true
      });
      home.scrollTop = 500 - 156;
      wheel(panel, 100);
      // 400 ms of held pull, an event every 100 ms so the gesture stays one burst.
      for (const wait of [100, 100, 100, 100]) {
        await jest.advanceTimersByTimeAsync(wait);
        wheel(panel, 100);
      }
      expect(bands(panel).map(h => h.getAttribute('aria-expanded'))).toEqual([
        'true',
        'false'
      ]);
      // The next event past 438 ms folds; both categories are open during the fold.
      await jest.advanceTimersByTimeAsync(39);
      wheel(panel, 100);
      await jest.advanceTimersByTimeAsync(50);
      expect(bands(panel).map(h => h.getAttribute('aria-expanded'))).toEqual([
        'true',
        'true'
      ]);
      // The fold settles on the next category.
      await jest.advanceTimersByTimeAsync(400);
      expect(bands(panel).map(h => h.getAttribute('aria-expanded'))).toEqual([
        'false',
        'true'
      ]);
    } finally {
      jest.useRealTimers();
    }
  });

  it('springs the pull preview back when the wheel stops, without moving the rows', async () => {
    jest.useFakeTimers();
    try {
      const panel = await panelWith(fakeApi());
      harmonica(panel);
      const [home, infra] = viewports(panel);
      Object.defineProperty(home, 'scrollHeight', {
        value: 500,
        configurable: true
      });
      home.scrollTop = 500 - 156;
      wheel(panel, 100);
      expect(home.style.height).toBe('153px');
      expect(infra.style.height).toBe('3px');
      // After 160 ms idle the damped spring runs and settles under 300 ms.
      await jest.advanceTimersByTimeAsync(160 + 400);
      expect(viewports(panel).map(v => v.style.height)).toEqual([
        '156px',
        '0px'
      ]);
      // Decoration only: the rows never moved.
      expect(home.scrollTop).toBe(500 - 156);
    } finally {
      jest.useRealTimers();
    }
  });

  it('keeps the pull preview for 160 ms idle, then springs it to zero', async () => {
    jest.useFakeTimers();
    try {
      const panel = await panelWith(fakeApi());
      harmonica(panel);
      const [home, infra] = viewports(panel);
      Object.defineProperty(home, 'scrollHeight', {
        value: 500,
        configurable: true
      });
      home.scrollTop = 500 - 156;
      wheel(panel, 100);
      expect(infra.style.height).toBe('3px');
      // Before 160 ms idle the preview stands.
      await jest.advanceTimersByTimeAsync(150);
      expect(home.style.height).toBe('153px');
      expect(infra.style.height).toBe('3px');
      // After it the spring returns the preview ...
      await jest.advanceTimersByTimeAsync(250);
      expect(parseFloat(infra.style.height)).toBeLessThan(3);
      expect(parseFloat(infra.style.height)).toBeGreaterThanOrEqual(0);
      // ... to zero.
      await jest.advanceTimersByTimeAsync(1000);
      expect(viewports(panel).map(v => v.style.height)).toEqual([
        '156px',
        '0px'
      ]);
    } finally {
      jest.useRealTimers();
    }
  });

  it('puts each category, the last included, in its own section with a band and a viewport', async () => {
    const panel = await panelWith(fakeApi());
    const sections = Array.from(
      panel.node.querySelectorAll(
        '.jp-PasskeyVaultPanel-list > .jp-PasskeyVaultPanel-section'
      )
    );
    expect(
      sections.map(section => [
        section.querySelector('.jp-PasskeyVaultPanel-sectionLabel')
          ?.textContent,
        Array.from(
          section.querySelectorAll(
            '.jp-PasskeyVaultPanel-viewport .jp-PasskeyVaultPanel-rowName'
          )
        ).map(name => name.textContent)
      ])
    ).toEqual([
      ['home (1)', ['nas/ugos']],
      ['infra (2)', ['github/api', 'gitlab/api']]
    ]);
    // The band is the section's first child; the rows sit inside the viewport.
    for (const section of sections) {
      expect(
        section.firstElementChild?.classList.contains(
          'jp-PasskeyVaultPanel-sectionHeader'
        )
      ).toBe(true);
      expect(
        section.querySelector('.jp-PasskeyVaultPanel-viewport')?.parentElement
      ).toBe(section);
    }
  });

  it('ignores the old collapsed-state key and opens the first category with entries', async () => {
    window.localStorage.setItem(
      '@stellarshenson/jupyterlab-passkey-extension:vault:collapsed',
      '["home"]'
    );
    const panel = await panelWith(fakeApi());
    expect(bands(panel).map(h => h.getAttribute('aria-expanded'))).toEqual([
      'true',
      'false'
    ]);
    // The old key is neither read nor written any more.
    expect(
      window.localStorage.getItem(
        '@stellarshenson/jupyterlab-passkey-extension:vault:collapsed'
      )
    ).toBe('["home"]');
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

  it('advances an age across the poll, with no Refresh click', async () => {
    jest.useFakeTimers();
    try {
      const used = new Date(Date.now() - 30_000).toISOString();
      const api = fakeApi({
        entries: jest.fn().mockResolvedValue([{ ...ENTRIES[0], used }])
      });
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      const line = panel.node.querySelector(
        '.jp-PasskeyVaultPanel-rowLine'
      ) as HTMLElement;
      const age = line.querySelector(
        '.jp-PasskeyVaultPanel-rowAge'
      ) as HTMLElement;
      expect(age.textContent).toBe('now');
      expect(line.classList.contains('jp-mod-recentlyActive')).toBe(true);
      // The clock moves on as in the Galata test; the poll carries the new age.
      jest.setSystemTime(Date.now() + 60_000);
      await jest.advanceTimersByTimeAsync(2 * REFRESH_MS);
      // The same line, redrawn in place: the list was not rebuilt or re-read.
      expect(panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine')).toBe(
        line
      );
      expect(age.textContent).toBe('2m ago');
      expect(line.classList.contains('jp-mod-recentlyActive')).toBe(false);
      expect(api.entries).toHaveBeenCalledTimes(1);
      panel.dispose();
    } finally {
      jest.useRealTimers();
    }
  });

  it('keeps the ages advancing while the Add form is open', async () => {
    jest.useFakeTimers();
    try {
      const used = new Date(Date.now() - 30_000).toISOString();
      const api = fakeApi({
        entries: jest.fn().mockResolvedValue([{ ...ENTRIES[0], used }])
      });
      const panel = new VaultPanel({
        api,
        openSettings: jest.fn(),
        host: HOST
      });
      Widget.attach(panel, document.body);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await jest.advanceTimersByTimeAsync(0);
      const age = panel.node.querySelector(
        '.jp-PasskeyVaultPanel-rowAge'
      ) as HTMLElement;
      expect(age.textContent).toBe('now');
      let answer: (v: undefined) => void = () => undefined;
      mockEditEntry.mockReturnValue(
        new Promise<undefined>(resolve => (answer = resolve))
      );
      (
        panel.node.querySelector('button[title="Add an entry"]') as HTMLElement
      ).click();
      jest.setSystemTime(Date.now() + 60_000);
      await jest.advanceTimersByTimeAsync(REFRESH_MS);
      expect(panel.node.getAttribute('aria-busy')).toBe('true');
      expect(age.textContent).toBe('1m ago');
      answer(undefined);
      await jest.advanceTimersByTimeAsync(0);
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

    it('keeps the unused-passkey notification of a refused registration when the vault is changed elsewhere', async () => {
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
      addMethod(panel, 'passkey');
      await flush();
      await flush();
      const refused = [
        'warn',
        expect.stringMatching(
          /^The passkey did not open the vault; delete the unused passkey dated .+ UTC\.$/
        )
      ];
      expect(toasts()).toEqual([refused]);
      expect(lines(panel)).toEqual([]);
      api.status.mockResolvedValue(status({ revision: 'changed-by-an-agent' }));
      await (panel as any)._tick();
      expect(toasts()).toEqual([refused]);
    });

    it('says the passkey may have been added, never unused, when the registration gets no answer and the read after it fails', async () => {
      browser();
      mockLaunch.mockResolvedValue({ button: { accept: true } });
      const gone = new NoAnswer();
      const api = fakeApi({ addPasskey: jest.fn().mockRejectedValue(gone) });
      const panel = await openCog(api);
      api.status.mockRejectedValue(gone);
      addMethod(panel, 'passkey');
      await flush();
      await flush();
      await flush();
      // The failed read is the panel's line; the action's outcome is a notification.
      expect(lines(panel)).toEqual([
        ['error', 'cannot reach the Jupyter server']
      ]);
      expect(toasts()).toEqual([['error', sentence(MAYBE_ADDED)]]);
    });

    it('reports a dismissed create prompt in amber, and keeps that notification once the passkeys change', async () => {
      const { create } = browser();
      create.mockRejectedValue(new DOMException('x', 'NotAllowedError'));
      mockLaunch.mockResolvedValue({ button: { accept: true } });
      const api = fakeApi();
      const panel = await openCog(api);
      addMethod(panel, 'passkey');
      await flush();
      await flush();
      const dismissed = [
        'warn',
        'The passkey request was cancelled or not allowed.'
      ];
      expect(toasts()).toEqual([dismissed]);
      expect(lines(panel)).toEqual([]);
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
      expect(toasts()).toEqual([dismissed]);
    });

    it('says a recovery change whose answer was lost is not confirmed, though the server answers again', async () => {
      fakePasskey();
      mockAskSecret.mockResolvedValue({ accepted: true, value: 'new words' });
      const api = fakeApi({
        replaceRecovery: jest.fn().mockRejectedValue(new NoAnswer())
      });
      const panel = await openCog(api);
      button(panel, 'Change').click();
      await flush();
      await flush();
      await flush();
      expect(lines(panel)).toEqual([]);
      expect(toasts()).toEqual([
        [
          'error',
          'Recovery change not confirmed - retry when the server answers.'
        ]
      ]);
    });

    it('says an unconfirmed passkey add, which stopped before the browser made a passkey, is not confirmed and can be done again', async () => {
      const { create } = browser();
      mockAskSecret.mockResolvedValue({
        accepted: true,
        value: 'recovery words'
      });
      const api = noPasskeyHere();
      api.challenge.mockRejectedValue(new NoAnswer());
      const panel = await openCog(api);
      api.status.mockRejectedValue(new NoAnswer());
      addMethod(panel, 'passkey');
      for (let i = 0; i < 6; i++) {
        await flush();
      }
      expect(create).not.toHaveBeenCalled();
      expect(lines(panel)).toEqual([
        ['error', 'cannot reach the Jupyter server']
      ]);
      expect(toasts()).toEqual([
        ['error', 'Passkey add not confirmed - retry when the server answers.']
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
      addMethod(panel, 'passkey');
      // Once the kind is chosen the proof request is the first step, before any
      // other dialog, and the line says the browser's sign-in is that proof, not the
      // new passkey.
      await Promise.resolve();
      await Promise.resolve();
      expect(order).toEqual(['get']);
      expect(text(panel)).toContain(
        'First confirm with a passkey you already have'
      );
      await flush();
      await flush();
      // The naming dialog gives the browser the fresh click it needs to create the
      // passkey.
      expect(order).toEqual([
        'get',
        'Name the new passkey',
        'create',
        'Confirm the new passkey',
        'get'
      ]);
      expect(mockAskSecret).not.toHaveBeenCalled();
      expect(api.addPasskey.mock.calls[0][1]).toEqual({
        cred_id: 'AAEC',
        prf: 'CQkJ'
      });
      expect(text(panel)).toContain('Passkey added');
    });

    it('registers with the recovery passphrase on a hostname with no passkey, asked before the browser creates one', async () => {
      const order: string[] = [];
      browser(order);
      mockLaunch.mockImplementation(async (dialog: any) => {
        order.push(dialog.options.title);
        return { button: { accept: true } };
      });
      mockAskSecret.mockImplementation(async () => {
        order.push('passphrase');
        return { accepted: true, value: 'recovery words' };
      });
      const api = noPasskeyHere();
      const panel = await openCog(api);
      addMethod(panel, 'passkey');
      await flush();
      await flush();
      expect(order).toEqual([
        'passphrase',
        'Name the new passkey',
        'create',
        'Confirm the new passkey',
        'get'
      ]);
      expect(mockAskSecret).toHaveBeenCalledWith(
        'Enter the current recovery passphrase',
        1,
        'Add passkey',
        undefined,
        undefined
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
      answerDialogs({
        'Name the new passkey': true,
        'Confirm the new passkey': true
      });
      mockAskSecret.mockImplementation(async (prompt: string) => {
        order.push(prompt);
        return { accepted: true, value: 'recovery words' };
      });
      const api = fakeApi();
      const panel = await openCog(api);
      addMethod(panel, 'passkey');
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
        addMethod(panel, 'passkey');
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

    it.each([
      // The passkey's own failure, before any passphrase.
      ['a passkey error', 'AbortError'],
      // A dismissed passkey, then the recovery passphrase, whose check gets no answer.
      ['a proof check with no answer', 'NotAllowedError']
    ])(
      'leaves no hint in the panel after a proof that fails with %s',
      async (_cause, getError) => {
        const { get, create } = browser();
        get.mockRejectedValueOnce(new DOMException('x', getError));
        mockAskSecret.mockResolvedValue({
          accepted: true,
          value: 'recovery words'
        });
        const api = fakeApi({
          checkRecovery: jest.fn().mockRejectedValue(new NoAnswer())
        });
        const panel = await openCog(api);
        addMethod(panel, 'passkey');
        await flush();
        await flush();
        expect(create).not.toHaveBeenCalled();
        expect(lines(panel)).toEqual([]);
        expect(toasts().map(([kind]) => kind)).toEqual(['error']);
        mockAskSecret.mockReset();
      }
    );

    it('names the passkey in its own dialog, then confirms it in a dialog with no field', async () => {
      browser();
      const bodies: Record<string, any> = {};
      mockLaunch.mockImplementation(async (dialog: any) => {
        const { title, body } = dialog.options;
        bodies[title] = body;
        if (title === 'Name the new passkey') {
          body.input.value = ' Work laptop ';
        }
        return { button: { accept: true } };
      });
      const api = fakeApi();
      const panel = await openCog(api);
      addMethod(panel, 'passkey');
      await flush();
      await flush();
      // The naming dialog says what comes next and holds the only field.
      const naming = bodies['Name the new passkey'].node as HTMLElement;
      expect(naming.textContent).toContain(
        'Passkey accepted - your browser creates the new passkey next'
      );
      expect(naming.querySelectorAll('input')).toHaveLength(1);
      // The confirm dialog is text: the name chosen, and nothing to type.
      expect(bodies['Confirm the new passkey']).toBe(
        'Passkey "Work laptop" created - confirm it to derive the vault key'
      );
      expect(api.addPasskey.mock.calls[0][0].label).toBe('Work laptop');
    });

    it('creates no passkey when the naming dialog is cancelled', async () => {
      const { create } = browser();
      answerDialogs({});
      const api = fakeApi();
      const panel = await openCog(api);
      addMethod(panel, 'passkey');
      await flush();
      await flush();
      expect(create).not.toHaveBeenCalled();
      expect(api.addPasskey).not.toHaveBeenCalled();
      expect(lines(panel)).toEqual([]);
    });

    it('says the created passkey is unused when the registration is cancelled at the confirm step', async () => {
      browser();
      answerDialogs({ 'Name the new passkey': true });
      const api = fakeApi();
      const panel = await openCog(api);
      addMethod(panel, 'passkey');
      await flush();
      await flush();
      expect(api.addPasskey).not.toHaveBeenCalled();
      expect(lines(panel)).toEqual([]);
      expect(toasts()).toEqual([
        [
          'warn',
          expect.stringMatching(
            /^Adding the passkey was cancelled; delete the unused passkey dated .+ UTC\.$/
          )
        ]
      ]);
    });

    it('says a refused proof left the created passkey unused', async () => {
      browser();
      answerDialogs({
        'Name the new passkey': true,
        'Confirm the new passkey': true
      });
      mockAskSecret.mockResolvedValue({ accepted: true, value: 'wrong' });
      const api = noPasskeyHere();
      api.addPasskey = jest
        .fn()
        .mockRejectedValue(new VaultError(403, 'wrong recovery passphrase'));
      const panel = await openCog(api);
      addMethod(panel, 'passkey');
      await flush();
      await flush();
      expect(toasts()).toEqual([
        [
          'warn',
          expect.stringMatching(
            /^Wrong recovery passphrase; delete the unused passkey dated \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC\.$/
          )
        ]
      ]);
    });

    it('keeps the unused passkey in the notification when the reason is too long for both', async () => {
      browser();
      answerDialogs({
        'Name the new passkey': true,
        'Confirm the new passkey': true
      });
      mockAskSecret.mockResolvedValue({ accepted: true, value: 'words' });
      const api = noPasskeyHere();
      api.addPasskey = jest
        .fn()
        .mockRejectedValue(new VaultError(403, TOO_MANY_CODES));
      const panel = await openCog(api);
      addMethod(panel, 'passkey');
      await flush();
      await flush();
      // toasts() also holds it to 140 characters.
      expect(toasts()).toEqual([
        [
          'warn',
          expect.stringMatching(
            /^Too many wrong codes - .+…; delete the unused passkey dated \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC\.$/
          )
        ]
      ]);
    });

    it("shows the page's own line for an answer that is not the vault's whole, with the unused passkey", async () => {
      browser();
      answerDialogs({
        'Name the new passkey': true,
        'Confirm the new passkey': true
      });
      mockAskSecret.mockResolvedValue({ accepted: true, value: 'words' });
      const forbidden = await notTheVault(403);
      const api = noPasskeyHere();
      api.addPasskey = jest.fn().mockRejectedValue(forbidden);
      const panel = await openCog(api);
      addMethod(panel, 'passkey');
      await flush();
      await flush();
      // The reason as the notification starts it; toasts() holds it to 140 characters.
      const reason = sentence(forbidden.message).slice(0, -1);
      expect(toasts()).toEqual([
        [
          'warn',
          expect.stringMatching(
            new RegExp(
              `^${literally(reason)}; delete the unused passkey dated \\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} UTC\\.$`
            )
          )
        ]
      ]);
    });

    it('shows its longest line whole in a notification: Password and passkey declined, the ways in, and the unused passkey', async () => {
      noPrfBrowser();
      answerDialogs({
        'Name the new passkey': true,
        'Confirm the new passkey': true,
        'Add password and passkey': 'Decline'
      });
      mockAskSecret.mockResolvedValue({
        accepted: true,
        value: 'recovery words'
      });
      const api = noPasskeyHere();
      const panel = await openCog(api);
      addMethod(panel, 'passkey');
      for (let i = 0; i < 6; i++) {
        await flush();
      }
      expect(api.addPair).not.toHaveBeenCalled();
      const [[kind, line], ...more] = toasts();
      expect(more).toEqual([]);
      expect(kind).toBe('warn');
      // What happened, then the ways in, then the passkey to delete: a retry on the
      // same authenticator would fail again, so none is advised.
      expect(line).toMatch(
        /^No PRF - passkey not added; use another passkey or Password and authenticator app; delete the unused passkey dated \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC\.$/
      );
      expect(lines(panel)).toEqual([]);
    });

    describe('a wrong recovery passphrase', () => {
      const PROMPT = 'Enter the current recovery passphrase';
      const WRONG = new VaultError(403, 'wrong recovery passphrase');
      const MFA = 'Add password and authenticator app';

      /** Each proof dialog answers with the next of `typed`, null for Cancel. */
      function answerProof(...typed: (string | null)[]): void {
        mockAskSecret.mockImplementation(async (prompt: string) => {
          if (prompt !== PROMPT) {
            return { accepted: true, value: 'a new secret of some length' };
          }
          const value = typed.shift() ?? null;
          return { accepted: value !== null, value };
        });
      }

      /** Title and line of every proof dialog opened so far. */
      const proofDialogs = () =>
        mockAskSecret.mock.calls
          .filter(call => call[0] === PROMPT)
          .map(call => [call[2], call[4]]);

      async function settle(): Promise<void> {
        for (let i = 0; i < 6; i++) {
          await flush();
        }
      }

      afterEach(() => mockAskSecret.mockReset());

      it.each<[string, (panel: VaultPanel) => void, string, number]>([
        ['Add passkey', panel => addMethod(panel, 'passkey'), 'addPasskey', 1],
        [MFA, panel => addMethod(panel, 'mfa'), 'addMfa', 0],
        [
          'Change recovery passphrase',
          panel => button(panel, 'Change').click(),
          'replaceRecovery',
          0
        ],
        [
          'Rotate data key',
          panel => button(panel, 'Rotate data key').click(),
          'rotate',
          0
        ]
      ])(
        '%s opens the same dialog with the line and goes on only with the right one',
        async (title, start, finalRequest, creates) => {
          const { get, create } = browser();
          answerDialogs(
            {
              'Name the new passkey': true,
              'Confirm the new passkey': true,
              [MFA]: true
            },
            '123456'
          );
          const api = noPasskeyHere();
          api.checkRecovery.mockRejectedValue(WRONG);
          const panel = await openCog(api);

          // Wrong, then Cancel: nothing past the proof ran, and no line is left.
          answerProof('wrong', null);
          start(panel);
          await settle();
          expect(proofDialogs()).toEqual([
            [title, undefined],
            [title, 'Wrong recovery passphrase']
          ]);
          expect(create).not.toHaveBeenCalled();
          expect(get).not.toHaveBeenCalled();
          expect(mockLaunch).not.toHaveBeenCalled();
          expect(api[finalRequest]).not.toHaveBeenCalled();
          expect(lines(panel)).toEqual([]);

          // Wrong, then right: the final request carries the right one.
          mockAskSecret.mockClear();
          api.checkRecovery
            .mockReset()
            .mockRejectedValueOnce(WRONG)
            .mockResolvedValue(undefined);
          answerProof('wrong', 'right');
          start(panel);
          await settle();
          expect(api.checkRecovery.mock.calls).toEqual([['wrong'], ['right']]);
          expect(create).toHaveBeenCalledTimes(creates);
          expect(api[finalRequest]).toHaveBeenCalledTimes(1);
          expect(api[finalRequest].mock.lastCall).toContainEqual({
            current: 'right'
          });
        }
      );

      it('gets its line on an authenticator with no PRF, whose flow never reaches a final request', async () => {
        const { get, create } = browser();
        get.mockResolvedValue({
          rawId: new Uint8Array([9]).buffer,
          getClientExtensionResults: () => ({})
        });
        const api = noPasskeyHere();
        api.checkRecovery.mockRejectedValue(WRONG);
        const panel = await openCog(api);
        answerProof('wrong', null);
        addMethod(panel, 'passkey');
        await settle();
        expect(proofDialogs()[1]).toEqual([
          'Add passkey',
          'Wrong recovery passphrase'
        ]);
        expect(create).not.toHaveBeenCalled();
      });

      it('stops on any other failure of the check, with its line and no second dialog', async () => {
        const { create } = browser();
        const api = noPasskeyHere();
        api.checkRecovery.mockRejectedValue(
          new VaultError(500, 'vault proof-check failed: disk')
        );
        const panel = await openCog(api);
        answerProof('right');
        addMethod(panel, 'passkey');
        await settle();
        expect(proofDialogs()).toHaveLength(1);
        expect(create).not.toHaveBeenCalled();
        expect(lines(panel)).toEqual([]);
        expect(toasts()).toEqual([
          ['error', 'Vault proof-check failed: disk.']
        ]);
      });
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
      button(panel, 'Confirm').click();
      now.mockRestore();
      await flush();
      expect(api.removePasskey).toHaveBeenCalledWith('AAEC');
      expect(button(panel, 'Add unlock method')).toBeTruthy();
    });

    it('lapses an armed Remove 5 s after arming, and never acts from the lapse', async () => {
      jest.useFakeTimers();
      try {
        const api = fakeApi();
        const panel = await openCog(api);
        button(panel, 'Remove').click();
        expect(button(panel, 'Confirm')).toBeTruthy();
        // One millisecond short of the lapse the arm still stands.
        await jest.advanceTimersByTimeAsync(4999);
        expect(button(panel, 'Confirm')).toBeTruthy();
        // Past 5 s the button reads its normal label again, and nothing ran.
        await jest.advanceTimersByTimeAsync(2);
        expect(button(panel, 'Remove').classList).not.toContain(
          'jp-mod-confirm'
        );
        expect(api.removePasskey).not.toHaveBeenCalled();
        // Armed again, a confirming click after ARM_DELAY_MS runs the action.
        button(panel, 'Remove').click();
        await jest.advanceTimersByTimeAsync(ARM_DELAY_MS + 100);
        button(panel, 'Confirm').click();
        await jest.advanceTimersByTimeAsync(0);
        expect(api.removePasskey).toHaveBeenCalledWith('AAEC');
        panel.dispose();
      } finally {
        jest.useRealTimers();
      }
    });

    it('lists every unlock method in one section, each with its one action', async () => {
      const api = fakeApi({
        status: jest.fn().mockResolvedValue(
          status({
            slots: [
              { type: 'recovery' },
              {
                type: 'passkey',
                cred_id: 'AAEC',
                rp_id: 'other.example.com',
                prf_salt: 'c2FsdA',
                label: 'laptop',
                created: '2026-09-26T10:00:00Z'
              },
              { type: 'password', created: '2026-10-02T10:00:00Z' }
            ],
            authenticator: { created: '2026-10-02T10:00:00Z' }
          })
        )
      });
      const panel = await openCog(api);
      const rows = Array.from(
        panel.node.querySelectorAll<HTMLElement>('[data-method]')
      );
      expect(rows.map(row => [row.dataset.method, row.textContent])).toEqual([
        [
          'passkey',
          'laptopPasskey, added 2026-09-26 10:00 UTC on other.example.comRemove'
        ],
        [
          'mfa',
          'Password and authenticator appAdded 2026-10-02 10:00 UTCRemove'
        ],
        ['recovery', 'Recovery passphraseChange']
      ]);
      // The recovery passphrase is changed, never removed; its button says which.
      expect(button(panel, 'Change').getAttribute('aria-label')).toBe(
        'Change recovery passphrase'
      );
      expect(
        Array.from(
          panel.node.querySelectorAll('.jp-PasskeyVaultPanel-sectionHeader')
        ).map(header => header.textContent)
      ).toEqual(['Security', 'Unlock methods', 'Data key', 'Settings']);
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
      button(panel, 'Change').click();
      await flush();
      await flush();
      await flush();
      const refused = ['error', 'The passkey did not open the vault.'];
      expect(toasts()).toEqual([refused]);
      // An agent edits an entry: nothing else would show the change was refused.
      api.status.mockResolvedValue(status({ revision: 'changed-by-an-agent' }));
      await (panel as any)._tick();
      expect(toasts()).toEqual([refused]);
      expect(lines(panel)).toEqual([]);
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
      button(panel, 'Change').click();
      await flush();
      await flush();
      await flush();
      expect(lines(panel)).toEqual([
        ['error', 'cannot reach the Jupyter server']
      ]);
      expect(toasts()).toEqual([
        [
          'error',
          'Recovery change not confirmed - retry when the server answers.'
        ]
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
      button(panel, 'Change').click();
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

    it('leaves the settings view when the panel is hidden', async () => {
      const panel = await openCog();
      const cog = panel.node.querySelector(
        'button[title="Vault settings and security"]'
      ) as HTMLElement;
      expect(cog.classList.contains('jp-mod-active')).toBe(true);
      expect(text(panel)).toContain('Add unlock method');
      MessageLoop.sendMessage(panel, Widget.Msg.BeforeHide);
      MessageLoop.sendMessage(panel, Widget.Msg.AfterShow);
      await flush();
      // Shown again, the panel is in its main view: the entries, the cog not pressed.
      expect(cog.classList.contains('jp-mod-active')).toBe(false);
      expect(text(panel)).not.toContain('Add unlock method');
      expect(text(panel)).toContain('github/api');
      MessageLoop.sendMessage(panel, Widget.Msg.BeforeHide);
    });

    it('keeps every header button in place in the cog view, disabling + and Filter', async () => {
      const panel = await openCog(fakeApi());
      const button = (title: string) =>
        panel.node.querySelector(
          `button[title="${title}"]`
        ) as HTMLButtonElement;
      const titles = [
        'Lock the vault',
        'Add an entry',
        'Filter entries',
        'Refresh',
        'Vault settings and security'
      ];
      for (const title of titles) {
        expect(button(title).style.display).toBe('');
        expect(button(title).style.visibility).toBe('');
      }
      expect(button('Add an entry').disabled).toBe(true);
      expect(button('Filter entries').disabled).toBe(true);
      expect(button('Lock the vault').disabled).toBe(false);
      expect(button('Refresh').disabled).toBe(false);
      expect(button('Vault settings and security').disabled).toBe(false);
    });

    it('does not return focus to the disabled + in the cog view', async () => {
      const panel = await openCog(fakeApi());
      const add = panel.node.querySelector(
        'button[title="Add an entry"]'
      ) as HTMLElement;
      (panel as any)._restoreFocus(add.dataset.focusKey);
      const refresh = panel.node.querySelector(
        'button[title="Refresh"]'
      ) as HTMLElement;
      expect(document.activeElement).not.toBe(add);
      expect(document.activeElement).toBe(refresh);
    });

    it('keeps every header button in place and disables the locked ones', async () => {
      const panel = await panelWith(
        fakeApi({
          status: jest
            .fn()
            .mockResolvedValue(status({ unlocked: false, remaining: null }))
        })
      );
      const button = (title: string) =>
        panel.node.querySelector(
          `button[title="${title}"]`
        ) as HTMLButtonElement;
      const titles = [
        'Lock the vault',
        'Add an entry',
        'Filter entries',
        'Refresh',
        'Vault settings and security'
      ];
      for (const title of titles) {
        expect(button(title).style.display).toBe('');
        expect(button(title).style.visibility).toBe('');
      }
      expect(button('Lock the vault').disabled).toBe(true);
      expect(button('Add an entry').disabled).toBe(true);
      expect(button('Filter entries').disabled).toBe(true);
      expect(button('Refresh').disabled).toBe(false);
      expect(button('Vault settings and security').disabled).toBe(false);
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
      button(panel, 'Change').click();
      // The passkey request runs from the click, before any dialog.
      expect(get).toHaveBeenCalled();
      expect(mockAskSecret).not.toHaveBeenCalled();
      await flush();
      await flush();
      expect(mockAskSecret).toHaveBeenCalledWith(
        expect.any(String),
        2,
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

    it('changes nothing when the prompt hands back no new passphrase', async () => {
      fakePasskey();
      // askSecret hands back no value when the field is left empty or the dialog is
      // cancelled.
      mockAskSecret.mockResolvedValue({ accepted: true, value: null });
      const api = fakeApi();
      const panel = await openCog(api);
      button(panel, 'Change').click();
      await flush();
      await flush();
      expect(api.replaceRecovery).not.toHaveBeenCalled();
      expect(text(panel)).not.toContain('Recovery passphrase changed');
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
      button(panel, 'Change').click();
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
      button(panel, 'Change').click();
      await flush();
      await flush();
      expect(mockAskSecret.mock.calls[0]).toEqual([
        'Enter the current recovery passphrase',
        1,
        'Change recovery passphrase',
        undefined,
        undefined
      ]);
      expect(api.replaceRecovery).toHaveBeenCalledWith('new words', {
        current: 'old words'
      });
    });

    it('offers the authenticator code for a recovery change on an unlocked vault', async () => {
      mockAskSecret.mockResolvedValue({ accepted: true, value: 'new words' });
      answerDialogs({ 'Change recovery passphrase': true }, '123456');
      const api = fakeApi({
        status: jest.fn().mockResolvedValue(
          status({
            slots: [{ type: 'recovery' }],
            authenticator: { created: '2026-10-02T10:00:00Z' }
          })
        )
      });
      const panel = await openCog(api);
      button(panel, 'Change').click();
      await flush();
      await flush();
      expect(mockLaunch.mock.calls[0][0].options.body.node.textContent).toBe(
        'Enter a code of the authenticator app'
      );
      expect(api.replaceRecovery).toHaveBeenCalledWith('new words', {
        code: '123456'
      });
    });

    it('says nothing changed when the recovery dialog is cancelled', async () => {
      fakePasskey();
      mockAskSecret.mockResolvedValue({ accepted: false, value: null });
      const api = fakeApi();
      const panel = await openCog(api);
      button(panel, 'Change').click();
      await flush();
      await flush();
      expect(api.replaceRecovery).not.toHaveBeenCalled();
      expect(text(panel)).not.toContain('Recovery passphrase changed');
    });

    it('shows the values in effect read-only, the data key, and opens the Settings Editor', async () => {
      const openSettings = jest.fn();
      const panel = await openCog(fakeApi(), openSettings);
      expect(text(panel)).toContain('Unlock duration4h');
      expect(text(panel)).toContain('Reveal window60s');
      expect(text(panel)).toContain('Shortest unlock password12 characters');
      expect(text(panel)).toContain('Key encryptionArgon2id (1), scrypt (0)');
      expect(text(panel)).toContain('Key rotation365 days');
      // The data key: its creation date, its age, its period and whether it is due.
      expect(text(panel)).toContain('Created2026-10-11 10:00 UTC');
      expect(text(panel)).toContain('Age10 days');
      expect(text(panel)).toContain('Period365 days');
      expect(text(panel)).toContain('Rotation dueno');
      expect(button(panel, 'Rotate data key')).toBeTruthy();
      // Read-only: the server's configuration file holds the policy.
      expect(
        panel.node.querySelectorAll('.jp-PasskeyVaultPanel-section input')
      ).toHaveLength(0);
      expect(text(panel)).toContain(
        'Vault file~/.local/share/jupyterlab-passkey/vault.json'
      );
      // One element per part, so a line breaks after a slash.
      expect(
        Array.from(
          panel.node.querySelectorAll('.jp-PasskeyVaultPanel-pathValue > span')
        ).map(part => part.textContent)
      ).toEqual([
        '~/',
        '.local/',
        'share/',
        'jupyterlab-passkey/',
        'vault.json'
      ]);
      button(panel, 'Open settings').click();
      expect(openSettings).toHaveBeenCalled();
    });

    it('names scrypt while an older slot still uses it, and turns a zero rotation period into off', async () => {
      const panel = await openCog(
        fakeApi({
          status: jest.fn().mockResolvedValue(
            status({
              slots: [
                { type: 'recovery', kdf: 'scrypt' },
                {
                  type: 'password',
                  kdf: 'argon2id',
                  created: '2026-10-02T10:00:00Z'
                }
              ],
              settings: {
                unlock_minutes: 240,
                password_min_length: 12,
                reveal_seconds: 60,
                rotate_days: 0
              },
              rotation: {
                created: '2026-10-11T10:00:00Z',
                age_days: 10,
                period_days: 0,
                due: false
              }
            })
          )
        })
      );
      expect(text(panel)).toContain('Key encryptionArgon2id (1), scrypt (1)');
      expect(text(panel)).toContain('Key rotationoff');
    });

    it('says a version-1 vault gets its data key at the next unlock', async () => {
      const panel = await openCog(
        fakeApi({
          status: jest.fn().mockResolvedValue(
            status({
              rotation: {
                created: null,
                age_days: null,
                period_days: 365,
                due: false
              }
            })
          )
        })
      );
      expect(text(panel)).toContain('Createdat the next unlock');
      expect(text(panel)).toContain('Agenone yet');
      expect(text(panel)).toContain('Period365 days');
    });

    it('rotates the data key with the proof the panel asks for, then shows the new date', async () => {
      fakePasskey();
      const api = fakeApi();
      const panel = await openCog(api);
      api.status.mockResolvedValue(
        status({
          rotation: {
            created: '2026-10-21T09:00:00Z',
            age_days: 0,
            period_days: 365,
            due: false
          }
        })
      );
      button(panel, 'Rotate data key').click();
      await flush();
      await flush();
      expect(mockAskSecret).not.toHaveBeenCalled();
      expect(api.rotate).toHaveBeenCalledWith({ cred_id: 'AAEC', prf: 'CQkJ' });
      expect(text(panel)).toContain('Data key rotated');
      expect(text(panel)).toContain('Created2026-10-21 09:00 UTC');
    });

    it('rotates with the recovery passphrase when no passkey matches, never a code', async () => {
      mockAskSecret.mockResolvedValue({ accepted: true, value: 'words' });
      answerDialogs({});
      const api = fakeApi({
        status: jest.fn().mockResolvedValue(
          status({
            slots: [{ type: 'recovery' }],
            authenticator: { created: '2026-10-02T10:00:00Z' }
          })
        )
      });
      const panel = await openCog(api);
      button(panel, 'Rotate data key').click();
      await flush();
      await flush();
      // A code holds no key, so the proof chooser offers none for a rotation.
      expect(mockLaunch).not.toHaveBeenCalled();
      expect(mockAskSecret).toHaveBeenCalledWith(
        'Enter the current recovery passphrase',
        1,
        'Rotate data key',
        undefined,
        undefined
      );
      expect(api.rotate).toHaveBeenCalledWith({ current: 'words' });
    });

    it('asks the proof of a rotation and of a recovery change inside the reveal window', async () => {
      mockAskSecret.mockResolvedValue({ accepted: true, value: 'words' });
      answerDialogs({});
      const api = fakeApi({
        proven: true,
        status: jest
          .fn()
          .mockResolvedValue(status({ slots: [{ type: 'recovery' }] }))
      });
      const panel = await openCog(api);
      button(panel, 'Rotate data key').click();
      await flush();
      await flush();
      expect(api.rotate).toHaveBeenCalledWith({ current: 'words' });
      button(panel, 'Change').click();
      await flush();
      await flush();
      expect(api.replaceRecovery).toHaveBeenCalledWith('words', {
        current: 'words'
      });
    });

    it('offers rotation on an unlocked vault, and asks for an unlock when it is due and locked', async () => {
      const locked = status({
        unlocked: false,
        remaining: null,
        rotation: {
          created: '2026-10-11T10:00:00Z',
          age_days: 375,
          period_days: 365,
          due: true
        }
      });
      const panel = await openCog(
        fakeApi({ status: jest.fn().mockResolvedValue(locked) })
      );
      expect(text(panel)).toContain('Rotation dueyes');
      expect(text(panel)).toContain('Unlock the vault to rotate the data key.');
      expect(() => button(panel, 'Rotate data key')).toThrow();
    });

    it('asks for an unlock only to remove an unlock method on a locked vault', async () => {
      const panel = await openCog(
        fakeApi({
          status: jest
            .fn()
            .mockResolvedValue(status({ unlocked: false, remaining: null }))
        })
      );
      expect(text(panel)).toContain(
        'Unlock the vault to remove an unlock method.'
      );
      expect(
        Array.from(panel.node.querySelectorAll('button')).some(
          b => b.textContent === 'Remove'
        )
      ).toBe(false);
      // A proof, not an unlock, is what a new unlock method needs.
      expect(button(panel, 'Add unlock method')).toBeTruthy();
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

  it('leaves the last entries drawn when a read after them fails', async () => {
    const api = fakeApi();
    const panel = await panelWith(api);
    api.status.mockRejectedValueOnce(new NoAnswer());
    await panel.refresh();
    expect(text(panel)).toContain('github/api');
    expect(lines(panel)).toEqual([
      ['error', 'cannot reach the Jupyter server']
    ]);
    panel.dispose();
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
      const filter = openFilter(panel);
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
      (panel as any)._message = { text: 'Data key rotated', at: Date.now() };
      (panel as any)._render();
      // Unlocked from the CLI: a read sees it, and the old line goes before it expires.
      await panel.refresh();
      expect(text(panel)).toContain('Unlocked');
      expect(lines(panel)).toEqual([]);
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

  it('asks the password in one field with nothing to tick, in Add and in Edit', () => {
    for (const entry of [undefined, ENTRIES[0]]) {
      const form = new EntryForm(async () => 'x', entry);
      expect(form.node.querySelectorAll('input[type="password"]')).toHaveLength(
        1
      );
      expect(form.node.querySelector('input[type="checkbox"]')).toBeNull();
      form.password.value = 'typed by hand';
      form.password.dispatchEvent(new Event('input'));
      expect(form.getValue().password).toBe('typed by hand');
    }
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

  it('offers each category in use once and sorted, and returns a typed one as typed', () => {
    const form = new EntryForm(
      async () => 'x',
      undefined,
      [],
      ['infra', '', 'home', 'infra']
    );
    Widget.attach(form, document.body);
    const toggle = form.node.querySelector(
      'button[aria-label="Existing categories"]'
    ) as HTMLButtonElement;
    toggle.click();
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    const menu = document.querySelector(
      '.jp-PasskeyVaultForm-categoryMenu'
    ) as HTMLElement;
    expect(
      Array.from(menu.querySelectorAll('.lm-Menu-itemLabel')).map(
        l => l.textContent
      )
    ).toEqual(['home', 'infra']);
    // Down to the first category, then Enter chooses it.
    menu.dispatchEvent(new KeyboardEvent('keydown', { keyCode: 40 }));
    menu.dispatchEvent(new KeyboardEvent('keydown', { keyCode: 13 }));
    expect(form.category.value).toBe('home');
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(document.querySelector('.jp-PasskeyVaultForm-categoryMenu')).toBe(
      null
    );
    // An item focused without the arrow keys, as a screen reader can, is the one Enter chooses.
    toggle.click();
    const second = document.querySelectorAll(
      '.jp-PasskeyVaultForm-categoryMenu .lm-Menu-item'
    )[1] as HTMLElement;
    second.focus();
    second.dispatchEvent(
      new KeyboardEvent('keydown', { keyCode: 13, bubbles: true })
    );
    expect(form.category.value).toBe('infra');
    // A category the menu does not list is the value as typed.
    form.category.value = 'travel';
    expect(form.getValue().category).toBe('travel');
    // Focus moved out of the open list without a pointer press, as a screen reader
    // can: keys in the other fields do their own work and choose no category.
    toggle.click();
    menu.dispatchEvent(new KeyboardEvent('keydown', { keyCode: 40 }));
    form.username.focus();
    const typed = new KeyboardEvent('keydown', {
      key: 'a',
      keyCode: 65,
      bubbles: true,
      cancelable: true
    });
    form.username.dispatchEvent(typed);
    expect(typed.defaultPrevented).toBe(false);
    form.notes.focus();
    form.notes.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Enter', keyCode: 13, bubbles: true })
    );
    expect(form.category.value).toBe('travel');
    expect(form.getValue().category).toBe('travel');
    form.dispose();
    // A vault with no category has none to offer.
    const empty = new EntryForm(async () => 'x');
    expect(
      (
        empty.node.querySelector(
          'button[aria-label="Existing categories"]'
        ) as HTMLButtonElement
      ).disabled
    ).toBe(true);
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

  it('confirms on the Delete button, translated or not', async () => {
    // The pressed button is the one of the dialog whose label reads Delete.
    mockLaunch.mockImplementation(async (dialog: any) => ({
      button: dialog.options.buttons[1]
    }));
    await expect(confirmDelete('nas/ugos')).resolves.toBe(true);

    setTranslator({ load: () => ({ __: (s: string) => `<${s}>` }) } as any);
    try {
      await expect(confirmDelete('nas/ugos')).resolves.toBe(true);
    } finally {
      setTranslator(null);
    }
  });
});

describe('the password and authenticator app', () => {
  const PASSWORD = {
    type: 'password' as const,
    created: '2026-10-02T10:00:00Z'
  };
  const APP = { created: '2026-10-02T10:00:00Z' };
  const NO_PASSKEY = [{ type: 'recovery' as const }];
  const ADD = 'Add password and authenticator app';
  const UNLOCK = 'Unlock with password';
  const withMfa = (over: Partial<IStatus> = {}) =>
    status({
      slots: [...status().slots, PASSWORD],
      authenticator: APP,
      ...over
    });
  const setupKey = (body: any): string =>
    body.node.querySelector('.jp-PasskeyVaultForm-setupKey').textContent;

  async function openCog(api: any): Promise<VaultPanel> {
    const panel = await panelWith(api);
    (
      panel.node.querySelector(
        'button[title="Vault settings and security"]'
      ) as HTMLElement
    ).click();
    return panel;
  }

  async function settle(): Promise<void> {
    for (let i = 0; i < 4; i++) {
      await flush();
    }
  }

  it('makes a setup key of 160 bits in base32, and the address a QR code carries', () => {
    const key = newSetupKey();
    expect(key).toMatch(/^[A-Z2-7]{32}$/);
    expect(newSetupKey()).not.toBe(key);
    expect(otpauthUri('ABCD2345', 'lab.example.com')).toBe(
      'otpauth://totp/JupyterLab%20vault%3Alab.example.com?secret=ABCD2345&issuer=JupyterLab%20vault'
    );
  });

  it('unlocks from the locked view with the password, then a code; the main button where this hostname has no passkey', async () => {
    mockAskSecret.mockResolvedValue({ accepted: true, value: 'everyday' });
    answerDialogs({ 'Unlock vault': true }, '123456');
    const locked = withMfa({ unlocked: false, remaining: null });
    const api = fakeApi({ status: jest.fn().mockResolvedValue(locked) });
    const panel = await panelWith(api);
    // Beside a passkey it is the second way in.
    expect(button(panel, 'Unlock with passkey').classList).toContain(
      'jp-mod-accept'
    );
    expect(button(panel, UNLOCK).classList).not.toContain('jp-mod-accept');
    button(panel, UNLOCK).click();
    await settle();
    expect(mockAskSecret).toHaveBeenCalledWith(
      'Enter the unlock password',
      1,
      'Unlock vault'
    );
    // The code's dialog: one field, Cancel and Unlock.
    const { options } = mockLaunch.mock.calls[0][0];
    expect(options.body.node.textContent).toBe(
      'Enter the code the authenticator app shows'
    );
    expect(options.buttons.map((b: any) => b.label)).toEqual([
      undefined,
      'Unlock'
    ]);
    expect(api.unlockPassword).toHaveBeenCalledWith('everyday', '123456');
    // The code is asked last: it stays right for less than a minute.
    expect(mockAskSecret.mock.invocationCallOrder[0]).toBeLessThan(
      mockLaunch.mock.invocationCallOrder[0]
    );
    panel.dispose();

    api.status.mockResolvedValue({
      ...locked,
      slots: [{ type: 'recovery' }, PASSWORD]
    });
    const other = await panelWith(api);
    expect(button(other, UNLOCK).classList).toContain('jp-mod-accept');
    // A cancelled password asks no code; a cancelled code sends nothing.
    api.unlockPassword.mockClear();
    mockLaunch.mockClear();
    mockAskSecret.mockResolvedValue({ accepted: false, value: null });
    button(other, UNLOCK).click();
    await settle();
    expect(mockLaunch).not.toHaveBeenCalled();
    mockAskSecret.mockResolvedValue({ accepted: true, value: 'everyday' });
    answerDialogs({});
    button(other, UNLOCK).click();
    await settle();
    expect(mockLaunch).toHaveBeenCalledTimes(1);
    expect(api.unlockPassword).not.toHaveBeenCalled();
    // No button without a password slot.
    api.status.mockResolvedValue(status({ unlocked: false, remaining: null }));
    await other.refresh();
    expect(() => button(other, UNLOCK)).toThrow();
  });

  it('adds the two from the cog view: the password twice, then a proof, then the app', async () => {
    const get = fakePasskey();
    mockAskSecret.mockResolvedValue({
      accepted: true,
      value: 'an everyday one'
    });
    const api = fakeApi({
      status: jest.fn().mockResolvedValue(
        status({
          authenticator: null,
          settings: {
            unlock_minutes: 240,
            password_min_length: 16,
            reveal_seconds: 60,
            rotate_days: 365
          }
        })
      )
    });
    const panel = await openCog(api);
    answerDialogs({ [ADD]: true }, '222222');
    api.status.mockResolvedValue(withMfa());
    addMethod(panel, 'mfa');
    // Nothing is added yet, so both methods can be chosen.
    expect(mockChoose).toHaveBeenCalledWith({ passkey: {}, mfa: {} });
    await settle();
    expect(mockAskSecret).toHaveBeenCalledWith(
      'Enter the new unlock password, at least 16 characters',
      2,
      ADD,
      { minLength: 16 }
    );
    expect(api.addMfa).toHaveBeenCalledWith(
      'an everyday one',
      expect.stringMatching(/^[A-Z2-7]{32}$/),
      '222222',
      { cred_id: 'AAEC', prf: 'CQkJ' }
    );
    // The password, then the proof, then the app: its code is typed last.
    const [typed, proven, scanned] = [mockAskSecret, get, mockLaunch].map(
      mock => mock.mock.invocationCallOrder[0]
    );
    expect(typed).toBeLessThan(proven);
    expect(proven).toBeLessThan(scanned);
    expect(mockLaunch.mock.calls[0][0].options.title).toBe(ADD);
    expect(text(panel)).toContain('Password and authenticator app added');
    // The re-read shows the method, to the minute, and a second one cannot be chosen.
    expect(text(panel)).toContain(
      'Password and authenticator appAdded 2026-10-02 10:00 UTC'
    );
    button(panel, 'Add unlock method').click();
    expect(mockChoose.mock.lastCall[0].mfa).toEqual({
      unavailable: 'Added 2026-10-02 10:00 UTC. Remove it to add another.'
    });
    // One Remove, in two steps, removes both.
    const remove = () =>
      panel.node.querySelector('[data-focus-key="mfa"]') as HTMLButtonElement;
    const now = jest.spyOn(Date, 'now').mockReturnValue(1000);
    remove().click();
    expect(remove().textContent).toBe('Confirm');
    now.mockReturnValue(1000 + ARM_DELAY_MS);
    remove().click();
    now.mockRestore();
    await flush();
    expect(api.removeMfa).toHaveBeenCalledTimes(1);
    expect(text(panel)).toContain('Password and authenticator app removed');
  });

  it('shows the longest not-confirmed line whole in a notification', async () => {
    fakePasskey();
    mockAskSecret.mockResolvedValue({
      accepted: true,
      value: 'a long password'
    });
    const gone = new NoAnswer();
    const api = fakeApi({
      status: jest.fn().mockResolvedValue(status({ authenticator: null })),
      addMfa: jest.fn().mockRejectedValue(gone)
    });
    const panel = await openCog(api);
    answerDialogs({ [ADD]: true }, '222222');
    api.status.mockRejectedValue(gone);
    addMethod(panel, 'mfa');
    await settle();
    expect(toasts()).toEqual([
      [
        'error',
        'Password and app add not confirmed - retry when the server answers.'
      ]
    ]);
  });

  it.each([403, 404] as const)(
    "keeps the app's unused entry whole in a notification after the page's own line for a %i that is not the vault's",
    async code => {
      fakePasskey();
      mockAskSecret.mockResolvedValue({
        accepted: true,
        value: 'a long password'
      });
      const refused = await notTheVault(code);
      // The proxy page's line is short now; a long reason keeps the cut exercised.
      const long = new VaultError(
        refused.status,
        `${refused.message} ${'the proxy page answered instead. '.repeat(3)}`
      );
      const api = fakeApi({
        status: jest.fn().mockResolvedValue(status({ authenticator: null })),
        addMfa: jest.fn().mockRejectedValue(long)
      });
      const panel = await openCog(api);
      answerDialogs({ [ADD]: true }, '222222');
      addMethod(panel, 'mfa');
      await settle();
      // toasts() holds it to 140 characters: the reason is cut, never the clause.
      const [[kind, line], ...more] = toasts();
      expect(more).toEqual([]);
      expect(kind).toBe('error');
      expect(line).toMatch(
        /…; the authenticator entry is unused - delete it in the app\.$/
      );
      expect(line).toHaveLength(TOAST_LIMIT);
      const cut = line.slice(0, line.indexOf('…'));
      expect(sentence(long.message).startsWith(cut)).toBe(true);
    }
  );

  it('adds nothing when the password dialog, the proof or the app dialog is cancelled', async () => {
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValue(status({ slots: NO_PASSKEY, authenticator: null }))
    });
    const panel = await openCog(api);
    const no = { accepted: false, value: null };
    const yes = { accepted: true, value: 'an everyday one' };
    // The password dialog.
    mockAskSecret.mockResolvedValue(no);
    addMethod(panel, 'mfa');
    await settle();
    expect(mockAskSecret).toHaveBeenCalledTimes(1);
    // The proof: with no passkey for this hostname, the recovery passphrase.
    mockAskSecret.mockResolvedValueOnce(yes).mockResolvedValueOnce(no);
    addMethod(panel, 'mfa');
    await settle();
    expect(mockAskSecret).toHaveBeenCalledTimes(3);
    expect(mockLaunch).not.toHaveBeenCalled();
    // The app's dialog.
    mockAskSecret.mockResolvedValue(yes);
    answerDialogs({});
    addMethod(panel, 'mfa');
    await settle();
    expect(mockLaunch).toHaveBeenCalledTimes(1);
    expect(api.addMfa).not.toHaveBeenCalled();
  });

  it('asks a passkey first; a code next when the action takes one; then the recovery passphrase', async () => {
    mockAskSecret.mockResolvedValue({ accepted: true, value: 'words' });
    const get = fakePasskey();
    const api = fakeApi();
    expect(
      await askProof(api, status({ authenticator: APP }), HOST, 'T', true)
    ).toEqual({ cred_id: 'AAEC', prf: 'CQkJ' });
    expect(mockLaunch).not.toHaveBeenCalled();

    // No passkey for this hostname: a code of the authenticator app, for the actions
    // that take one (add passkey, add MFA, replace recovery), on an unlocked vault.
    const unlocked = status({ slots: NO_PASSKEY, authenticator: APP });
    answerDialogs({ T: true }, '123456');
    expect(await askProof(api, unlocked, HOST, 'T', true)).toEqual({
      code: '123456'
    });

    // The code dialog offers the recovery passphrase instead.
    answerDialogs({ T: 'Use recovery passphrase' });
    expect(await askProof(api, unlocked, HOST, 'T', true)).toEqual({
      current: 'words'
    });
    expect(mockAskSecret).toHaveBeenLastCalledWith(
      'Enter the current recovery passphrase',
      1,
      'T',
      undefined,
      undefined
    );

    // A rotation passes no `code`: the same vault asks the passphrase at once.
    mockLaunch.mockClear();
    expect(await askProof(api, unlocked, HOST, 'T')).toEqual({
      current: 'words'
    });
    expect(mockLaunch).not.toHaveBeenCalled();

    // A locked vault offers no code: a code proves only through an unlocked vault.
    const locked = status({
      slots: NO_PASSKEY,
      authenticator: APP,
      unlocked: false,
      remaining: null
    });
    expect(await askProof(api, locked, HOST, 'T', true)).toEqual({
      current: 'words'
    });
    expect(mockLaunch).not.toHaveBeenCalled();

    // Cancelled: null.
    answerDialogs({});
    expect(await askProof(api, unlocked, HOST, 'T', true)).toBeNull();

    // A passkey that does not answer leaves the code, and the prompt says why.
    get.mockRejectedValue(new DOMException('x', 'NotAllowedError'));
    answerDialogs({ T: true }, '123456');
    expect(
      await askProof(api, status({ authenticator: APP }), HOST, 'T', true)
    ).toEqual({ code: '123456' });
    expect(mockLaunch.mock.lastCall[0].options.body.node.textContent).toBe(
      'No passkey answered - enter a code of the authenticator app instead'
    );
  });

  it.each<[string, VaultError]>([
    ['a lost answer', new NoAnswer()],
    ['a 5xx answer', new VaultError(500, 'vault proof-check failed: disk')],
    [
      "a 403 that is not the vault's",
      new VaultError(403, 'the vault did not answer (HTTP 403)')
    ],
    ['a missing vault', new VaultError(400, 'no vault at /tmp/vault.json')]
  ])('asks no second time after %s', async (_what, failure) => {
    mockAskSecret
      .mockResolvedValueOnce({ accepted: true, value: 'words' })
      .mockResolvedValue({ accepted: false, value: null });
    const api = fakeApi({
      checkRecovery: jest.fn().mockRejectedValue(failure)
    });
    await expect(
      askProof(api, status({ slots: NO_PASSKEY }), HOST, 'T')
    ).rejects.toBe(failure);
    expect(mockAskSecret).toHaveBeenCalledTimes(1);
  });

  it('checks neither a passkey nor a code: a check would use the code up', async () => {
    fakePasskey();
    const api = fakeApi();
    await askProof(api, status({ authenticator: APP }), HOST, 'T', true);
    answerDialogs({ T: true }, '123456');
    await askProof(
      api,
      status({ slots: NO_PASSKEY, authenticator: APP }),
      HOST,
      'T',
      true
    );
    expect(api.checkRecovery).not.toHaveBeenCalled();
  });

  it('adds the app whose setup key the dialog shows, with the password; a wrong code opens it again with the same key', async () => {
    const api = fakeApi({
      addMfa: jest
        .fn()
        .mockRejectedValueOnce(new VaultError(403, 'wrong code'))
        .mockResolvedValue(undefined)
    });
    const proof = { current: 'words' };
    answerDialogs({ [ADD]: true }, '111111');
    expect(await registerMfa(api, 'everyday', proof, HOST, ADD)).toBe(true);
    const [first, second] = mockLaunch.mock.calls.map(c => c[0].options.body);
    // In groups of four, as an app shows a key.
    expect(setupKey(first)).toMatch(/^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);
    expect(setupKey(second)).toBe(setupKey(first));
    expect(first.node.querySelector('svg[role="img"] path')).not.toBeNull();
    expect(first.node.textContent).not.toContain('Wrong code');
    expect(second.node.textContent).toContain(
      'Wrong code. Enter the code the app shows now.'
    );
    const key = setupKey(first).replace(/ /g, '');
    expect(api.addMfa.mock.calls).toEqual([
      ['everyday', key, '111111', proof],
      ['everyday', key, '111111', proof]
    ]);

    // Cancelled: nothing is sent. Any other refusal is the caller's to report.
    api.addMfa.mockClear();
    answerDialogs({});
    expect(await registerMfa(api, 'everyday', proof, HOST, ADD)).toBe(false);
    expect(api.addMfa).not.toHaveBeenCalled();
    // The server refused after the app took the setup key: the line names the app's
    // entry, which gives codes of a key the vault does not hold.
    api.addMfa.mockRejectedValue(
      new VaultError(403, 'wrong recovery passphrase')
    );
    answerDialogs({ [ADD]: true }, '111111');
    const refused = await registerMfa(api, 'everyday', proof, HOST, ADD).catch(
      e => e
    );
    expect(refused).toBeInstanceOf(VaultError);
    expect(refused.status).toBe(403);
    expect(refused.message).toBe(
      'wrong recovery passphrase; the authenticator entry is unused - delete it in the app'
    );
    expect(api.addMfa).toHaveBeenCalledTimes(1);
    // A lost answer and a 5xx answer are not refusals: the two may have been added,
    // so nothing is said about the app's entry.
    for (const unknown of [
      new NoAnswer(),
      new VaultError(504, 'the vault did not answer (HTTP 504)')
    ]) {
      api.addMfa.mockRejectedValue(unknown);
      answerDialogs({ [ADD]: true }, '111111');
      await expect(registerMfa(api, 'everyday', proof, HOST, ADD)).rejects.toBe(
        unknown
      );
    }
  });

  it('offers no Remove on a locked vault, and still offers to add a method', async () => {
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValue(withMfa({ unlocked: false, remaining: null }))
    });
    const panel = await openCog(api);
    expect(panel.node.querySelector('[data-focus-key="mfa"]')).toBeNull();
    expect(text(panel)).toContain(
      'Unlock the vault to remove an unlock method.'
    );
    // A proof, not an unlock, adds a method: offered locked as well.
    expect(button(panel, 'Add unlock method')).toBeTruthy();
  });

  it('redraws when the two are added or removed elsewhere', async () => {
    const api = fakeApi({
      status: jest.fn().mockResolvedValue(status({ authenticator: null }))
    });
    const panel = await openCog(api);
    api.status.mockResolvedValue(withMfa());
    await (panel as any)._tick();
    expect(text(panel)).toContain(
      'Password and authenticator appAdded 2026-10-02 10:00 UTC'
    );
  });

  it('takes no code for a password an earlier build added without an app, and says which half is there', async () => {
    // 1.1.28 to 1.1.31 added the password and the app apart from each other.
    mockAskSecret.mockResolvedValue({ accepted: true, value: 'everyday' });
    const lone = status({
      slots: [...status().slots, PASSWORD],
      authenticator: null
    });
    const api = fakeApi({
      status: jest
        .fn()
        .mockResolvedValue({ ...lone, unlocked: false, remaining: null })
    });
    const panel = await panelWith(api);
    button(panel, UNLOCK).click();
    await settle();
    expect(mockLaunch).not.toHaveBeenCalled();
    expect(api.unlockPassword).toHaveBeenCalledWith('everyday', undefined);
    panel.dispose();

    api.status.mockResolvedValue(lone);
    const cog = await openCog(api);
    const row = () =>
      (cog.node.querySelector('[data-method="mfa"]') as HTMLElement)
        .textContent;
    expect(row()).toBe(
      'Password and authenticator appPassword only, added 2026-10-02 10:00 UTCRemove'
    );
    api.status.mockResolvedValue(status({ authenticator: APP }));
    await cog.refresh();
    expect(row()).toBe(
      'Password and authenticator appApp only, added 2026-10-02 10:00 UTCRemove'
    );
    // Neither half can be completed: the method is removed and added again.
    button(cog, 'Add unlock method').click();
    expect(mockChoose.mock.lastCall[0].mfa).toEqual({
      unavailable: 'Added 2026-10-02 10:00 UTC. Remove it to add another.'
    });
  });

  it('puts the unlock password before the recovery passphrase in the popup, after a code', async () => {
    mockViewEntry.mockResolvedValue(null);
    const api = fakeApi({ status: jest.fn().mockResolvedValue(withMfa()) });
    const panel = await panelWith(api);
    (
      panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
    ).click();
    await flush();
    expect(mockViewEntry.mock.calls[0][1].typed).toEqual([
      'code',
      'password',
      'passphrase'
    ]);
  });
});

describe('the dialog that offers the unlock methods', () => {
  const { chooseUnlockMethod } = jest.requireActual('../vault/dialogs');
  const methods = (dialog: any): HTMLButtonElement[] =>
    Array.from(dialog.options.body.node.querySelectorAll('button'));
  const options = (dialog: any): [string, string, boolean][] =>
    methods(dialog).map(button => {
      const [name, help] = Array.from(button.children);
      // The button is named by the method and described by the line under it.
      expect(button.getAttribute('aria-labelledby')).toBe(name.id);
      expect(button.getAttribute('aria-describedby')).toBe(help.id);
      return [
        name.textContent as string,
        help.textContent as string,
        button.disabled
      ];
    });
  const press = (dialog: any, kind: string): void =>
    (
      dialog.options.body.node.querySelector(
        `button[data-method="${kind}"]`
      ) as HTMLButtonElement
    ).click();

  it('offers a passkey, and a password with an authenticator app, as buttons with one line each', async () => {
    answerDialogs({});
    // Cancelled: no method.
    expect(await chooseUnlockMethod({ passkey: {}, mfa: {} })).toBeNull();
    const dialog = mockLaunch.mock.calls[0][0];
    expect(dialog.options.title).toBe('Add unlock method');
    // Cancel is the dialog's only button of its own: a press on a method chooses it.
    expect(dialog.options.buttons).toEqual([{ accept: false }]);
    expect(dialog.options.focusNodeSelector).toBe(
      '.jp-PasskeyVaultForm-choice:enabled'
    );
    expect(options(dialog)).toEqual([
      ['Passkey', 'Fingerprint, face, PIN or security key.', false],
      [
        'Password and authenticator app',
        'A password, then a 6-digit code from your phone.',
        false
      ]
    ]);
  });

  it('says why a method cannot be chosen, and returns the method pressed', async () => {
    mockLaunch.mockImplementation(async (dialog: any) => {
      // A method that cannot be added is a disabled button: a press does nothing.
      press(dialog, 'mfa');
      expect(dialog.rejected).toBe(false);
      // A press on a method chooses it and closes the dialog.
      press(dialog, 'passkey');
      expect(dialog.rejected).toBe(true);
      return { button: { accept: false } };
    });
    const states = {
      passkey: {},
      mfa: {
        unavailable: 'Added 2026-10-02 10:00 UTC. Remove it to add another.'
      }
    };
    expect(await chooseUnlockMethod(states)).toBe('passkey');
    expect(options(mockLaunch.mock.calls[0][0])).toEqual([
      ['Passkey', 'Fingerprint, face, PIN or security key.', false],
      [
        'Password and authenticator app',
        'Added 2026-10-02 10:00 UTC. Remove it to add another.',
        true
      ]
    ]);
  });

  it('offers the set-up choice in order, with one line each, and Later in place of Cancel', async () => {
    answerDialogs({});
    await chooseUnlockMethod({ passkey: {}, mfa: {}, later: {} });
    const dialog = mockLaunch.mock.calls[0][0];
    expect(dialog.options.buttons).toEqual([]);
    expect(options(dialog)).toEqual([
      ['Passkey', 'Fingerprint, face, PIN or security key.', false],
      [
        'Password and authenticator app',
        'A password, then a 6-digit code from your phone.',
        false
      ],
      ['Later', 'Only the recovery passphrase opens the vault for now.', false]
    ]);
  });

  it('returns Later when it is pressed', async () => {
    mockLaunch.mockImplementation(async (dialog: any) => {
      press(dialog, 'later');
      return { button: { accept: false } };
    });
    expect(await chooseUnlockMethod({ mfa: {}, later: {} })).toBe('later');
  });

  it('shows the reason of a dialog opened again above the buttons, read with the focused one', async () => {
    answerDialogs({});
    await chooseUnlockMethod(
      { mfa: {}, later: {} },
      undefined,
      'Adding the passkey was cancelled.'
    );
    const { body } = mockLaunch.mock.calls[0][0].options;
    const line = body.node.firstChild;
    expect(line.textContent).toBe('Adding the passkey was cancelled.');
    expect(line.dataset.state).toBe('mismatch');
    expect(
      methods(mockLaunch.mock.calls[0][0])[0].getAttribute('aria-describedby')
    ).toContain(line.id);
  });

  it('keeps the arrow keys from Dialog with no footer button, where they would throw', async () => {
    const reached = async (states: any): Promise<boolean> => {
      let hit = false;
      mockLaunch.mockImplementation(async (dialog: any) => {
        const body = dialog.options.body;
        Widget.attach(body, document.body);
        const reachedDialog = (): void => {
          hit = true;
        };
        body.node.addEventListener('keydown', reachedDialog, true);
        methods(dialog)[0].dispatchEvent(
          new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true })
        );
        body.dispose();
        return { button: { accept: false } };
      });
      await chooseUnlockMethod(states);
      return hit;
    };
    expect(await reached({ mfa: {}, later: {} })).toBe(false);
    // With a Cancel button the arrow keys reach it, as Dialog intends.
    expect(await reached({ passkey: {}, mfa: {} })).toBe(true);
  });

  it('lets Enter on a method press it instead of the default dialog button', async () => {
    mockLaunch.mockImplementation(async (dialog: any) => {
      const body = dialog.options.body;
      Widget.attach(body, document.body);
      const reachedDialog = jest.fn();
      body.node.addEventListener('keydown', reachedDialog, true);
      methods(dialog)[0].dispatchEvent(
        new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })
      );
      expect(reachedDialog).not.toHaveBeenCalled();
      body.dispose();
      return { button: { accept: false } };
    });
    await chooseUnlockMethod({ passkey: {}, mfa: {} });
    expect(mockLaunch).toHaveBeenCalledTimes(1);
  });
});

describe('viewEntry', () => {
  // The panel tests replace viewEntry; this is the function itself.
  const { viewEntry } = jest.requireActual('../vault/dialogs');
  const how = {
    proven: () => false,
    passkey: jest.fn(),
    reveal: jest.fn(),
    typed: ['passphrase']
  };

  it('tells the pressed button by its label, translated or not', async () => {
    const pressed = async (label: string) => {
      answerDialogs({ 'nas/ugos': label });
      return viewEntry(ENTRIES[2], how);
    };
    expect(await pressed('Edit')).toBe('edit');
    expect(await pressed('Delete')).toBe('delete');
    expect(await pressed('Close')).toBeNull();

    setTranslator({ load: () => ({ __: (s: string) => `<${s}>` }) } as any);
    try {
      expect(await pressed('<Edit>')).toBe('edit');
      expect(await pressed('<Delete>')).toBe('delete');
      expect(await pressed('<Close>')).toBeNull();
    } finally {
      setTranslator(null);
    }
  });
});

describe('EntryView', () => {
  const SECRET = 's3cret-value';

  const PASSKEY: Proof = { cred_id: 'AAEC', prf: 'CQkJ' };

  /** A popup that asks a proof and whose passkey answers, unless `over` says otherwise. */
  function view(
    reveal: (proof?: Proof) => Promise<string>,
    over: Record<string, any> = {}
  ): EntryView {
    const v = new EntryView(ENTRIES[2], {
      proven: () => false,
      passkey: async () => PASSKEY,
      reveal,
      typed: ['passphrase'],
      ...over
    });
    Widget.attach(v, document.body);
    return v;
  }

  const line = (v: EntryView) =>
    v.node.querySelector('.jp-PasskeyVaultForm-help')!.textContent;
  const noPasskey = () =>
    Promise.reject(new VaultError(0, 'no passkey was added for this host'));

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

  it('asks no proof while this tab has just unlocked or proven', async () => {
    const reveal = jest.fn().mockResolvedValue(SECRET);
    const passkey = jest.fn();
    const v = view(reveal, { proven: () => true, passkey });
    v.eye.click();
    await flush();
    expect(passkey).not.toHaveBeenCalled();
    expect(reveal).toHaveBeenCalledWith(undefined);
    expect(v.password.value).toBe(SECRET);
    expect(v.node.querySelector('.jp-PasskeyVaultForm-proof')).toBeNull();
    expect(line(v)).toBe('');
    v.dispose();
  });

  it('says why when the read with no proof is refused, and asks a proof once the minute is over', async () => {
    let proven = true;
    const reveal = jest
      .fn()
      .mockRejectedValueOnce(new VaultError(423, 'the vault is locked'))
      .mockResolvedValue(SECRET);
    const v = view(reveal, { proven: () => proven });
    v.eye.click();
    await flush();
    expect(line(v)).toBe('The password was not shown: the vault is locked');
    expect(v.password.value).not.toContain(SECRET);
    proven = false;
    v.eye.click();
    await flush();
    expect(reveal).toHaveBeenLastCalledWith(PASSKEY);
    expect(v.password.value).toBe(SECRET);
    v.dispose();
  });

  it('shows it is waiting from the click on the eye until the passkey request ends', async () => {
    const waiting = (v: EntryView) => ({
      busy: v.eye.getAttribute('aria-busy'),
      spinner: v.eye.querySelector('.jp-PasskeyVaultForm-spinner') !== null,
      line: v.node.querySelector('.jp-PasskeyVaultForm-help')!.textContent
    });
    const idle = { busy: null, spinner: false };
    // The wait covers the passkey request and the server's answer to its proof.
    const endings: [(end: any) => void, () => Promise<string>, string][] = [
      [end => end.resolve(PASSKEY), async () => SECRET, ''],
      [
        end => end.reject(new DOMException('x', 'NotAllowedError')),
        async () => SECRET,
        'No passkey answered. Enter the recovery passphrase to show the password.'
      ],
      [
        end => end.resolve(PASSKEY),
        () => Promise.reject(new VaultError(403, 'refused')),
        'The password was not shown: refused'
      ]
    ];
    for (const [finish, reveal, line] of endings) {
      const end: any = {};
      const v = view(reveal, {
        passkey: () =>
          new Promise<Proof>((resolve, reject) =>
            Object.assign(end, { resolve, reject })
          )
      });
      expect(waiting(v)).toEqual({ ...idle, line: '' });
      v.eye.click();
      expect(waiting(v)).toEqual({
        busy: 'true',
        spinner: true,
        line: 'Waiting for your passkey'
      });
      finish(end);
      await flush();
      expect(waiting(v)).toEqual({ ...idle, line });
      // The eye has its icon again: open after a password, crossed otherwise.
      expect(v.eye.querySelector('[data-icon]')).not.toBeNull();
      v.dispose();
    }
  });

  it('says so when the entry has no password', async () => {
    const v = view(jest.fn().mockResolvedValue(''));
    v.eye.click();
    await flush();
    expect(v.node.textContent).toContain('This entry has no password');
    v.dispose();
  });

  it('keeps the dots, says no error and asks the other proof when the passkey prompt is cancelled', async () => {
    const reveal = jest.fn();
    const v = view(reveal, {
      passkey: () => Promise.reject(new DOMException('x', 'NotAllowedError'))
    });
    v.eye.click();
    await flush();
    expect(v.password.type).toBe('password');
    expect(reveal).not.toHaveBeenCalled();
    expect(line(v)).toBe(
      'No passkey answered. Enter the recovery passphrase to show the password.'
    );
    expect(v.proof.isConnected).toBe(true);
    v.dispose();
  });

  it('asks the recovery passphrase in a row of its own when this hostname has no passkey', async () => {
    const reveal = jest.fn().mockResolvedValue(SECRET);
    const v = view(reveal, { passkey: noPasskey });
    // Until the eye is pressed the popup holds no field to type in.
    expect(v.proof.isConnected).toBe(false);
    v.eye.click();
    await flush();
    expect(line(v)).toBe(
      'No passkey was added for this host. Enter the recovery passphrase to show the password.'
    );
    expect(v.proof.type).toBe('password');
    expect(v.proof.getAttribute('aria-label')).toBe('Recovery passphrase');
    expect(document.activeElement).toBe(v.proof);
    // The only proof to type: no link to another.
    expect(v.useNext.isConnected).toBe(false);
    // An empty field sends nothing.
    v.prove.click();
    await flush();
    expect(reveal).not.toHaveBeenCalled();
    v.proof.value = 'the passphrase';
    v.prove.click();
    await flush();
    expect(reveal).toHaveBeenCalledWith({ current: 'the passphrase' });
    expect(v.password.value).toBe(SECRET);
    expect(v.password.type).toBe('text');
    // The row is gone and holds nothing; the eye hides and shows from here on.
    expect(v.proof.isConnected).toBe(false);
    expect(v.proof.value).toBe('');
    expect(line(v)).toBe('');
    v.eye.click();
    expect(v.password.type).toBe('password');
    expect(reveal).toHaveBeenCalledTimes(1);
    v.dispose();
  });

  it('keeps the row and says why after a wrong proof, and sends the proof on Enter', async () => {
    const reveal = jest
      .fn()
      .mockRejectedValueOnce(new VaultError(403, 'wrong recovery passphrase'))
      .mockResolvedValue(SECRET);
    const v = view(reveal, { passkey: noPasskey });
    v.eye.click();
    await flush();
    const enter = () => {
      const event = new KeyboardEvent('keydown', {
        key: 'Enter',
        bubbles: true,
        cancelable: true
      });
      v.proof.dispatchEvent(event);
      return event;
    };
    // Enter never reaches the dialog, whose default button is Close.
    const reachedDialog = jest.fn();
    v.node.addEventListener('keydown', reachedDialog);
    v.proof.value = 'a guess';
    expect(enter().defaultPrevented).toBe(true);
    await flush();
    expect(reachedDialog).not.toHaveBeenCalled();
    expect(line(v)).toBe(
      'The password was not shown: wrong recovery passphrase'
    );
    expect(v.password.type).toBe('password');
    expect(v.proof.isConnected).toBe(true);
    expect(v.proof.value).toBe('');
    expect(document.activeElement).toBe(v.proof);
    // A press on the eye while the row is open goes to the row, not to a passkey.
    v.eye.click();
    await flush();
    expect(reveal).toHaveBeenCalledTimes(1);
    v.proof.value = 'the passphrase';
    enter();
    await flush();
    expect(v.password.value).toBe(SECRET);
    v.dispose();
  });

  it('asks the typed proofs in their order: a code, the unlock password, the recovery passphrase', async () => {
    const reveal = jest.fn().mockResolvedValue(SECRET);
    const all = {
      passkey: noPasskey,
      typed: ['code', 'password', 'passphrase']
    };
    const v = view(reveal, all);
    v.eye.click();
    await flush();
    expect(line(v)).toBe(
      'No passkey was added for this host. Enter a code of the authenticator app to show the password.'
    );
    expect(v.proof.type).toBe('text');
    expect(v.proof.inputMode).toBe('numeric');
    expect(v.proof.getAttribute('aria-label')).toBe(
      'Code of the authenticator app'
    );
    expect(v.useNext.textContent).toBe('Use the unlock password');
    // Enter on Show and on the link stays with that button: the dialog, whose
    // default button is Close, never gets it.
    const reachedDialog = jest.fn();
    v.node.addEventListener('keydown', reachedDialog);
    for (const target of [v.prove, v.useNext]) {
      const event = new KeyboardEvent('keydown', {
        key: 'Enter',
        bubbles: true,
        cancelable: true
      });
      target.dispatchEvent(event);
      expect(event.defaultPrevented).toBe(false);
    }
    expect(reachedDialog).not.toHaveBeenCalled();
    v.proof.value = '123456';
    v.prove.click();
    await flush();
    expect(reveal).toHaveBeenLastCalledWith({ code: '123456' });
    v.dispose();

    // The link moves on one proof at a time, and what was typed is not kept.
    const other = view(reveal, all);
    other.eye.click();
    await flush();
    other.proof.value = '123';
    other.useNext.click();
    expect(line(other)).toBe(
      'No passkey was added for this host. Enter the unlock password to show the password.'
    );
    expect(other.proof.value).toBe('');
    expect(other.proof.type).toBe('password');
    expect(other.proof.getAttribute('aria-label')).toBe('Unlock password');
    expect(other.useNext.textContent).toBe('Use the recovery passphrase');
    other.proof.value = 'an everyday password';
    other.prove.click();
    await flush();
    expect(reveal).toHaveBeenLastCalledWith({
      password: 'an everyday password'
    });
    other.dispose();

    const last = view(reveal, all);
    last.eye.click();
    await flush();
    last.useNext.click();
    last.useNext.click();
    expect(line(last)).toBe(
      'No passkey was added for this host. Enter the recovery passphrase to show the password.'
    );
    // From the last proof the link goes back to the first: a proof passed over can
    // still be chosen.
    expect(last.useNext.textContent).toBe(
      'Use a code of the authenticator app'
    );
    last.proof.value = 'the passphrase';
    last.prove.click();
    await flush();
    expect(reveal).toHaveBeenLastCalledWith({ current: 'the passphrase' });
    last.dispose();
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
    // The server's refusal of a passkey is an error, not a reason to ask another proof.
    expect(v.proof.isConnected).toBe(false);
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
  it('docks the panel on the chosen side, now and when the side changes, and sends nothing', () => {
    const values: Record<string, unknown> = { sidebar: 'right' };
    const read: string[] = [];
    const listeners: Array<() => void> = [];
    const settings: any = {
      get: (key: string) => {
        read.push(key);
        return { composite: values[key] };
      },
      changed: { connect: (fn: () => void) => listeners.push(fn) }
    };
    const api = fakeApi();
    const dock = jest.fn();
    connectSettings(settings, dock);
    expect(dock).toHaveBeenLastCalledWith('right');
    values.sidebar = 'left';
    listeners.forEach(fn => fn());
    expect(dock).toHaveBeenLastCalledWith('left');
    // A change that leaves the side alone does not dock again: that collapses the
    // open panel.
    listeners.forEach(fn => fn());
    expect(dock).toHaveBeenCalledTimes(2);
    // Only the sidebar is the page's setting; the vault's policy lives on the server.
    expect(read.every(key => key === 'sidebar')).toBe(true);
    expect((api as any).setConfig).toBeUndefined();
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

it('describes an entry in its row tooltip, one line per field and time that is set', () => {
  const ago = (ms: number): string => new Date(Date.now() - ms).toISOString();
  const full = {
    ...ENTRIES[0],
    used: ago(5 * 60_000),
    updated: ago(3 * 3_600_000),
    created: ago(4 * 86_400_000)
  };
  expect(entryTooltip(full).split('\n')).toEqual([
    'github/api',
    'Username: me',
    'URL: https://github.com',
    'Category: infra',
    'Last used: 5m ago',
    'Updated: 3h ago',
    'Created: 4d ago'
  ]);
  const bare = {
    ...full,
    username: '',
    url: '',
    category: '',
    updated: '',
    used: undefined
  };
  expect(entryTooltip(bare).split('\n')).toEqual([
    'github/api',
    'Last used: never',
    'Created: 4d ago'
  ]);
});

// --------------------------------------------------------------------------- //
// Password and passkey: an unlock password with a passkey that has no PRF
// --------------------------------------------------------------------------- //

describe('Password and passkey', () => {
  const PAIR_SLOT = {
    type: 'password-passkey' as const,
    kdf: 'argon2id',
    cred_id: 'CQ',
    rp_id: 'localhost',
    origin: location.origin,
    label: 'Phone',
    created: '2026-11-02T10:00:00Z'
  };
  const APP_SLOT = {
    type: 'password' as const,
    kdf: 'argon2id',
    created: '2026-10-02T10:00:00Z'
  };
  const APP = { created: '2026-10-02T10:00:00Z' };
  const challengeBytes = (options: any) => Array.from(options.challenge);
  const CHALLENGE_BYTES = Array.from(new Uint8Array(b64urlToBuf(CHALLENGE)));
  const MAYBE_EXACTLY = new RegExp(`^${literally(MAYBE_ADDED)}$`);

  // clearAllMocks leaves the answers a test queued and did not use.
  beforeEach(() => {
    mockAskSecret.mockReset();
    mockLaunch.mockReset();
  });

  /**
   * Answer each dialog in turn: for a chooser the method to press, for a code dialog
   * `Submit:<code>`, else the label of the button to press; none left is Escape.
   */
  function pressInTurn(...answers: string[]): void {
    mockLaunch.mockImplementation(async (dialog: any) => {
      const answer = answers.shift();
      const body = dialog.options.body;
      if (typeof body === 'object' && body && 'chosen' in body) {
        body.chosen = answer ?? null;
        return { button: { accept: false } };
      }
      const [label, code] = (answer ?? '').split(':');
      if (code !== undefined) {
        body.code.value = code;
      }
      return {
        button: dialog.options.buttons.find((b: any) => b.label === label) ?? {
          accept: false
        }
      };
    });
  }

  const titles = () =>
    mockLaunch.mock.calls.map(([dialog]: any[]) => dialog.options.title);

  it('finds the slot only at the exact origin it was added at', () => {
    const slots: any[] = [
      { type: 'recovery' },
      { ...PAIR_SLOT, origin: 'https://lab.example.com' }
    ];
    expect(pairSlot(slots, 'https://lab.example.com')?.cred_id).toBe('CQ');
    expect(pairSlot(slots, 'https://lab.example.com:8443')).toBeUndefined();
    expect(
      pairSlot(
        [{ type: 'passkey', cred_id: 'CQ', origin: 'https://lab.example.com' }],
        'https://lab.example.com'
      )
    ).toBeUndefined();
  });

  describe('registration', () => {
    it('hands a passkey with no PRF on with its registration and the signature of its one get, both over the server challenge read before the naming click', async () => {
      const { create, get } = noPrfBrowser();
      pressInTurn('Create passkey', 'Confirm passkey', 'Continue');
      mockAskSecret.mockResolvedValueOnce({
        accepted: true,
        value: 'a long password'
      });
      const api = fakeApi();
      await registerWithProof(
        api,
        { current: 'recovery words' },
        'Phone',
        HOST
      );
      // The challenge, the naming click, create, the confirming click, get.
      const order = [
        api.challenge.mock.invocationCallOrder[0],
        mockLaunch.mock.invocationCallOrder[0],
        create.mock.invocationCallOrder[0],
        mockLaunch.mock.invocationCallOrder[1],
        get.mock.invocationCallOrder[0]
      ];
      expect(order).toEqual([...order].sort((a, b) => a - b));
      expect(api.challenge).toHaveBeenCalledTimes(1);
      expect(create).toHaveBeenCalledTimes(1);
      expect(get).toHaveBeenCalledTimes(1);
      expect(challengeBytes(create.mock.calls[0][0].publicKey)).toEqual(
        CHALLENGE_BYTES
      );
      expect(challengeBytes(get.mock.calls[0][0].publicKey)).toEqual(
        CHALLENGE_BYTES
      );
      // The server takes the public key from the registration, not from the page.
      const sent = api.addPair.mock.calls[0][0];
      expect(sent.registration).toEqual(REGISTRATION);
      expect(sent).not.toHaveProperty('public_key');
      expect(sent.assertion).toEqual(ASSERTION);
      expect(api.addPasskey).not.toHaveBeenCalled();
    });

    it('asks one challenge at a PRF registration and sends no registration; an assertion proof asks none and is sent with the slot', async () => {
      fakePasskey();
      const create = jest
        .fn()
        .mockResolvedValue({ rawId: new Uint8Array([9]).buffer });
      Object.assign(navigator.credentials, { create });
      pressInTurn('Create passkey', 'Confirm passkey');
      const api = fakeApi();
      expect(await registerWithProof(api, { current: 'pw' }, '', HOST)).toBe(
        'passkey'
      );
      expect(api.challenge).toHaveBeenCalledTimes(1);
      expect(challengeBytes(create.mock.calls[0][0].publicKey)).toEqual(
        CHALLENGE_BYTES
      );
      expect(Object.keys(api.addPasskey.mock.calls[0][0]).sort()).toEqual([
        'cred_id',
        'label',
        'prf',
        'prf_salt',
        'rp_id'
      ]);
      api.challenge.mockClear();
      mockLaunch.mockReset();
      pressInTurn('Create passkey', 'Confirm passkey');
      await registerWithProof(api, { assertion: ASSERTION }, '', HOST);
      expect(api.challenge).not.toHaveBeenCalled();
      expect(challengeBytes(create.mock.calls[1][0].publicKey)).not.toEqual(
        CHALLENGE_BYTES
      );
      expect(api.addPasskey.mock.calls[1][1]).toEqual({ assertion: ASSERTION });
    });

    it('reports the passkey unused when the rest of the flow stops', async () => {
      noPrfBrowser();
      await expect(
        registerPasskey(
          fakeApi(),
          'x',
          async () => true,
          { current: 'pw' },
          HOST,
          jest
            .fn()
            .mockRejectedValue(
              new VaultError(0, 'adding the passkey was declined')
            ),
          CHALLENGE
        )
      ).rejects.toThrow(unused('adding the passkey was declined'));
    });

    it.each<[string, VaultError, RegExp]>([
      [
        'a refusal',
        new VaultError(403, 'the passkey check failed or expired - try again'),
        unused('the passkey check failed or expired - try again')
      ],
      ['a lost answer', new NoAnswer(), MAYBE_EXACTLY],
      [
        'a 5xx answer',
        new VaultError(500, 'vault password-passkey failed: OSError'),
        MAYBE_EXACTLY
      ]
    ])(
      'reports %s of the last request as unused only for a 4xx answer',
      async (_what, failure, said) => {
        noPrfBrowser();
        pressInTurn('Create passkey', 'Confirm passkey', 'Continue');
        mockAskSecret.mockResolvedValueOnce({
          accepted: true,
          value: 'a long password'
        });
        const api = fakeApi({ addPair: jest.fn().mockRejectedValue(failure) });
        await expect(
          registerWithProof(api, { current: 'recovery words' }, 'Phone', HOST)
        ).rejects.toThrow(said);
      }
    );

    it('runs the offer, a new unlock password in two fields and one request, under one title, with one create and one get', async () => {
      const { create, get } = noPrfBrowser();
      pressInTurn('Create passkey', 'Confirm passkey', 'Continue');
      mockAskSecret.mockResolvedValueOnce({
        accepted: true,
        value: 'a long password'
      });
      const api = fakeApi();
      // The type of the slot stored, so the panel and the CLI name the method.
      expect(
        await registerWithProof(
          api,
          { current: 'recovery words' },
          'Phone',
          HOST
        )
      ).toBe('password-passkey');
      expect(titles()).toEqual([
        'Name the new passkey',
        'Confirm the new passkey',
        'Add password and passkey'
      ]);
      const offer = mockLaunch.mock.calls[2][0].options;
      expect(offer.body).toBe(
        'No PRF: the passkey cannot hold the vault key. A new unlock password decrypts the vault and the server checks the passkey; a copy of the vault opens with the password alone.'
      );
      expect(offer.buttons.map((b: any) => b.label)).toEqual([
        'Decline',
        'Continue'
      ]);
      expect(mockAskSecret).toHaveBeenCalledWith(
        'Enter the new unlock password, at least 12 characters',
        2,
        'Add password and passkey',
        { minLength: 12 }
      );
      expect(create).toHaveBeenCalledTimes(1);
      expect(get).toHaveBeenCalledTimes(1);
      expect(api.addPair).toHaveBeenCalledWith(
        {
          password: 'a long password',
          cred_id: 'CQ',
          rp_id: HOST,
          registration: REGISTRATION,
          label: 'Phone',
          assertion: ASSERTION
        },
        { current: 'recovery words' }
      );
      expect(api.addPasskey).not.toHaveBeenCalled();
    });

    it.each<[string, string[], { accepted: boolean; value: string | null }]>([
      ['Decline', ['Decline'], { accepted: true, value: 'a long password' }],
      ['a cancelled password', ['Continue'], { accepted: false, value: null }]
    ])('sends nothing on %s', async (_what, offer, typed) => {
      noPrfBrowser();
      pressInTurn('Create passkey', 'Confirm passkey', ...offer);
      mockAskSecret.mockResolvedValueOnce(typed);
      const api = fakeApi();
      await expect(
        registerWithProof(api, { current: 'recovery words' }, 'Phone', HOST)
      ).rejects.toThrow(unused(NO_PRF));
      expect(api.addPair).not.toHaveBeenCalled();
      expect(api.addPasskey).not.toHaveBeenCalled();
    });

    it('asks a code again before the last request, because the first one has expired; a passphrase is not asked again', async () => {
      noPrfBrowser();
      const withApp = status({
        slots: [{ type: 'recovery' }, APP_SLOT],
        authenticator: APP
      });
      pressInTurn(
        'Create passkey',
        'Confirm passkey',
        'Continue',
        'Submit:222222'
      );
      mockAskSecret.mockResolvedValueOnce({
        accepted: true,
        value: 'a long password'
      });
      const api = fakeApi({ status: jest.fn().mockResolvedValue(withApp) });
      await registerWithProof(api, { code: '111111' }, 'Phone', HOST);
      expect(titles()[3]).toBe('Add password and passkey');
      expect(api.addPair.mock.calls[0][1]).toEqual({ code: '222222' });
      // With the recovery passphrase, the last request takes the same proof.
      mockLaunch.mockReset();
      pressInTurn('Create passkey', 'Confirm passkey', 'Continue');
      mockAskSecret.mockResolvedValueOnce({
        accepted: true,
        value: 'a long password'
      });
      await registerWithProof(
        api,
        { current: 'recovery words' },
        'Phone',
        HOST
      );
      expect(mockLaunch).toHaveBeenCalledTimes(3);
      expect(api.addPair.mock.calls[1][1]).toEqual({
        current: 'recovery words'
      });
    });

    it('refuses before any dialog when the vault has the method already', async () => {
      noPrfBrowser();
      pressInTurn('Create passkey', 'Confirm passkey');
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValue(
            status({ slots: [{ type: 'recovery' }, PAIR_SLOT] })
          )
      });
      await expect(
        registerWithProof(api, { current: 'recovery words' }, 'Phone', HOST)
      ).rejects.toThrow(
        unused('Password and passkey already added - remove it first')
      );
      expect(titles()).toEqual([
        'Name the new passkey',
        'Confirm the new passkey'
      ]);
      expect(mockAskSecret).not.toHaveBeenCalled();
      expect(api.addPair).not.toHaveBeenCalled();
    });
  });

  describe('the proof', () => {
    /** An unlocked vault with a PRF passkey for HOST, the pair here and the app pair. */
    const all = () =>
      status({
        slots: [...status().slots, PAIR_SLOT, APP_SLOT],
        authenticator: APP
      });

    /** A first passkey request that gives no PRF, then `then` for the pair's. */
    function prfGivesNothing(then: () => Promise<any>): jest.Mock {
      const get = jest
        .fn()
        .mockResolvedValueOnce({
          rawId: new Uint8Array([0, 1, 2]).buffer,
          getClientExtensionResults: () => ({})
        })
        .mockImplementationOnce(then);
      Object.defineProperty(navigator, 'credentials', {
        value: { get },
        configurable: true
      });
      return get;
    }

    it('asks the passkey of Password and passkey after a PRF passkey that gave nothing, before a code', async () => {
      const get = prfGivesNothing(async () => signed());
      pressInTurn('Use passkey');
      const api = fakeApi();
      const proof = await askProof(api, all(), HOST, 'Add passkey', true);
      expect(proof).toEqual({ assertion: ASSERTION });
      const dialog = mockLaunch.mock.calls[0][0].options;
      expect(dialog.title).toBe('Add passkey');
      expect(dialog.body).toBe(
        'This passkey cannot unlock the vault - confirm with the passkey of Password and passkey instead.'
      );
      expect(dialog.buttons.map((b: any) => b.label)).toEqual([
        undefined,
        'Use another proof',
        'Use passkey'
      ]);
      // The challenge is read before the click that the passkey request follows.
      expect(api.challenge.mock.invocationCallOrder[0]).toBeLessThan(
        mockLaunch.mock.invocationCallOrder[0]
      );
      const options = get.mock.calls[1][0].publicKey;
      expect(options.extensions).toBeUndefined();
      expect(options.rpId).toBe('localhost');
      expect(options.userVerification).toBe('required');
      expect(
        Array.from(new Uint8Array(options.allowCredentials[0].id))
      ).toEqual([9]);
      expect(challengeBytes(options)).toEqual(CHALLENGE_BYTES);
    });

    it('asks the passkey of Password and passkey on a vault with no PRF passkey for this hostname', async () => {
      const { get } = noPrfBrowser();
      pressInTurn('Use passkey');
      const proof = await askProof(
        fakeApi(),
        status({ slots: [{ type: 'recovery' }, PAIR_SLOT] }),
        HOST,
        'Add passkey',
        true
      );
      expect(proof).toEqual({ assertion: ASSERTION });
      expect(mockLaunch.mock.calls[0][0].options.body).toBe(
        'Confirm with the passkey of Password and passkey.'
      );
      // The one passkey request is the pair's: no PRF request comes before it.
      expect(get).toHaveBeenCalledTimes(1);
      expect(get.mock.calls[0][0].publicKey.extensions).toBeUndefined();
    });

    it('moves on to the code with Use another proof, and after a dismissed prompt', async () => {
      prfGivesNothing(async () => signed());
      pressInTurn('Use another proof', 'Submit:123456');
      expect(
        await askProof(fakeApi(), all(), HOST, 'Add passkey', true)
      ).toEqual({ code: '123456' });
      prfGivesNothing(async () => {
        throw new DOMException('x', 'NotAllowedError');
      });
      mockLaunch.mockReset();
      pressInTurn('Use passkey', 'Submit:654321');
      expect(
        await askProof(fakeApi(), all(), HOST, 'Add passkey', true)
      ).toEqual({ code: '654321' });
      expect(mockLaunch.mock.calls[1][0].options.body.node.textContent).toBe(
        'No passkey answered - enter a code of the authenticator app instead'
      );
    });

    it('is not offered for a rotation, on a locked vault, or at another origin', async () => {
      for (const [s, code] of [
        [all(), false],
        [{ ...all(), unlocked: false }, true],
        [
          status({
            slots: [
              { type: 'recovery' },
              { ...PAIR_SLOT, origin: 'https://elsewhere' }
            ]
          }),
          true
        ]
      ] as [IStatus, boolean][]) {
        prfGivesNothing(async () => signed());
        mockLaunch.mockReset();
        mockAskSecret.mockResolvedValueOnce({ accepted: false, value: null });
        const api = fakeApi();
        await askProof(api, s, HOST, 'Rotate data key', code);
        expect(api.challenge).not.toHaveBeenCalled();
        expect(titles()).not.toContain('Rotate data key');
      }
    });
  });

  describe('unlock', () => {
    const lockedWith = (slots: any[]) =>
      status({ unlocked: false, remaining: null, slots });

    it('offers it in the chooser only when the vault has it, and asks the password, then the passkey', async () => {
      const { get } = noPrfBrowser();
      pressInTurn('pair');
      mockAskSecret.mockResolvedValueOnce({ accepted: true, value: 'pw' });
      const api = fakeApi();
      await unlockWithChoice(
        api,
        lockedWith([{ type: 'recovery' }, PAIR_SLOT]),
        HOST
      );
      const body = mockLaunch.mock.calls[0][0].options.body.node;
      expect(methodNames(body)).toEqual([
        'Passkey',
        'Password and authenticator app',
        'Password and passkey',
        'Recovery passphrase'
      ]);
      expect(
        (body.querySelector('[data-method="pair"]') as HTMLButtonElement)
          .disabled
      ).toBe(false);
      expect(mockAskSecret).toHaveBeenCalledWith(
        'Enter the unlock password',
        1,
        'Unlock vault'
      );
      // The chooser is the one dialog: no Use passkey dialog follows the password.
      expect(titles()).toEqual(['Unlock vault']);
      expect(get).toHaveBeenCalledTimes(1);
      expect(get.mock.calls[0][0].publicKey.extensions).toBeUndefined();
      expect(api.unlockPair).toHaveBeenCalledWith('pw', ASSERTION);
      expect(api.unlockPassword).not.toHaveBeenCalled();
      // A vault without the method sees the chooser it saw before.
      mockLaunch.mockReset();
      pressInTurn();
      await expect(
        unlockWithChoice(api, lockedWith([{ type: 'recovery' }]), HOST)
      ).rejects.toThrow('the unlock was cancelled');
      expect(
        methodNames(mockLaunch.mock.calls[0][0].options.body.node)
      ).toEqual([
        'Passkey',
        'Password and authenticator app',
        'Recovery passphrase'
      ]);
    });

    it('reads the challenge before the password dialog, makes no network read between its Submit and the passkey request, and the passkey signs it', async () => {
      const { get } = noPrfBrowser();
      mockAskSecret.mockResolvedValueOnce({ accepted: true, value: 'pw' });
      const api = fakeApi();
      expect(await unlockWithPair(api, PAIR_SLOT as ISlot)).toBe(true);
      // The password dialog's Submit is the click the passkey request follows, so
      // there is no dialog of its own, and a network read in between can lose the click.
      expect(mockLaunch).not.toHaveBeenCalled();
      const asked = mockAskSecret.mock.invocationCallOrder[0];
      const prompted = get.mock.invocationCallOrder[0];
      expect(api.challenge.mock.invocationCallOrder[0]).toBeLessThan(asked);
      const reads: number[] = [];
      for (const m of Object.values(api)) {
        if (jest.isMockFunction(m)) {
          reads.push(...m.mock.invocationCallOrder);
        }
      }
      expect(reads.filter(at => at > asked && at < prompted)).toEqual([]);
      expect(challengeBytes(get.mock.calls[0][0].publicKey)).toEqual(
        CHALLENGE_BYTES
      );
      expect(api.unlockPair).toHaveBeenCalledWith('pw', ASSERTION);
      expect(api.unlockPair.mock.invocationCallOrder[0]).toBeGreaterThan(
        prompted
      );
    });

    it('names the address when the method was added at another one', async () => {
      pressInTurn();
      await expect(
        unlockWithChoice(
          fakeApi(),
          lockedWith([
            { type: 'recovery' },
            { ...PAIR_SLOT, origin: 'https://lab.example.com:8443' }
          ]),
          HOST
        )
      ).rejects.toThrow('the unlock was cancelled');
      const choice =
        mockLaunch.mock.calls[0][0].options.body.node.querySelector(
          '[data-method="pair"]'
        ) as HTMLButtonElement;
      expect(choice.disabled).toBe(true);
      expect(choice.textContent).toBe(
        'Password and passkeyNo passkey was added for this address.'
      );
    });

    it('sends nothing when the password dialog is cancelled or the passkey prompt dismissed', async () => {
      const { get } = noPrfBrowser();
      const api = fakeApi();
      const s = lockedWith([{ type: 'recovery' }, PAIR_SLOT]);
      pressInTurn('pair');
      mockAskSecret.mockResolvedValueOnce({ accepted: false, value: null });
      await expect(unlockWithChoice(api, s, HOST)).rejects.toThrow(
        'the unlock was cancelled'
      );
      expect(get).not.toHaveBeenCalled();
      mockLaunch.mockReset();
      pressInTurn('pair');
      mockAskSecret.mockResolvedValueOnce({ accepted: true, value: 'pw' });
      get.mockRejectedValueOnce(new DOMException('x', 'NotAllowedError'));
      const fail = jest.fn();
      await expect(unlockWithChoice(api, s, HOST, fail)).rejects.toThrow('x');
      expect(get).toHaveBeenCalledTimes(1);
      expect(api.unlockPair).not.toHaveBeenCalled();
      // Only a refusal of the server is said in the page; a dismissal is the user's.
      expect(fail).not.toHaveBeenCalled();
    });
  });

  describe('the panel', () => {
    const UNLOCK_PAIR = 'Unlock with password and passkey';
    const locked = (slots: any[]) =>
      status({ unlocked: false, remaining: null, slots });

    it('unlocks from the locked view: the main button and no hint where no PRF passkey is here', async () => {
      noPrfBrowser();
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValue(locked([{ type: 'recovery' }, PAIR_SLOT]))
      });
      const panel = await panelWith(api);
      expect(button(panel, UNLOCK_PAIR).classList).toContain('jp-mod-accept');
      expect(text(panel)).not.toContain('No passkey configured');
      mockAskSecret.mockResolvedValueOnce({ accepted: true, value: 'pw' });
      button(panel, UNLOCK_PAIR).click();
      for (let i = 0; i < 4; i++) {
        await flush();
      }
      expect(api.unlockPair).toHaveBeenCalledWith('pw', ASSERTION);
      panel.dispose();
      // Beside a PRF passkey for this hostname it is the second way in.
      api.status.mockResolvedValue(locked([...status().slots, PAIR_SLOT]));
      const other = await panelWith(api);
      expect(button(other, UNLOCK_PAIR).classList).not.toContain(
        'jp-mod-accept'
      );
      // At another address there is no button, and the hint says so.
      api.status.mockResolvedValue(
        locked([{ type: 'recovery' }, { ...PAIR_SLOT, origin: 'https://x' }])
      );
      await other.refresh();
      expect(() => button(other, UNLOCK_PAIR)).toThrow();
      expect(text(other)).toContain('No passkey configured');
      // ACC-PANEL-226: with the app pair as well, Unlock with password stays beside it.
      api.status.mockResolvedValue(
        locked([{ type: 'recovery' }, APP_SLOT, PAIR_SLOT])
      );
      await other.refresh();
      expect(button(other, UNLOCK_PAIR)).toBeTruthy();
      expect(button(other, 'Unlock with password')).toBeTruthy();
    });

    it('names the address where Password and passkey was added at another port of this host', async () => {
      const there = `https://${HOST}:8443`;
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValue(
            locked([
              { type: 'recovery' },
              { ...PAIR_SLOT, rp_id: HOST, origin: there }
            ])
          )
      });
      const panel = await panelWith(api);
      expect(() => button(panel, UNLOCK_PAIR)).toThrow();
      expect(
        Array.from(
          panel.node.querySelectorAll('.jp-PasskeyVaultPanel-hint'),
          hint => hint.textContent
        )
      ).toEqual([
        `Password and passkey added at ${there} - open JupyterLab there`
      ]);
      expect(button(panel, 'Use recovery passphrase')).toBeTruthy();
      panel.dispose();
      // At another hostname this tab's host has no slot of any kind: the advice stays.
      api.status.mockResolvedValue(
        locked([
          { type: 'recovery' },
          {
            ...PAIR_SLOT,
            rp_id: 'other.example',
            origin: 'https://other.example'
          }
        ])
      );
      const other = await panelWith(api);
      expect(text(other)).toContain('No passkey configured');
    });

    it('reads Password and passkey added when the passkey added in the cog view has no PRF, and Passkey added for one with a PRF', async () => {
      noPrfBrowser();
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValue(status({ slots: [{ type: 'recovery' }] }))
      });
      const panel = await panelWith(api);
      (
        panel.node.querySelector(
          'button[title="Vault settings and security"]'
        ) as HTMLElement
      ).click();
      // The recovery passphrase as the proof, then the new unlock password.
      mockAskSecret
        .mockResolvedValueOnce({ accepted: true, value: 'recovery words' })
        .mockResolvedValueOnce({ accepted: true, value: 'a long password' });
      pressInTurn('Create passkey', 'Confirm passkey', 'Continue');
      addMethod(panel, 'passkey');
      for (let i = 0; i < 6; i++) {
        await flush();
      }
      expect(api.addPair).toHaveBeenCalledTimes(1);
      expect(lines(panel)).toEqual([['info', 'Password and passkey added']]);
      expect(toasts()).toEqual([]);
      // A passkey with a PRF.
      fakePasskey();
      Object.assign(navigator.credentials, {
        create: jest
          .fn()
          .mockResolvedValue({ rawId: new Uint8Array([9]).buffer })
      });
      mockAskSecret.mockResolvedValueOnce({
        accepted: true,
        value: 'recovery words'
      });
      pressInTurn('Create passkey', 'Confirm passkey');
      addMethod(panel, 'passkey');
      for (let i = 0; i < 6; i++) {
        await flush();
      }
      expect(api.addPasskey).toHaveBeenCalledTimes(1);
      expect(lines(panel)).toEqual([['info', 'Passkey added']]);
    });

    it.each<[string, VaultError, string]>([
      [
        'a wrong password',
        new VaultError(400, 'wrong unlock password'),
        'Wrong unlock password.'
      ],
      [
        'a challenge that expired while the password dialog was open',
        new VaultError(403, 'the passkey check failed or expired - try again'),
        'The passkey check failed or expired - try again.'
      ]
    ])(
      '%s: a notification, and the vault stays locked',
      async (_what, refusal, said) => {
        const { get } = noPrfBrowser();
        const api = fakeApi({
          status: jest
            .fn()
            .mockResolvedValue(locked([{ type: 'recovery' }, PAIR_SLOT])),
          unlockPair: jest.fn().mockRejectedValue(refusal)
        });
        const panel = await panelWith(api);
        mockAskSecret.mockResolvedValueOnce({ accepted: true, value: 'wrong' });
        button(panel, UNLOCK_PAIR).click();
        for (let i = 0; i < 4; i++) {
          await flush();
        }
        // The passkey was asked, and the server's refusal is a notification.
        expect(get).toHaveBeenCalledTimes(1);
        expect(lines(panel)).toEqual([]);
        expect(toasts()).toEqual([['error', said]]);
        expect(text(panel)).toContain('Locked');
      }
    );

    it('lists one row in the cog view with a two-step Remove, and the eye proves with the passkey', async () => {
      const { get } = noPrfBrowser();
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValue(
            status({ slots: [{ type: 'recovery' }, PAIR_SLOT] })
          )
      });
      const panel = await panelWith(api);
      (
        panel.node.querySelector(
          'button[title="Vault settings and security"]'
        ) as HTMLElement
      ).click();
      const row = panel.node.querySelector(
        '[data-method="pair"]'
      ) as HTMLElement;
      expect(row.textContent).toBe(
        'Password and passkeyAdded 2026-11-02 10:00 UTC PhoneRemove'
      );
      const remove = () =>
        panel.node.querySelector(
          '[data-focus-key="pair"]'
        ) as HTMLButtonElement;
      const now = jest.spyOn(Date, 'now').mockReturnValue(1000);
      remove().click();
      now.mockReturnValue(1000 + ARM_DELAY_MS);
      remove().click();
      now.mockRestore();
      await flush();
      expect(api.removePasskey).toHaveBeenCalledWith('CQ');
      expect(text(panel)).toContain('Password and passkey removed');
      // At another address the row says where it was added.
      api.status.mockResolvedValue(
        status({
          slots: [
            { type: 'recovery' },
            { ...PAIR_SLOT, origin: 'https://lab.example.com:8443' }
          ]
        })
      );
      await panel.refresh();
      expect(
        (panel.node.querySelector('[data-method="pair"]') as HTMLElement)
          .textContent
      ).toContain('Phone on https://lab.example.com:8443');
      // The eye: no PRF passkey here, so the passkey of the pair signs a challenge.
      api.status.mockResolvedValue(
        status({ slots: [{ type: 'recovery' }, PAIR_SLOT] })
      );
      await panel.refresh();
      (panel as any)._view = 'main';
      (panel as any)._render();
      let how: any;
      mockViewEntry.mockImplementation(async (_entry: any, h: any) => {
        how = h;
        return null;
      });
      (
        panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
      ).click();
      await flush();
      expect(await how.passkey()).toEqual({ assertion: ASSERTION });
      expect(api.challenge).toHaveBeenCalledTimes(1);
      expect(challengeBytes(get.mock.calls[0][0].publicKey)).toEqual(
        CHALLENGE_BYTES
      );
      // The password alone of this method is not among the typed proofs.
      expect(how.typed).toEqual(['passphrase']);
    });

    it('the eye asks a PRF passkey of this hostname before the passkey of the pair', async () => {
      const get = fakePasskey();
      mockViewEntry.mockResolvedValue(null);
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValue(status({ slots: [...status().slots, PAIR_SLOT] }))
      });
      const panel = await panelWith(api);
      (
        panel.node.querySelector('.jp-PasskeyVaultPanel-rowLine') as HTMLElement
      ).click();
      await flush();
      const how = mockViewEntry.mock.calls[0][1];
      expect(await how.passkey()).toEqual({ cred_id: 'AAEC', prf: 'CQkJ' });
      expect(api.challenge).not.toHaveBeenCalled();
      expect(get).toHaveBeenCalledTimes(1);
      expect(get.mock.calls[0][0].publicKey.rpId).toBe(HOST);
    });

    it('adds no button to the Add unlock method chooser', async () => {
      const api = fakeApi({
        status: jest
          .fn()
          .mockResolvedValue(
            status({ slots: [{ type: 'recovery' }, PAIR_SLOT] })
          )
      });
      const panel = await panelWith(api);
      (
        panel.node.querySelector(
          'button[title="Vault settings and security"]'
        ) as HTMLElement
      ).click();
      mockChoose.mockResolvedValueOnce(null);
      button(panel, 'Add unlock method').click();
      expect(Object.keys(mockChoose.mock.calls[0][0])).toEqual([
        'passkey',
        'mfa'
      ]);
    });
  });
});
