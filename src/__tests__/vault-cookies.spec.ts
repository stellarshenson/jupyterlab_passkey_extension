/**
 * Unit tests for cookie entries and rename in the vault frontend: the Add choice, the
 * cookie form and its preview, the cookie row and popup with the kept request headers,
 * and rename through the edit
 * form. The REST API and the dialogs' launch are faked; widgets render into jsdom.
 */

import { Widget } from '@lumino/widgets';

const mockLaunch = jest.fn();
const mockEditEntry = jest.fn();
const mockViewEntry = jest.fn();
const mockChooseType = jest.fn();
const mockWarning = jest.fn(() => 'warn');
const mockError = jest.fn(() => 'error');
jest.mock('../passphrase', () => ({
  askSecret: jest.fn(),
  launchWithEscape: (...a: any[]) => mockLaunch(...a)
}));
// The panel tests replace the dialogs it opens; the dialog tests take the real ones.
jest.mock('../vault/dialogs', () => ({
  ...jest.requireActual('../vault/dialogs'),
  editEntry: (...a: any[]) => mockEditEntry(...a),
  viewEntry: (...a: any[]) => mockViewEntry(...a),
  chooseEntryType: () => mockChooseType()
}));
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
    warning: (...a: any[]) => mockWarning(...(a as [])),
    error: (...a: any[]) => mockError(...(a as [])),
    dismiss: jest.fn()
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
      constructor(private readonly _options: { name: string }) {}
      element() {
        const span = document.createElement('span');
        span.dataset.icon = this._options.name;
        return span;
      }
    }
  };
});

import { IEntry, VaultError } from '../vault/api';
import { EntryForm, EntryView, PREVIEW_MS } from '../vault/dialogs';
import { VaultPanel } from '../vault/panel';

const { chooseEntryType, editEntry } = jest.requireActual('../vault/dialogs');

/** A cookie value no page may show: the tests look for it in the DOM. */
const MARKER = 'fake-cookie-value-7Qp';
const PASTE = `curl 'https://shop.example.com/' -H 'Cookie: sid=${MARKER}; theme=dark'`;
/** A header value no page may show. */
const HEADER_MARKER = 'fake-header-value-9Zk';
/** A Copy as cURL with two cookies, two headers the entry keeps and one it drops. */
const PASTE_HEADERS = `curl 'https://app.example.com/api' -H 'accept: */*' -H 'authorization: Bearer ${HEADER_MARKER}' -b 'sid=${MARKER}; tok=fake' -H 'x-csrf-token: ${HEADER_MARKER}-csrf'`;
const NOW = Date.now() / 1000;

const LOGIN: IEntry = {
  name: 'nas/ugos',
  username: 'konrad',
  url: 'https://nas',
  category: 'home',
  notes: '',
  created: '',
  updated: '',
  type: 'login'
};

/** A live jar: a session cookie and one that expired; one cookie is left. */
const SHOP: IEntry = {
  name: 'shop/session',
  username: '',
  url: 'https://shop.example.com',
  category: 'web',
  notes: '',
  created: '',
  updated: '',
  type: 'cookies',
  cookies: [
    { domain: 'shop.example.com', name: 'sid', expires: null },
    { domain: 'example.com', name: 'theme', expires: 1000000000 }
  ]
};

/** A jar whose every cookie is past its expiry. */
const STALE: IEntry = {
  ...SHOP,
  name: 'shop/stale',
  cookies: [{ domain: 'old.example.com', name: 'sid', expires: NOW - 60 }]
};

/** A jar with the names of the request headers kept beside it. */
const APP: IEntry = {
  ...SHOP,
  name: 'app/session',
  headers: ['authorization', 'x-csrf-token']
};

/** A copied request that carried a header to keep and no cookie. */
const TOKEN: IEntry = {
  ...SHOP,
  name: 'api/token',
  cookies: [],
  headers: ['Authorization']
};

const SUMMARY = {
  count: 2,
  domains: ['example.com', 'shop.example.com'],
  names: ['sid', 'theme'],
  expired: 1,
  headers: [] as string[]
};

/** What PASTE_HEADERS reads as. */
const WITH_HEADERS = {
  count: 2,
  domains: ['app.example.com'],
  names: ['sid', 'tok'],
  expired: 0,
  headers: ['authorization', 'x-csrf-token']
};

/** What a copy with one header to keep and no cookie reads as. */
const HEADER_ONLY = {
  count: 0,
  domains: [] as string[],
  names: [] as string[],
  expired: 0,
  headers: ['Authorization']
};

function status(): any {
  return {
    initialized: true,
    unlocked: true,
    remaining: 4 * 3600,
    holder: {
      name: 'memory',
      about: '',
      summary: 'strong',
      protection: '',
      capabilities: {},
      details: [],
      notice: null
    },
    slots: [{ type: 'recovery', kdf: 'argon2id' }],
    settings: {
      unlock_minutes: 240,
      password_min_length: 12,
      reveal_seconds: 60,
      rotate_days: 365
    },
    path: '~/.local/share/jupyterlab-passkey/vault.json'
  };
}

function fakeApi(over: Record<string, any> = {}): any {
  return {
    status: jest.fn().mockResolvedValue(status()),
    entries: jest.fn().mockResolvedValue([LOGIN, SHOP, STALE]),
    add: jest.fn().mockResolvedValue(undefined),
    edit: jest.fn().mockResolvedValue(undefined),
    rename: jest.fn().mockResolvedValue(undefined),
    parseCookies: jest.fn().mockResolvedValue(SUMMARY),
    generate: jest.fn().mockResolvedValue('generated-pw'),
    proven: false,
    ...over
  };
}

async function panelWith(api: any): Promise<VaultPanel> {
  const panel = new VaultPanel({ api, openSettings: jest.fn(), host: 'lab' });
  Widget.attach(panel, document.body);
  await panel.refresh();
  return panel;
}

const flush = () => new Promise(r => setTimeout(r, 0));

function row(panel: VaultPanel, name: string): HTMLElement {
  return panel.node.querySelector(
    `[data-focus-key="row:${name}"]`
  ) as HTMLElement;
}

function pressAdd(panel: VaultPanel): void {
  (
    panel.node.querySelector('button[title="Add an entry"]') as HTMLElement
  ).click();
}

/** The labels of a form's or a popup's fields, in order. */
function labels(widget: Widget): (string | null)[] {
  return Array.from(
    widget.node.querySelectorAll('.jp-PasskeyVaultForm-label')
  ).map(l => l.textContent);
}

/** Type `value` into `field`, as a paste does. */
function type(field: HTMLInputElement | HTMLTextAreaElement, value: string) {
  field.value = value;
  field.dispatchEvent(new Event('input', { bubbles: true }));
}

/**
 * Dialog's gate on Save: on every `input`, in document capture, Save is disabled while
 * anything in the form is :invalid. Registered after the form is attached, as Dialog's is.
 */
function saveGate(f: EntryForm): { disabled: boolean; remove: () => void } {
  const gate = { disabled: false, remove: (): void => undefined };
  const check = () => {
    gate.disabled = !!f.node.querySelector(':invalid');
  };
  document.addEventListener('input', check, true);
  gate.remove = () => document.removeEventListener('input', check, true);
  return gate;
}

/** The line under the paste field. */
function preview(form: EntryForm): string | null {
  return (form.cookies as HTMLTextAreaElement)
    .closest('.jp-PasskeyVaultForm-field')!
    .querySelector('.jp-PasskeyVaultForm-help')!.textContent;
}

afterEach(() => {
  jest.useRealTimers();
  document.body.innerHTML = '';
  jest.clearAllMocks();
});

describe('the Add choice', () => {
  const choices = (dialog: any): [string, string][] =>
    Array.from<HTMLButtonElement>(
      dialog.options.body.node.querySelectorAll('button')
    ).map(button => {
      const [name, help] = Array.from(button.children);
      // Named by the kind, described by the line under it.
      expect(button.getAttribute('aria-labelledby')).toBe(name.id);
      expect(button.getAttribute('aria-describedby')).toBe(help.id);
      return [name.textContent as string, help.textContent as string];
    });

  it('offers Password and Cookies with one short line each, and Cancel as its only other button', async () => {
    mockLaunch.mockResolvedValue({ button: { accept: false } });
    expect(await chooseEntryType()).toBeNull();
    const dialog = mockLaunch.mock.calls[0][0];
    expect(dialog.options.title).toBe('Add entry');
    expect(dialog.options.buttons).toEqual([{ accept: false }]);
    expect(choices(dialog)).toEqual([
      ['Password', 'A username and a password for a site.'],
      ['Cookies', 'Cookies and request headers of a browser session, pasted.']
    ]);
    // The same classes as the unlock method chooser.
    expect(
      dialog.options.body.node.querySelectorAll(
        'button.jp-PasskeyVaultForm-choice'
      )
    ).toHaveLength(2);
  });

  it('returns the kind pressed, and closes', async () => {
    for (const kind of ['login', 'cookies']) {
      mockLaunch.mockImplementationOnce(async (dialog: any) => {
        (
          dialog.options.body.node.querySelector(
            `button[data-method="${kind}"]`
          ) as HTMLButtonElement
        ).click();
        expect(dialog.rejected).toBe(true);
        return { button: { accept: false } };
      });
      expect(await chooseEntryType()).toBe(kind);
    }
  });

  it('opens no form and starts no action when the choice is cancelled', async () => {
    mockChooseType.mockResolvedValue(null);
    const api = fakeApi();
    const panel = await panelWith(api);
    pressAdd(panel);
    await flush();
    expect(mockChooseType).toHaveBeenCalledTimes(1);
    expect(mockEditEntry).not.toHaveBeenCalled();
    expect(panel.node.getAttribute('aria-busy')).toBeNull();
    expect(api.status).toHaveBeenCalledTimes(1);
  });

  it('opens the password form for Password and the cookie form for Cookies', async () => {
    const api = fakeApi();
    const panel = await panelWith(api);
    mockEditEntry.mockResolvedValue(null);
    mockChooseType.mockResolvedValueOnce('login');
    pressAdd(panel);
    await flush();
    await flush();
    expect(mockEditEntry.mock.calls[0][4]).toBeUndefined();
    mockChooseType.mockResolvedValueOnce('cookies');
    pressAdd(panel);
    await flush();
    await flush();
    expect(mockEditEntry.mock.calls[1][4]).toEqual(expect.any(Function));
  });
});

describe('the cookie form', () => {
  /** An Add cookie form whose reads answer `parse`. */
  function form(parse: jest.Mock, entry?: IEntry): EntryForm {
    const f = new EntryForm(async () => 'x', entry, [], [], parse);
    Widget.attach(f, document.body);
    return f;
  }

  it('has name, URL, a multi-line paste field, category and notes, and no password', () => {
    const f = form(jest.fn());
    expect(labels(f)).toEqual([
      'Name',
      'Username',
      'URL',
      'Cookies',
      'Category',
      'Notes'
    ]);
    expect(f.cookies?.tagName).toBe('TEXTAREA');
    expect(f.node.querySelector('input[type="password"]')).toBeNull();
    // Never sent to a spelling service or filled in by the browser.
    expect(f.cookies?.spellcheck).toBe(false);
    expect(f.cookies?.autocomplete).toBe('off');
    f.dispose();
  });

  it('keeps Save disabled in Add until a paste is read', () => {
    const parse = jest.fn();
    const f = form(parse);
    expect(f.cookies?.validity.valid).toBe(false);
    expect(parse).not.toHaveBeenCalled();
    f.dispose();
  });

  it('reads the paste once, 300 ms after its last change, with the URL field', async () => {
    jest.useFakeTimers();
    const parse = jest.fn().mockResolvedValue(SUMMARY);
    const f = form(parse);
    type(f.url, 'https://shop.example.com');
    type(f.cookies!, 'curl one');
    await jest.advanceTimersByTimeAsync(200);
    type(f.cookies!, PASTE);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS - 1);
    expect(parse).not.toHaveBeenCalled();
    // Save waits for the read of the text now in the field.
    expect(f.cookies?.validity.valid).toBe(false);
    expect(preview(f)).toBe('Reading the cookies...');
    await jest.advanceTimersByTimeAsync(1);
    expect(parse).toHaveBeenCalledTimes(1);
    expect(parse).toHaveBeenCalledWith(PASTE, 'https://shop.example.com');
    await jest.advanceTimersByTimeAsync(0);
    expect(f.cookies?.validity.valid).toBe(true);
    f.dispose();
  });

  it('shows the count, the domains and the names read, never a value', async () => {
    jest.useFakeTimers();
    const f = form(jest.fn().mockResolvedValue(SUMMARY));
    type(f.cookies!, PASTE);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(preview(f)).toBe(
      '2 cookies read, 1 expired, from example.com, shop.example.com: sid, theme'
    );
    // The paste is the field's value only: no text or attribute of the page holds it.
    expect(f.node.textContent).not.toContain(MARKER);
    expect(f.node.innerHTML).not.toContain(MARKER);
    f.dispose();
  });

  it('says why nothing was read and keeps Save disabled', async () => {
    jest.useFakeTimers();
    const f = form(
      jest
        .fn()
        .mockRejectedValue(
          new VaultError(
            400,
            "Cookie header line 1: no domain - give the site's url with --url"
          )
        )
    );
    type(f.cookies!, `sid=${MARKER}`);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(preview(f)).toBe(
      "No cookie was read: Cookie header line 1: no domain - give the site's url in the URL field"
    );
    expect(f.cookies?.validity.valid).toBe(false);
    expect(f.node.innerHTML).not.toContain(MARKER);
    f.dispose();
  });

  it('keeps Save disabled for a paste whose every cookie has expired, and says to copy them again', async () => {
    jest.useFakeTimers();
    const one = {
      count: 1,
      domains: ['a.example'],
      names: ['sid'],
      expired: 1,
      headers: [] as string[]
    };
    const parse = jest
      .fn()
      .mockResolvedValueOnce({ ...SUMMARY, expired: 2 })
      .mockResolvedValue(one);
    const f = form(parse);
    type(f.cookies!, PASTE);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(preview(f)).toBe(
      '2 cookies read, all expired - copy the cookies again from the browser'
    );
    expect(f.cookies?.validationMessage).toBe('Every cookie has expired');
    type(f.cookies!, `${PASTE}\n`);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(preview(f)).toBe(
      '1 cookie read, all expired - copy the cookies again from the browser'
    );
    expect(f.cookies?.validity.valid).toBe(false);
    f.dispose();
    // Edit saves nothing of such a paste either: its line promises no replacement.
    const edit = form(jest.fn().mockResolvedValue(one), SHOP);
    type(edit.cookies!, PASTE);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(preview(edit)).toBe(
      '1 cookie read, all expired - copy the cookies again from the browser'
    );
    expect(edit.cookies?.validity.valid).toBe(false);
    edit.dispose();
  });

  it('names the header count and the header names beside the cookie summary, never a value', async () => {
    jest.useFakeTimers();
    const parse = jest
      .fn()
      .mockResolvedValueOnce(WITH_HEADERS)
      .mockResolvedValue({ ...WITH_HEADERS, headers: ['authorization'] });
    const f = form(parse);
    type(f.cookies!, PASTE_HEADERS);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(preview(f)).toBe(
      '2 cookies read, from app.example.com: sid, tok; 2 headers: authorization, x-csrf-token'
    );
    expect(f.cookies?.validity.valid).toBe(true);
    // The paste is the field's value only: no text or attribute of the page holds it.
    for (const marker of [HEADER_MARKER, MARKER]) {
      expect(f.node.textContent).not.toContain(marker);
      expect(f.node.innerHTML).not.toContain(marker);
    }
    type(f.cookies!, `${PASTE_HEADERS}\n`);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(preview(f)).toBe(
      '2 cookies read, from app.example.com: sid, tok; 1 header: authorization'
    );
    f.dispose();
  });

  it('names the headers of a paste with a header and no cookie, with no domain and no cookie name', async () => {
    jest.useFakeTimers();
    const f = form(jest.fn().mockResolvedValue(HEADER_ONLY));
    type(
      f.cookies!,
      `curl 'https://api.example.com/' -H 'Authorization: Bearer ${HEADER_MARKER}'`
    );
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(preview(f)).toBe('0 cookies read; 1 header: Authorization');
    expect(f.node.innerHTML).not.toContain(HEADER_MARKER);
    f.dispose();
  });

  it('enables Save for an unexpired cookie and for a header with no cookie, and not for cookies that all expired', async () => {
    jest.useFakeTimers();
    const parse = jest
      .fn()
      .mockResolvedValueOnce(WITH_HEADERS)
      .mockResolvedValueOnce(HEADER_ONLY)
      // The headers of a paste whose cookies all expired do not enable Save.
      .mockResolvedValueOnce({ ...WITH_HEADERS, expired: 2 });
    const f = form(parse);
    await jest.advanceTimersByTimeAsync(0);
    // The name is the form's other gate on Save.
    type(f.name, 'app/session');
    const save = saveGate(f);
    const read = async (text: string) => {
      type(f.cookies!, text);
      expect(save.disabled).toBe(true);
      await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    };
    await read(PASTE_HEADERS);
    expect(save.disabled).toBe(false);
    await read(`${PASTE_HEADERS}\n`);
    expect(save.disabled).toBe(false);
    expect(f.cookies?.validity.valid).toBe(true);
    await read(`${PASTE_HEADERS}\n\n`);
    expect(save.disabled).toBe(true);
    expect(f.cookies?.validationMessage).toBe('Every cookie has expired');
    expect(preview(f)).toBe(
      '2 cookies read, all expired - copy the cookies again from the browser'
    );
    save.remove();
    f.dispose();
  });

  it('makes Dialog look at Save again once the answer comes, without reading again', async () => {
    jest.useFakeTimers();
    const parse = jest.fn().mockResolvedValue(SUMMARY);
    const f = form(parse);
    // The form's own first check of the name field, before the paste.
    await jest.advanceTimersByTimeAsync(0);
    type(f.cookies!, PASTE);
    // Dialog checks validity on any `input` event, in document capture.
    const dialogChecks = jest.fn();
    document.addEventListener('input', dialogChecks, true);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    document.removeEventListener('input', dialogChecks, true);
    expect(dialogChecks).toHaveBeenCalledTimes(1);
    expect(dialogChecks.mock.calls[0][0].target).toBe(f.node);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(parse).toHaveBeenCalledTimes(1);
    f.dispose();
  });

  it('disables Save the moment the paste or the URL changes, or the paste is cleared', async () => {
    jest.useFakeTimers();
    const f = form(jest.fn().mockResolvedValue(SUMMARY));
    type(f.name, 'shop/new');
    await jest.advanceTimersByTimeAsync(0);
    const save = saveGate(f);
    type(f.cookies!, PASTE);
    expect(save.disabled).toBe(true);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(save.disabled).toBe(false);
    type(f.cookies!, `${PASTE}\n`);
    expect(save.disabled).toBe(true);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(save.disabled).toBe(false);
    type(f.url, 'https://shop.example.com');
    expect(save.disabled).toBe(true);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(save.disabled).toBe(false);
    // Add with nothing pasted has nothing to save.
    type(f.cookies!, '');
    expect(save.disabled).toBe(true);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(save.disabled).toBe(true);
    save.remove();
    f.dispose();
  });

  it('drops the answer for a text that has changed since', async () => {
    jest.useFakeTimers();
    let first: (v: unknown) => void = () => undefined;
    const parse = jest
      .fn()
      .mockReturnValueOnce(new Promise(r => (first = r)))
      .mockResolvedValueOnce({ ...SUMMARY, count: 1, names: ['sid'] });
    const f = form(parse);
    type(f.cookies!, 'old paste');
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    type(f.cookies!, PASTE);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    first(SUMMARY);
    await jest.advanceTimersByTimeAsync(0);
    expect(preview(f)).toContain('1 cookie read');
    f.dispose();
  });

  it('reads the paste again when the URL changes, and not while the paste is empty', async () => {
    jest.useFakeTimers();
    const parse = jest.fn().mockResolvedValue(SUMMARY);
    const f = form(parse);
    type(f.url, 'https://a.example');
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(parse).not.toHaveBeenCalled();
    type(f.cookies!, 'sid=1');
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    type(f.url, 'https://b.example');
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(parse.mock.calls).toEqual([
      ['sid=1', 'https://a.example'],
      ['sid=1', 'https://b.example']
    ]);
    f.dispose();
  });

  it('keeps the line of the last read while a URL change is read, and says Reading for a paste change', async () => {
    jest.useFakeTimers();
    const refusal = new VaultError(400, 'Cookie header line 1: no domain');
    const parse = jest
      .fn()
      .mockRejectedValueOnce(refusal)
      .mockResolvedValueOnce(SUMMARY)
      .mockResolvedValue({ ...SUMMARY, count: 1, names: ['sid'], expired: 0 });
    const f = form(parse);
    type(f.cookies!, PASTE);
    expect(preview(f)).toBe('Reading the cookies...');
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    const refused = 'No cookie was read: Cookie header line 1: no domain';
    expect(preview(f)).toBe(refused);
    // The refusal stays while the URL is typed; Save waits for the new read.
    type(f.url, 'https://shop.example.com');
    expect(preview(f)).toBe(refused);
    expect(f.cookies?.validity.valid).toBe(false);
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    const read =
      '2 cookies read, 1 expired, from example.com, shop.example.com: sid, theme';
    expect(preview(f)).toBe(read);
    // So does a result, until the new read answers.
    type(f.url, 'https://shop.example.com/a');
    await jest.advanceTimersByTimeAsync(PREVIEW_MS - 1);
    expect(preview(f)).toBe(read);
    expect(f.cookies?.validity.valid).toBe(false);
    await jest.advanceTimersByTimeAsync(1);
    expect(preview(f)).toBe(
      '1 cookie read, from example.com, shop.example.com: sid'
    );
    expect(f.cookies?.validity.valid).toBe(true);
    type(f.cookies!, `${PASTE}\n`);
    expect(preview(f)).toBe('Reading the cookies...');
    f.dispose();
  });

  it('sends no read once the form is closed', async () => {
    jest.useFakeTimers();
    const parse = jest.fn().mockResolvedValue(SUMMARY);
    const f = form(parse);
    type(f.cookies!, PASTE);
    f.dispose();
    await jest.advanceTimersByTimeAsync(PREVIEW_MS);
    expect(parse).not.toHaveBeenCalled();
  });

  it('answers the type, the username and the pasted text in Add', () => {
    const f = form(jest.fn());
    type(f.name, 'shop/new');
    type(f.url, 'https://shop.example.com');
    f.cookies!.value = PASTE;
    expect(f.getValue()).toEqual({
      name: 'shop/new',
      username: '',
      url: 'https://shop.example.com',
      category: '',
      notes: '',
      type: 'cookies',
      cookies: PASTE
    });
    f.dispose();
  });

  it('lets Enter type a line break in the paste field', () => {
    const f = form(jest.fn());
    const reachedDialog = jest.fn();
    f.node.addEventListener('keydown', reachedDialog, true);
    f.cookies!.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })
    );
    expect(reachedDialog).not.toHaveBeenCalled();
    f.dispose();
  });

  describe('in Edit', () => {
    it('keeps the jar with an empty paste field, and Save is enabled', () => {
      const parse = jest.fn();
      const f = form(parse, SHOP);
      expect(labels(f)).toEqual([
        'Name',
        'Username',
        'URL',
        'Cookies',
        'Category',
        'Notes'
      ]);
      expect(f.cookies?.validity.valid).toBe(true);
      expect(preview(f)).toBe('Leave empty to keep the 2 cookies');
      // No cookies and no type: the server keeps the jar and the type.
      expect(f.getValue()).toEqual({
        name: 'shop/session',
        username: '',
        url: 'https://shop.example.com',
        category: 'web',
        notes: ''
      });
      expect(parse).not.toHaveBeenCalled();
      f.dispose();
    });

    it('enables Save when a paste that was not read is cleared, which keeps the jar', async () => {
      jest.useFakeTimers();
      const f = form(
        jest
          .fn()
          .mockRejectedValue(
            new VaultError(400, 'Cookie header line 1: no domain')
          ),
        SHOP
      );
      await jest.advanceTimersByTimeAsync(0);
      const save = saveGate(f);
      type(f.cookies!, 'sid=1');
      await jest.advanceTimersByTimeAsync(PREVIEW_MS);
      expect(save.disabled).toBe(true);
      type(f.cookies!, '');
      expect(save.disabled).toBe(false);
      expect(preview(f)).toBe('Leave empty to keep the 2 cookies');
      expect(f.getValue()).not.toHaveProperty('cookies');
      save.remove();
      f.dispose();
    });

    it('replaces the jar with a paste that reads', async () => {
      jest.useFakeTimers();
      const f = form(jest.fn().mockResolvedValue(SUMMARY), SHOP);
      type(f.cookies!, PASTE);
      await jest.advanceTimersByTimeAsync(PREVIEW_MS);
      expect(preview(f)).toBe(
        '2 cookies read, 1 expired, from example.com, shop.example.com: sid, theme. Save replaces the current cookies'
      );
      expect(f.getValue().cookies).toBe(PASTE);
      expect(f.getValue()).not.toHaveProperty('type');
      f.dispose();
    });

    it('says an empty paste keeps the headers too, and a paste that reads replaces them', async () => {
      jest.useFakeTimers();
      const f = form(jest.fn().mockResolvedValue(SUMMARY), APP);
      expect(preview(f)).toBe(
        'Leave empty to keep the 2 cookies and the 2 headers'
      );
      // A paste with no header of its own leaves the entry with none.
      type(f.cookies!, PASTE);
      await jest.advanceTimersByTimeAsync(PREVIEW_MS);
      expect(preview(f)).toBe(
        '2 cookies read, 1 expired, from example.com, shop.example.com: sid, theme. Save replaces the current cookies and headers'
      );
      f.dispose();
      const token = form(jest.fn(), TOKEN);
      expect(preview(token)).toBe('Leave empty to keep the 1 header');
      expect(token.cookies?.validity.valid).toBe(true);
      token.dispose();
    });

    it('answers only the URL when only the URL changed', async () => {
      mockLaunch.mockImplementation(async (dialog: any) => {
        dialog.options.body.url.value = 'https://shop.example.com/v2';
        return { button: { accept: true } };
      });
      const value = await editEntry(async () => 'x', SHOP, [], [], jest.fn());
      expect(value).toEqual({
        name: 'shop/session',
        url: 'https://shop.example.com/v2'
      });
    });
  });
});

describe('a cookie entry in the panel', () => {
  const ICON = '[data-icon="jupyterlab-passkey-extension:cookie"]';

  it('saves the cookie form through POST vault/entries, its preview read by the server', async () => {
    mockChooseType.mockResolvedValue('cookies');
    mockEditEntry.mockImplementation(async (...args: any[]) => {
      const parse = args[4];
      await parse(PASTE, 'https://shop.example.com');
      return {
        name: 'shop/new',
        url: 'https://shop.example.com',
        type: 'cookies',
        cookies: PASTE
      };
    });
    const api = fakeApi();
    const panel = await panelWith(api);
    pressAdd(panel);
    await flush();
    await flush();
    expect(api.parseCookies).toHaveBeenCalledWith(
      PASTE,
      'https://shop.example.com'
    );
    expect(api.add).toHaveBeenCalledWith('shop/new', {
      url: 'https://shop.example.com',
      type: 'cookies',
      cookies: PASTE
    });
  });

  it("shows a cookie icon on a cookie entry's row and none on a password entry's", async () => {
    const panel = await panelWith(fakeApi());
    expect(row(panel, 'nas/ugos').querySelector(ICON)).toBeNull();
    const icon = row(panel, 'shop/session').querySelector(ICON) as HTMLElement;
    expect(icon.classList).toContain('jp-PasskeyVaultPanel-rowIcon');
    expect(icon.getAttribute('aria-hidden')).toBe('true');
    // Before the name, in the column of the status dot.
    expect(icon.nextElementSibling?.className).toBe(
      'jp-PasskeyVaultPanel-rowName'
    );
  });

  it('shows the expired badge only when no cookie is left unexpired', async () => {
    const panel = await panelWith(fakeApi());
    const badge = (name: string) =>
      row(panel, name).querySelector('.jp-PasskeyVault-expired');
    expect(badge('nas/ugos')).toBeNull();
    // One expired cookie beside a session cookie: the jar still sends one.
    expect(badge('shop/session')).toBeNull();
    expect(badge('shop/stale')?.textContent).toBe('expired');
    expect(row(panel, 'shop/stale').getAttribute('aria-label')).toBe(
      'shop/stale, cookies, expired, never used'
    );
    expect(row(panel, 'shop/session').getAttribute('aria-label')).toBe(
      'shop/session, cookies, never used'
    );
  });

  it('shows no expired badge on the row of an entry with no cookie', async () => {
    const panel = await panelWith(
      fakeApi({ entries: jest.fn().mockResolvedValue([TOKEN, STALE]) })
    );
    const line = row(panel, 'api/token');
    expect(line.querySelector('.jp-PasskeyVault-expired')).toBeNull();
    expect(line.getAttribute('aria-label')).toBe(
      'api/token, cookies, never used'
    );
    expect(line.querySelector(ICON)).not.toBeNull();
    // The tick that draws a badge when a last cookie expires draws none here.
    (panel as any)._redrawAges();
    expect(line.querySelector('.jp-PasskeyVault-expired')).toBeNull();
    expect(
      row(panel, 'shop/stale').querySelector('.jp-PasskeyVault-expired')
    ).not.toBeNull();
  });

  it('draws the badge when the last cookie expires while the row stands', async () => {
    const soon: IEntry = {
      ...STALE,
      name: 'shop/soon',
      cookies: [{ domain: 'a.example', name: 'sid', expires: NOW + 30 }]
    };
    const panel = await panelWith(
      fakeApi({ entries: jest.fn().mockResolvedValue([soon]) })
    );
    const line = row(panel, 'shop/soon');
    expect(line.querySelector('.jp-PasskeyVault-expired')).toBeNull();
    const now = jest.spyOn(Date, 'now').mockReturnValue((NOW + 60) * 1000);
    try {
      (panel as any)._redrawAges();
    } finally {
      now.mockRestore();
    }
    expect(row(panel, 'shop/soon')).toBe(line);
    expect(line.querySelector('.jp-PasskeyVault-expired')).not.toBeNull();
  });

  it('opens the cookie form for a cookie entry in Edit, and the password form for a password entry', async () => {
    mockEditEntry.mockResolvedValue(null);
    const panel = await panelWith(fakeApi());
    for (const name of ['shop/session', 'nas/ugos']) {
      mockViewEntry.mockResolvedValueOnce('edit');
      row(panel, name).click();
      await flush();
      await flush();
    }
    expect(mockEditEntry.mock.calls[0][1]).toEqual(SHOP);
    expect(mockEditEntry.mock.calls[0][4]).toEqual(expect.any(Function));
    expect(mockEditEntry.mock.calls[1][4]).toBeUndefined();
  });
});

describe('the cookie entry popup', () => {
  const reveal = jest.fn();

  function view(entry: IEntry): EntryView {
    const v = new EntryView(entry, {
      proven: () => false,
      passkey: jest.fn(),
      reveal,
      typed: ['passphrase']
    });
    Widget.attach(v, document.body);
    return v;
  }

  /** The texts of a table's header cells and of its rows' cells. */
  function cells(table: HTMLTableElement): (string | null)[][] {
    return [table.tHead!.rows[0], ...Array.from(table.tBodies[0].rows)].map(r =>
      Array.from(r.cells).map(c => c.textContent)
    );
  }

  it('lists the kept header names under the cookie table, with no value and no eye', () => {
    const v = view({
      ...APP,
      // A value the list never carries: were one there, the table would not show it.
      value: HEADER_MARKER
    } as any);
    expect(labels(v)).toEqual([
      'Name',
      'Username',
      'URL',
      'Cookies',
      'Headers',
      'Category',
      'Notes'
    ]);
    const tables = v.node.querySelectorAll('table');
    expect(Array.from(tables).map(t => t.getAttribute('aria-label'))).toEqual([
      'Cookies',
      'Headers'
    ]);
    // The cookie table's markup: its class, its box, and a tooltip with the whole name.
    expect(tables[1].className).toBe(tables[0].className);
    expect(tables[1].parentElement?.className).toBe(
      'jp-PasskeyVaultForm-cookieBox'
    );
    expect(cells(tables[1])).toEqual([
      ['Name'],
      ['authorization'],
      ['x-csrf-token']
    ]);
    expect(tables[1].tBodies[0].rows[0].cells[0].title).toBe('authorization');
    // No eye, no button, and nothing that reads a value from the server.
    expect(v.node.querySelector('.jp-PasskeyVaultForm-eye')).toBeNull();
    expect(v.node.querySelectorAll('button')).toHaveLength(0);
    expect(v.node.querySelector('input[type="password"]')).toBeNull();
    expect(reveal).not.toHaveBeenCalled();
    expect(v.node.innerHTML).not.toContain(HEADER_MARKER);
    v.dispose();
  });

  it('shows no cookie table for an entry with no cookie, and its header names', () => {
    const v = view(TOKEN);
    expect(labels(v)).toEqual([
      'Name',
      'Username',
      'URL',
      'Headers',
      'Category',
      'Notes'
    ]);
    const tables = v.node.querySelectorAll('table');
    expect(tables).toHaveLength(1);
    expect(tables[0].getAttribute('aria-label')).toBe('Headers');
    expect(cells(tables[0])).toEqual([['Name'], ['Authorization']]);
    expect(v.node.querySelector('.jp-PasskeyVault-expired')).toBeNull();
    expect(v.node.querySelectorAll('button')).toHaveLength(0);
    v.dispose();
  });

  it("shows each cookie's domain, name and expiry, session with none, expired marked", () => {
    const v = view(SHOP);
    expect(labels(v)).toEqual([
      'Name',
      'Username',
      'URL',
      'Cookies',
      'Category',
      'Notes'
    ]);
    const table = v.node.querySelector('table') as HTMLTableElement;
    expect(
      Array.from(table.querySelectorAll('th')).map(th => th.textContent)
    ).toEqual(['Domain', 'Name', 'Expires']);
    const rows = Array.from(table.tBodies[0].rows).map(r =>
      Array.from(r.cells).map(c => c.textContent)
    );
    expect(rows).toEqual([
      ['shop.example.com', 'sid', 'session'],
      ['example.com', 'theme', '2001-09-09 01:46 UTC expired']
    ]);
    expect(
      table.tBodies[0].rows[1].querySelector('.jp-PasskeyVault-expired')
    ).not.toBeNull();
    expect(
      table.tBodies[0].rows[0].querySelector('.jp-PasskeyVault-expired')
    ).toBeNull();
    v.dispose();
  });

  it('has no eye and no password field, and shows no value', () => {
    const v = view({
      ...SHOP,
      // A value the list never carries: were one there, the table would not show it.
      cookies: [
        {
          domain: 'shop.example.com',
          name: 'sid',
          expires: null,
          value: MARKER
        }
      ] as any
    });
    expect(v.node.querySelector('.jp-PasskeyVaultForm-eye')).toBeNull();
    expect(v.node.querySelector('input[type="password"]')).toBeNull();
    expect(v.node.querySelectorAll('button')).toHaveLength(0);
    expect(v.node.innerHTML).not.toContain(MARKER);
    v.dispose();
  });
});

describe('rename in the edit form', () => {
  it('lets Edit change the name, and refuses a name another entry has under the field', () => {
    const f = new EntryForm(async () => 'x', LOGIN, ['shop/session']);
    Widget.attach(f, document.body);
    expect(f.name.readOnly).toBe(false);
    type(f.name, 'shop/session');
    expect(f.name.validity.valid).toBe(false);
    const help = f.name
      .closest('.jp-PasskeyVaultForm-field')!
      .querySelector('.jp-PasskeyVaultForm-help')!;
    expect(help.textContent).toBe('An entry named shop/session already exists');
    type(f.name, 'nas/renamed');
    expect(f.name.validity.valid).toBe(true);
    expect(help.textContent).toBe('');
    f.dispose();
  });

  it('answers the new name from editEntry, and opens on the name field', async () => {
    mockLaunch.mockImplementation(async (dialog: any) => {
      dialog.options.body.name.value = ' nas/renamed ';
      return { button: { accept: true } };
    });
    expect(await editEntry(async () => 'x', LOGIN)).toEqual({
      name: 'nas/renamed'
    });
    expect(mockLaunch.mock.calls[0][0].options.focusNodeSelector).toBe('input');
  });

  it('renames first, then writes the changed fields under the new name', async () => {
    mockViewEntry.mockResolvedValue('edit');
    mockEditEntry.mockResolvedValue({ name: 'nas/renamed', notes: 'rack 2' });
    const api = fakeApi();
    const panel = await panelWith(api);
    row(panel, 'nas/ugos').click();
    await flush();
    await flush();
    // The other entries' names are the ones taken.
    expect(mockEditEntry.mock.calls[0][2]).toEqual([
      'shop/session',
      'shop/stale'
    ]);
    expect(api.rename).toHaveBeenCalledWith('nas/ugos', 'nas/renamed');
    expect(api.edit).toHaveBeenCalledWith('nas/renamed', { notes: 'rack 2' });
    expect(api.rename.mock.invocationCallOrder[0]).toBeLessThan(
      api.edit.mock.invocationCallOrder[0]
    );
  });

  it('sends only the rename when only the name changed', async () => {
    mockViewEntry.mockResolvedValue('edit');
    mockEditEntry.mockResolvedValue({ name: 'shop/renamed' });
    const api = fakeApi();
    const panel = await panelWith(api);
    row(panel, 'shop/session').click();
    await flush();
    await flush();
    expect(api.rename).toHaveBeenCalledWith('shop/session', 'shop/renamed');
    expect(api.edit).not.toHaveBeenCalled();
  });

  it('writes nothing more when the server refuses a name taken meanwhile', async () => {
    mockViewEntry.mockResolvedValue('edit');
    mockEditEntry.mockResolvedValue({ name: 'other', notes: 'x' });
    const api = fakeApi({
      rename: jest
        .fn()
        .mockRejectedValue(
          new VaultError(409, "an entry named 'other' already exists")
        )
    });
    const panel = await panelWith(api);
    row(panel, 'nas/ugos').click();
    await flush();
    await flush();
    expect(api.edit).not.toHaveBeenCalled();
    expect(mockError).toHaveBeenCalledWith(
      "An entry named 'other' already exists.",
      { autoClose: false }
    );
  });
});
