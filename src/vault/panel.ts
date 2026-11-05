import { Notification } from '@jupyterlab/apputils';

import {
  addIcon,
  filterIcon,
  lockIcon,
  refreshIcon,
  settingsIcon,
  LabIcon
} from '@jupyterlab/ui-components';

import { Message } from '@lumino/messaging';

import { Widget } from '@lumino/widgets';

import { askSecret } from '../passphrase';

import { mapCeremonyError } from '../passkey-util';

import { trans } from '../trans';

import {
  ICapabilities,
  IEntry,
  ISlot,
  IStatus,
  NoAnswer,
  VaultApi,
  VaultError
} from './api';

import {
  ADD_MFA,
  askNewPassword,
  askProof,
  askUnlockCode,
  chooseFirstMethod,
  chooseUnlockMethod,
  confirmDelete,
  editEntry,
  NEW_RECOVERY,
  registerMfa,
  registerWithProof,
  sentence,
  UnlockMethod,
  unlockWithPair,
  viewEntry
} from './dialogs';

import {
  describeFailure,
  ipAddressAdvice,
  isIpAddress,
  matchingSlots,
  pairSlot,
  passkeyAssertion,
  passkeyPrf,
  shareUnlock,
  unlockWithPasskey,
  Unused
} from './webauthn';

/** How often a visible panel re-reads the vault state. */
export const REFRESH_MS = 15000;

/** Left out of the security view as detail; `vault status` still prints them. */
const CLI_ONLY: (keyof ICapabilities)[] = ['holder_ttl', 'container_isolated'];

/** What the body is drawn from: a change in any of it needs a full re-render. */
function shape(s: IStatus | null): string {
  return JSON.stringify([
    s?.initialized,
    s?.unlocked,
    // A passkey by its id; a typed slot, which has none, by its type, date and KDF.
    s?.slots.map(x => `${x.cred_id ?? `${x.type} ${x.created}`} ${x.kdf}`),
    s?.authenticator?.created,
    s?.settings,
    s?.rotation,
    s?.revision,
    s?.holder.name,
    s?.holder.capabilities,
    s?.holder.notice,
    s?.path
  ]);
}

/** A slot's creation time to the minute, so two passkeys added the same day differ. */
function addedAt(created: string | undefined): string {
  return `${(created ?? '').slice(0, 16).replace('T', ' ')} UTC`;
}

/**
 * The same time as two parts of a row's detail line, the day and the minute: the
 * line wraps between its parts, never inside one.
 */
function dayAndMinute(created: string | undefined): [string, string] {
  const [day, ...minute] = addedAt(created).split(' ');
  return [day, minute.join(' ')];
}

/**
 * When the unlock password and the authenticator app were added, or undefined with
 * neither. The two are added together; a vault written by 1.1.28 to 1.1.31 can hold
 * one without the other.
 */
function mfaAdded(s: IStatus): string | undefined {
  return (
    s.authenticator?.created ??
    s.slots.find(x => x.type === 'password')?.created
  );
}

/**
 * How many of the vault's typed slots use each key derivation. Passkey slots carry
 * no KDF and count in neither.
 */
function encryptionOf(slots: ISlot[]): string {
  const modern = slots.filter(x => x.kdf === 'argon2id').length;
  const legacy = slots.filter(x => x.kdf === 'scrypt').length;
  return `Argon2id (${modern}), scrypt (${legacy})`;
}

export function formatRemaining(seconds: number): string {
  if (seconds < 60) {
    return `${Math.ceil(seconds)}s`;
  }
  // Rounded up: a vault that is still unlocked never reads "0m left".
  const minutes = Math.ceil(seconds / 60);
  const h = Math.floor(minutes / 60);
  return h > 0 ? `${h}h ${minutes % 60}m` : `${minutes}m`;
}

/**
 * How long ago `stamp` was, with the thresholds and labels of the AI sessions
 * panel; "never" when the entry carries no usable stamp.
 */
export function formatAgo(stamp?: string): string {
  const at = stamp ? Date.parse(stamp) : NaN;
  if (!Number.isFinite(at)) {
    return 'never';
  }
  const age = Date.now() - at;
  if (age < 60_000) {
    return 'now';
  }
  if (age < 3_600_000) {
    return `${Math.floor(age / 60_000)}m ago`;
  }
  if (age < 86_400_000) {
    return `${Math.floor(age / 3_600_000)}h ago`;
  }
  if (age < 30 * 86_400_000) {
    return `${Math.floor(age / 86_400_000)}d ago`;
  }
  if (age < 365 * 86_400_000) {
    return `${Math.floor(age / (30 * 86_400_000))}mo ago`;
  }
  return `${Math.floor(age / (365 * 86_400_000))}y ago`;
}

/** An entry row's tooltip: the name, then each field and time that is set, and Last used always (never when unused); never the password. */
export function entryTooltip(e: IEntry): string {
  return [
    e.name,
    e.username && `Username: ${e.username}`,
    e.url && `URL: ${e.url}`,
    e.category && `Category: ${e.category}`,
    `Last used: ${formatAgo(e.used)}`,
    e.updated && `Updated: ${formatAgo(e.updated)}`,
    e.created && `Created: ${formatAgo(e.created)}`
  ]
    .filter(Boolean)
    .join('\n');
}

/** An unlock duration in hours and minutes, a zero part left out: 4h, 1h 30m, 45m. */
export function formatMinutes(minutes: number): string {
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return [h ? `${h}h` : '', m ? `${m}m` : ''].filter(Boolean).join(' ');
}

export interface IVaultPanelOptions {
  api: VaultApi;
  /** Opens the Settings Editor at the vault settings. */
  openSettings: () => void;
  /** The hostname passkeys are matched against; the tab's own by default. */
  host?: string;
  /** Called with each state the panel reads and the time that read began. */
  onRead?: (status: IStatus, since: number) => void;
}

/** The banner's line of a success or a hint: `at` is when it was set. */
type Message_ = { text: string; at: number } | null;

/** How long an armed two-step button ignores clicks: a double-click never confirms. */
export const ARM_DELAY_MS = 500;

/** An armed two-step button lapses this long after arming: always 5 s. */
export const ARM_LAPSE_MS = 5000;

/**
 * An action whose request got no answer, or got a refusal while its final read
 * failed: it may have landed. The vault's state shows whether it did.
 */
const NOT_CONFIRMED = 'Not confirmed - no server answer; wait for the panel';

/** The same for a named action whose outcome the vault's state does not show. */
const AGAIN = 'not confirmed - retry when the server answers';

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className: string,
  text?: string
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.className = className;
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

const C = 'jp-PasskeyVaultPanel';

/**
 * The sidebar tab icon while a vault exists: the lock of `lockIcon` in the colour
 * class of the other sidebar icons. `lockIcon` is one shade dimmer (`jp-icon4`),
 * which reads as inactive, and stays the tab icon while there is no vault.
 * It is also the Settings Editor icon, which schema/vault.json names, so the two
 * names stay equal.
 */
const vaultIcon = new LabIcon({
  name: 'jupyterlab-passkey-extension:vault',
  svgstr:
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" viewBox="0 0 24 23"><path class="jp-icon3" fill="#616161" d="M12 17a2 2 0 0 0 2-2 2 2 0 0 0-2-2 2 2 0 0 0-2 2 2 2 0 0 0 2 2m6-9a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V10a2 2 0 0 1 2-2h1V6a5 5 0 0 1 5-5 5 5 0 0 1 5 5v2zm-6-5a3 3 0 0 0-3 3v2h6V6a3 3 0 0 0-3-3"/></svg>'
});

/** The harmonica's values, from the design system's Harmonica navigation chapter. */
const EXPAND_STEP = 160; // px of free space one wheel event may take
const HOLD_MS = 438; // the held pull before a switch
const GESTURE_GAP_MS = 220; // a pause that starts a new gesture
const PULL_STEP = 3; // px the neighbour eases in per event
const PULL_MAX = 22; // the cap of the pull preview
const PULL_RELEASE_MS = 160; // idle before the spring starts
const FOLD_MS = 400; // the fold from one category to the next
const SETTLE_MS = 250; // wheel ignored after a switch
const WHEEL_LINE_PX = 16; // px in one line-mode wheel delta

/** One category of the main list: its band, and the viewport that scrolls its rows. */
interface ICategory {
  category: string;
  section: HTMLDivElement;
  header: HTMLButtonElement;
  caret: HTMLSpanElement;
  viewport: HTMLDivElement;
}

/**
 * A path as one element per part, each ending in its slash, so that the line breaks
 * after a slash: a hyphen at a line end would read as a hyphenation mark, not as part
 * of the name.
 */
function pathValue(path: string): HTMLElement {
  const value = el('span', `${C}-pathValue`);
  path.split('/').forEach((part, i, parts) => {
    value.append(el('span', '', i < parts.length - 1 ? `${part}/` : part));
  });
  return value;
}

/** The vault sidebar panel: create, unlock, browse and manage the vault. */
export class VaultPanel extends Widget {
  constructor(options: IVaultPanelOptions) {
    super();
    this._api = options.api;
    this._openSettings = options.openSettings;
    this._host = options.host ?? location.hostname;
    this._onRead = options.onRead;

    this.id = 'jp-passkey-vault';
    this.addClass(C);
    this.title.icon = lockIcon;
    this.title.caption = trans.__('Vault');

    const header = el('div', `${C}-header`);
    header.appendChild(el('span', `${C}-headerTitle`, 'Vault'));
    this._lockButton = this._iconButton(lockIcon, 'Lock the vault', () =>
      this._act(() => this._api.lock())
    );
    this._addButton = this._iconButton(addIcon, 'Add an entry', () =>
      this._add()
    );
    this._filterButton = this._iconButton(filterIcon, 'Filter entries', () =>
      this._toggleFilter()
    );
    this._refreshButton = this._iconButton(refreshIcon, 'Refresh', () =>
      this.refresh()
    );
    this._cogButton = this._iconButton(
      settingsIcon,
      'Vault settings and security',
      () => {
        this._view = this._view === 'settings' ? 'main' : 'settings';
        this._disarm();
        this._render();
      }
    );
    header.append(
      this._lockButton,
      this._addButton,
      this._filterButton,
      this._refreshButton,
      this._cogButton
    );

    this._statusLine = el('div', `${C}-status`);
    this._banner = el('div', `${C}-banner`);
    this._banner.setAttribute('role', 'status');
    this._body = el('div', `${C}-body`);
    // The status row's padding is measured from this probe, in every view.
    this._gutterProbe = el('div', `${C}-gutterProbe`);
    this._gutterProbe.setAttribute('aria-hidden', 'true');

    this._filter = el('input', `${C}-filterInput`);
    this._filter.type = 'search';
    this._filter.placeholder = trans.__('Filter entries...');
    this._filter.setAttribute(
      'aria-label',
      trans.__('Filter by name, username or URL')
    );
    this._filter.dataset.focusKey = 'filter';
    this._filter.addEventListener('input', () => this._renderList());
    this._list = el('div', `${C}-list`);

    // The banner is below the body: a line that appears or expires shrinks the body
    // from the bottom and never moves the entries under the pointer.
    this.node.append(
      header,
      this._statusLine,
      this._body,
      this._gutterProbe,
      this._banner
    );
    // The harmonica's gesture is global: the wheel anywhere over the panel drives the
    // category in focus, never the one under the pointer.
    this.node.addEventListener('wheel', this._onWheel, { passive: false });
    this._render();
  }

  /** Re-read the state and, when unlocked, the entry list. */
  async refresh(): Promise<void> {
    const before = shape(this._status);
    const since = Date.now();
    try {
      this._status = await this._api.status();
      this._readAt = Date.now();
      this._onRead?.(this._status, since);
      this._entries = this._status.unlocked ? await this._api.entries() : [];
      this._entriesRead = true;
      this._readError = null;
    } catch (e) {
      if (e instanceof VaultError && e.status === 423 && this._status) {
        // Both reads answered; the vault locked between them.
        this._status = { ...this._status, unlocked: false, remaining: null };
        this._readError = null;
        this._entries = [];
        this._entriesRead = false;
      } else {
        this._readError = describeFailure(e);
        // The last entries stay drawn while the banner says why.
        this._entriesRead = false;
      }
    }
    // Not while an action runs: its line reports its own change.
    if (!this._busy && shape(this._status) !== before) {
      this._dropStale();
    }
    if (this._busy) {
      // An action runs, maybe behind a dialog: a redraw now would replace the element
      // the dialog returns focus to. The action redraws when it ends (`_act`).
      this._renderStatus();
    } else {
      this._render();
    }
  }

  protected onAfterShow(msg: Message): void {
    void this.refresh();
    this._stopTimer();
    this._timer = window.setInterval(() => void this._tick(), REFRESH_MS);
    document.addEventListener('visibilitychange', this._onVisibility);
  }

  protected onBeforeHide(msg: Message): void {
    this._stopTimer();
    this._stopHarmonica();
    // A panel shown again starts in its main view, not in the settings it was left in.
    if (this._view === 'settings') {
      this._view = 'main';
      this._disarm();
      // An action that runs redraws when it ends (`_act`).
      if (!this._busy) {
        this._render();
      }
    }
  }

  /** Moved to the other sidebar, the panel is detached with no hide message. */
  protected onBeforeDetach(msg: Message): void {
    this._stopTimer();
    this._stopHarmonica();
  }

  /** A splitter drag changes the free space and the scrollbar without a render. */
  protected onResize(msg: Widget.ResizeMessage): void {
    if (this._sections.length > 0) {
      this._stopHarmonica();
      this._layoutHeights();
    } else {
      this._syncGutter();
    }
  }

  // -- state reads ----------------------------------------------------------

  /** Changed elsewhere (the CLI, another tab): a line about the old state is stale. */
  private _dropStale(): void {
    this._message = null;
  }

  /** Read the state as the panel's own poll does, with the panel shown or hidden. */
  poll(): Promise<void> {
    return this._tick();
  }

  private async _tick(): Promise<void> {
    if (document.hidden) {
      // A hidden tab reads nothing, as JupyterLab's own polls do: the panel adds no
      // traffic through JupyterHub's proxy from a background tab.
      return;
    }
    if (this._busy) {
      // The action reads and redraws when it ends. A read now could write an older
      // status back, or take the action's change for one made elsewhere; the age
      // repaint sends no request and rebuilds nothing the open form depends on.
      this._renderStatus();
      this._redrawAges();
      return;
    }
    const before = shape(this._status);
    const since = Date.now();
    try {
      this._status = await this._api.status();
      this._readAt = Date.now();
      this._onRead?.(this._status, since);
      if (this._busy) {
        // An action began during the read: it reads and redraws when it ends.
        this._renderStatus();
        return;
      }
    } catch (e) {
      // A failed read: the local countdown still runs out on time. The next answer reads
      // everything again (below), which clears the line.
      this._readError = describeFailure(e);
      this._renderStatus();
      this._renderBanner();
      return;
    }
    if (shape(this._status) !== before) {
      this._dropStale();
      await this.refresh();
      return;
    }
    if (this._readError) {
      // The last read failed: try again now the server answers.
      await this.refresh();
      return;
    }
    // A success line stays one full refresh period.
    if (this._message && Date.now() - this._message.at >= REFRESH_MS) {
      this._message = null;
    }
    this._renderStatus();
    this._renderBanner();
    // The ages stay true between reads. No `_render`: it rebuilds the body, and a
    // filter being typed would lose its focus and caret.
    if (this._status?.unlocked && this._view === 'main') {
      this._redrawAges();
    }
  }

  /** Redraw each rendered row's age from the entries last read. */
  private _redrawAges(): void {
    const rows = Array.from(
      this._body.querySelectorAll<HTMLElement>(`.${C}-rowLine`)
    );
    for (const line of rows) {
      const key = line.dataset.focusKey ?? '';
      const name = key.startsWith('row:') ? key.slice('row:'.length) : '';
      const entry = this._entries.find(e => e.name === name);
      if (entry) {
        this._paintAge(entry, line);
      }
    }
  }

  /**
   * Said during a proof's passkey request, which the browser shows as a sign-in: the
   * user would otherwise expect to create the new passkey there. Cleared once the
   * proof is in (`clearLine`).
   */
  private _sayProofFirst(s: IStatus): void {
    if (matchingSlots(s.slots, this._host).length > 0) {
      this._message = {
        text: 'First confirm with a passkey you already have',
        at: Date.now()
      };
      this._renderBanner();
    }
  }

  /**
   * Clear the banner's line: the proof is in, or a step was done in this tab outside
   * the panel (a CLI's unlock or new passkey) - an action in this tab, which clears
   * the line and the failure notification as the panel's own next action does.
   */
  clearLine(): void {
    this._message = null;
    this._dismissFailure();
    this._renderBanner();
  }

  /**
   * Report a failure as a notification with no timeout, in place of the panel's last
   * one: amber (`warn`) or red. A line in the panel would follow the user into every
   * view; the user dismisses a notification, and the next action does. Public for the
   * refusal of a Password and passkey unlock a CLI raises in this tab, which the CLI
   * may no longer wait for.
   */
  fail(text: string, warn: boolean): void {
    this._dismissFailure();
    this._failure = (warn ? Notification.warning : Notification.error)(text, {
      autoClose: false
    });
  }

  private _dismissFailure(): void {
    if (this._failure !== null) {
      Notification.dismiss(this._failure);
      this._failure = null;
    }
  }

  private _remaining(): number | null {
    const s = this._status;
    if (!s || !s.unlocked || s.remaining === null) {
      return null;
    }
    return s.remaining - (Date.now() - this._readAt) / 1000;
  }

  private _stopTimer(): void {
    if (this._timer !== null) {
      window.clearInterval(this._timer);
      this._timer = null;
    }
    document.removeEventListener('visibilitychange', this._onVisibility);
  }

  /** The tab shown again: read at once, not up to 15 s later (`_tick` skips a hide). */
  private readonly _onVisibility = (): void => void this._tick();

  // -- actions --------------------------------------------------------------

  /**
   * Run an action, report the outcome, then re-read. Success shows `done` in the
   * banner, or `done` of what the action resolved to; an action that resolves to
   * `false` was cancelled, and reports nothing. A
   * failure is a notification (`fail`), amber for a passkey the browser made but the
   * vault did not take and for a dismissed passkey prompt (the user's choice), red
   * otherwise. `unconfirmed` is its text when the request may have landed. One at a
   * time: a second click while one runs is ignored - a second WebAuthn request would
   * fail and report an error over the first one's success.
   */
  private async _act(
    action: () => Promise<unknown>,
    done?: string | ((result: unknown) => string),
    unconfirmed = NOT_CONFIRMED
  ): Promise<void> {
    if (this._busy) {
      return;
    }
    this._busy = true;
    this.node.classList.add('jp-mod-busy');
    this.node.setAttribute('aria-busy', 'true');
    this._message = null;
    this._dismissFailure();
    this._disarm();
    let unanswered = false;
    let answered = false;
    let failure: { text: string; warn: boolean } | null = null;
    try {
      const result = await action();
      this._message =
        result !== false && done
          ? {
              text: typeof done === 'string' ? done : done(result),
              at: Date.now()
            }
          : null;
    } catch (e) {
      // A proof that fails leaves its hint (`_sayProofFirst`) with no request running.
      this._message = null;
      unanswered = e instanceof NoAnswer;
      answered = e instanceof VaultError && e.status > 0;
      failure = {
        text: e instanceof VaultError ? e.short : describeFailure(e),
        warn: e instanceof Unused || mapCeremonyError(e) === 'not-allowed'
      };
    }
    try {
      // Read the new state while still busy: a tick in between would take the
      // action's own change for one made elsewhere and drop the line above.
      await this.refresh();
      if (failure && (unanswered || (answered && this._readError !== null))) {
        // No answer came, or an answer came (maybe not the vault's: a proxy page) while
        // the server could not be read after it: the request may have landed. A failed
        // read's own line says why. A refusal made in the page never left it.
        failure.text = unconfirmed;
      }
    } finally {
      this._busy = false;
      this.node.classList.remove('jp-mod-busy');
      this.node.removeAttribute('aria-busy');
      this._render();
      if (failure) {
        this.fail(sentence(failure.text), failure.warn);
      }
    }
  }

  private _create(s: IStatus): Promise<void> {
    return this._act(
      async () => {
        const { accepted, value } = await askSecret(
          NEW_RECOVERY,
          2,
          'Create vault'
        );
        if (!accepted || value === null) {
          return false;
        }
        try {
          await this._api.init(value);
        } catch (e) {
          // A lost answer: the vault may have been written all the same. A read
          // settles it, and a vault that exists goes on to the choice of a method.
          const read =
            e instanceof NoAnswer
              ? await this._api.status().catch(() => null)
              : null;
          if (!read?.initialized) {
            throw e;
          }
        }
        await chooseFirstMethod(
          this._api,
          value,
          s.settings.password_min_length,
          this._host
        );
      },
      'Vault created',
      // Its state shows whether it landed: no advice to create again.
      'Vault creation not confirmed - the server stopped answering'
    );
  }

  private _unlockPasskey(): Promise<void> {
    return this._act(async () => {
      // Only the locked view offers this, and it renders from a status already read.
      await shareUnlock(() =>
        unlockWithPasskey(this._api, this._status as IStatus, this._host)
      );
    });
  }

  /**
   * Unlock with the unlock password and a code of the authenticator app: the two are
   * one unlock method. The code is asked last, because it stays right for less than
   * a minute.
   */
  private _unlockPassword(s: IStatus): Promise<void> {
    return this._act(async () => {
      const { accepted, value } = await askSecret(
        'Enter the unlock password',
        1,
        'Unlock vault'
      );
      if (!accepted || value === null) {
        return;
      }
      // A vault written by 1.1.28 to 1.1.31 can hold a password and no app.
      const code = s.authenticator ? await askUnlockCode() : undefined;
      if (code !== null) {
        await this._api.unlockPassword(value, code);
      }
    });
  }

  /** Unlock with Password and passkey: the password, then the passkey. */
  private _unlockPair(slot: ISlot): Promise<void> {
    return this._act(() => unlockWithPair(this._api, slot));
  }

  /**
   * Add an unlock method: the user chooses it, then that method's own steps run.
   * The choice is made before the panel is busy, so backing out leaves no line.
   */
  private async _addMethod(s: IStatus): Promise<void> {
    if (this._busy) {
      return;
    }
    const mfa = mfaAdded(s);
    const kind = await chooseUnlockMethod({
      passkey: isIpAddress(this._host)
        ? { unavailable: sentence(ipAddressAdvice(s.slots)) }
        : {},
      mfa: mfa
        ? { unavailable: `Added ${addedAt(mfa)}. Remove it to add another.` }
        : {}
    });
    if (kind === 'passkey') {
      await this._addPasskey(s);
    } else if (kind === 'mfa') {
      await this._addMfa(s);
    }
  }

  private _addPasskey(s: IStatus): Promise<void> {
    return this._act(
      async () => {
        this._sayProofFirst(s);
        const proof = await askProof(
          this._api,
          s,
          this._host,
          'Add passkey',
          true
        );
        this.clearLine();
        return (
          proof !== null && registerWithProof(this._api, proof, '', this._host)
        );
      },
      // A passkey with no PRF is stored as Password and passkey.
      stored =>
        stored === 'password-passkey'
          ? 'Password and passkey added'
          : 'Passkey added',
      // Only a failed read before the browser's `create` reaches this text, so no
      // passkey was made and a retry cannot add a second one.
      `Passkey add ${AGAIN}`
    );
  }

  /**
   * Add the unlock password and the authenticator app, which are one unlock method:
   * the password, then a proof, then the app. The app's code is typed last,
   * because the request checks it and a code stays right for less than a minute.
   */
  private _addMfa(s: IStatus): Promise<void> {
    return this._act(
      async () => {
        const password = await askNewPassword(s.settings.password_min_length);
        if (password === null) {
          return false;
        }
        this._sayProofFirst(s);
        const proof = await askProof(this._api, s, this._host, ADD_MFA, true);
        this.clearLine();
        return (
          proof !== null &&
          registerMfa(this._api, password, proof, this._host, ADD_MFA)
        );
      },
      'Password and authenticator app added',
      `Password and app add ${AGAIN}`
    );
  }

  private _changeRecovery(s: IStatus): Promise<void> {
    return this._act(
      async () => {
        this._sayProofFirst(s);
        const proof = await askProof(
          this._api,
          s,
          this._host,
          'Change recovery passphrase',
          true
        );
        this.clearLine();
        if (proof === null) {
          return false;
        }
        const { accepted, value } = await askSecret(
          'Enter the new recovery passphrase, and store it offline',
          2,
          'Change recovery passphrase'
        );
        if (!accepted || value === null) {
          return false;
        }
        await this._api.replaceRecovery(value, proof);
      },
      'Recovery passphrase changed',
      `Recovery change ${AGAIN}`
    );
  }

  /**
   * Rotate the data key: the entries and the authenticator secret are re-sealed under
   * a new key. The proof is a passkey or the recovery passphrase; a code alone holds
   * no key, so none is offered. The vault must be unlocked.
   */
  private _rotate(s: IStatus): Promise<void> {
    return this._act(
      async () => {
        this._sayProofFirst(s);
        const proof = await askProof(
          this._api,
          s,
          this._host,
          'Rotate data key',
          false
        );
        this.clearLine();
        if (proof === null) {
          return false;
        }
        await this._api.rotate(proof);
      },
      'Data key rotated',
      `Key rotation ${AGAIN}`
    );
  }

  private _unlockRecovery(): Promise<void> {
    return this._act(async () => {
      const { accepted, value } = await askSecret(
        'Enter the recovery passphrase',
        1,
        'Unlock vault'
      );
      if (accepted && value !== null) {
        await this._api.unlockRecovery(value);
      }
    });
  }

  private _add(): Promise<void> {
    if (this._lockedMeanwhile()) {
      return Promise.resolve();
    }
    return this._act(async () => {
      const value = await editEntry(
        () => this._api.generate(),
        undefined,
        this._entries.map(e => e.name),
        this._entries.map(e => e.category)
      );
      if (value) {
        const { name, ...fields } = value;
        await this._api.add(name, fields);
        // The new row shows whatever the filter was.
        this._filter.value = '';
      }
    });
  }

  private _edit(entry: IEntry): Promise<void> {
    return this._act(
      async () => {
        // Only the fields the form changed (see editEntry): a field changed elsewhere
        // meanwhile stays.
        const value = await editEntry(
          () => this._api.generate(),
          entry,
          [],
          this._entries.map(e => e.category)
        );
        if (value) {
          const { name, ...changed } = value;
          if (Object.keys(changed).length > 0) {
            await this._api.edit(name, changed);
            // The saved row shows whatever the filter was.
            this._filter.value = '';
          }
        }
      },
      undefined,
      `Change to ${entry.name} ${AGAIN}`
    );
  }

  private _delete(entry: IEntry): Promise<void> {
    return this._act(async () => {
      if (!(await confirmDelete(entry.name))) {
        return false;
      }
      await this._api.remove(entry.name);
    }, `Deleted ${entry.name}`);
  }

  /** The entry's popup, then the Edit or Delete chosen there. */
  private async _open(entry: IEntry): Promise<void> {
    // The popup opens only in the unlocked view, which renders from a status read.
    const status = this._status as IStatus;
    const choice = await viewEntry(entry, {
      proven: () => this._api.proven,
      passkey: async () => {
        const pair =
          matchingSlots(status.slots, this._host).length === 0
            ? pairSlot(status.slots)
            : undefined;
        if (pair) {
          // No dialog for the click: a failure opens the row of typed proofs.
          return {
            assertion: await passkeyAssertion(pair, await this._api.challenge())
          };
        }
        const { credId, prf } = await passkeyPrf(status, this._host);
        return { cred_id: credId, prf };
      },
      reveal: async proof => {
        const value = await this._api.revealPassword(entry.name, proof);
        // The server stamped the use: read the row again behind the open popup.
        void this.refresh();
        return value;
      },
      typed: [
        ...(status.authenticator ? (['code'] as const) : []),
        ...(status.slots.some(x => x.type === 'password')
          ? (['password'] as const)
          : []),
        'passphrase'
      ]
    });
    // Back to the row (a redraw meanwhile keeps its focus key), the filter when the
    // entry is gone, Refresh when the list is: a form opened next returns focus there.
    this._restoreFocus(`row:${entry.name}`);
    if (choice === null || this._lockedMeanwhile()) {
      return;
    }
    // The entry as last read: it may have changed while the popup was open.
    const current = this._entries.find(e => e.name === entry.name);
    if (!current && this._entriesRead) {
      this.fail(`${entry.name} was deleted.`, true);
      this._render();
      return;
    }
    if (choice === 'edit') {
      await this._edit(current ?? entry);
    } else if (choice === 'delete') {
      await this._delete(entry);
    }
  }

  /**
   * True when the unlock ran out since the last read - the popup was open, or the
   * 15 s read has not come yet. The panel then draws the locked view, with its
   * unlock, and says so, in place of a form that could not save.
   */
  private _lockedMeanwhile(): boolean {
    if ((this._remaining() ?? 0) > 0) {
      return false;
    }
    this.fail('Vault locked - unlock and retry.', true);
    this._render();
    return true;
  }

  /**
   * Show or hide the filter field, as the filter button of the AI assistants panels
   * does. Hiding clears the filter, so no filter the user cannot see narrows the rows.
   */
  private _toggleFilter(): void {
    this._filterShown = !this._filterShown;
    if (!this._filterShown) {
      this._filter.value = '';
    }
    this._render();
    if (this._filterShown) {
      this._filter.focus();
    }
  }

  /**
   * A two-step button: the first click arms it, the second acts. Clicks within
   * ARM_DELAY_MS of arming are ignored, so a double-click never confirms; the arm
   * lapses ARM_LAPSE_MS after arming, so a forgotten arm never acts.
   */
  private _twoStep(
    key: string,
    label: string,
    action: () => Promise<void>
  ): HTMLButtonElement {
    const armed = this._armed === key;
    const button = this._button(
      armed ? 'Confirm' : label,
      () => {
        if (this._armed !== key) {
          if (this._armTimer !== null) {
            window.clearTimeout(this._armTimer);
          }
          this._armed = key;
          this._armedAt = Date.now();
          this._armTimer = window.setTimeout(() => {
            this._armTimer = null;
            if (this._armed === key) {
              this._armed = null;
              this._armedAt = 0;
              this._render();
            }
          }, ARM_LAPSE_MS);
          this._render();
        } else if (Date.now() - this._armedAt >= ARM_DELAY_MS) {
          this._disarm();
          void action();
        }
      },
      false,
      key
    );
    button.classList.add('jp-mod-warn');
    if (armed) {
      button.classList.add('jp-mod-confirm');
    }
    return button;
  }

  /** Disarm a two-step button and stop its lapse. */
  private _disarm(): void {
    if (this._armTimer !== null) {
      window.clearTimeout(this._armTimer);
      this._armTimer = null;
    }
    this._armed = null;
    this._armedAt = 0;
  }

  // -- rendering ------------------------------------------------------------

  private _render(): void {
    const focus = this._focusKey();
    // A redraw rebuilds the list: a fold or a spring has nothing left to act on.
    this._stopHarmonica();
    this._sections = [];
    this._baseHeights = [];
    this.node.classList.remove('jp-mod-harmonica');
    // First: a countdown that ran out marks the state locked, and the body follows.
    this._renderStatus();
    const s = this._status;
    const unlocked = !!s?.unlocked;
    // Every header icon keeps its place on every view; one that cannot act here
    // is disabled, so a click aimed at it does nothing and Lock never moves.
    const onList = this._view === 'main';
    this._lockButton.disabled = !unlocked;
    this._addButton.disabled = !unlocked || !onList;
    this._filterButton.disabled = !unlocked || !onList;
    // The pressed state is drawn with a class, which says nothing to a screen reader.
    this._filterButton.classList.toggle('jp-mod-active', this._filterShown);
    this._filterButton.setAttribute('aria-pressed', String(this._filterShown));
    this._cogButton.classList.toggle(
      'jp-mod-active',
      this._view === 'settings'
    );
    this._cogButton.setAttribute(
      'aria-pressed',
      String(this._view === 'settings')
    );
    this._renderBanner();

    this._body.replaceChildren();
    if (s) {
      if (this._view === 'settings') {
        this._renderSettings(s);
      } else if (!s.initialized) {
        this._renderCreate(s);
      } else if (!s.unlocked) {
        this._renderLocked(s);
      } else {
        if (this._filterShown) {
          const box = el('div', `${C}-filterBox`);
          box.appendChild(this._filter);
          this._body.appendChild(box);
        }
        this._body.appendChild(this._list);
        this._renderList();
      }
    }
    this._restoreFocus(focus);
    this._syncGutter();
  }

  /**
   * The scrollbar width the status row outside takes as extra right padding. It comes
   * from the probe that always shows a scrollbar, so the row keeps one place in every
   * view and section.
   */
  private _syncGutter(): void {
    // Measured: an overlay scrollbar takes no width, so a fixed value would be wrong.
    const gutter =
      this._gutterProbe.offsetWidth - this._gutterProbe.clientWidth;
    this.node.style.setProperty('--jp-passkey-vault-gutter', `${gutter}px`);
  }

  private _renderBanner(): void {
    const shown = JSON.stringify([
      this._view === 'main' ? this._status?.holder.notice : null,
      this._message?.text,
      this._message?.at,
      this._readError
    ]);
    if (shown === this._bannerShown) {
      // role=status announces every change: an unchanged banner is left alone.
      return;
    }
    this._bannerShown = shown;
    this._banner.replaceChildren();
    // The fallback notice as the server wrote it: what happened and why, in one line.
    if (this._status?.holder.notice && this._view === 'main') {
      this._banner.appendChild(
        el('div', `${C}-notice`, this._status.holder.notice)
      );
    }
    if (this._message) {
      const line = el('div', `${C}-message`, this._message.text);
      line.dataset.kind = 'info';
      this._banner.appendChild(line);
    }
    if (this._readError) {
      const line = el('div', `${C}-message`, this._readError);
      line.dataset.kind = 'error';
      this._banner.appendChild(line);
    }
    if (this._sections.length > 0) {
      // The banner sits below the body that holds the list, so a line appearing or
      // expiring changes the list's height; the fold's next frame rewrites both
      // heights and its last frame re-lays out, so a mid-fold change is skipped here
      // to keep the entering band from blanking its viewport and flipping its
      // aria-expanded for one frame.
      if (!this._folding) {
        this._layoutHeights();
      }
    }
  }

  /** The key of the control that has focus in this panel, to find it again after a render. */
  private _focusKey(): string | undefined {
    const active = document.activeElement as HTMLElement | null;
    return active && this.node.contains(active)
      ? active.dataset.focusKey
      : undefined;
  }

  private _restoreFocus(key: string | undefined): void {
    if (key === undefined) {
      return;
    }
    const nodes = Array.from(
      this.node.querySelectorAll<HTMLElement>('[data-focus-key]')
    );
    // The focused control can be gone (a deleted entry, a lock): keep focus in the
    // panel rather than dropping it to the page - on the filter, or on Refresh, never
    // on a control whose next Space or Enter would start an action.
    const target =
      nodes.find(
        node =>
          node.dataset.focusKey === key && !(node as HTMLButtonElement).disabled
      ) ?? (this._filter.isConnected ? this._filter : this._refreshButton);
    target.focus();
  }

  private _renderStatus(): void {
    const s = this._status;
    this._statusLine.replaceChildren();
    if (!s) {
      return;
    }
    const icon = s.initialized ? vaultIcon : lockIcon;
    if (this.title.icon !== icon) {
      this.title.icon = icon;
    }
    const remaining = this._remaining();
    const unlocked = s.unlocked && remaining !== null && remaining > 0;
    const diode = el('span', `${C}-diode`);
    diode.classList.toggle('jp-mod-active', unlocked);
    const text = !s.initialized
      ? 'No vault'
      : unlocked
        ? `Unlocked, ${formatRemaining(remaining)} left`
        : 'Locked';
    const holder = el('span', `${C}-holder`, s.holder.name);
    holder.title = s.holder.name;
    this._statusLine.append(diode, el('span', `${C}-stateText`, text), holder);
    if (s.unlocked && !unlocked) {
      // The local countdown ran out before the next read: take it as locked, then
      // read. Marking it first means a failed read cannot bring this branch back
      // round and read again without end.
      this._status = { ...s, unlocked: false, remaining: null };
      // Not while an action runs: it reads when it ends (see `_tick`).
      if (!this._busy) {
        void this.refresh();
      }
    }
  }

  private _renderCreate(s: IStatus): void {
    const section = el('div', `${C}-empty`);
    if (isIpAddress(this._host)) {
      // Said before the passphrase is typed: here the vault gets no passkey.
      section.appendChild(el('p', `${C}-hint`, sentence(ipAddressAdvice())));
    }
    section.appendChild(
      this._button('Create vault', () => this._create(s), true)
    );
    this._body.appendChild(section);
  }

  private _renderLocked(s: IStatus): void {
    const section = el('div', `${C}-empty`);
    const usable = matchingSlots(s.slots, this._host).length > 0;
    const pair = pairSlot(s.slots);
    // Password and passkey added at another port or scheme of this host: a passkey
    // with no PRF added here would end in the refusal of a second one.
    const elsewhere = s.slots.find(
      x => x.type === 'password-passkey' && x.rp_id === this._host
    );
    if (usable) {
      section.appendChild(
        this._button('Unlock with passkey', () => this._unlockPasskey(), true)
      );
    } else if (!pair) {
      section.appendChild(
        el(
          'p',
          `${C}-hint`,
          isIpAddress(this._host)
            ? sentence(ipAddressAdvice(s.slots))
            : elsewhere
              ? `Password and passkey added at ${elsewhere.origin} - open JupyterLab there`
              : 'No passkey configured'
        )
      );
    }
    if (pair) {
      section.appendChild(
        this._button(
          'Unlock with password and passkey',
          () => this._unlockPair(pair),
          !usable
        )
      );
    }
    if (s.slots.some(x => x.type === 'password')) {
      section.appendChild(
        this._button(
          'Unlock with password',
          () => this._unlockPassword(s),
          // The way in where this hostname has no passkey.
          !usable
        )
      );
    }
    // A link, not a button: the passkey is the way in, the passphrase the fallback.
    const recovery = this._button('Use recovery passphrase', () =>
      this._unlockRecovery()
    );
    recovery.className = `${C}-link`;
    section.appendChild(recovery);
    this._body.appendChild(section);
  }

  private _renderList(): void {
    const focus = this._focusKey();
    this._fillList();
    this._restoreFocus(focus);
    // Filtering can drop the list below the overflow threshold and remove the scrollbar.
    this._syncGutter();
  }

  private _fillList(): void {
    this._stopHarmonica();
    this._sections = [];
    this._baseHeights = [];
    const query = this._filter.value.trim().toLowerCase();
    const shown = this._entries.filter(
      e =>
        !query ||
        [e.name, e.username, e.url].some(v => v.toLowerCase().includes(query))
    );
    this._list.replaceChildren();
    if (shown.length === 0) {
      this._openCategory = null;
      this.node.classList.remove('jp-mod-harmonica');
      this._list.appendChild(
        el(
          'p',
          `${C}-hint`,
          !this._entriesRead
            ? 'The entries could not be read.'
            : this._entries.length
              ? 'No entry matches the filter.'
              : 'No entries yet.'
        )
      );
      this._syncGutter();
      return;
    }
    const groups = new Map<string, IEntry[]>();
    for (const e of shown) {
      const key = e.category || 'Uncategorised';
      groups.set(key, [...(groups.get(key) ?? []), e]);
    }
    const categories = [...groups.keys()].sort((a, b) => a.localeCompare(b));
    // The open category stays open after a filter change while it has matches;
    // otherwise the first with matches opens.
    const focus = Math.max(0, categories.indexOf(this._openCategory ?? ''));
    this._focus = focus;
    this._openCategory = categories[focus];
    categories.forEach((category, i) => {
      const group = groups.get(category) as IEntry[];
      // A section, as in the cog view; the separator is drawn only while it is folded, so the open section draws none.
      const section = el('div', `${C}-section`);
      // A band: the same button with aria-expanded as the AI assistants panels' headers.
      const header = el('button', `${C}-sectionHeader`);
      header.type = 'button';
      header.dataset.focusKey = `category:${category}`;
      const caret = el('span', `${C}-caret`);
      // Decorative - the state it draws is already on the header's aria-expanded.
      caret.setAttribute('aria-hidden', 'true');
      header.append(
        caret,
        el('span', `${C}-sectionLabel`, `${category} (${group.length})`)
      );
      header.addEventListener('click', () => this._openSection(i));
      // The viewport owns the scrollbar at the panel's right edge; the rows scroll
      // inside it. Collapsed viewports keep their rows for the pull preview.
      const viewport = el('div', `${C}-viewport`);
      // Pre-set inert so the first _freeSpace counts the folded border the [inert] rule paints; _apply sets inert only after the measurement.
      if (i !== this._focus) {
        viewport.setAttribute('inert', '');
      }
      for (const e of group) {
        viewport.appendChild(this._row(e));
      }
      section.append(header, viewport);
      this._list.appendChild(section);
      this._sections.push({ category, section, header, caret, viewport });
    });
    this.node.classList.add('jp-mod-harmonica');
    this._layoutHeights();
  }

  // -- harmonica ------------------------------------------------------------

  /** One category takes the list's height; the pull is a render offset on top of it. */
  private _layoutHeights(): void {
    const free = this._freeSpace();
    this._baseHeights = this._sections.map((_, i) =>
      i === this._focus ? free : 0
    );
    this._apply();
    this._syncGutter();
  }

  /** The rows' space: the list less each section's band and divider, clamped at 0. */
  private _freeSpace(): number {
    let bands = 0;
    for (const s of this._sections) {
      bands += s.section.offsetHeight - s.viewport.offsetHeight;
    }
    return Math.max(0, this._list.clientHeight - bands);
  }

  /** Draw the base heights, with the pull as an offset on its two boundary sections. */
  private _apply(): void {
    const short = this._freeSpace() <= 0;
    this._list.classList.toggle('jp-mod-short', short);
    this._sections.forEach((s, i) => {
      // Boundary tests read the base height, never the rendered one.
      const base = this._baseHeights[i] ?? 0;
      let extra = 0;
      if (this._pull.amount > 0) {
        if (i === this._pull.from) {
          extra = -this._pull.amount;
        } else if (i === this._pull.to) {
          extra = this._pull.amount;
        }
      }
      // A panel too short for the bands: the open category keeps its natural height
      // and the list scrolls, so no band is hidden.
      s.viewport.style.height =
        short && i === this._focus ? '' : `${Math.max(0, base + extra)}px`;
      // A pull shows a folded neighbour without opening it: openness is the base height.
      const open = short ? i === this._focus : base > 0;
      s.header.setAttribute('aria-expanded', String(open));
      s.caret.textContent = open ? '▾' : '▸';
      // Collapsed rows stay rendered for the pull preview but leave the tab order.
      if (open) {
        s.viewport.removeAttribute('inert');
      } else {
        s.viewport.setAttribute('inert', '');
      }
    });
  }

  /** Open a category from its band: every other one folds to its band at once. */
  private _openSection(i: number): void {
    if (this._folding) {
      return;
    }
    this._stopHarmonica();
    this._focus = i;
    this._openCategory = this._sections[i].category;
    this._layoutHeights();
    this._sections[i].viewport.scrollTop = 0;
  }

  /** The focused category takes up to `step` px more, from the other open sections. */
  private _grow(step: number): boolean {
    let want = Math.min(
      step,
      this._freeSpace() - (this._baseHeights[this._focus] ?? 0)
    );
    if (want <= 0) {
      return false;
    }
    const others = this._baseHeights
      .map((h, i) => (i !== this._focus && h > 0 ? i : -1))
      .filter(i => i >= 0);
    const total = others.reduce((sum, i) => sum + this._baseHeights[i], 0);
    if (total <= 0) {
      return false;
    }
    want = Math.min(want, total);
    let left = want;
    others.forEach((i, n) => {
      const take = Math.min(
        n === others.length - 1
          ? left
          : Math.round((want * this._baseHeights[i]) / total),
        this._baseHeights[i],
        left
      );
      this._baseHeights[i] -= take;
      left -= take;
    });
    this._baseHeights[this._focus] += want - left;
    this._apply();
    return true;
  }

  /** Ease the boundary neighbour in by a step, and spring back when the wheel stops. */
  private _pullTo(from: number, to: number): void {
    this._pull.from = from;
    this._pull.to = to;
    this._pull.amount = Math.min(PULL_MAX, this._pull.amount + PULL_STEP);
    this._apply();
    if (this._pullTimer !== null) {
      window.clearTimeout(this._pullTimer);
    }
    this._pullTimer = window.setTimeout(
      () => this._springBack(),
      PULL_RELEASE_MS
    );
  }

  private _clearPull(): void {
    if (this._pullTimer !== null) {
      window.clearTimeout(this._pullTimer);
      this._pullTimer = null;
    }
    if (this._pull.amount > 0) {
      this._pull = { from: -1, to: -1, amount: 0 };
      this._apply();
    }
  }

  /** The damped spring of the pull preview; it moves no scroll position. */
  private _springBack(): void {
    this._pullTimer = null;
    const from = this._pull.amount;
    if (from <= 0 || this._folding) {
      return;
    }
    let start: number | null = null;
    const frame = (t: number): void => {
      if (start === null) {
        start = t;
      }
      const x = (t - start) / 1000;
      const a = from * Math.exp(-7 * x) * Math.cos(16 * x);
      if (Math.abs(a) < 0.4 || x > 0.7) {
        this._pull = { from: -1, to: -1, amount: 0 };
        this._frame = null;
        this._apply();
        return;
      }
      this._pull.amount = Math.abs(a);
      this._apply();
      this._frame = window.requestAnimationFrame(frame);
    };
    this._frame = window.requestAnimationFrame(frame);
  }

  /** Fold `from` into its band while `to` opens over FOLD_MS, then settle. */
  private _foldInto(to: number, dir: number): void {
    if (to < 0 || to >= this._sections.length) {
      return;
    }
    this._folding = true;
    const from = this._focus;
    const total = this._baseHeights[from] ?? 0;
    let start: number | null = null;
    const frame = (t: number): void => {
      if (start === null) {
        start = t;
      }
      const p = Math.min(1, (t - start) / FOLD_MS);
      const e = 1 - Math.pow(1 - p, 3);
      const span = Math.min(total, this._freeSpace());
      this._baseHeights[from] = Math.round(span * (1 - e));
      this._baseHeights[to] = Math.round(span * e);
      this._apply();
      // The last rows stay in view through the fold: the leaving viewport pins to
      // its bottom; the entering one to its top downward, its bottom upward.
      this._sections[from].viewport.scrollTop =
        this._sections[from].viewport.scrollHeight;
      this._sections[to].viewport.scrollTop =
        dir > 0 ? 0 : this._sections[to].viewport.scrollHeight;
      if (p < 1) {
        this._frame = window.requestAnimationFrame(frame);
        return;
      }
      this._focus = to;
      this._openCategory = this._sections[to].category;
      this._hold = null;
      this._armedSwitch = null;
      this._folding = false;
      this._frame = null;
      this._settleUntil = Date.now() + SETTLE_MS;
      this._layoutHeights();
    };
    this._frame = window.requestAnimationFrame(frame);
  }

  /** The next category with rows in a direction, or -1. */
  private _openFrom(i: number, dir: number): number {
    for (let j = i; j >= 0 && j < this._sections.length; j += dir) {
      if ((this._baseHeights[j] ?? 0) > 0) {
        return j;
      }
    }
    return -1;
  }

  /** Stop a fold or a spring and drop the pull; the next render rebuilds the list. */
  private _stopHarmonica(): void {
    if (this._frame !== null) {
      window.cancelAnimationFrame(this._frame);
      this._frame = null;
    }
    if (this._pullTimer !== null) {
      window.clearTimeout(this._pullTimer);
      this._pullTimer = null;
    }
    this._folding = false;
    this._hold = null;
    this._armedSwitch = null;
    this._pull = { from: -1, to: -1, amount: 0 };
  }

  /**
   * The harmonica's one gesture: the wheel anywhere over the panel drives the category
   * in focus - expand, scroll, pull, then fold. Other views keep their own scrolling.
   */
  private readonly _onWheel = (e: WheelEvent): void => {
    if (
      this._view !== 'main' ||
      !this._status?.unlocked ||
      this._sections.length === 0
    ) {
      return;
    }
    if (!e.deltaY) {
      return;
    }
    const now = Date.now();
    if (this._folding || now < this._settleUntil) {
      // A fold, and the settle after it, swallows the carried momentum.
      e.preventDefault();
      return;
    }
    if (this._freeSpace() <= 0) {
      // The bands alone do not fit: the list scrolls natively, as before.
      return;
    }
    // A gap before this event means a new gesture, not the tail of the last one.
    const newBurst = now - this._lastWheel > GESTURE_GAP_MS;
    this._lastWheel = now;
    const dir = e.deltaY > 0 ? 1 : -1;
    e.preventDefault();
    // Firefox mouse wheels report lines, not pixels; the native scroll is already off.
    const dy =
      e.deltaMode === WheelEvent.DOM_DELTA_LINE
        ? e.deltaY * WHEEL_LINE_PX
        : e.deltaY;
    let i = this._focus;
    if ((this._baseHeights[i] ?? 0) === 0) {
      i = this._openFrom(i, dir);
      if (i < 0) {
        return;
      }
      this._focus = i;
    }
    const step = Math.min(Math.abs(dy) || 100, EXPAND_STEP);
    // 1. The focused category takes the whole list first.
    if (this._grow(step)) {
      this._hold = null;
      this._armedSwitch = null;
      this._clearPull();
      return;
    }
    // 2. Then its rows scroll.
    const viewport = this._sections[i].viewport;
    const base = this._baseHeights[i] ?? 0;
    const maxTop = viewport.scrollHeight - base;
    const canScroll =
      base > 12 &&
      (dir > 0 ? viewport.scrollTop < maxTop - 1 : viewport.scrollTop > 1);
    if (canScroll) {
      this._hold = null;
      this._armedSwitch = null;
      this._clearPull();
      viewport.scrollTop += dy;
      return;
    }
    // 3. At the end of the rows the neighbour eases in, so the gesture shows what it
    // pulls on. A hold switches, or a fresh gesture after stopping: a wide swipe
    // that reaches the end stops there.
    const to = i + dir;
    if (to < 0 || to >= this._sections.length) {
      this._clearPull();
      return;
    }
    this._pullTo(i, to);
    if (dir < 0) {
      this._sections[to].viewport.scrollTop =
        this._sections[to].viewport.scrollHeight;
    }
    if (
      this._armedSwitch &&
      this._armedSwitch.dir === dir &&
      this._armedSwitch.i === i &&
      newBurst
    ) {
      this._armedSwitch = null;
      this._hold = null;
      this._clearPull();
      this._foldInto(to, dir);
      return;
    }
    if (!this._hold || this._hold.dir !== dir || this._hold.i !== i) {
      this._hold = { dir, i, since: now };
      this._armedSwitch = { dir, i };
      return;
    }
    if (now - this._hold.since < HOLD_MS) {
      return;
    }
    this._armedSwitch = null;
    this._hold = null;
    this._clearPull();
    this._foldInto(to, dir);
  };

  /** A row is the entry's name, username and last-used age; a click or Enter opens its popup. */
  private _row(e: IEntry): HTMLElement {
    const line = el('button', `${C}-rowLine`);
    line.type = 'button';
    line.dataset.focusKey = `row:${e.name}`;
    line.setAttribute('aria-haspopup', 'dialog');
    line.append(
      el('span', `${C}-rowName`, e.name),
      el('span', `${C}-rowUser`, e.username),
      el('span', `${C}-rowAge`)
    );
    line.addEventListener('click', () => void this._open(e));
    this._paintAge(e, line);
    return line;
  }

  /**
   * Draw an entry's age on its row: the age text, the recent and stale classes, the
   * aria-label's part and the tooltip. The tick runs it again while the row stands,
   * so an age that crosses a threshold changes without a redraw.
   */
  private _paintAge(e: IEntry, line: HTMLElement): void {
    const ago = formatAgo(e.used);
    const age = e.used ? Date.now() - Date.parse(e.used) : NaN;
    // The AI sessions panel's thresholds; never used counts as older than any age, so it dims.
    line.classList.toggle('jp-mod-recentlyActive', age < 60_000);
    line.classList.toggle(
      'jp-mod-stale',
      Number.isNaN(age) || age > 7 * 86_400_000
    );
    const label = e.username ? `${e.name}, ${e.username}` : e.name;
    const ageText = e.used ? `last used ${ago}` : 'never used';
    line.setAttribute('aria-label', `${label}, ${ageText}`);
    line.title = entryTooltip(e);
    const span = line.querySelector<HTMLElement>(`.${C}-rowAge`);
    if (span) {
      span.textContent = ago;
    }
  }

  private _renderSettings(s: IStatus): void {
    const security = this._section('Security');
    const h = s.holder;
    // Short values here; the explanations are the tooltips, and `vault status`
    // prints them all.
    // The holder's family (memory), with the mechanism (memory/memfd_secret) in
    // the tooltip.
    const about = `${h.name} - ${h.about}`;
    security.append(
      this._pair(
        'Key holder',
        h.name.split('/')[0],
        h.notice ? `${about}. ${h.notice}` : about
      ),
      this._pair('Protection', h.summary, h.protection)
    );
    // Every capability reads yes when the key is safer: yes is green, no amber.
    for (const d of h.details.filter(x => !CLI_ONLY.includes(x.key))) {
      const on = h.capabilities[d.key];
      const row = this._pair(d.label, on ? 'yes' : 'no', d.text);
      row.classList.add('jp-PasskeyVaultPanel-capability');
      row.dataset.capability = d.key;
      row.dataset.protection = on ? 'present' : 'missing';
      security.appendChild(row);
    }

    const methods = this._section('Unlock methods');
    if (!s.initialized) {
      methods.appendChild(el('p', `${C}-hint`, 'Create the vault first.'));
    } else {
      // Removing needs an unlocked vault; adding and changing need a proof, not an
      // unlock, so their buttons are offered locked as well.
      const remove = (
        key: string,
        request: () => Promise<void>,
        done: string
      ): HTMLButtonElement | undefined =>
        s.unlocked
          ? this._twoStep(key, 'Remove', () => this._act(request, done))
          : undefined;
      for (const slot of s.slots.filter(x => x.type === 'passkey')) {
        const detail = ['Passkey, added', ...dayAndMinute(slot.created)];
        methods.appendChild(
          this._method(
            'passkey',
            slot.label ?? '',
            slot.rp_id === this._host
              ? detail
              : [...detail, `on ${slot.rp_id}`],
            remove(
              `passkey:${slot.cred_id}`,
              () => this._api.removePasskey(slot.cred_id as string),
              'Passkey removed'
            )
          )
        );
      }
      const mfa = mfaAdded(s);
      if (mfa) {
        const [day, minute] = dayAndMinute(mfa);
        // A vault written by 1.1.28 to 1.1.31 can hold one without the other.
        const whole =
          s.authenticator && s.slots.some(x => x.type === 'password');
        const half = s.authenticator
          ? 'App only, added'
          : 'Password only, added';
        methods.appendChild(
          this._method(
            'mfa',
            'Password and authenticator app',
            whole ? [`Added ${day}`, minute] : [half, day, minute],
            remove(
              'mfa',
              () => this._api.removeMfa(),
              'Password and authenticator app removed'
            )
          )
        );
      }
      for (const slot of s.slots.filter(x => x.type === 'password-passkey')) {
        const detail = [
          'Added',
          ...dayAndMinute(slot.created),
          slot.label ?? ''
        ];
        methods.appendChild(
          this._method(
            'pair',
            'Password and passkey',
            slot.origin === location.origin
              ? detail
              : [...detail, `on ${slot.origin}`],
            remove(
              'pair',
              () => this._api.removePasskey(slot.cred_id as string),
              'Password and passkey removed'
            )
          )
        );
      }
      // Always there: the vault is created with it, and it is changed, never removed.
      const change = this._button(
        'Change',
        () => this._changeRecovery(s),
        false,
        'recovery'
      );
      change.setAttribute('aria-label', trans.__('Change recovery passphrase'));
      methods.appendChild(
        this._method('recovery', 'Recovery passphrase', [], change)
      );
      if (
        !s.unlocked &&
        (s.authenticator || s.slots.some(x => x.type !== 'recovery'))
      ) {
        methods.appendChild(
          el('p', `${C}-hint`, 'Unlock the vault to remove an unlock method.')
        );
      }
      methods.appendChild(
        this._button('Add unlock method', () => this._addMethod(s))
      );
    }

    const sections = [security, methods];
    if (s.rotation) {
      const key = this._section('Data key');
      key.append(
        this._pair(
          'Created',
          s.rotation.created
            ? addedAt(s.rotation.created)
            : 'at the next unlock'
        ),
        this._pair(
          'Age',
          s.rotation.age_days === null
            ? 'none yet'
            : `${s.rotation.age_days} ${s.rotation.age_days === 1 ? 'day' : 'days'}`
        ),
        this._pair(
          'Period',
          s.rotation.period_days === 0
            ? 'off'
            : `${s.rotation.period_days} ${s.rotation.period_days === 1 ? 'day' : 'days'}`
        ),
        this._pair('Rotation due', s.rotation.due ? 'yes' : 'no')
      );
      // The server rotates only an unlocked vault.
      if (s.unlocked) {
        key.appendChild(this._button('Rotate data key', () => this._rotate(s)));
      } else if (s.rotation.due) {
        key.appendChild(
          el('p', `${C}-hint`, 'Unlock the vault to rotate the data key.')
        );
      }
      sections.push(key);
    }

    // The values in effect, read-only: the server's configuration file holds them.
    const settings = this._section('Settings');
    const period = s.rotation?.period_days ?? s.settings.rotate_days;
    settings.append(
      this._pair('Unlock duration', formatMinutes(s.settings.unlock_minutes)),
      this._pair('Reveal window', `${s.settings.reveal_seconds}s`),
      this._pair(
        'Shortest unlock password',
        `${s.settings.password_min_length} characters`
      ),
      this._pair('Key encryption', encryptionOf(s.slots)),
      this._pair(
        'Key rotation',
        period === 0 ? 'off' : `${period} ${period === 1 ? 'day' : 'days'}`
      ),
      this._pathPair('Vault file', s.path),
      this._button('Open settings', () => this._openSettings())
    );

    this._body.append(...sections, settings);
  }

  // -- small builders ---------------------------------------------------------

  private _section(title: string): HTMLElement {
    const section = el('div', `${C}-section`);
    section.appendChild(el('div', `${C}-sectionHeader`, title));
    return section;
  }

  /**
   * An unlock method's row: its name over a line of detail, and its one action.
   * Each part of the detail stays whole when the line wraps, so a date never breaks
   * at its hyphen. `kind` is for a stylesheet or a test to find the row by.
   */
  private _method(
    kind: 'recovery' | UnlockMethod,
    name: string,
    detail: string[],
    action?: HTMLButtonElement
  ): HTMLElement {
    const row = el('div', `${C}-method`);
    row.dataset.method = kind;
    const text = el('div', `${C}-methodText`);
    text.appendChild(el('div', `${C}-rowName`, name));
    if (detail.length > 0) {
      const line = el('div', `${C}-rowUser`);
      detail.forEach((part, i) =>
        line.append(i ? ' ' : '', el('span', '', part))
      );
      text.appendChild(line);
    }
    row.appendChild(text);
    if (action) {
      row.appendChild(action);
    }
    return row;
  }

  /** A label over a path on its own line. */
  private _pathPair(label: string, path: string): HTMLElement {
    const row = el('div', `${C}-pathPair`);
    row.append(el('div', `${C}-pairLabel`, label), pathValue(path));
    return row;
  }

  /** A label and a short value; `details`, when given, is the row's tooltip. */
  private _pair(label: string, value: string, details?: string): HTMLElement {
    const row = el('div', `${C}-pair`);
    if (details) {
      row.title = details;
    }
    row.append(
      el('span', `${C}-pairLabel`, label),
      el('span', `${C}-pairValue`, value)
    );
    return row;
  }

  private _button(
    label: string,
    onClick: () => void | Promise<void>,
    primary = false,
    focusKey = label
  ): HTMLButtonElement {
    const button = el(
      'button',
      `jp-mod-styled ${C}-button${primary ? ' jp-mod-accept' : ''}`,
      label
    );
    button.type = 'button';
    button.dataset.focusKey = focusKey;
    button.addEventListener('click', () => void onClick());
    return button;
  }

  private _iconButton(
    icon: LabIcon,
    title: string,
    onClick: () => void | Promise<void>
  ): HTMLButtonElement {
    const button = el('button', `${C}-iconButton`);
    button.type = 'button';
    button.title = title;
    button.setAttribute('aria-label', title);
    button.dataset.focusKey = title;
    button.appendChild(icon.element({ tag: 'span' }));
    button.addEventListener('click', () => void onClick());
    return button;
  }

  private readonly _api: VaultApi;
  private readonly _openSettings: () => void;
  private readonly _host: string;
  private readonly _onRead?: (status: IStatus, since: number) => void;
  private readonly _lockButton: HTMLButtonElement;
  private readonly _addButton: HTMLButtonElement;
  private readonly _filterButton: HTMLButtonElement;
  private readonly _cogButton: HTMLButtonElement;
  private readonly _refreshButton: HTMLButtonElement;
  private readonly _statusLine: HTMLDivElement;
  private readonly _banner: HTMLDivElement;
  private readonly _body: HTMLDivElement;
  private readonly _gutterProbe: HTMLDivElement;
  private readonly _filter: HTMLInputElement;
  private readonly _list: HTMLDivElement;
  private _status: IStatus | null = null;
  private _readAt = 0;
  private _entries: IEntry[] = [];
  private _view: 'main' | 'settings' = 'main';
  private _filterShown = false;
  /** The category open at rest; a filter change keeps it while it has matches. */
  private _openCategory: string | null = null;
  private _sections: ICategory[] = [];
  private _baseHeights: number[] = [];
  private _focus = 0;
  /** The pull preview: an offset on the two boundary sections, never a base height. */
  private _pull = { from: -1, to: -1, amount: 0 };
  private _pullTimer: number | null = null;
  private _hold: { dir: number; i: number; since: number } | null = null;
  private _armedSwitch: { dir: number; i: number } | null = null;
  private _lastWheel = 0;
  private _folding = false;
  private _settleUntil = 0;
  private _frame: number | null = null;
  private _armed: string | null = null;
  private _bannerShown = '';
  private _entriesRead = true;
  private _armedAt = 0;
  private _armTimer: number | null = null;
  private _busy = false;
  private _message: Message_ = null;
  /** The id of the notification of the last failed action, until it is dismissed. */
  private _failure: string | null = null;
  /** Why the last read failed; the next successful read clears it. */
  private _readError: string | null = null;
  private _timer: number | null = null;
}
