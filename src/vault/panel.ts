import {
  addIcon,
  lockIcon,
  refreshIcon,
  settingsIcon,
  LabIcon
} from '@jupyterlab/ui-components';

import { Message } from '@lumino/messaging';

import { Widget } from '@lumino/widgets';

import { askSecret } from '../passphrase';

import { mapCeremonyError } from '../passkey-util';

import {
  ICapabilities,
  IEntry,
  IStatus,
  NoAnswer,
  VaultApi,
  VaultError
} from './api';

import {
  askProof,
  confirmDelete,
  editEntry,
  registerWithProof,
  viewEntry
} from './dialogs';

import {
  describeFailure,
  ipAddressAdvice,
  isIpAddress,
  matchingSlots,
  revealWithPasskey,
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
    s?.slots.map(x => x.cred_id),
    s?.settings.unlock_minutes,
    s?.revision,
    s?.holder.name,
    s?.holder.capabilities,
    s?.holder.notice,
    s?.path
  ]);
}

/** A lower-case message as a sentence for the panel. */
function sentence(text: string): string {
  return `${text[0].toUpperCase()}${text.slice(1)}.`;
}

/** A slot's creation time to the minute, so two passkeys added the same day differ. */
function addedAt(created: string | undefined): string {
  return `${(created ?? '').slice(0, 16).replace('T', ' ')} UTC`;
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
}

/** An action's or a guard's banner line: `at` is when it was set. */
type Message_ = {
  kind: 'error' | 'warn' | 'info';
  text: string;
  at: number;
  /** Kept when a read finds the vault changed: nothing else shows the outcome. */
  keep?: boolean;
} | null;

/**
 * An action that did part of its work: reported as a warning, not an error. `unused`
 * when the rest left a passkey the browser made and the vault did not take.
 */
class PartlyDone extends Error {
  constructor(
    message: string,
    readonly unused: boolean
  ) {
    super(message);
  }
}

/** How long an armed two-step button ignores clicks: a double-click never confirms. */
export const ARM_DELAY_MS = 500;

/**
 * An action whose request got no answer, or got a refusal while its final read
 * failed: it may have landed.
 */
const NOT_CONFIRMED = 'Not confirmed by the vault';

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

    this.id = 'jp-passkey-vault';
    this.addClass(C);
    this.title.icon = lockIcon;
    this.title.caption = 'Vault';

    const header = el('div', `${C}-header`);
    header.appendChild(el('span', `${C}-headerTitle`, 'Vault'));
    this._lockButton = this._iconButton(lockIcon, 'Lock the vault', () =>
      this._act(() => this._api.lock())
    );
    this._addButton = this._iconButton(addIcon, 'Add an entry', () =>
      this._add()
    );
    this._refreshButton = this._iconButton(refreshIcon, 'Refresh', () =>
      this.refresh()
    );
    this._cogButton = this._iconButton(
      settingsIcon,
      'Vault settings and security',
      () => {
        this._view = this._view === 'settings' ? 'main' : 'settings';
        this._armed = null;
        this._render();
      }
    );
    header.append(
      this._lockButton,
      this._addButton,
      this._refreshButton,
      this._cogButton
    );

    this._statusLine = el('div', `${C}-status`);
    this._banner = el('div', `${C}-banner`);
    this._banner.setAttribute('role', 'status');
    this._body = el('div', `${C}-body`);

    this._filter = el('input', `${C}-filterInput`);
    this._filter.type = 'search';
    this._filter.placeholder = 'Filter entries';
    this._filter.setAttribute('aria-label', 'Filter by name, username or URL');
    this._filter.dataset.focusKey = 'filter';
    this._filter.addEventListener('input', () => this._renderList());
    this._list = el('div', `${C}-list`);

    // The banner is below the body: a line that appears or expires shrinks the body
    // from the bottom and never moves the entries under the pointer.
    this.node.append(header, this._statusLine, this._body, this._banner);
    this._render();
  }

  /**
   * The vault state as last read. The unlock command reads it so the WebAuthn call
   * is not behind a network read: some browsers let a click's user activation lapse.
   */
  get status(): IStatus | null {
    return this._status;
  }

  /** Re-read the state and, when unlocked, the entry list. */
  async refresh(): Promise<void> {
    const before = shape(this._status);
    try {
      this._status = await this._api.status();
      this._readAt = Date.now();
      this._entries = this._status.unlocked ? await this._api.entries() : [];
      this._entriesRead = true;
      this._readError = null;
    } catch (e) {
      if (e instanceof VaultError && e.status === 423 && this._status) {
        // Both reads answered; the vault locked between them.
        this._status = { ...this._status, unlocked: false, remaining: null };
        this._readError = null;
      } else {
        this._readError = describeFailure(e);
      }
      this._entries = [];
      this._entriesRead = false;
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
  }

  /** Moved to the other sidebar, the panel is detached with no hide message. */
  protected onBeforeDetach(msg: Message): void {
    this._stopTimer();
  }

  // -- state reads ----------------------------------------------------------

  /** Changed elsewhere (the CLI, another tab): a line about the old state is stale. */
  private _dropStale(): void {
    if (!this._message?.keep) {
      this._message = null;
    }
  }

  private async _tick(): Promise<void> {
    if (document.hidden) {
      // A hidden tab reads nothing, as JupyterLab's own polls do: the panel adds no
      // traffic through JupyterHub's proxy from a background tab.
      return;
    }
    if (this._busy) {
      // The action reads and redraws when it ends. A read now could write an older
      // status back, or take the action's change for one made elsewhere.
      this._renderStatus();
      return;
    }
    const before = shape(this._status);
    try {
      this._status = await this._api.status();
      this._readAt = Date.now();
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
    if (
      this._message?.kind === 'info' &&
      Date.now() - this._message.at >= REFRESH_MS
    ) {
      this._message = null;
    }
    this._renderStatus();
    this._renderBanner();
  }

  /**
   * Said during a proof's passkey request, which the browser shows as a sign-in: the
   * user would otherwise expect to create the new passkey there. Cleared once the
   * proof is in (`clearLine`).
   */
  private _sayProofFirst(s: IStatus): void {
    if (matchingSlots(s.slots, this._host).length > 0) {
      this._message = {
        kind: 'info',
        text: 'First confirm with a passkey you already have',
        at: Date.now()
      };
      this._renderBanner();
    }
  }

  /**
   * Clear the banner's line: the proof is in, or a step was done in this tab outside
   * the panel (a CLI's unlock or registration) - an action in this tab, which clears
   * any line as the panel's own next action does.
   */
  clearLine(): void {
    this._message = null;
    this._renderBanner();
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
   * Run an action, report the outcome in the banner, then re-read. An action that
   * resolves to `false` was cancelled, and reports nothing. One at a time: a second
   * click while one runs is ignored - a second WebAuthn request would fail and
   * report an error over the first one's success. `keep` names an action whose
   * outcome the vault's state does not show (a passkey made, the recovery passphrase
   * changed): its line outlives a change made elsewhere. `onlyUnused` keeps only a
   * line about a passkey the browser made: Create's and Register's other outcomes show
   * in the vault's passkey slots.
   */
  private async _act(
    action: () => Promise<unknown>,
    done?: string,
    keep?: string,
    onlyUnused = false
  ): Promise<void> {
    if (this._busy) {
      return;
    }
    this._busy = true;
    this.node.classList.add('jp-mod-busy');
    this.node.setAttribute('aria-busy', 'true');
    this._message = null;
    this._armed = null;
    let unanswered = false;
    let answered = false;
    let unused = false;
    try {
      const result = await action();
      this._message =
        result !== false && done
          ? { kind: 'info', text: done, at: Date.now() }
          : null;
    } catch (e) {
      // Amber, not red: a step done in part, a passkey the browser made but the vault
      // did not take, and a dismissed passkey prompt (the user's choice). A kept line
      // can outlive the moment, so it names its action unless it says what it reports.
      unanswered = e instanceof NoAnswer;
      unused = e instanceof Unused || (e instanceof PartlyDone && e.unused);
      answered = e instanceof VaultError && e.status > 0;
      this._message =
        e instanceof PartlyDone || e instanceof Unused
          ? { kind: 'warn', text: e.message, at: Date.now() }
          : {
              kind: mapCeremonyError(e) === 'not-allowed' ? 'warn' : 'error',
              text: keep
                ? `${keep}: ${describeFailure(e)}`
                : describeFailure(e),
              at: Date.now()
            };
    }
    if (this._message && keep && (!onlyUnused || unused)) {
      this._message.keep = true;
    }
    try {
      // Read the new state while still busy: a tick in between would take the
      // action's own change for one made elsewhere and drop the line above.
      await this.refresh();
      if (
        (unanswered || (answered && this._readError !== null)) &&
        this._message !== null
      ) {
        // No answer came, or an answer came (maybe not the vault's: a proxy page) while
        // the server could not be read after it: the request may have landed. A failed
        // read's own line says why. A refusal made in the page never left it. Create's
        // line (`onlyUnused`) gets no next step and is not kept: the vault's state
        // shows whether it landed.
        this._message = {
          ...this._message,
          text: !keep
            ? NOT_CONFIRMED
            : onlyUnused
              ? `${keep} not confirmed by the vault`
              : `${keep} not confirmed by the vault - do it again once the server answers`,
          keep: !onlyUnused
        };
      }
    } finally {
      this._busy = false;
      this.node.classList.remove('jp-mod-busy');
      this.node.removeAttribute('aria-busy');
      this._render();
    }
  }

  private _create(): Promise<void> {
    return this._act(
      async () => {
        const { accepted, value } = await askSecret(
          'Choose a recovery passphrase and store it offline - it is the only way in without a passkey.',
          false,
          'Create vault'
        );
        if (!accepted || value === null) {
          return false;
        }
        try {
          await this._api.init(value);
        } catch (e) {
          // A lost answer: the vault may have been written all the same. A read
          // settles it, and a vault that exists goes on to its passkey step.
          const s =
            e instanceof NoAnswer
              ? await this._api.status().catch(() => null)
              : null;
          if (!s?.initialized) {
            throw e;
          }
        }
        if (isIpAddress(this._host)) {
          return;
        }
        try {
          // The passphrase just chosen is the proof the server asks for a new passkey.
          await registerWithProof(
            this._api,
            { current: value },
            '',
            this._host
          );
        } catch (e) {
          throw new PartlyDone(
            `Vault created, but no passkey was registered (${describeFailure(e)}). Add one under Vault settings and security (the cog).`,
            e instanceof Unused
          );
        }
      },
      'Vault created',
      'Vault creation',
      true
    );
  }

  private _unlockPasskey(): Promise<void> {
    return this._act(async () => {
      // Only the locked view offers this, and it renders from a status already read.
      await unlockWithPasskey(this._api, this._status as IStatus, this._host);
    });
  }

  private _unlockRecovery(): Promise<void> {
    return this._act(async () => {
      const { accepted, value } = await askSecret(
        'Enter the recovery passphrase',
        true,
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
        this._entries.map(e => e.name)
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
        const value = await editEntry(() => this._api.generate(), entry);
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
      `Change to ${entry.name}`
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
    const choice = await viewEntry(entry, () =>
      // The popup opens only in the unlocked view, which renders from a status read.
      revealWithPasskey(
        this._api,
        this._status as IStatus,
        entry.name,
        this._host
      )
    );
    // Back to the row (a redraw meanwhile keeps its focus key), the filter when the
    // entry is gone, Refresh when the list is: a form opened next returns focus there.
    this._restoreFocus(`row:${entry.name}`);
    if (choice === null || this._lockedMeanwhile()) {
      return;
    }
    // The entry as last read: it may have changed while the popup was open.
    const current = this._entries.find(e => e.name === entry.name);
    if (!current && this._entriesRead) {
      this._message = {
        kind: 'warn',
        text: `${entry.name} was deleted elsewhere`,
        at: Date.now()
      };
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
    this._message = {
      kind: 'warn',
      text: 'The vault locked - unlock it, then try again',
      at: Date.now()
    };
    this._render();
    return true;
  }

  /**
   * A two-step button: the first click arms it, the second acts. Clicks within
   * ARM_DELAY_MS of arming are ignored, so a double-click never confirms.
   */
  private _twoStep(
    key: string,
    label: string,
    action: () => Promise<void>
  ): HTMLButtonElement {
    const armed = this._armed === key;
    const button = this._button(
      armed ? `Confirm ${label.toLowerCase()}` : label,
      () => {
        if (this._armed !== key) {
          this._armed = key;
          this._armedAt = Date.now();
          this._render();
        } else if (Date.now() - this._armedAt >= ARM_DELAY_MS) {
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

  // -- rendering ------------------------------------------------------------

  private _render(): void {
    const focus = this._focusKey();
    // First: a countdown that ran out marks the state locked, and the body follows.
    this._renderStatus();
    const s = this._status;
    const unlocked = !!s?.unlocked;
    this._lockButton.style.display = unlocked ? '' : 'none';
    // Hidden in the cog view but kept in place, so Lock never moves under the pointer.
    this._addButton.style.display = unlocked ? '' : 'none';
    this._addButton.style.visibility = this._view === 'main' ? '' : 'hidden';
    this._cogButton.classList.toggle(
      'jp-mod-active',
      this._view === 'settings'
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
        const box = el('div', `${C}-filterBox`);
        box.appendChild(this._filter);
        this._body.append(box, this._list);
        this._renderList();
      }
    }
    this._restoreFocus(focus);
  }

  private _renderBanner(): void {
    const shown = JSON.stringify([
      this._view === 'main' ? this._status?.holder.notice : null,
      this._message?.kind,
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
      line.dataset.kind = this._message.kind;
      this._banner.appendChild(line);
    }
    if (this._readError) {
      const line = el('div', `${C}-message`, this._readError);
      line.dataset.kind = 'error';
      this._banner.appendChild(line);
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
          node.dataset.focusKey === key &&
          node.style.display !== 'none' &&
          node.style.visibility !== 'hidden'
      ) ?? (this._filter.isConnected ? this._filter : this._refreshButton);
    target.focus();
  }

  private _renderStatus(): void {
    const s = this._status;
    this._statusLine.replaceChildren();
    if (!s) {
      return;
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
    const hint = el('p', `${C}-hint`);
    hint.append(
      'No vault at ',
      pathValue(s.path),
      ' yet. A vault keeps passwords encrypted under a key that your passkey, or a recovery passphrase, unlocks.'
    );
    section.appendChild(hint);
    if (isIpAddress(this._host)) {
      // Said before the passphrase is typed: here the vault gets no passkey.
      section.appendChild(el('p', `${C}-hint`, sentence(ipAddressAdvice())));
    }
    section.appendChild(
      this._button('Create vault', () => this._create(), true)
    );
    this._body.appendChild(section);
  }

  private _renderLocked(s: IStatus): void {
    const section = el('div', `${C}-empty`);
    const usable = matchingSlots(s.slots, this._host).length > 0;
    if (usable) {
      section.appendChild(
        this._button('Unlock with passkey', () => this._unlockPasskey(), true)
      );
    } else {
      section.appendChild(
        el(
          'p',
          `${C}-hint`,
          isIpAddress(this._host)
            ? sentence(ipAddressAdvice(s.slots))
            : `No passkey is registered for ${this._host}. Register one under Vault settings and security (the cog) with the recovery passphrase.`
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
  }

  private _fillList(): void {
    const query = this._filter.value.trim().toLowerCase();
    const shown = this._entries.filter(
      e =>
        !query ||
        [e.name, e.username, e.url].some(v => v.toLowerCase().includes(query))
    );
    this._list.replaceChildren();
    if (shown.length === 0) {
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
      return;
    }
    const groups = new Map<string, IEntry[]>();
    for (const e of shown) {
      const key = e.category || 'Uncategorised';
      groups.set(key, [...(groups.get(key) ?? []), e]);
    }
    for (const category of [...groups.keys()].sort((a, b) =>
      a.localeCompare(b)
    )) {
      const group = groups.get(category) as IEntry[];
      this._list.appendChild(
        el('div', `${C}-sectionHeader`, `${category} (${group.length})`)
      );
      for (const e of group) {
        this._list.appendChild(this._row(e));
      }
    }
  }

  /** A row is the entry's name and username; a click or Enter opens its popup. */
  private _row(e: IEntry): HTMLElement {
    const line = el('button', `${C}-rowLine`);
    line.type = 'button';
    line.dataset.focusKey = `row:${e.name}`;
    const label = e.username ? `${e.name}, ${e.username}` : e.name;
    line.title = label;
    line.setAttribute('aria-label', label);
    line.setAttribute('aria-haspopup', 'dialog');
    line.append(
      el('span', `${C}-rowName`, e.name),
      el('span', `${C}-rowUser`, e.username)
    );
    line.addEventListener('click', () => void this._open(e));
    return line;
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

    const passkeys = this._section('Passkeys');
    const slots = s.slots.filter(x => x.type === 'passkey');
    if (!s.initialized) {
      passkeys.appendChild(el('p', `${C}-hint`, 'Create the vault first.'));
    } else {
      if (slots.length === 0) {
        passkeys.appendChild(el('p', `${C}-hint`, 'No passkey registered.'));
      }
      for (const slot of slots) {
        const row = el('div', `${C}-passkey`);
        const text = el('div', `${C}-passkeyText`);
        text.append(
          el('div', `${C}-rowName`, slot.label ?? ''),
          el(
            'div',
            `${C}-rowUser`,
            slot.rp_id === this._host
              ? `added ${addedAt(slot.created)}`
              : `added ${addedAt(slot.created)} on ${slot.rp_id}`
          )
        );
        row.appendChild(text);
        if (s.unlocked) {
          row.appendChild(
            this._twoStep(`passkey:${slot.cred_id}`, 'Remove', () =>
              this._act(
                () => this._api.removePasskey(slot.cred_id as string),
                'Passkey removed'
              )
            )
          );
        }
        passkeys.appendChild(row);
      }
      if (!s.unlocked && slots.length > 0) {
        passkeys.appendChild(
          el('p', `${C}-hint`, 'Unlock the vault to remove passkeys.')
        );
      }
      // A proof, not an unlock, is what the server asks for: offered locked as well.
      passkeys.appendChild(
        isIpAddress(this._host)
          ? el('p', `${C}-hint`, sentence(ipAddressAdvice(s.slots)))
          : this._button('Register new passkey', () =>
              this._act(
                async () => {
                  this._sayProofFirst(s);
                  const proof = await askProof(
                    s,
                    this._host,
                    'Register new passkey'
                  );
                  this.clearLine();
                  return (
                    proof !== null &&
                    registerWithProof(this._api, proof, '', this._host)
                  );
                },
                'Passkey registered',
                'Passkey registration',
                true
              )
            )
      );
    }

    const recovery = this._section('Recovery');
    if (s.initialized) {
      recovery.appendChild(
        this._button('Change recovery passphrase', () =>
          this._act(
            async () => {
              this._sayProofFirst(s);
              const proof = await askProof(
                s,
                this._host,
                'Change recovery passphrase'
              );
              this.clearLine();
              if (proof === null) {
                return false;
              }
              const { accepted, value } = await askSecret(
                'Enter the new recovery passphrase twice, and store it offline',
                false,
                'Change recovery passphrase'
              );
              if (!accepted || value === null) {
                return false;
              }
              await this._api.replaceRecovery(value, proof);
            },
            'Recovery passphrase changed',
            'Recovery passphrase change'
          )
        )
      );
    } else {
      recovery.appendChild(el('p', `${C}-hint`, 'Create the vault first.'));
    }

    const settings = this._section('Settings');
    settings.append(
      this._pair('Unlock duration', formatMinutes(s.settings.unlock_minutes)),
      this._pathPair('Vault file', s.path),
      this._button('Open settings', () => this._openSettings())
    );

    this._body.append(security, passkeys, recovery, settings);
  }

  // -- small builders ---------------------------------------------------------

  private _section(title: string): HTMLElement {
    const section = el('div', `${C}-section`);
    section.appendChild(el('div', `${C}-sectionHeader`, title));
    return section;
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
  private readonly _lockButton: HTMLButtonElement;
  private readonly _addButton: HTMLButtonElement;
  private readonly _cogButton: HTMLButtonElement;
  private readonly _refreshButton: HTMLButtonElement;
  private readonly _statusLine: HTMLDivElement;
  private readonly _banner: HTMLDivElement;
  private readonly _body: HTMLDivElement;
  private readonly _filter: HTMLInputElement;
  private readonly _list: HTMLDivElement;
  private _status: IStatus | null = null;
  private _readAt = 0;
  private _entries: IEntry[] = [];
  private _view: 'main' | 'settings' = 'main';
  private _armed: string | null = null;
  private _bannerShown = '';
  private _entriesRead = true;
  private _armedAt = 0;
  private _busy = false;
  private _message: Message_ = null;
  /** Why the last read failed; the next successful read clears it. */
  private _readError: string | null = null;
  private _timer: number | null = null;
}
