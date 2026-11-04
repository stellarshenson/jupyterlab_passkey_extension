import { Dialog } from '@jupyterlab/apputils';

import { LabIcon } from '@jupyterlab/ui-components';

import { CommandRegistry } from '@lumino/commands';

import { Menu, Widget } from '@lumino/widgets';

import { askSecret, launchWithEscape } from '../passphrase';

import { mapCeremonyError } from '../passkey-util';

import { trans } from '../trans';

import {
  IEntry,
  IEntryFields,
  ISlot,
  IStatus,
  Proof,
  VaultApi,
  VaultError
} from './api';

import { newSetupKey, otpauthUri, qrSvg } from './totp';

import {
  describeFailure,
  fit,
  INewPair,
  ipAddressAdvice,
  isIpAddress,
  matchingSlots,
  pairSlot,
  passkeyAssertion,
  passkeyPrf,
  registerPasskey,
  stored,
  unlockWithPasskey
} from './webauthn';

export interface IEntryFormValue extends IEntryFields {
  name: string;
}

/**
 * The add / edit form. Save is gated on a name that no other entry has, the way the
 * passphrase dialog gates Submit: Dialog disables its accept button while anything
 * in the body matches `:invalid`, and a custom validity on the name field puts it
 * there - so a taken name is refused before the dialog closes and loses the input.
 */
export class EntryForm extends Widget {
  readonly name: HTMLInputElement;
  readonly username: HTMLInputElement;
  readonly password: HTMLInputElement;
  readonly url: HTMLInputElement;
  readonly category: HTMLInputElement;
  readonly notes: HTMLTextAreaElement;
  readonly generate: HTMLButtonElement;

  constructor(
    private readonly _generate: () => Promise<string>,
    entry?: IEntry,
    private readonly _taken: string[] = [],
    categories: string[] = []
  ) {
    super();
    this.addClass('jp-PasskeyVaultForm');
    this.name = input('text', entry?.name);
    this.name.required = true;
    if (entry) {
      // The name is the key an edit is addressed by.
      this.name.readOnly = true;
    }
    this._nameHelp = document.createElement('div');
    this._nameHelp.className = 'jp-PasskeyVaultForm-help';
    this.username = input('text', entry?.username);
    this.password = input('password');
    // Never let the browser or a password manager fill in, or keep, this value.
    this.password.autocomplete = 'new-password';

    this.generate = document.createElement('button');
    this.generate.type = 'button';
    this.generate.className = 'jp-mod-styled jp-PasskeyVaultForm-generate';
    this.generate.textContent = trans.__('Generate');
    this.generate.addEventListener('click', () => {
      this._generate().then(
        value => {
          this.password.value = value;
          this._showPasswordHelp();
        },
        e => {
          // The field keeps what it held: the rule for Save still applies.
          this._showPasswordHelp();
          const rule = this._passwordHelp.textContent;
          const failed = `No password was generated: ${
            e instanceof Error ? e.message : String(e)
          }`;
          this._passwordHelp.textContent = rule ? `${failed}. ${rule}` : failed;
        }
      );
    });
    const passwordRow = document.createElement('div');
    passwordRow.className = 'jp-PasskeyVaultForm-row';
    passwordRow.append(this.password, this.generate);
    this._passwordHelp = document.createElement('div');
    this._passwordHelp.className = 'jp-PasskeyVaultForm-help';
    this._editing = !!entry;
    this._showPasswordHelp();
    this.password.addEventListener('input', () => this._showPasswordHelp());

    this.url = input('text', entry?.url);
    this.category = input('text', entry?.category);
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'jp-PasskeyVaultForm-categoryToggle';
    toggle.setAttribute('aria-label', trans.__('Existing categories'));
    toggle.setAttribute('aria-haspopup', 'menu');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.append(arrow());
    // Joined to the field as the eye is to the password field.
    const combo = document.createElement('div');
    combo.className =
      'jp-PasskeyVaultForm-row jp-PasskeyVaultForm-joined jp-PasskeyVaultForm-category';
    combo.append(this.category, toggle);
    const menu = new Menu({ commands: new CommandRegistry() });
    menu.addClass('jp-PasskeyVaultForm-categoryMenu');
    // Each category in use once, in the order of the panel's category headers.
    for (const category of [...new Set(categories)]
      .filter(Boolean)
      .sort((a, b) => a.localeCompare(b))) {
      const command = `passkey-vault:category-${category}`;
      menu.commands.addCommand(command, {
        label: category,
        describedBy: { args: {} },
        execute: () => {
          this.category.value = category;
          this.category.dispatchEvent(new Event('input', { bubbles: true }));
          this.category.dispatchEvent(new Event('change', { bubbles: true }));
          this.category.focus();
        }
      });
      menu.addItem({ command });
    }
    // A vault with no category has none to offer, and an empty menu says nothing.
    toggle.disabled = menu.items.length === 0;
    // The menu is a widget of the page body, so the dialog body, which clips its own
    // overflow, cannot clip it.
    toggle.addEventListener('click', event => {
      event.preventDefault();
      const rect = combo.getBoundingClientRect();
      // The menu is attached to the page body, where a percentage says nothing
      // about the dialog; the width of the field bounds it in pixels.
      menu.node.style.maxWidth = rect.width + 'px';
      toggle.setAttribute('aria-expanded', 'true');
      menu.open(rect.left, rect.bottom);
    });
    menu.aboutToClose.connect(() => {
      toggle.setAttribute('aria-expanded', 'false');
      // Closing removes the focused menu item from the page; Escape returns to the arrow.
      toggle.focus();
    });
    this._menu = menu;
    this._toggle = toggle;
    this.notes = document.createElement('textarea');
    this.notes.className = 'jp-mod-styled jp-PasskeyVaultForm-notes';
    this.notes.value = entry?.notes ?? '';

    this.node.append(
      field('Name', this.name, this._nameHelp),
      field('Username', this.username),
      field('Password', passwordRow, this._passwordHelp, this.password),
      field('URL', this.url),
      field('Category', combo, undefined, this.category),
      field('Notes', this.notes)
    );
    this._validate();
  }

  /**
   * In Edit: an empty field keeps the current password, a filled one replaces it. Add
   * has no help line; this also clears a Generate failure once a password is there.
   */
  private _showPasswordHelp(): void {
    this._passwordHelp.textContent = !this._editing
      ? ''
      : this.password.value
        ? trans.__('Save replaces the current password')
        : KEEP_HELP;
  }

  getValue(): IEntryFormValue {
    const value: IEntryFormValue = {
      name: this.name.value.trim(),
      username: this.username.value,
      url: this.url.value,
      category: this.category.value,
      notes: this.notes.value
    };
    if (this.password.value !== '') {
      value.password = this.password.value;
    }
    return value;
  }

  onAfterAttach(): void {
    // Capture phase, ahead of Dialog's own listener - see PassphraseBody.
    document.addEventListener('input', this._revalidate, true);
    document.addEventListener('keydown', this._keepEnterInNotes, true);
    window.addEventListener('focus', this._keepFocusInMenu, true);
    window.addEventListener('keydown', this._keysToMenu, true);
    void Promise.resolve().then(() => {
      this.name.dispatchEvent(new Event('input', { bubbles: true }));
    });
  }

  onBeforeDetach(): void {
    document.removeEventListener('input', this._revalidate, true);
    document.removeEventListener('keydown', this._keepEnterInNotes, true);
    window.removeEventListener('focus', this._keepFocusInMenu, true);
    window.removeEventListener('keydown', this._keysToMenu, true);
  }

  /** Close the category menu with the dialog, so no menu stays in the page body. */
  dispose(): void {
    this._menu.dispose();
    super.dispose();
  }

  /**
   * Dialog's keydown handler calls preventDefault on every Enter, so no line break
   * could be typed in Notes and Enter on Generate or the category arrow did nothing.
   * Stopped here, in document capture, Enter never reaches it and does its own work.
   */
  private readonly _keepEnterInNotes = (event: KeyboardEvent): void => {
    if (
      event.key === 'Enter' &&
      (event.target === this.notes ||
        event.target === this.generate ||
        event.target === this._toggle)
    ) {
      event.stopPropagation();
    }
  };

  /**
   * The open category menu is in the page body, outside the dialog, and Dialog's
   * document-capture focus listener pulls any focus outside the dialog back to its
   * first field. Stopped here, in window capture, focus stays on the open menu.
   */
  private readonly _keepFocusInMenu = (event: FocusEvent): void => {
    if (
      event.target instanceof Node &&
      this._menu.node.contains(event.target)
    ) {
      event.stopPropagation();
      // The stop also blocks the item's own onfocus, which sets the item Enter chooses.
      const i = Array.prototype.indexOf.call(
        this._menu.contentNode.children,
        event.target
      );
      if (i >= 0) {
        this._menu.activeIndex = i;
      }
    }
  };

  /**
   * While the category menu is open, a key on the arrow or in the menu goes to the
   * menu, which stops it, so Escape and Enter never reach launchWithEscape or Dialog,
   * both in document capture. Window capture runs first; the arrow also covers the
   * frame before the menu takes focus.
   */
  private readonly _keysToMenu = (event: KeyboardEvent): void => {
    const t = event.target as Node;
    if (
      this._menu.isAttached &&
      (t === this._toggle || this._menu.node.contains(t))
    ) {
      this._menu.handleEvent(event);
    }
  };

  private readonly _revalidate = (event: Event): void => {
    if (event.target === this.name) {
      this._validate();
    }
  };

  private _validate(): void {
    const name = this.name.value.trim();
    const taken = this._taken.includes(name)
      ? `An entry named ${name} already exists`
      : '';
    this.name.setCustomValidity(name === '' ? 'An entry needs a name' : taken);
    // Said under the field: a greyed-out Save alone does not say why.
    this._nameHelp.textContent = taken;
  }

  private readonly _passwordHelp: HTMLDivElement;
  private readonly _editing: boolean;
  private readonly _nameHelp: HTMLDivElement;
  private readonly _menu: Menu;
  private readonly _toggle: HTMLButtonElement;
}

const KEEP_HELP = 'Leave empty to keep the current password';

/** A lower-case message as a sentence of its own. */
export function sentence(text: string): string {
  return `${text[0].toUpperCase()}${text.slice(1)}.`;
}

/** The down arrow of the button that opens the list of the categories in use. */
function arrow(): SVGSVGElement {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(ns, 'path');
  path.setAttribute('d', 'M6 9l6 6 6-6');
  svg.append(path);
  return svg;
}

function input(type: string, value?: string): HTMLInputElement {
  const node = document.createElement('input');
  node.type = type;
  node.className = 'jp-mod-styled jp-PasskeyVaultForm-input';
  node.value = value ?? '';
  return node;
}

let fieldCount = 0;

/**
 * A visible label over a control, and an optional help line under it that screen
 * readers announce with the field. `target` is the input the label names, when
 * `control` is a row holding more than the input.
 */
function field(
  text: string,
  control: HTMLElement,
  help?: HTMLElement,
  target: HTMLElement = control
): HTMLDivElement {
  const box = document.createElement('div');
  box.className = 'jp-PasskeyVaultForm-field';
  const label = document.createElement('label');
  label.className = 'jp-PasskeyVaultForm-label';
  label.textContent = text;
  const id = `jp-PasskeyVaultForm-field-${++fieldCount}`;
  target.id = id;
  label.htmlFor = id;
  box.append(label, control);
  if (help) {
    help.id = `${id}-help`;
    target.setAttribute('aria-describedby', help.id);
    box.appendChild(help);
  }
  return box;
}

/**
 * Open the add or edit form; null when cancelled. `taken` are the names in use,
 * `categories` the categories the Category field offers. It
 * answers the name and only the fields the user changed - the form's own loading (a
 * textarea turns CRLF into LF, a one-line field drops line breaks) is no change, and
 * the vault stores a field an add leaves out as empty.
 */
export async function editEntry(
  generate: () => Promise<string>,
  entry?: IEntry,
  taken: string[] = [],
  categories: string[] = []
): Promise<IEntryFormValue | null> {
  const body = new EntryForm(generate, entry, taken, categories);
  const dialog = new Dialog({
    title: entry ? trans.__('Edit entry') : trans.__('Add entry'),
    body,
    // Dialog focuses its default button after the body attaches; this names the
    // first field to type in instead - Name in Add, Username in Edit.
    focusNodeSelector: 'input:not([readonly])',
    hasClose: false,
    buttons: [
      Dialog.cancelButton(),
      Dialog.okButton({ label: trans.__('Save'), accept: true })
    ]
  });
  dialog.addClass('jp-PasskeyVaultForm-dialog');
  const loaded = body.getValue();
  const result = await launchWithEscape(dialog);
  if (!result.button.accept) {
    return null;
  }
  const value = body.getValue();
  for (const key of ['username', 'url', 'category', 'notes'] as const) {
    if (value[key] === loaded[key]) {
      delete value[key];
    }
  }
  return value;
}

// The eye shows the password's state: open while it is shown, crossed while hidden.
const eyeIcon = new LabIcon({
  name: 'jupyterlab-passkey-extension:eye',
  svgstr:
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path class="jp-icon3" fill="#616161" d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17a5 5 0 1 1 0-10 5 5 0 0 1 0 10zm0-8a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"/></svg>'
});

const eyeOffIcon = new LabIcon({
  name: 'jupyterlab-passkey-extension:eye-off',
  svgstr:
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path class="jp-icon3" fill="#616161" d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/></svg>'
});

/** Eight characters of nothing: the dots the password field shows before a reveal. */
const HIDDEN = '        ';

/** A proof typed in the entry popup, where a passkey is not the proof. */
export type TypedProof = 'code' | 'password' | 'passphrase';

const TYPED: Record<
  TypedProof,
  { ask: string; label: string; proof: (value: string) => Proof }
> = {
  code: {
    ask: 'a code of the authenticator app',
    label: trans.__('Code of the authenticator app'),
    proof: code => ({ code })
  },
  password: {
    ask: 'the unlock password',
    label: trans.__('Unlock password'),
    proof: password => ({ password })
  },
  passphrase: {
    ask: 'the recovery passphrase',
    label: trans.__('Recovery passphrase'),
    proof: current => ({ current })
  }
};

/** How the entry popup gets the password. */
export interface IReveal {
  /** True while the eye asks no proof. */
  proven: () => boolean;
  /**
   * The proof of a passkey request: a passkey with PRF for this hostname, else the
   * passkey of Password and passkey added at this address.
   */
  passkey: () => Promise<Proof>;
  /** The password: for a proof, or with none while `proven`. */
  reveal: (proof?: Proof) => Promise<string>;
  /**
   * The proofs to type that this vault has, in the order they are asked: the first
   * is asked, and a link under its row moves on to the next; from the last it goes
   * back to the first.
   */
  typed: TypedProof[];
}

/**
 * An entry, read-only, laid out like the edit form. The password is not in the page
 * until a reveal returns it: the eye asks for it once, then only hides and shows it.
 * In the reveal window after an unlock or a proof in this tab the eye asks no proof. After that it
 * asks a passkey first. With none for this hostname, or no answer, a row
 * under the field asks a proof to type: a code of the authenticator app, the unlock
 * password or the recovery passphrase, whichever of them the vault has.
 */
export class EntryView extends Widget {
  readonly password: HTMLInputElement;
  readonly eye: HTMLButtonElement;
  /** The typed proof: its field, its button, and the link to the next proof. */
  readonly proof: HTMLInputElement;
  readonly prove: HTMLButtonElement;
  readonly useNext: HTMLButtonElement;

  constructor(
    entry: IEntry,
    private readonly _how: IReveal
  ) {
    super();
    this.addClass('jp-PasskeyVaultForm');
    this.addClass('jp-mod-view');
    const shown = (value: string) => {
      const node = input('text', value);
      node.readOnly = true;
      return node;
    };
    this.password = input('password', HIDDEN);
    this.password.readOnly = true;
    // A shown password is copied whole: a click selects all of it, where a
    // double-click would stop at the symbols a generated password holds.
    const selectAll = () => {
      if (this.password.type === 'text') {
        this.password.select();
      }
    };
    this.password.addEventListener('click', selectAll);
    this.password.addEventListener('focus', selectAll);
    this.eye = document.createElement('button');
    this.eye.type = 'button';
    this.eye.className = 'jp-mod-styled jp-PasskeyVaultForm-eye';
    this.eye.addEventListener('click', () => void this._toggle());
    this._show(false);
    const passwordRow = document.createElement('div');
    passwordRow.className =
      'jp-PasskeyVaultForm-row jp-PasskeyVaultForm-joined';
    passwordRow.append(this.password, this.eye);
    this._help = document.createElement('div');
    this._help.className = 'jp-PasskeyVaultForm-help';
    // Announced: the eye keeps focus, so a failed reveal is otherwise silent.
    this._help.setAttribute('role', 'status');

    this.proof = input('password');
    // Never let the browser or a password manager fill in, or keep, this value.
    this.proof.autocomplete = 'off';
    this.prove = document.createElement('button');
    this.prove.type = 'button';
    this.prove.className = 'jp-mod-styled jp-PasskeyVaultForm-prove';
    this.prove.textContent = trans.__('Show');
    this.prove.addEventListener('click', () => void this._prove());
    this._proofRow = document.createElement('div');
    this._proofRow.className = 'jp-PasskeyVaultForm-row';
    this._proofRow.append(this.proof, this.prove);
    this.useNext = document.createElement('button');
    this.useNext.type = 'button';
    this.useNext.className = 'jp-PasskeyVaultForm-link';
    // In the page only while a proof is typed: until then the popup holds
    // read-only fields and the eye, nothing else.
    this._proofBox = document.createElement('div');
    this._proofBox.className = 'jp-PasskeyVaultForm-proof';
    this.useNext.addEventListener('click', () => {
      this._typed = [...this._typed.slice(1), this._typed[0]];
      this._askProof();
    });

    const notes = document.createElement('textarea');
    notes.className = 'jp-mod-styled jp-PasskeyVaultForm-notes';
    notes.readOnly = true;
    notes.value = entry.notes;

    this._passwordField = field(
      'Password',
      passwordRow,
      this._help,
      this.password
    );
    this.node.append(
      field('Name', shown(entry.name)),
      field('Username', shown(entry.username)),
      this._passwordField,
      field('URL', shown(entry.url)),
      field('Category', shown(entry.category)),
      field('Notes', notes)
    );
  }

  onAfterAttach(): void {
    document.addEventListener('keydown', this._keepEnter, true);
  }

  onBeforeDetach(): void {
    document.removeEventListener('keydown', this._keepEnter, true);
  }

  /**
   * Dialog swallows Enter on a body control and presses its default button, Close;
   * see EntryForm._keepEnterInNotes. Enter on the eye, on Show and on the link to
   * the next proof presses that button, and Enter in the proof field sends the proof.
   */
  private readonly _keepEnter = (event: KeyboardEvent): void => {
    if (event.key !== 'Enter') {
      return;
    }
    if (
      event.target === this.eye ||
      event.target === this.prove ||
      event.target === this.useNext
    ) {
      event.stopPropagation();
    } else if (event.target === this.proof) {
      event.stopPropagation();
      event.preventDefault();
      void this._prove();
    }
  };

  private async _toggle(): Promise<void> {
    if (this._revealed) {
      this._show(this.password.type === 'password');
      return;
    }
    if (this._pending) {
      return;
    }
    if (this._proofBox.isConnected) {
      this.proof.focus();
      return;
    }
    if (this._how.proven()) {
      this._wait('');
      await this._reveal();
      return;
    }
    // The passkey prompt is the browser's and can open late or behind the window:
    // the eye and the line under the field say the click was taken.
    this._wait('Waiting for your passkey');
    let proof: Proof;
    try {
      proof = await this._how.passkey();
    } catch (e) {
      this._waited();
      this._show(false);
      // No answer is a cancel, or a passkey kept on another device; the page's own
      // refusal is a hostname with no passkey, or a passkey that gives no PRF. Each
      // leaves the other proofs. A cancel is the user's choice: no error is said.
      if (mapCeremonyError(e) === 'not-allowed') {
        this._reason = 'No passkey answered.';
      } else if (e instanceof VaultError) {
        this._reason = sentence(e.message);
      } else {
        this._help.textContent = `The password was not shown: ${describeFailure(e)}`;
        return;
      }
      this._typed = this._how.typed;
      this._askProof();
      return;
    }
    await this._reveal(proof);
  }

  /** Open the row for the first of the typed proofs, with a link to the next. */
  private _askProof(): void {
    const [kind, next] = this._typed;
    const code = kind === 'code';
    if (next) {
      this.useNext.textContent = `Use ${TYPED[next].ask}`;
    }
    this._proofBox.replaceChildren(
      this._proofRow,
      ...(next ? [this.useNext] : [])
    );
    this._passwordField.appendChild(this._proofBox);
    this.proof.value = '';
    this.proof.type = code ? 'text' : 'password';
    this.proof.inputMode = code ? 'numeric' : 'text';
    this.proof.setAttribute('aria-label', TYPED[kind].label);
    this._help.textContent = `${this._reason} Enter ${TYPED[kind].ask} to show the password.`;
    this.proof.focus();
  }

  private async _prove(): Promise<void> {
    const value = this.proof.value;
    if (this._pending || value === '') {
      return;
    }
    this._wait('');
    await this._reveal(TYPED[this._typed[0]].proof(value));
  }

  /** Ask the server for the password; `_wait` was called. */
  private async _reveal(proof?: Proof): Promise<void> {
    try {
      this.password.value = await this._how.reveal(proof);
      this._revealed = true;
      this._proofBox.remove();
      this.proof.value = '';
      this._show(true);
      this._help.textContent = this.password.value
        ? ''
        : trans.__('This entry has no password');
      this.eye.focus();
    } catch (e) {
      this._show(false);
      this._help.textContent = `The password was not shown: ${describeFailure(e)}`;
      if (this._proofBox.isConnected) {
        // The row stays for another try; what was typed proved nothing.
        this.proof.value = '';
        this.proof.focus();
      }
    } finally {
      this._waited();
    }
  }

  private _wait(line: string): void {
    this._pending = true;
    const spinner = document.createElement('span');
    spinner.className = 'jp-PasskeyVaultForm-spinner';
    this.eye.replaceChildren(spinner);
    this.eye.setAttribute('aria-busy', 'true');
    this._help.textContent = line;
  }

  private _waited(): void {
    this._pending = false;
    this.eye.removeAttribute('aria-busy');
  }

  private _show(on: boolean): void {
    this.password.type = on ? 'text' : 'password';
    this.eye.replaceChildren(
      (on ? eyeIcon : eyeOffIcon).element({ tag: 'span' })
    );
    const label = on ? 'Hide password' : 'Show password';
    this.eye.title = label;
    this.eye.setAttribute('aria-label', label);
  }

  private readonly _help: HTMLDivElement;
  private readonly _passwordField: HTMLDivElement;
  private readonly _proofRow: HTMLDivElement;
  private readonly _proofBox: HTMLDivElement;
  private _revealed = false;
  private _pending = false;
  /** Why a proof is typed, and the typed proofs with the one asked now first. */
  private _reason = '';
  private _typed: TypedProof[] = [];
}

/**
 * Open an entry in the read-only popup. Resolves to the action chosen - `edit` or
 * `delete` - or null when closed.
 */
export async function viewEntry(
  entry: IEntry,
  how: IReveal
): Promise<'edit' | 'delete' | null> {
  // The pressed button is told by its label, so both read the same strings.
  const edit = trans.__('Edit');
  const remove = trans.__('Delete');
  const dialog = new Dialog({
    title: entry.name,
    body: new EntryView(entry, how),
    // Focus on the eye, and Enter on a one-line field closes (Close is the default
    // button): a read-only view is left, not edited, by the key pressed to read it.
    focusNodeSelector: '.jp-PasskeyVaultForm-eye',
    defaultButton: 1,
    hasClose: false,
    buttons: [
      Dialog.warnButton({ label: remove }),
      Dialog.cancelButton({ label: trans.__('Close') }),
      Dialog.okButton({ label: edit })
    ]
  });
  dialog.addClass('jp-PasskeyVaultForm-dialog');
  const { label } = (await launchWithEscape(dialog)).button;
  return label === edit ? 'edit' : label === remove ? 'delete' : null;
}

/** Ask before deleting `name`; true when confirmed. */
export async function confirmDelete(name: string): Promise<boolean> {
  // The pressed button is told by its label, so both read the same string.
  const remove = trans.__('Delete');
  const result = await launchWithEscape(
    new Dialog({
      title: trans.__('Delete entry'),
      body: `Delete ${name}? This cannot be undone.`,
      hasClose: false,
      buttons: [Dialog.cancelButton(), Dialog.warnButton({ label: remove })],
      // Enter cancels: the popup before it closes on Enter, and a delete has no undo.
      defaultButton: 0
    })
  );
  return result.button.label === remove;
}

/** The naming step's body: what happens next, and a name for the passkey. */
class PasskeyNameForm extends Widget {
  readonly input: HTMLInputElement;

  constructor(suggested: string, intro: string) {
    super();
    this.addClass('jp-PasskeyVaultForm');
    const text = document.createElement('p');
    text.textContent = intro;
    this.input = document.createElement('input');
    this.input.type = 'text';
    this.input.className = 'jp-mod-styled jp-PasskeyVaultForm-input';
    this.input.value = suggested;
    const help = document.createElement('div');
    help.className = 'jp-PasskeyVaultForm-help';
    help.textContent = trans.__(
      'Shown in the passkey list, for example "Work laptop"'
    );
    this.node.append(text, field('Name', this.input, help));
  }

  getValue(): string {
    return this.input.value.trim();
  }
}

/**
 * The first step of a passkey registration: the user names the passkey. Its button
 * is the fresh click the browser needs before it creates the passkey. Resolves to
 * the name, or null when the user backs out.
 */
async function nameNewPasskey(
  suggested: string,
  intro: string
): Promise<string | null> {
  const body = new PasskeyNameForm(suggested, intro);
  const result = await launchWithEscape(
    new Dialog({
      title: trans.__('Name the new passkey'),
      body,
      // Typing starts in the name field; a space typed on the button would create.
      focusNodeSelector: 'input',
      hasClose: false,
      buttons: [
        Dialog.cancelButton(),
        Dialog.okButton({ label: trans.__('Create passkey'), accept: true })
      ]
    })
  );
  return result.button.accept ? body.getValue() : null;
}

/**
 * The last step of a passkey registration, after the browser created the passkey.
 * Its button is the fresh click the PRF request needs. Resolves to false when the
 * user backs out.
 */
async function confirmNewPasskey(name: string): Promise<boolean> {
  const result = await launchWithEscape(
    new Dialog({
      title: trans.__('Confirm the new passkey'),
      body: `Passkey "${name}" created - confirm it to derive the vault key`,
      hasClose: false,
      buttons: [
        Dialog.cancelButton(),
        Dialog.okButton({ label: trans.__('Confirm passkey'), accept: true })
      ]
    })
  );
  return result.button.accept;
}

/** The six digits an authenticator app shows. */
function codeInput(): HTMLInputElement {
  const node = input('text');
  node.classList.add('jp-PasskeyVaultForm-code');
  node.inputMode = 'numeric';
  node.autocomplete = 'one-time-code';
  // Six digits, or three and three with the space an app shows between them: the
  // server drops the space.
  node.maxLength = 7;
  node.required = true;
  node.pattern = '[0-9]{3} ?[0-9]{3}';
  return node;
}

/**
 * A dialog body that asks for a code. Dialog disables its accept button while the
 * body holds an invalid field, but checks only on `input`: the event sent on attach
 * makes it check the empty field too - see PassphraseBody.
 */
class CodeForm extends Widget {
  readonly code = codeInput();

  constructor(prompt: string) {
    super();
    this.addClass('jp-PasskeyVaultForm');
    this.node.append(field(prompt, this.code));
  }

  onAfterAttach(): void {
    void Promise.resolve().then(() => {
      this.code.dispatchEvent(new Event('input', { bubbles: true }));
    });
  }
}

const USE_PASSPHRASE = 'Use recovery passphrase';

/**
 * Open a dialog that asks a code. `submit` labels its accept button; `extra` are
 * buttons between Cancel and that one. Resolves to the button pressed and the code.
 */
async function launchCodeDialog(
  prompt: string,
  title: string,
  submit: string,
  extra: Dialog.IButton[] = []
): Promise<{ button: Dialog.IButton; code: string }> {
  const body = new CodeForm(prompt);
  const { button } = await launchWithEscape(
    new Dialog({
      title,
      body,
      focusNodeSelector: 'input',
      hasClose: false,
      buttons: [
        Dialog.cancelButton(),
        ...extra,
        Dialog.okButton({ label: submit, accept: true })
      ]
    })
  );
  return { button, code: body.code.value };
}

/**
 * Ask for the code that unlocks the vault with the unlock password. Resolves to null
 * when cancelled.
 */
export async function askUnlockCode(): Promise<string | null> {
  const { button, code } = await launchCodeDialog(
    'Enter the code the authenticator app shows',
    'Unlock vault',
    'Unlock'
  );
  return button.accept ? code : null;
}

/**
 * Ask for a code of the authenticator app. Resolves to the proof, to `passphrase`
 * when the user chose the recovery passphrase, or to null when cancelled.
 */
async function askCode(
  prompt: string,
  title: string
): Promise<Proof | 'passphrase' | null> {
  const { button, code } = await launchCodeDialog(prompt, title, 'Submit', [
    Dialog.cancelButton({ label: USE_PASSPHRASE })
  ]);
  if (button.accept) {
    return { code };
  }
  return button.label === USE_PASSPHRASE ? 'passphrase' : null;
}

/** The server's refusal of a recovery passphrase. */
const WRONG_PASSPHRASE = 'wrong recovery passphrase';

const USE_PASSKEY = 'Use passkey';
const USE_ANOTHER = 'Use another proof';

/**
 * Ask for the passkey of Password and passkey as a proof, or `Use another proof`. Its
 * `Use passkey` button is the click the passkey request needs, because the challenge
 * was read from the server since the last click. Resolves to the choice, or null when
 * cancelled.
 */
async function askUsePasskey(
  title: string,
  text: string
): Promise<'passkey' | 'another' | null> {
  const { button } = await launchWithEscape(
    new Dialog({
      title,
      body: text,
      hasClose: false,
      buttons: [
        Dialog.cancelButton(),
        Dialog.cancelButton({ label: USE_ANOTHER }),
        Dialog.okButton({ label: USE_PASSKEY, accept: true })
      ]
    })
  );
  if (button.accept) {
    return 'passkey';
  }
  return button.label === USE_ANOTHER ? 'another' : null;
}

/**
 * The proof the server asks before a rotation, a recovery change or a new unlock
 * method: a passkey request when a passkey for this hostname exists. With none - or
 * when that request gets no answer, or the passkey gives no PRF - the passkey of
 * Password and passkey when `code` is set, the vault has one for this address and is
 * unlocked; then a code of the authenticator app when `code` is set, the vault has
 * one and is unlocked; else, or when the user chooses it, the current recovery
 * passphrase. A code and a passkey with no PRF hold no key of their own: the server
 * takes them for a new passkey, a new unlock method and a recovery change, but not
 * for a rotation, whose caller leaves `code` false. The server checks
 * a recovery passphrase as soon as it is typed, so a wrong one opens the same dialog
 * again before the browser or an app is asked for anything; the request that acts
 * checks every proof again, and it is the only check of a code, which a check uses up.
 * Call it straight from a click: the passkey request comes before any other await.
 * Resolves to null when a dialog is cancelled.
 */
export async function askProof(
  api: VaultApi,
  status: IStatus,
  host: string,
  title: string,
  code = false
): Promise<Proof | null> {
  let lead = '';
  if (matchingSlots(status.slots, host).length > 0) {
    try {
      const { credId, prf } = await passkeyPrf(status, host);
      return { cred_id: credId, prf };
    } catch (e) {
      // This hostname's passkeys can sit on another device - a second machine
      // registering its own - so a refused or dismissed request falls back, and so
      // does the page's own refusal of a passkey that gives no PRF.
      if (mapCeremonyError(e) === 'not-allowed') {
        lead = 'No passkey answered - ';
      } else if (e instanceof VaultError) {
        lead = 'This passkey cannot unlock the vault - ';
      } else {
        throw e;
      }
    }
  }
  // A passkey with no PRF holds no key: as a code, it proves only while the vault is
  // unlocked, and only for the actions whose caller takes a code.
  const pair = code && status.unlocked ? pairSlot(status.slots) : undefined;
  if (pair) {
    const challenge = await api.challenge();
    const answer = await askUsePasskey(
      title,
      lead
        ? `${lead}confirm with the passkey of Password and passkey instead.`
        : 'Confirm with the passkey of Password and passkey.'
    );
    if (answer === null) {
      return null;
    }
    if (answer === 'passkey') {
      try {
        return { assertion: await passkeyAssertion(pair, challenge) };
      } catch (e) {
        if (mapCeremonyError(e) !== 'not-allowed') {
          throw e;
        }
        lead = 'No passkey answered - ';
      }
    }
  }
  const prompt = (proof: string) =>
    lead ? `${lead}enter ${proof} instead` : `Enter ${proof}`;
  // A code holds no key: it proves only while the vault is unlocked, and only for
  // the actions whose caller takes one.
  if (code && status.unlocked && status.authenticator) {
    const answer = await askCode(
      prompt('a code of the authenticator app'),
      title
    );
    if (answer !== 'passphrase') {
      return answer;
    }
  }
  let note: string | undefined;
  for (;;) {
    const { accepted, value } = await askSecret(
      prompt('the current recovery passphrase'),
      1,
      title,
      undefined,
      note
    );
    if (!accepted || value === null) {
      return null;
    }
    try {
      await api.checkRecovery(value);
      return { current: value };
    } catch (e) {
      if (!(e instanceof VaultError && e.message === WRONG_PASSPHRASE)) {
        throw e;
      }
      note = 'Wrong recovery passphrase';
    }
  }
}

/**
 * The unlock methods the panel adds: a passkey, the unlock password with an
 * authenticator app (`mfa`), which open the vault only together, and an unlock
 * password with a passkey that has no PRF (`pair`), which a passkey registration
 * offers when the passkey has no PRF.
 */
export type UnlockMethod = 'passkey' | 'mfa' | 'pair';

/** Every way the vault opens, as the unlock chooser offers them. */
export type VaultMethod = UnlockMethod | 'recovery';

/** A button of the chooser: a method, or Later at set-up, which adds none. */
type MethodChoice = VaultMethod | 'later';

/** Each choice as the dialog that offers them names it, with one line on what it is. */
const METHODS: Record<MethodChoice, { label: string; about: string }> = {
  passkey: {
    label: trans.__('Passkey'),
    about: 'Fingerprint, face, PIN or security key.'
  },
  mfa: {
    label: trans.__('Password and authenticator app'),
    about: 'A password, then a 6-digit code from your phone.'
  },
  pair: {
    label: trans.__('Password and passkey'),
    about: 'A password, then your passkey.'
  },
  recovery: {
    label: trans.__('Recovery passphrase'),
    about: 'The passphrase you stored offline.'
  },
  later: {
    label: trans.__('Later'),
    about: 'Only the recovery passphrase opens the vault for now.'
  }
};

/** A method's state in this vault: `unavailable` says why it cannot be chosen now. */
export interface IMethodState {
  unavailable?: string;
}

/** The chooser's line of a dialog opened again after a step failed. */
const NOTE_ID = 'jp-PasskeyVaultForm-note';

/** With no footer button, Dialog's arrow keys throw on a focus target that is not there. */
const KEYS_NO_FOOTER = ['Enter', 'ArrowLeft', 'ArrowRight'];

/** The body of the dialog that offers the methods: one button for each. */
class MethodForm extends Widget {
  /** The method whose button was pressed. */
  chosen: MethodChoice | null = null;

  /**
   * `close` closes the dialog once a method is chosen. `note` shows a line above the
   * buttons, for a dialog opened again after a step failed.
   */
  constructor(
    states: Partial<Record<MethodChoice, IMethodState>>,
    close: () => void,
    note?: string
  ) {
    super();
    this.addClass('jp-PasskeyVaultForm');
    this._kept = 'later' in states ? KEYS_NO_FOOTER : ['Enter'];
    if (note) {
      const line = document.createElement('div');
      line.id = NOTE_ID;
      line.className = 'jp-PassphraseDialog-status';
      line.dataset.state = 'mismatch';
      line.textContent = note;
      this.node.appendChild(line);
    }
    for (const kind of (Object.keys(METHODS) as MethodChoice[]).filter(
      kind => kind in states
    )) {
      const { label, about } = METHODS[kind];
      const { unavailable } = states[kind] ?? {};
      const name = document.createElement('span');
      name.textContent = label;
      const help = document.createElement('span');
      help.className = 'jp-PasskeyVaultForm-help';
      help.textContent = unavailable ?? about;
      const choice = document.createElement('button');
      choice.type = 'button';
      choice.className = 'jp-mod-styled jp-PasskeyVaultForm-choice';
      choice.dataset.method = kind;
      choice.disabled = unavailable !== undefined;
      // The button is named by the method alone; the line under the name is read after
      // it. A button takes the focus when the dialog opens, so the note is read with it.
      name.id = `jp-PasskeyVaultForm-method-${kind}`;
      help.id = `${name.id}-help`;
      choice.setAttribute('aria-labelledby', name.id);
      choice.setAttribute(
        'aria-describedby',
        note ? `${NOTE_ID} ${help.id}` : help.id
      );
      choice.append(name, help);
      choice.addEventListener('click', () => {
        this.chosen = kind;
        close();
      });
      this.node.appendChild(choice);
    }
  }

  onAfterAttach(): void {
    document.addEventListener('keydown', this._keepEnter, true);
  }

  onBeforeDetach(): void {
    document.removeEventListener('keydown', this._keepEnter, true);
  }

  /** The keys kept from Dialog while the focus is on a method. */
  private readonly _kept: string[];

  /** Dialog swallows Enter on a body control; see EntryView._keepEnter. Enter on a method presses it. */
  private readonly _keepEnter = (event: KeyboardEvent): void => {
    if (
      this._kept.includes(event.key) &&
      this.node.contains(event.target as Node)
    ) {
      event.stopPropagation();
    }
  };
}

/**
 * Ask which unlock method to add: a press on a method chooses it and closes the
 * dialog. Resolves to null when the user backs out. `title` names the question, so
 * the same buttons serve adding a method and unlocking. `note` is the reason of a
 * dialog opened again. With Later among the choices it replaces Cancel: Cancel beside
 * it would suggest the vault goes away.
 */
export async function chooseUnlockMethod(
  states: Partial<Record<MethodChoice, IMethodState>>,
  title: string = trans.__('Add unlock method'),
  note?: string
): Promise<MethodChoice | null> {
  const body = new MethodForm(states, () => dialog.reject(), note);
  const dialog = new Dialog({
    title,
    body,
    focusNodeSelector: '.jp-PasskeyVaultForm-choice:enabled',
    hasClose: false,
    buttons: 'later' in states ? [] : [Dialog.cancelButton()]
  });
  await launchWithEscape(dialog);
  return body.chosen;
}

/**
 * Unlock with Password and passkey: the password, then the passkey, then one request.
 * The challenge is read before the password dialog, so the passkey request follows
 * that dialog's Submit with no network read between: the Submit is the click the
 * request needs. A challenge that expired or was replaced while the dialog was open is
 * the server's refusal, which the caller reports. The page holds the password during
 * the passkey prompt, as it holds the app pair's while the code is typed. Resolves to
 * false when cancelled.
 */
export async function unlockWithPair(
  api: VaultApi,
  slot: ISlot
): Promise<boolean> {
  const challenge = await api.challenge();
  const { accepted, value } = await askSecret(
    'Enter the unlock password',
    1,
    'Unlock vault'
  );
  if (!accepted || value === null) {
    return false;
  }
  await api.unlockPair(value, await passkeyAssertion(slot, challenge));
  return true;
}

/**
 * Ask how to unlock the vault, then unlock by the method chosen: a passkey for this
 * hostname, the unlock password with a code, the unlock password with a passkey that
 * has no PRF, or the recovery passphrase. Throws the cancellation as one line for the
 * CLI. `fail` reports a refusal of Password and passkey in the page too.
 */
export async function unlockWithChoice(
  api: VaultApi,
  status: IStatus,
  host: string = location.hostname,
  fail?: (text: string) => void
): Promise<void> {
  const kind = await chooseUnlockMethod(
    {
      passkey: isIpAddress(host)
        ? { unavailable: sentence(ipAddressAdvice(status.slots)) }
        : matchingSlots(status.slots, host).length > 0
          ? {}
          : { unavailable: `No passkey was added for ${host}.` },
      mfa: status.slots.some(slot => slot.type === 'password')
        ? {}
        : { unavailable: 'No unlock password was set.' },
      ...(status.slots.some(slot => slot.type === 'password-passkey')
        ? {
            pair: pairSlot(status.slots)
              ? {}
              : { unavailable: 'No passkey was added for this address.' }
          }
        : {}),
      recovery: {}
    },
    trans.__('Unlock vault')
  );
  if (kind === 'passkey') {
    await unlockWithPasskey(api, status, host);
  } else if (kind === 'mfa') {
    const { accepted, value } = await askSecret(
      'Enter the unlock password',
      1,
      'Unlock vault'
    );
    if (!accepted || value === null) {
      throw new VaultError(0, 'the unlock was cancelled');
    }
    const code = status.authenticator ? await askUnlockCode() : undefined;
    if (code === null) {
      throw new VaultError(0, 'the unlock was cancelled');
    }
    await api.unlockPassword(value, code);
  } else if (kind === 'pair') {
    const unlocked = await unlockWithPair(
      api,
      pairSlot(status.slots) as ISlot
    ).catch(e => {
      // The page says the server's refusal too: a challenge lives 600 s and the CLI
      // waits 120 s by default, so the refusal of one that expired reaches no CLI.
      // Only the CLI's unlock comes here; the panel reports its own failures.
      if (e instanceof VaultError && e.status > 0) {
        fail?.(sentence(e.short));
      }
      throw e;
    });
    if (!unlocked) {
      throw new VaultError(0, 'the unlock was cancelled');
    }
  } else if (kind === 'recovery') {
    const { accepted, value } = await askSecret(
      'Enter the recovery passphrase',
      1,
      'Unlock vault'
    );
    if (!accepted || value === null) {
      throw new VaultError(0, 'the unlock was cancelled');
    }
    await api.unlockRecovery(value);
  } else {
    throw new VaultError(0, 'the unlock was cancelled');
  }
}

/** The body of the dialog that adds an app: the QR code, the setup key, and the code field. */
class AuthenticatorForm extends Widget {
  readonly code = codeInput();

  constructor(setupKey: string, host: string, note: string) {
    super();
    this.addClass('jp-PasskeyVaultForm');
    const text = document.createElement('p');
    text.textContent = trans.__(
      'Scan the QR code or enter the setup key, then the app code'
    );
    const qr = document.createElement('div');
    qr.className = 'jp-PasskeyVaultForm-qr';
    const picture = qrSvg(otpauthUri(setupKey, host));
    picture.setAttribute('role', 'img');
    picture.setAttribute('aria-label', trans.__('QR code of the setup key'));
    qr.appendChild(picture);
    // In groups of four, as apps show a key, so it can be compared by eye.
    const key = document.createElement('div');
    key.className = 'jp-PasskeyVaultForm-setupKey';
    key.textContent = setupKey.replace(/(.{4})(?=.)/g, '$1 ');
    const help = document.createElement('div');
    help.className = 'jp-PasskeyVaultForm-help';
    help.setAttribute('role', 'status');
    help.textContent = note;
    this.node.append(
      text,
      qr,
      field('Setup key', key),
      field('Code from the app', this.code, help)
    );
  }

  onAfterAttach(): void {
    void Promise.resolve().then(() => {
      this.code.dispatchEvent(new Event('input', { bubbles: true }));
    });
  }
}

/** The title of every dialog that adds the pair. */
export const ADD_MFA = 'Add password and authenticator app';

/** The title of every dialog that adds Password and passkey. */
const ADD_PAIR = 'Add password and passkey';

/**
 * The step of a new unlock password: two fields, with Submit disabled under the
 * minimum length. `title` names the method it is for. Null when the user backs out.
 */
export async function askNewPassword(
  minLength: number,
  title: string = ADD_MFA
): Promise<string | null> {
  const { accepted, value } = await askSecret(
    `Enter the new unlock password, at least ${minLength} characters`,
    2,
    title,
    { minLength }
  );
  return accepted ? value : null;
}

/** The server's refusal of a code that is not the one the app shows now. */
const WRONG_CODE = 'wrong code';

/**
 * Add the unlock password `password` and an authenticator app with a proof: the
 * dialog shows a new setup key, and the server stores the two for the code the app
 * then shows. A wrong code opens the dialog again with the same key, so the app is
 * not set up twice. Any other refusal (a 4xx answer) comes after the app took the key,
 * so its line names the app's entry as unused. Resolves to false when the user backs
 * out.
 */
export async function registerMfa(
  api: VaultApi,
  password: string,
  proof: Proof,
  host: string,
  title: string
): Promise<boolean> {
  const setupKey = newSetupKey();
  let note = '';
  for (;;) {
    const body = new AuthenticatorForm(setupKey, host, note);
    const { button } = await launchWithEscape(
      new Dialog({
        title,
        body,
        // Typing starts in the code field, the one field to fill in.
        focusNodeSelector: '.jp-PasskeyVaultForm-code',
        hasClose: false,
        buttons: [
          Dialog.cancelButton(),
          Dialog.okButton({ label: trans.__('Add'), accept: true })
        ]
      })
    );
    if (!button.accept) {
      return false;
    }
    try {
      await api.addMfa(password, setupKey, body.code.value, proof);
      return true;
    } catch (e) {
      if (!(e instanceof VaultError && e.message === WRONG_CODE)) {
        // Only a 4xx answer is a refusal. After a lost answer or a 5xx the two may
        // have been added.
        const clause =
          '; the authenticator entry is unused - delete it in the app';
        throw e instanceof VaultError && e.status >= 400 && e.status < 500
          ? new VaultError(e.status, e.message + clause, fit(e.message, clause))
          : e;
      }
      note = 'Wrong code. Enter the code the app shows now.';
    }
  }
}

/**
 * The rest of a registration whose passkey has no PRF: the offer of Password and
 * passkey, a new unlock password, and one request that stores both. `proof` is the
 * one given before the passkey was created; a code is asked again, because a code
 * typed before two passkey prompts and a password has expired. Declined, or cancelled
 * at any step, it throws a line that names the other ways in, and the registration
 * reports the passkey unused.
 */
async function offerPair(
  api: VaultApi,
  pair: INewPair,
  proof: Proof,
  host: string
): Promise<void> {
  const status = await api.status();
  if (status.slots.some(s => s.type === 'password-passkey')) {
    throw new VaultError(
      0,
      'Password and passkey already added - remove it first'
    );
  }
  // What happened, then the ways that work: a retry on this authenticator fails again.
  const declined = new VaultError(
    0,
    'no PRF - passkey not added; use another passkey or Password and authenticator app'
  );
  const { button } = await launchWithEscape(
    new Dialog({
      title: ADD_PAIR,
      body: trans.__(
        'No PRF: the passkey cannot hold the vault key. A new unlock password decrypts the vault and the server checks the passkey; a copy of the vault opens with the password alone.'
      ),
      hasClose: false,
      buttons: [
        Dialog.cancelButton({ label: trans.__('Decline') }),
        Dialog.okButton({ label: trans.__('Continue'), accept: true })
      ]
    })
  );
  if (!button.accept) {
    throw declined;
  }
  const password = await askNewPassword(
    status.settings.password_min_length,
    ADD_PAIR
  );
  if (password === null) {
    throw declined;
  }
  const final =
    'code' in proof ? await askProof(api, status, host, ADD_PAIR, true) : proof;
  if (final === null) {
    throw declined;
  }
  await stored(
    api.addPair(
      {
        password,
        cred_id: pair.credId,
        rp_id: host,
        registration: pair.registration,
        label: pair.label,
        assertion: pair.assertion
      },
      final
    )
  );
}

/**
 * Add a new passkey with a proof. The user names the passkey first; that
 * dialog's button is also the fresh click the browser needs, after a passkey
 * request, before it creates the new passkey. `label` is the name offered. Resolves
 * to false when the user backs out before the browser created anything, else to the
 * type of the slot stored: `password-passkey` for a passkey with no PRF.
 */
export async function registerWithProof(
  api: VaultApi,
  proof: Proof,
  label: string,
  host: string
): Promise<false | ISlot['type']> {
  // Before the dialog whose click the `create` follows: a network read must not sit
  // between a click and a WebAuthn call. An assertion proof holds the one live
  // challenge until the request uses it, and its vault has Password and passkey
  // already, so this registration needs none.
  const challenge = 'assertion' in proof ? undefined : await api.challenge();
  const name = await nameNewPasskey(
    label,
    'prf' in proof
      ? 'Passkey accepted - your browser creates the new passkey next'
      : 'Your browser creates the passkey next.'
  );
  if (name === null) {
    return false;
  }
  return registerPasskey(
    api,
    name,
    confirmNewPasskey,
    proof,
    host,
    pair => offerPair(api, pair, proof, host),
    challenge
  );
}

/** The prompt of a new vault's passphrase, the first step of every set-up in the tab. */
export const NEW_RECOVERY =
  'Choose a recovery passphrase and store it offline - it opens the vault when no other method can';

/**
 * The last step of a set-up: the user adds an unlock method or leaves the recovery
 * slot alone. `passphrase`, just chosen, is the proof for either method, so it is not
 * asked again. A method step that fails or is cancelled opens the choice again with
 * its reason as a line in the dialog, because a notification would stay behind the
 * dialog. Later, or Escape, ends the set-up with the vault created and unlocked. At an
 * IP address, which cannot hold a passkey, the choice has no Passkey.
 */
export async function chooseFirstMethod(
  api: VaultApi,
  passphrase: string,
  minLength: number,
  host: string
): Promise<void> {
  const proof = { current: passphrase };
  let note: string | undefined;
  for (;;) {
    const kind = await chooseUnlockMethod(
      { ...(isIpAddress(host) ? {} : { passkey: {} }), mfa: {}, later: {} },
      undefined,
      note
    );
    if (kind !== 'passkey' && kind !== 'mfa') {
      return;
    }
    try {
      if (kind === 'passkey') {
        if (await registerWithProof(api, proof, '', host)) {
          return;
        }
        note = 'Adding the passkey was cancelled.';
      } else {
        const password = await askNewPassword(minLength);
        if (
          password !== null &&
          (await registerMfa(api, password, proof, host, ADD_MFA))
        ) {
          return;
        }
        note = 'Adding the password and authenticator app was cancelled.';
      }
    } catch (e) {
      note = sentence(describeFailure(e));
    }
  }
}

/** The recovery step's outcome as the one line the waiting CLI prints. */
function stepError(outcome: string): VaultError {
  return new VaultError(
    0,
    `recovery passphrase step ${outcome} - rerun the command to continue`
  );
}

/**
 * Set the vault up from the notification a command with no terminal raised: the
 * recovery passphrase, then the choice of an unlock method. `status` is the state the
 * press read: a vault made after the notification was raised needs neither, and the
 * command unlocks it the normal way.
 */
export async function setupVault(
  api: VaultApi,
  status: IStatus,
  host: string
): Promise<void> {
  if (status.initialized) {
    return;
  }
  const { accepted, value } = await askSecret(NEW_RECOVERY, 2, 'Create vault');
  if (!accepted || value === null) {
    throw stepError('was cancelled');
  }
  try {
    await api.init(value);
  } catch (e) {
    throw stepError(`failed (${describeFailure(e)})`);
  }
  await chooseFirstMethod(
    api,
    value,
    status.settings.password_min_length,
    host
  );
}
