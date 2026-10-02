import { Dialog } from '@jupyterlab/apputils';

import { LabIcon } from '@jupyterlab/ui-components';

import { Widget } from '@lumino/widgets';

import { askSecret, launchWithEscape } from '../passphrase';

import { mapCeremonyError } from '../passkey-util';

import {
  IEntry,
  IEntryFields,
  IStatus,
  Proof,
  VaultApi,
  VaultError
} from './api';

import { newSetupKey, otpauthUri, qrSvg } from './totp';

import {
  describeFailure,
  matchingSlots,
  passkeyPrf,
  registerPasskey
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
    private readonly _taken: string[] = []
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
    this.generate.textContent = 'Generate';
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
    this.notes = document.createElement('textarea');
    this.notes.className = 'jp-mod-styled jp-PasskeyVaultForm-notes';
    this.notes.value = entry?.notes ?? '';

    this.node.append(
      field('Name', this.name, this._nameHelp),
      field('Username', this.username),
      field('Password', passwordRow, this._passwordHelp, this.password),
      field('URL', this.url),
      field('Category', this.category),
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
        ? 'Save replaces the current password'
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
    void Promise.resolve().then(() => {
      this.name.dispatchEvent(new Event('input', { bubbles: true }));
    });
  }

  onBeforeDetach(): void {
    document.removeEventListener('input', this._revalidate, true);
    document.removeEventListener('keydown', this._keepEnterInNotes, true);
  }

  /**
   * Dialog's keydown handler calls preventDefault on every Enter, so no line break
   * could be typed in Notes and Enter on Generate did nothing. Stopped here, in
   * document capture, Enter never reaches it and does its own work.
   */
  private readonly _keepEnterInNotes = (event: KeyboardEvent): void => {
    if (
      event.key === 'Enter' &&
      (event.target === this.notes || event.target === this.generate)
    ) {
      event.stopPropagation();
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
}

const KEEP_HELP = 'Leave empty to keep the current password';

/** A lower-case message as a sentence of its own. */
export function sentence(text: string): string {
  return `${text[0].toUpperCase()}${text.slice(1)}.`;
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
 * Open the add or edit form; null when cancelled. `taken` are the names in use. It
 * answers the name and only the fields the user changed - the form's own loading (a
 * textarea turns CRLF into LF, a one-line field drops line breaks) is no change, and
 * the vault stores a field an add leaves out as empty.
 */
export async function editEntry(
  generate: () => Promise<string>,
  entry?: IEntry,
  taken: string[] = []
): Promise<IEntryFormValue | null> {
  const body = new EntryForm(generate, entry, taken);
  const dialog = new Dialog({
    title: entry ? 'Edit entry' : 'Add entry',
    body,
    // Dialog focuses its default button after the body attaches; this names the
    // first field to type in instead - Name in Add, Username in Edit.
    focusNodeSelector: 'input:not([readonly])',
    hasClose: false,
    buttons: [
      Dialog.cancelButton(),
      Dialog.okButton({ label: 'Save', accept: true })
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
    label: 'Code of the authenticator app',
    proof: code => ({ code })
  },
  password: {
    ask: 'the unlock password',
    label: 'Unlock password',
    proof: password => ({ password })
  },
  passphrase: {
    ask: 'the recovery passphrase',
    label: 'Recovery passphrase',
    proof: current => ({ current })
  }
};

/** How the entry popup gets the password. */
export interface IReveal {
  /** The proof of a passkey request for this hostname. */
  passkey: () => Promise<Proof>;
  /** The password, for a proof. */
  reveal: (proof: Proof) => Promise<string>;
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
 * The eye asks a passkey first. With none for this hostname, or no answer, a row
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
    this.prove.textContent = 'Show';
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
  private async _reveal(proof: Proof): Promise<void> {
    try {
      this.password.value = await this._how.reveal(proof);
      this._revealed = true;
      this._proofBox.remove();
      this.proof.value = '';
      this._show(true);
      this._help.textContent = this.password.value
        ? ''
        : 'This entry has no password';
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
  const dialog = new Dialog({
    title: entry.name,
    body: new EntryView(entry, how),
    // Focus on the eye, and Enter on a one-line field closes (Close is the default
    // button): a read-only view is left, not edited, by the key pressed to read it.
    focusNodeSelector: '.jp-PasskeyVaultForm-eye',
    defaultButton: 1,
    hasClose: false,
    buttons: [
      Dialog.warnButton({ label: 'Delete' }),
      Dialog.cancelButton({ label: 'Close' }),
      Dialog.okButton({ label: 'Edit' })
    ]
  });
  dialog.addClass('jp-PasskeyVaultForm-dialog');
  const { label } = (await launchWithEscape(dialog)).button;
  return label === 'Edit' ? 'edit' : label === 'Delete' ? 'delete' : null;
}

/** Ask before deleting `name`; true when confirmed. */
export async function confirmDelete(name: string): Promise<boolean> {
  const result = await launchWithEscape(
    new Dialog({
      title: 'Delete entry',
      body: `Delete ${name}? This cannot be undone.`,
      hasClose: false,
      buttons: [Dialog.cancelButton(), Dialog.warnButton({ label: 'Delete' })],
      // Enter cancels: the popup before it closes on Enter, and a delete has no undo.
      defaultButton: 0
    })
  );
  return result.button.label === 'Delete';
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
    help.textContent =
      'Tells this passkey apart from others in the list, for example "Work laptop"';
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
      title: 'Name the new passkey',
      body,
      // Typing starts in the name field; a space typed on the button would create.
      focusNodeSelector: 'input',
      hasClose: false,
      buttons: [
        Dialog.cancelButton(),
        Dialog.okButton({ label: 'Create passkey', accept: true })
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
      title: 'Confirm the new passkey',
      body: `The passkey "${name}" was created. Confirm it once more so the vault can derive its key from it.`,
      hasClose: false,
      buttons: [
        Dialog.cancelButton(),
        Dialog.okButton({ label: 'Confirm passkey', accept: true })
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
 * Ask for a code of the authenticator app. Resolves to the proof, to `passphrase`
 * when the user chose the recovery passphrase, or to null when cancelled.
 */
async function askCode(
  prompt: string,
  title: string
): Promise<Proof | 'passphrase' | null> {
  const body = new CodeForm(prompt);
  const { button } = await launchWithEscape(
    new Dialog({
      title,
      body,
      focusNodeSelector: 'input',
      hasClose: false,
      buttons: [
        Dialog.cancelButton(),
        Dialog.cancelButton({ label: USE_PASSPHRASE }),
        Dialog.okButton({ label: 'Submit', accept: true })
      ]
    })
  );
  if (button.accept) {
    return { code: body.code.value };
  }
  return button.label === USE_PASSPHRASE ? 'passphrase' : null;
}

/**
 * The proof the server asks before a recovery change, a new passkey or a new
 * authenticator app: a passkey request when a passkey for this hostname exists.
 * With none - or when that request gets no answer, or the passkey gives no PRF - a
 * code of the authenticator app when the vault has one and is unlocked,
 * else, or when the user chooses it, the current recovery passphrase. Call it
 * straight from a click: the passkey request comes before any other await. Resolves
 * to null when a dialog is cancelled.
 */
export async function askProof(
  status: IStatus,
  host: string,
  title: string
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
  const prompt = (proof: string) =>
    lead ? `${lead}enter ${proof} instead` : `Enter ${proof}`;
  // A code holds no key: it proves only while the vault is unlocked.
  if (status.unlocked && status.authenticator) {
    const answer = await askCode(
      prompt('a code of the authenticator app'),
      title
    );
    if (answer !== 'passphrase') {
      return answer;
    }
  }
  const { accepted, value } = await askSecret(
    prompt('the current recovery passphrase'),
    true,
    title
  );
  return accepted && value !== null ? { current: value } : null;
}

/** The kinds of sign-in method the panel adds. */
export type SignInMethod = 'passkey' | 'password' | 'authenticator';

/**
 * What each kind may do, as the dialog that offers them says it. The server holds the
 * rule (`PROOFS` in service.py); this is its wording for the person who chooses.
 */
const METHODS: Record<SignInMethod, { label: string; about: string }> = {
  passkey: {
    label: 'Passkey',
    about:
      'Unlocks the vault, and is asked before a password is shown, a sign-in method is added or the recovery passphrase is changed.'
  },
  password: {
    label: 'Unlock password',
    about:
      'Unlocks the vault, and is accepted before a password is shown. It is not accepted before a sign-in method is added or the recovery passphrase is changed.'
  },
  authenticator: {
    label: 'Authenticator app',
    about:
      'Its code is accepted where a passkey is asked while the vault is unlocked. It does not unlock the vault.'
  }
};

/** A kind's state in this vault: `unavailable` says why it cannot be chosen now. */
export interface IMethodState {
  note?: string;
  unavailable?: string;
}

/** The body of the dialog that offers the kinds: one radio button for each. */
class MethodForm extends Widget {
  constructor(states: Record<SignInMethod, IMethodState>) {
    super();
    this.addClass('jp-PasskeyVaultForm');
    for (const kind of Object.keys(METHODS) as SignInMethod[]) {
      const { label, about } = METHODS[kind];
      const { note, unavailable } = states[kind];
      const radio = document.createElement('input');
      radio.type = 'radio';
      radio.name = 'jp-PasskeyVaultForm-method';
      radio.value = kind;
      radio.disabled = unavailable !== undefined;
      radio.checked = !radio.disabled && this.getValue() === null;
      const text = document.createElement('span');
      text.className = 'jp-PasskeyVaultForm-choiceText';
      const name = document.createElement('span');
      name.textContent = label;
      const help = document.createElement('span');
      help.className = 'jp-PasskeyVaultForm-help';
      help.textContent = unavailable ?? (note ? `${about} ${note}` : about);
      text.append(name, help);
      // The radio button is named by the kind alone; what the kind does is read after it.
      name.id = `jp-PasskeyVaultForm-method-${kind}`;
      help.id = `${name.id}-help`;
      radio.setAttribute('aria-labelledby', name.id);
      radio.setAttribute('aria-describedby', help.id);
      const choice = document.createElement('label');
      choice.className = 'jp-PasskeyVaultForm-choice';
      choice.classList.toggle('jp-mod-disabled', radio.disabled);
      choice.append(radio, text);
      this.node.appendChild(choice);
    }
  }

  getValue(): SignInMethod | null {
    const checked = this.node.querySelector<HTMLInputElement>('input:checked');
    return checked ? (checked.value as SignInMethod) : null;
  }
}

/**
 * Ask which kind of sign-in method to add. Resolves to null when the user backs out.
 */
export async function chooseSignInMethod(
  states: Record<SignInMethod, IMethodState>
): Promise<SignInMethod | null> {
  const body = new MethodForm(states);
  const { button } = await launchWithEscape(
    new Dialog({
      title: 'Add sign-in method',
      body,
      focusNodeSelector: 'input:checked',
      hasClose: false,
      buttons: [
        Dialog.cancelButton(),
        Dialog.okButton({ label: 'Continue', accept: true })
      ]
    })
  );
  return button.accept ? body.getValue() : null;
}

/** The body of the dialog that adds an app: the QR code, the setup key, and the code field. */
class AuthenticatorForm extends Widget {
  readonly code = codeInput();

  constructor(setupKey: string, host: string, note: string) {
    super();
    this.addClass('jp-PasskeyVaultForm');
    const text = document.createElement('p');
    text.textContent =
      'Scan the QR code with the authenticator app, or type the setup key into the app. Then enter the code the app shows.';
    const qr = document.createElement('div');
    qr.className = 'jp-PasskeyVaultForm-qr';
    const picture = qrSvg(otpauthUri(setupKey, host));
    picture.setAttribute('role', 'img');
    picture.setAttribute('aria-label', 'QR code of the setup key');
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

/** The server's refusal of a code that is not the one the app shows now. */
const WRONG_CODE = 'wrong code';

/**
 * Add an authenticator app with a proof: the dialog shows a new setup key, and
 * the server stores it for the code the app then shows. A wrong code opens the dialog
 * again with the same key, so the app is not set up twice. Resolves to false when
 * the user backs out.
 */
export async function registerAuthenticator(
  api: VaultApi,
  proof: Proof,
  host: string
): Promise<boolean> {
  const setupKey = newSetupKey();
  let note = '';
  for (;;) {
    const body = new AuthenticatorForm(setupKey, host, note);
    const { button } = await launchWithEscape(
      new Dialog({
        title: 'Add authenticator app',
        body,
        // Typing starts in the code field, the one field to fill in.
        focusNodeSelector: '.jp-PasskeyVaultForm-code',
        hasClose: false,
        buttons: [
          Dialog.cancelButton(),
          Dialog.okButton({ label: 'Add', accept: true })
        ]
      })
    );
    if (!button.accept) {
      return false;
    }
    try {
      await api.addAuthenticator(setupKey, body.code.value, proof);
      return true;
    } catch (e) {
      if (!(e instanceof VaultError && e.message === WRONG_CODE)) {
        throw e;
      }
      note = 'Wrong code. Enter the code the app shows now.';
    }
  }
}

/**
 * Add a new passkey with a proof. The user names the passkey first; that
 * dialog's button is also the fresh click the browser needs, after a passkey
 * request, before it creates the new passkey. `label` is the name offered. Resolves
 * to false when the user backs out before the browser created anything.
 */
export async function registerWithProof(
  api: VaultApi,
  proof: Proof,
  label: string,
  host: string
): Promise<boolean> {
  const name = await nameNewPasskey(
    label,
    'prf' in proof
      ? 'Your passkey was accepted. Your browser creates the new passkey next.'
      : 'Your browser creates the passkey next.'
  );
  if (name === null) {
    return false;
  }
  await registerPasskey(api, name, confirmNewPasskey, proof, host);
  return true;
}
