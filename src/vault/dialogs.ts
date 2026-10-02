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

/**
 * An entry, read-only, laid out like the edit form. The password is not in the page
 * until `reveal` returns it: the eye asks for it once, then only hides and shows it.
 */
export class EntryView extends Widget {
  readonly password: HTMLInputElement;
  readonly eye: HTMLButtonElement;

  constructor(
    entry: IEntry,
    private readonly _reveal: () => Promise<string>
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
    const notes = document.createElement('textarea');
    notes.className = 'jp-mod-styled jp-PasskeyVaultForm-notes';
    notes.readOnly = true;
    notes.value = entry.notes;

    this.node.append(
      field('Name', shown(entry.name)),
      field('Username', shown(entry.username)),
      field('Password', passwordRow, this._help, this.password),
      field('URL', shown(entry.url)),
      field('Category', shown(entry.category)),
      field('Notes', notes)
    );
  }

  onAfterAttach(): void {
    document.addEventListener('keydown', this._keepEnterOnEye, true);
  }

  onBeforeDetach(): void {
    document.removeEventListener('keydown', this._keepEnterOnEye, true);
  }

  /** Dialog swallows Enter on a body button; see EntryForm._keepEnterInNotes. */
  private readonly _keepEnterOnEye = (event: KeyboardEvent): void => {
    if (event.key === 'Enter' && event.target === this.eye) {
      event.stopPropagation();
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
    this._pending = true;
    // The passkey prompt is the browser's and can open late or behind the window:
    // the eye and the line under the field say the click was taken.
    const spinner = document.createElement('span');
    spinner.className = 'jp-PasskeyVaultForm-spinner';
    this.eye.replaceChildren(spinner);
    this.eye.setAttribute('aria-busy', 'true');
    this._help.textContent = 'Waiting for your passkey';
    try {
      this.password.value = await this._reveal();
      this._revealed = true;
      this._show(true);
      this._help.textContent = this.password.value
        ? ''
        : 'This entry has no password';
    } catch (e) {
      this._show(false);
      // A cancelled passkey prompt is the user's choice: the dots stay, nothing is said.
      this._help.textContent =
        mapCeremonyError(e) === 'not-allowed'
          ? ''
          : `The password was not shown: ${describeFailure(e)}`;
    } finally {
      this._pending = false;
      this.eye.removeAttribute('aria-busy');
    }
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
  private _revealed = false;
  private _pending = false;
}

/**
 * Open an entry in the read-only popup. Resolves to the action chosen - `edit` or
 * `delete` - or null when closed.
 */
export async function viewEntry(
  entry: IEntry,
  reveal: () => Promise<string>
): Promise<'edit' | 'delete' | null> {
  const dialog = new Dialog({
    title: entry.name,
    body: new EntryView(entry, reveal),
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

/**
 * The proof the server asks before a recovery change or a new passkey: a passkey
 * request when a passkey for this hostname exists, else - or when that request gets
 * no answer, or the passkey gives no PRF - the current recovery passphrase. Call it
 * straight from a click: the passkey request comes before any other await. Resolves
 * to null when the passphrase dialog is cancelled.
 */
export async function askProof(
  status: IStatus,
  host: string,
  title: string
): Promise<Proof | null> {
  let prompt = 'Enter the current recovery passphrase';
  if (matchingSlots(status.slots, host).length > 0) {
    try {
      const { credId, prf } = await passkeyPrf(status, host);
      return { cred_id: credId, prf };
    } catch (e) {
      // This hostname's passkeys can sit on another device - a second machine
      // registering its own - so a refused or dismissed request falls back, and so
      // does the page's own refusal of a passkey that gives no PRF.
      if (mapCeremonyError(e) === 'not-allowed') {
        prompt =
          'No passkey answered - enter the current recovery passphrase instead';
      } else if (e instanceof VaultError) {
        prompt =
          'This passkey cannot unlock the vault - enter the current recovery passphrase instead';
      } else {
        throw e;
      }
    }
  }
  const { accepted, value } = await askSecret(prompt, true, title);
  return accepted && value !== null ? { current: value } : null;
}

/**
 * Register a new passkey with a proof. The user names the passkey first; that
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
