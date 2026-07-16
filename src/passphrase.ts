import { Dialog, showDialog } from '@jupyterlab/apputils';

import { ServerConnection } from '@jupyterlab/services';

import { Widget } from '@lumino/widgets';

import { requestAPI } from './request';

export interface IPassphraseArgs {
  nonce: string;
  prompt?: string;
}

/**
 * Dialog body: two password fields that must match.
 *
 * Native inputs carry jp-mod-styled so the lab themes their focus ring and
 * sizing; the mismatch banner is only revealed once both fields are non-empty,
 * so it does not shout while the user is still typing.
 */
class PassphraseBody extends Widget {
  readonly first: HTMLInputElement;
  readonly second: HTMLInputElement;
  private readonly _error: HTMLDivElement;

  constructor(prompt: string) {
    super();
    this.addClass('jp-PassphraseDialog-body');

    const label = document.createElement('div');
    label.className = 'jp-PassphraseDialog-prompt';
    label.textContent = prompt;

    this.first = PassphraseBody._input('Passphrase');
    this.second = PassphraseBody._input('Confirm passphrase');

    this._error = document.createElement('div');
    this._error.className = 'jp-PassphraseDialog-error';
    this._error.textContent = 'Passphrases do not match';
    this._error.hidden = true;

    const revalidate = () => this._validate();
    this.first.addEventListener('input', revalidate);
    this.second.addEventListener('input', revalidate);

    this.node.appendChild(label);
    this.node.appendChild(this.first);
    this.node.appendChild(this.second);
    this.node.appendChild(this._error);
  }

  /** The agreed passphrase, or null when empty or mismatched. */
  get value(): string | null {
    const v = this.first.value;
    return v !== '' && v === this.second.value ? v : null;
  }

  onAfterAttach(): void {
    this.first.focus();
  }

  private _validate(): void {
    // Only complain once the confirm field has content - not mid-keystroke.
    this._error.hidden = this.second.value === '' || this.value !== null;
  }

  private static _input(placeholder: string): HTMLInputElement {
    const input = document.createElement('input');
    input.type = 'password';
    input.placeholder = placeholder;
    input.className = 'jp-mod-styled jp-PassphraseDialog-input';
    // Never let the browser or a password manager retain a recovery passphrase.
    input.autocomplete = 'new-password';
    return input;
  }
}

/**
 * Prompt for a passphrase (entered twice) and relay it to the server.
 *
 * The passphrase is confirmed to match in the dialog, then POSTed to the
 * "passphrase" endpoint, which writes it raw to an atomic 0600 relay file so a
 * local client can read it. Returns true when a passphrase was relayed, false
 * when the user cancelled. The value is never logged.
 */
export async function runPassphrase(
  args: IPassphraseArgs,
  serverSettings: ServerConnection.ISettings
): Promise<boolean> {
  const body = new PassphraseBody(args.prompt ?? 'Enter the passphrase twice');

  const result = await showDialog({
    title: 'Passphrase',
    body,
    buttons: [
      Dialog.cancelButton(),
      Dialog.okButton({ label: 'Submit', accept: true })
    ]
  });

  // A mismatch reaching this point means the user accepted anyway - treat it as
  // a cancel rather than relaying a value they did not confirm.
  const passphrase = body.value;
  if (!result.button.accept || passphrase === null) {
    return false;
  }

  await requestAPI<void>('passphrase', serverSettings, {
    method: 'POST',
    body: JSON.stringify({ nonce: args.nonce, passphrase })
  });

  return true;
}
