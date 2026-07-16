import { Dialog } from '@jupyterlab/apputils';

import { ServerConnection } from '@jupyterlab/services';

import { Widget } from '@lumino/widgets';

import { requestAPI } from './request';

export interface IPassphraseArgs {
  nonce: string;
  prompt?: string;
}

/** Whether the two fields agree yet, and what to tell the user about it. */
type MatchState = 'pending' | 'match' | 'mismatch';

/**
 * Dialog body: two password fields that must match.
 *
 * Native inputs carry jp-mod-styled so the lab themes their focus ring and
 * sizing. The status line always occupies its row - only its visibility flips -
 * so the dialog never changes height as the user types.
 */
class PassphraseBody extends Widget {
  readonly first: HTMLInputElement;
  readonly second: HTMLInputElement;
  private readonly _status: HTMLDivElement;

  constructor(prompt: string) {
    super();
    this.addClass('jp-PassphraseDialog-body');

    const label = document.createElement('div');
    label.className = 'jp-PassphraseDialog-prompt';
    label.textContent = prompt;

    this.first = PassphraseBody._input('Passphrase');
    this.second = PassphraseBody._input('Confirm passphrase');

    this._status = document.createElement('div');
    this._status.className = 'jp-PassphraseDialog-status';

    // Keeps the widget correct on its own terms, detached and untested by a
    // Dialog. The capture-phase listener added on attach is what wins the race
    // with Dialog's own gate; _validate is idempotent, so both firing is fine.
    const revalidate = () => this._validate();
    this.first.addEventListener('input', revalidate);
    this.second.addEventListener('input', revalidate);

    this.node.appendChild(label);
    this.node.appendChild(this.first);
    this.node.appendChild(this.second);
    this.node.appendChild(this._status);

    this._validate();
  }

  /** The agreed passphrase, or null when empty or mismatched. */
  get value(): string | null {
    const v = this.first.value;
    return v !== '' && v === this.second.value ? v : null;
  }

  /** What the status line is currently reporting. */
  get state(): MatchState {
    return (this._status.dataset.state as MatchState) ?? 'pending';
  }

  onAfterAttach(): void {
    // Dialog reads validity from a document-level `input` listener in the CAPTURE
    // phase. The per-field listeners above are on the bubble phase, so on their
    // own they update validity AFTER Dialog has already read it, leaving the gate
    // one keystroke stale - Submit stays disabled over a matching pair. Register
    // here instead: Lumino runs a child's onAfterAttach before its parent's, and
    // same-target capture listeners fire in registration order, so this lands
    // ahead of Dialog's and validity is fresh by the time Dialog looks.
    document.addEventListener('input', this._revalidate, true);

    this.first.focus();

    // Dialog only re-checks on `input`, and nothing has typed yet, so Submit
    // would open enabled over two empty fields. Seed the gate once Dialog's own
    // listener exists; a microtask suffices, as both onAfterAttach calls land in
    // the same task.
    void Promise.resolve().then(() => {
      this.second.dispatchEvent(new Event('input', { bubbles: true }));
    });
  }

  onBeforeDetach(): void {
    document.removeEventListener('input', this._revalidate, true);
  }

  /** Bound so add/removeEventListener agree on the identity. */
  private readonly _revalidate = (event: Event): void => {
    if (event.target === this.first || event.target === this.second) {
      this._validate();
    }
  };

  private _validate(): void {
    const matched = this.value !== null;

    // This IS the Submit gate, not decoration: Dialog._checkValidation disables
    // every accept button whenever its subtree matches `:invalid`, and a custom
    // validity message is what puts this field there. Empty counts as invalid
    // too - `value` is null until both fields agree on something non-empty.
    this.second.setCustomValidity(
      matched ? '' : 'Enter the same passphrase in both fields'
    );

    // Quiet until the confirm field has content - not mid-keystroke.
    const state: MatchState = matched
      ? 'match'
      : this.second.value === ''
        ? 'pending'
        : 'mismatch';
    this._status.dataset.state = state;
    this._status.textContent =
      state === 'match' ? 'Passphrases match' : 'Passphrases do not match';
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

  // Built directly rather than via showDialog (which is exactly this) so the
  // instance is in hand for reject() below.
  const dialog = new Dialog({
    title: 'Passphrase',
    body,
    // Cancel and Submit are the only ways out. hasClose:true would add a close
    // button AND dismiss on any click outside the dialog - and a passphrase
    // prompt that vanishes on a stray click leaves the CLI blocked on a relay
    // that is never coming, looking like a hang rather than a cancel.
    hasClose: false,
    buttons: [
      Dialog.cancelButton(),
      Dialog.okButton({ label: 'Submit', accept: true })
    ]
  });

  // hasClose:false switches Escape off along with the rest, and Escape is the one
  // dismissal worth keeping. Dialog's own keydown handler sits on its node in the
  // capture phase and swallows Escape without acting on it, so a listener on that
  // node or below never sees the event - document capture runs first.
  const onEscape = (event: KeyboardEvent) => {
    if (event.key === 'Escape') {
      dialog.reject();
    }
  };
  document.addEventListener('keydown', onEscape, true);

  let result: Dialog.IResult<unknown>;
  try {
    result = await dialog.launch();
  } finally {
    document.removeEventListener('keydown', onEscape, true);
  }

  // Submit is gated on a match, but re-check rather than trust the gate: this is
  // the last point before a value the user never confirmed reaches disk.
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
