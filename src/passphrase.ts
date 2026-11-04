import { Dialog } from '@jupyterlab/apputils';

import { ServerConnection } from '@jupyterlab/services';

import { Widget } from '@lumino/widgets';

import { requestAPI } from './request';

import { trans } from './trans';

export interface IPassphraseArgs {
  nonce: string;
  prompt?: string;
  /** true asks the value in two fields that must agree; the calling agent decides. */
  twice?: boolean;
}

/** Whether the two fields agree yet, and what to tell the user about it. */
type MatchState = 'pending' | 'match' | 'mismatch' | 'short';

/**
 * Dialog body: a password field, and a second one to confirm it when the caller
 * asks for two. The number of fields is never the user's choice.
 *
 * Double entry catches a typo in a passphrase being SET, where nothing else
 * will - get it wrong and the mistake surfaces at the next unlock, by which
 * time the right value is forgotten. It earns nothing for a secret being
 * PASTED out of a password manager, or for one that is checked at once, so those
 * take one field: the source of truth is already on the clipboard, and asking for
 * it twice only invites two pastes of the same mistake.
 *
 * Native inputs carry jp-mod-styled so the lab themes their focus ring and
 * sizing. The status line always occupies its row - only its visibility flips -
 * so the dialog never changes height as the user types.
 */
class PassphraseBody extends Widget {
  readonly first: HTMLInputElement;
  readonly second: HTMLInputElement;
  private readonly _status: HTMLDivElement;
  private readonly _announce: HTMLDivElement;
  private readonly _noun: string;
  private readonly _confirming: boolean;

  /**
   * `password` says the secret being set is a password, not a passphrase, and how
   * short it may be: the words of the fields and the status line follow it. `note` is
   * a line under the fields that says why the dialog opened again.
   */
  constructor(
    prompt: string,
    fields: 1 | 2,
    private readonly _password?: { minLength: number },
    note?: string
  ) {
    super();
    this.addClass('jp-PassphraseDialog-body');

    const label = document.createElement('div');
    label.className = 'jp-PassphraseDialog-prompt';
    label.textContent = prompt;

    this._noun = _password ? 'Password' : 'Passphrase';
    this._confirming = fields === 2;
    this.first = PassphraseBody._input(
      this._confirming ? this._noun : 'Secret'
    );
    this.second = PassphraseBody._input(`Confirm ${this._noun.toLowerCase()}`);

    // Two elements for one message, because the two jobs have opposite needs.
    //
    // _status is the row you see: it holds its space at every state and only
    // flips `visibility`, so the dialog's bottom edge never walks under the
    // pointer. Blanking its text while pending would drop the line box and
    // collapse it - the very jump the reserved row exists to prevent - so its
    // text is always set, and `aria-hidden` keeps that from being read out.
    //
    // _announce is the row a screen reader hears: it must sit in the
    // accessibility tree from the start, because a live region that is INSERTED
    // already holding its text is not reliably announced - and `visibility:
    // hidden` (which is what keeps _status quiet while pending) takes a node out
    // of that tree entirely. So this one is always present, always empty until
    // there is something true to say, and clipped to zero geometry so it cannot
    // touch the height _status is busy defending.
    this._status = document.createElement('div');
    this._announce = document.createElement('div');
    this._status.className = 'jp-PassphraseDialog-status';
    this._announce.className = 'jp-PassphraseDialog-announce';
    this._status.setAttribute('aria-hidden', 'true');
    this._announce.setAttribute('role', 'status');

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
    this.node.appendChild(this._announce);
    if (note) {
      const line = document.createElement('div');
      line.id = 'jp-PassphraseDialog-note';
      line.className = 'jp-PassphraseDialog-status';
      line.dataset.state = 'mismatch';
      line.textContent = note;
      // Read out with the field, which takes the focus when the dialog opens: a live
      // region inserted already holding its text is not reliably announced.
      this.first.setAttribute('aria-describedby', line.id);
      this.node.appendChild(line);
    }

    this.second.hidden = !this._confirming;
    this._status.hidden = !this._confirming;
    this._validate();
  }

  /** The agreed value, or null when empty or mismatched. */
  get value(): string | null {
    const v = this.first.value;
    if (v === '') {
      return null;
    }
    return this._confirming && v !== this.second.value ? null : v;
  }

  /** What the status line is currently reporting. */
  get state(): MatchState {
    return (this._status.dataset.state as MatchState) || 'pending';
  }

  /** The field Dialog's validity gate hangs off; see the constructor. */
  private get _gate(): HTMLInputElement {
    return this._confirming ? this.second : this.first;
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

    // Dialog only re-checks on `input`, and nothing has typed yet, so Submit
    // would open enabled over empty fields. Seed the gate once Dialog's own
    // listener exists; a microtask suffices, as both onAfterAttach calls land in
    // the same task.
    void Promise.resolve().then(() => {
      this._gate.dispatchEvent(new Event('input', { bubbles: true }));
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
    const short = (this.value ?? '').length < (this._password?.minLength ?? 0);

    // This IS the Submit gate, not decoration: Dialog._checkValidation disables
    // every accept button whenever its subtree matches `:invalid`, and a custom
    // validity message is what puts this field there. Empty counts as invalid
    // either way - `value` is null until there is something non-empty, and (with
    // a confirm field) until both agree on it.
    this._gate.setCustomValidity(
      !matched
        ? this._confirming
          ? `Enter the same ${this._noun.toLowerCase()} in both fields`
          : 'Enter the secret'
        : short
          ? `Enter at least ${this._password?.minLength} characters`
          : ''
    );

    // One field has nothing to compare, and its status row stays hidden.
    if (!this._confirming) {
      return;
    }

    // Quiet until the confirm field has content - not mid-keystroke.
    const state: MatchState = matched
      ? short
        ? 'short'
        : 'match'
      : this.second.value === ''
        ? 'pending'
        : 'mismatch';

    // Only on a real transition. Assigning textContent replaces the text node even
    // when the string is identical, and to a live region that is a change worth
    // announcing - so an unguarded write here would say "Passphrases do not match"
    // on every keystroke of a 20-character field, twice over, since _validate runs
    // from both the bubble listeners and the capture one. This is what keeps the
    // method idempotent now that anything is listening.
    if (this._status.dataset.state === state) {
      return;
    }
    this._status.dataset.state = state;
    this._status.textContent =
      state === 'match'
        ? `${this._noun}s match`
        : state === 'short'
          ? `Too short: at least ${this._password?.minLength} characters`
          : `${this._noun}s do not match`;
    // Empty while pending, so the live region announces nothing until the user has
    // given it something to be about - see the constructor for why this is not just
    // the same node with its visibility flipped.
    this._announce.textContent =
      state === 'pending' ? '' : this._status.textContent;
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
 * Prompt for a secret - once by default, twice with `twice` - and relay it to
 * the server.
 *
 * A single entry need only be non-empty; two entries are a caller asking for
 * confirmation, and must match. Either way the value is POSTed to the "passphrase" endpoint,
 * which writes it raw to a relay (a keyctl key, or an atomic 0600 file) so a
 * local client can read it -
 * a vault, a .env, anything that should never see the value cross a terminal.
 * Returns true when a value was relayed, false when the user cancelled. The
 * value is never logged.
 */
export async function runPassphrase(
  args: IPassphraseArgs,
  serverSettings: ServerConnection.ISettings
): Promise<boolean> {
  const twice = args.twice === true;
  const { accepted, value: passphrase } = await askSecret(
    args.prompt ?? (twice ? 'Enter the passphrase twice' : 'Enter the secret'),
    twice ? 2 : 1
  );

  if (!accepted) {
    // Say so, rather than saying nothing. The relay is the only channel back to the
    // waiting CLI, so a silent dismissal is indistinguishable from a button nobody
    // has clicked - and the caller sits out its whole timeout before reporting a
    // refusal the user made at once. The marker carries no secret.
    await requestAPI<void>('passphrase', serverSettings, {
      method: 'POST',
      body: JSON.stringify({ nonce: args.nonce, cancelled: true })
    });
    return false;
  }

  // Submit is gated on a match, but re-check rather than trust the gate: this is the
  // last point before a value the user never confirmed reaches disk. Nothing is
  // signalled here - an accepted dialog with no value is a bug in the gate, not a
  // decision the user made, and it must not be reported to the caller as a refusal.
  if (passphrase === null) {
    return false;
  }

  await requestAPI<void>('passphrase', serverSettings, {
    method: 'POST',
    body: JSON.stringify({ nonce: args.nonce, passphrase })
  });

  return true;
}

/**
 * Launch a dialog built with hasClose:false, keeping Escape as a way out.
 *
 * hasClose:false switches Escape off along with the rest, and Escape is the one
 * dismissal worth keeping. Dialog's own keydown handler sits on its node in the
 * capture phase and swallows Escape without acting on it, so a listener on that
 * node or below never sees the event - document capture runs first.
 */
export async function launchWithEscape<T>(
  dialog: Dialog<T>
): Promise<Dialog.IResult<T>> {
  const onEscape = (event: KeyboardEvent) => {
    // A dialog launched while another is open waits in a queue; only the one on
    // screen closes. Closing it attaches the next before that one's listener runs,
    // so the first listener marks the key as used.
    if (
      event.key === 'Escape' &&
      dialog.isAttached &&
      !event.defaultPrevented
    ) {
      event.preventDefault();
      dialog.reject();
    }
  };
  document.addEventListener('keydown', onEscape, true);
  try {
    return await dialog.launch();
  } finally {
    document.removeEventListener('keydown', onEscape, true);
  }
}

/**
 * Ask for a secret in the passphrase dialog and return it, relaying nothing.
 *
 * `fields` is required, because the caller decides by the kind of secret and no
 * control leaves it to the user: 2 for a recovery passphrase or a new unlock
 * password, whose two fields must agree; 1 for an entry value, an unlock and a
 * proof. `accepted` is false when the user cancelled; `value` is null when the
 * dialog was accepted without a confirmed value, which the Submit gate should
 * prevent. The vault panel asks for its recovery passphrase through this, and
 * with `password` for a new unlock password, which must have its minimum length
 * before Submit works. `note` shows a line under the fields, for a dialog opened
 * again after a refusal.
 */
export async function askSecret(
  prompt: string,
  fields: 1 | 2,
  title?: string,
  password?: { minLength: number },
  note?: string
): Promise<{ accepted: boolean; value: string | null }> {
  const body = new PassphraseBody(prompt, fields, password, note);

  // Built directly rather than via showDialog (which is exactly this) so the
  // instance can be passed to launchWithEscape.
  const dialog = new Dialog({
    title:
      title ?? (fields === 1 ? trans.__('Secret') : trans.__('Passphrase')),
    body,
    // hasClose:true would add a close button AND dismiss on any click outside the
    // dialog - and a passphrase prompt that vanishes on a stray click leaves the
    // CLI blocked on a relay that is never coming, looking like a hang rather than
    // a cancel.
    hasClose: false,
    // Dialog focuses its default button after the body attaches; this names the
    // passphrase field instead, so typing starts there.
    focusNodeSelector: 'input',
    buttons: [
      Dialog.cancelButton(),
      Dialog.okButton({ label: trans.__('Submit'), accept: true })
    ]
  });

  const result = await launchWithEscape(dialog);
  return result.button.accept
    ? { accepted: true, value: body.value }
    : { accepted: false, value: null };
}
