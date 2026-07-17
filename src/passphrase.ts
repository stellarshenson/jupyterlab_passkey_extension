import { Dialog } from '@jupyterlab/apputils';

import { ServerConnection } from '@jupyterlab/services';

import { Widget } from '@lumino/widgets';

import { requestAPI } from './request';

export interface IPassphraseArgs {
  nonce: string;
  prompt?: string;
  once?: boolean;
}

/** Whether the two fields agree yet, and what to tell the user about it. */
type MatchState = 'pending' | 'match' | 'mismatch';

/**
 * Dialog body: a password field, and a second one to confirm it unless `once`.
 *
 * Double entry catches a typo in a passphrase being SET, where nothing else
 * will - get it wrong and the mistake surfaces at the next unlock, by which
 * time the right value is forgotten. It earns nothing for a secret being
 * PASTED out of a password manager, which is why `once` exists: the source of
 * truth is already on the clipboard, and asking for it twice only invites two
 * pastes of the same mistake.
 *
 * Native inputs carry jp-mod-styled so the lab themes their focus ring and
 * sizing. The status line always occupies its row - only its visibility flips -
 * so the dialog never changes height as the user types.
 */
class PassphraseBody extends Widget {
  readonly first: HTMLInputElement;
  readonly second: HTMLInputElement | null;
  private readonly _status: HTMLDivElement | null;
  private readonly _announce: HTMLDivElement | null;
  private readonly _gate: HTMLInputElement;

  constructor(prompt: string, once: boolean) {
    super();
    this.addClass('jp-PassphraseDialog-body');

    const label = document.createElement('div');
    label.className = 'jp-PassphraseDialog-prompt';
    label.textContent = prompt;

    this.first = PassphraseBody._input(once ? 'Secret' : 'Passphrase');
    this.second = once ? null : PassphraseBody._input('Confirm passphrase');

    // The field Dialog's validity gate hangs off: the confirm field where there
    // is one, since that is where a mismatch is discovered, and the only field
    // where there is not.
    this._gate = this.second ?? this.first;

    // Nothing to report without a second field to disagree with the first.
    this._status = once ? null : document.createElement('div');
    this._announce = once ? null : document.createElement('div');
    if (this._status && this._announce) {
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
      this._status.className = 'jp-PassphraseDialog-status';
      this._status.setAttribute('aria-hidden', 'true');
      this._announce.className = 'jp-PassphraseDialog-announce';
      this._announce.setAttribute('role', 'status');
    }

    // Keeps the widget correct on its own terms, detached and untested by a
    // Dialog. The capture-phase listener added on attach is what wins the race
    // with Dialog's own gate; _validate is idempotent, so both firing is fine.
    const revalidate = () => this._validate();
    this.first.addEventListener('input', revalidate);
    this.second?.addEventListener('input', revalidate);

    this.node.appendChild(label);
    this.node.appendChild(this.first);
    if (this.second) {
      this.node.appendChild(this.second);
    }
    if (this._status) {
      this.node.appendChild(this._status);
    }
    if (this._announce) {
      this.node.appendChild(this._announce);
    }

    this._validate();
  }

  /** The agreed value, or null when empty or mismatched. */
  get value(): string | null {
    const v = this.first.value;
    if (v === '') {
      return null;
    }
    return this.second === null || v === this.second.value ? v : null;
  }

  /** What the status line is currently reporting. */
  get state(): MatchState {
    return (this._status?.dataset.state as MatchState) ?? 'pending';
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

    // This IS the Submit gate, not decoration: Dialog._checkValidation disables
    // every accept button whenever its subtree matches `:invalid`, and a custom
    // validity message is what puts this field there. Empty counts as invalid
    // either way - `value` is null until there is something non-empty, and (with
    // a confirm field) until both agree on it.
    this._gate.setCustomValidity(
      matched
        ? ''
        : this.second === null
          ? 'Enter the secret'
          : 'Enter the same passphrase in both fields'
    );

    if (!this.second || !this._status || !this._announce) {
      return;
    }

    // Quiet until the confirm field has content - not mid-keystroke.
    const state: MatchState = matched
      ? 'match'
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
      state === 'match' ? 'Passphrases match' : 'Passphrases do not match';
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
 * Prompt for a secret - twice by default, once with `once` - and relay it to
 * the server.
 *
 * Two entries are confirmed to match in the dialog; a single entry need only be
 * non-empty. Either way the value is POSTed to the "passphrase" endpoint, which
 * writes it raw to an atomic 0600 relay file so a local client can read it -
 * a vault, a .env, anything that should never see the value cross a terminal.
 * Returns true when a value was relayed, false when the user cancelled. The
 * value is never logged.
 */
export async function runPassphrase(
  args: IPassphraseArgs,
  serverSettings: ServerConnection.ISettings
): Promise<boolean> {
  const once = args.once === true;
  const body = new PassphraseBody(
    args.prompt ?? (once ? 'Enter the secret' : 'Enter the passphrase twice'),
    once
  );

  // Built directly rather than via showDialog (which is exactly this) so the
  // instance is in hand for reject() below.
  const dialog = new Dialog({
    title: once ? 'Secret' : 'Passphrase',
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
