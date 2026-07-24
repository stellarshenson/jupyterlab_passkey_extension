import { Dialog } from '@jupyterlab/apputils';

import { ServerConnection } from '@jupyterlab/services';

import { Widget } from '@lumino/widgets';

import { requestAPI } from './request';

export interface IShowArgs {
  nonce: string;
  label?: string;
}

/**
 * Show a code a local client staged, as an image the page never holds as text.
 *
 * The counterpart of `copy` for a value the user must READ rather than paste - a
 * one-time authenticator code, a pairing code. The server renders the staged code
 * to a distorted PNG and this only ever receives that image, so the code is absent
 * from the notifications broadcast, the DOM as text, and the accessibility tree.
 * An OCR pass on a screenshot still has to beat the distortion.
 *
 * The fetch is a one-shot consume, so the code is gone from the server the moment
 * the image comes back - a dismissed dialog cannot be reopened, and a second click
 * simply 404s. The code is never logged and never leaves the server as text.
 */
export async function runShow(
  args: IShowArgs,
  serverSettings: ServerConnection.ISettings
): Promise<void> {
  const { png } = await requestAPI<{ png: string }>('render', serverSettings, {
    method: 'POST',
    body: JSON.stringify({ nonce: args.nonce })
  });

  const body = new Widget();
  body.addClass('jp-PasskeyCode-body');

  if (args.label) {
    // The label is a name the caller chose, never the code - safe as text.
    const label = document.createElement('div');
    label.className = 'jp-PasskeyCode-label';
    label.textContent = args.label;
    body.node.appendChild(label);
  }

  const img = document.createElement('img');
  img.className = 'jp-PasskeyCode-image';
  // Deliberately empty alt text: the code must not re-enter the accessibility
  // tree the image exists to keep it out of. Closing that channel is the point.
  img.alt = '';
  img.src = `data:image/png;base64,${png}`;
  body.node.appendChild(img);

  // hasClose:false, mirroring the passphrase dialog: the default (true) dismisses
  // the dialog on any click outside it, which closes it out from under the user the
  // moment focus moves. The Close button is the one way out; nothing is waiting on
  // the far side, so no Escape handler is needed here.
  await new Dialog({
    title: 'Code',
    body,
    hasClose: false,
    buttons: [Dialog.okButton({ label: 'Close' })]
  }).launch();
}
