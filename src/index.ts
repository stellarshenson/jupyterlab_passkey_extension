import {
  JupyterFrontEnd,
  JupyterFrontEndPlugin
} from '@jupyterlab/application';

import { ICommandPalette } from '@jupyterlab/apputils';

import { ITranslator } from '@jupyterlab/translation';

import { runPasskey, IPasskeyArgs, PasskeyOp } from './passkey';

import type { IPassphraseArgs } from './passphrase';

import { runCopy, ICopyArgs } from './copy';

import type { IShowArgs } from './show';

import { setTranslator, trans } from './trans';

import { vaultPlugin } from './vault/plugin';

const COMMAND_ID = 'passkey:run';
const PASSPHRASE_COMMAND_ID = 'passkey:passphrase';
const COPY_COMMAND_ID = 'passkey:copy';
const SHOW_COMMAND_ID = 'passkey:show';

/** What every bridge command's `nonce` argument is. */
const NONCE =
  'Names the one-shot relay of this request; [A-Za-z0-9_-]{16,128}.';

/**
 * Initialization data for the jupyterlab_passkey_extension extension.
 */
const plugin: JupyterFrontEndPlugin<void> = {
  id: 'jupyterlab_passkey_extension:plugin',
  description:
    "Jupyterlab extension to allow passkeys to be captured by Jupyterlab with supporting API, CLI etc - to allow internal functionality such as vaults or secrets to be using the passkey functionality of the user's browser or operating system",
  autoStart: true,
  optional: [ICommandPalette, ITranslator],
  activate: (
    app: JupyterFrontEnd,
    palette: ICommandPalette | null,
    translator: ITranslator | null
  ) => {
    console.log(
      'JupyterLab extension jupyterlab_passkey_extension is activated!'
    );
    setTranslator(translator);

    app.commands.addCommand(COMMAND_ID, {
      label: trans.__('Run Passkey Ceremony'),
      describedBy: {
        args: {
          type: 'object',
          properties: {
            op: {
              type: 'string',
              enum: ['create', 'get'],
              description: 'create registers a passkey, get asserts one.'
            },
            nonce: { type: 'string', description: NONCE },
            rp_id: {
              type: 'string',
              description:
                'WebAuthn RP ID: the hostname of the JupyterLab tab, never an IP address.'
            },
            cred_id: {
              type: 'string',
              description:
                'For get: the base64url credential id a create returned.'
            },
            prf_salt: {
              type: 'string',
              description:
                'A base64url 32-byte salt; the PRF is evaluated when it is present.'
            },
            user: {
              type: 'object',
              description:
                'For create: id (base64url), name and displayName of the user.'
            }
          },
          required: ['op', 'nonce', 'rp_id']
        }
      },
      execute: args => {
        const { op, ...rest } = args as unknown as {
          op: PasskeyOp;
        } & IPasskeyArgs;
        return runPasskey(op, rest, app.serviceManager.serverSettings);
      }
    });

    app.commands.addCommand(PASSPHRASE_COMMAND_ID, {
      label: trans.__('Enter Passphrase'),
      describedBy: {
        args: {
          type: 'object',
          properties: {
            nonce: { type: 'string', description: NONCE },
            prompt: {
              type: 'string',
              description: 'The text the dialog asks with.'
            },
            once: {
              type: 'boolean',
              description:
                'true asks the value once, with no field to confirm it.'
            }
          },
          required: ['nonce']
        }
      },
      execute: async args => {
        const { runPassphrase } = await import('./passphrase');
        const passphraseArgs = args as unknown as IPassphraseArgs;
        return runPassphrase(passphraseArgs, app.serviceManager.serverSettings);
      }
    });

    app.commands.addCommand(COPY_COMMAND_ID, {
      label: trans.__('Copy Secret To Clipboard'),
      describedBy: {
        args: {
          type: 'object',
          properties: {
            nonce: { type: 'string', description: NONCE },
            label: {
              type: 'string',
              description:
                'Names the secret when the page asks for a second click.'
            }
          },
          required: ['nonce']
        }
      },
      execute: args => {
        const copyArgs = args as unknown as ICopyArgs;
        return runCopy(copyArgs, app.serviceManager.serverSettings);
      }
    });

    app.commands.addCommand(SHOW_COMMAND_ID, {
      label: trans.__('Show Code'),
      describedBy: {
        args: {
          type: 'object',
          properties: {
            nonce: { type: 'string', description: NONCE },
            label: {
              type: 'string',
              description: 'The name shown above the image of the code.'
            }
          },
          required: ['nonce']
        }
      },
      execute: async args => {
        const { runShow } = await import('./show');
        const showArgs = args as unknown as IShowArgs;
        return runShow(showArgs, app.serviceManager.serverSettings);
      }
    });

    if (palette) {
      palette.addItem({ command: COMMAND_ID, category: trans.__('Passkey') });
      palette.addItem({
        command: PASSPHRASE_COMMAND_ID,
        category: trans.__('Passkey')
      });
      palette.addItem({
        command: COPY_COMMAND_ID,
        category: trans.__('Passkey')
      });
      palette.addItem({
        command: SHOW_COMMAND_ID,
        category: trans.__('Passkey')
      });
    }
  }
};

export default [plugin, vaultPlugin];
