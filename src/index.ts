import {
  JupyterFrontEnd,
  JupyterFrontEndPlugin
} from '@jupyterlab/application';

import { ICommandPalette } from '@jupyterlab/apputils';

import { runPasskey, IPasskeyArgs, PasskeyOp } from './passkey';

const COMMAND_ID = 'passkey:run';

/**
 * Initialization data for the jupyterlab_passkey_extension extension.
 */
const plugin: JupyterFrontEndPlugin<void> = {
  id: 'jupyterlab_passkey_extension:plugin',
  description:
    "Jupyterlab extension to allow passkeys to be captured by Jupyterlab with supporting API, CLI etc - to allow internal functionality such as vaults or secrets to be using the passkey functionality of the user's browser or operating system",
  autoStart: true,
  optional: [ICommandPalette],
  activate: (app: JupyterFrontEnd, palette: ICommandPalette | null) => {
    console.log(
      'JupyterLab extension jupyterlab_passkey_extension is activated!'
    );

    app.commands.addCommand(COMMAND_ID, {
      label: 'Run Passkey Ceremony',
      execute: args => {
        const { op, ...rest } = args as unknown as {
          op: PasskeyOp;
        } & IPasskeyArgs;
        return runPasskey(op, rest, app.serviceManager.serverSettings);
      }
    });

    if (palette) {
      palette.addItem({ command: COMMAND_ID, category: 'Passkey' });
    }
  }
};

export default plugin;
