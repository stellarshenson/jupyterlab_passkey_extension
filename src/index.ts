import {
  JupyterFrontEnd,
  JupyterFrontEndPlugin
} from '@jupyterlab/application';

import { requestAPI } from './request';

/**
 * Initialization data for the jupyterlab_passkey_extension extension.
 */
const plugin: JupyterFrontEndPlugin<void> = {
  id: 'jupyterlab_passkey_extension:plugin',
  description: 'Jupyterlab extension to allow passkeys to be captured by Jupyterlab with supporting API, CLI etc - to allow internal functionality such as vaults or secrets to be using the passkey functionality of the user\'s browser or operating system',
  autoStart: true,
  activate: (app: JupyterFrontEnd) => {
    console.log('JupyterLab extension jupyterlab_passkey_extension is activated!');

    requestAPI<any>('hello', app.serviceManager.serverSettings)
      .then(data => {
        console.log(data);
      })
      .catch(reason => {
        console.error(
          `The jupyterlab_passkey_extension server extension appears to be missing.\n${reason}`
        );
      });
  }
};

export default plugin;
