import {
  JupyterFrontEnd,
  JupyterFrontEndPlugin
} from '@jupyterlab/application';

import { ISettingRegistry } from '@jupyterlab/settingregistry';

import { ITranslator } from '@jupyterlab/translation';

import { requestAPI } from '../request';

import { setTranslator, trans } from '../trans';

import { VaultApi, VaultError } from './api';

// eslint-disable-next-line jupyter/prefer-lazy-imports -- activate() needs the panel class at once
import { VaultPanel } from './panel';

const VAULT_PLUGIN_ID = 'jupyterlab_passkey_extension:vault';
const UNLOCK_COMMAND = 'passkey:vault-unlock';
export const REGISTER_COMMAND = 'passkey:vault-register';
const PANEL_RANK = 900;

export type Side = 'left' | 'right';

/**
 * Move the panel to the chosen sidebar now and on every change. The vault's policy -
 * the unlock duration, the reveal window, the shortest unlock password and the
 * rotation period - lives in the server's configuration file, so the page has none to
 * send.
 */
export function connectSettings(
  settings: ISettingRegistry.ISettings,
  dock: (side: Side) => void
): void {
  let docked: Side | null = null;
  const apply = (): void => {
    const side =
      settings.get('sidebar').composite === 'left' ? 'left' : 'right';
    // Only on a change of side: docking again collapses the open panel.
    if (side !== docked) {
      docked = side;
      dock(side);
    }
  };
  apply();
  settings.changed.connect(apply);
}

/**
 * Run a vault step for a CLI that raised a notification, and answer it through the
 * result relay it waits on: `ok`, or the reason as one line. The PRF never goes
 * into that relay - the page sends it straight to the vault endpoint.
 */
async function answerCli(
  app: JupyterFrontEnd,
  nonce: string | undefined,
  step: () => Promise<unknown>,
  panel: VaultPanel
): Promise<void> {
  const { describeFailure } = await import('./webauthn');
  let body: Record<string, unknown>;
  try {
    await step();
    body = { ok: true };
    panel.clearLine();
  } catch (e) {
    body = { ok: false, error: describeFailure(e) };
  }
  if (nonce) {
    await requestAPI<void>('result', app.serviceManager.serverSettings, {
      method: 'POST',
      body: JSON.stringify({ nonce, ...body })
    });
  }
  await panel.refresh();
}

export const vaultPlugin: JupyterFrontEndPlugin<void> = {
  id: VAULT_PLUGIN_ID,
  description:
    'A password vault the Jupyter server keeps, unlocked with a passkey, with an unlock password and an authenticator code, or with the recovery passphrase',
  autoStart: true,
  optional: [ISettingRegistry, ITranslator],
  activate: async (
    app: JupyterFrontEnd,
    settingRegistry: ISettingRegistry | null,
    translator: ITranslator | null
  ) => {
    const { askProof, registerWithProof } = await import('./dialogs');
    const { ipAddressAdvice, isIpAddress, matchingSlots, unlockWithPasskey } =
      await import('./webauthn');
    setTranslator(translator);
    const api = new VaultApi(app.serviceManager.serverSettings);
    const panel = new VaultPanel({
      api,
      openSettings: () =>
        void app.commands.execute('settingeditor:open', {
          // The title in schema/vault.json, which the Settings Editor searches.
          query: 'Passkey Vault'
        })
    });
    // Read the state now, so the unlock command a CLI raises has the passkey slots
    // without a network read between the click and the WebAuthn call.
    void panel.refresh();
    const dock = (side: Side): void => {
      // Lumino re-parents on add(), so the same call docks and moves.
      app.shell.add(panel, side, { rank: PANEL_RANK });
    };

    app.commands.addCommand(UNLOCK_COMMAND, {
      label: trans.__('Unlock Vault With Passkey'),
      describedBy: {
        args: {
          type: 'object',
          properties: {
            nonce: {
              type: 'string',
              description:
                'Names the relay the outcome is posted to; with none, nothing is posted.'
            }
          }
        }
      },
      execute: args =>
        answerCli(
          app,
          args.nonce as string | undefined,
          async () => {
            // The state this tab last read keeps the WebAuthn call free of a network
            // read. With no passkey for this hostname in it, it can be stale (a
            // passkey registered since), so it is read again.
            let status = panel.status ?? (await api.status());
            if (matchingSlots(status.slots, location.hostname).length === 0) {
              status = await api.status();
            }
            return unlockWithPasskey(api, status);
          },
          panel
        )
    });

    app.commands.addCommand(REGISTER_COMMAND, {
      label: trans.__('Add Vault Passkey'),
      describedBy: {
        args: {
          type: 'object',
          properties: {
            nonce: {
              type: 'string',
              description:
                'Names the relay the outcome is posted to; with none, nothing is posted.'
            },
            label: {
              type: 'string',
              description: 'The name offered for the new passkey.'
            }
          }
        }
      },
      execute: args =>
        answerCli(
          app,
          args.nonce as string | undefined,
          async () => {
            // The proof is asked here, not at the terminal: no secret has to reach
            // this page through a relay. Read now, not from the state this tab last
            // read: a vault re-created or switched since would be offered the old
            // vault's passkeys, and the browser would create a passkey it refuses.
            const status = await api.status();
            const host = location.hostname;
            if (isIpAddress(host)) {
              // Said before a passphrase is asked for nothing.
              throw new VaultError(0, ipAddressAdvice(status.slots));
            }
            const proof = await askProof(status, host, 'Add passkey', true);
            const label = (args.label as string) ?? '';
            if (
              proof === null ||
              !(await registerWithProof(api, proof, label, host))
            ) {
              throw new VaultError(0, 'adding the passkey was cancelled');
            }
          },
          panel
        )
    });

    if (settingRegistry) {
      try {
        connectSettings(await settingRegistry.load(VAULT_PLUGIN_ID), dock);
        return;
      } catch (e) {
        console.warn('vault: settings unavailable, using defaults', e);
      }
    }
    dock('right');
  }
};
