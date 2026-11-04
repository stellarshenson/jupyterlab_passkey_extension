import {
  JupyterFrontEnd,
  JupyterFrontEndPlugin
} from '@jupyterlab/application';

import { Notification } from '@jupyterlab/apputils';

import { ISettingRegistry } from '@jupyterlab/settingregistry';

import { ITranslator } from '@jupyterlab/translation';

import { requestAPI } from '../request';

import { setTranslator, trans } from '../trans';

import { IStatus, VaultApi, VaultError } from './api';

// eslint-disable-next-line jupyter/prefer-lazy-imports -- activate() needs the panel class at once
import { REFRESH_MS, VaultPanel } from './panel';

const VAULT_PLUGIN_ID = '@stellarshenson/jupyterlab-passkey-extension:vault';
const UNLOCK_COMMAND = 'passkey:vault-unlock';
export const REGISTER_COMMAND = 'passkey:vault-register';
export const SETUP_COMMAND = 'passkey:vault-setup';
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
 * into that relay - the page sends it straight to the vault endpoint. With
 * `seenInStatus`, a success is not posted: the CLI reads it in vault status, which
 * can end its wait before a post arrives, and nothing would collect that post. A
 * registration's step resolves to the type of the slot it stored, which `ok` carries
 * as `method`, so the CLI names the method.
 */
async function answerCli(
  app: JupyterFrontEnd,
  nonce: string | undefined,
  step: () => Promise<unknown>,
  panel: VaultPanel,
  seenInStatus = false
): Promise<void> {
  const { describeFailure } = await import('./webauthn');
  let body: Record<string, unknown>;
  try {
    const stored = await step();
    body =
      typeof stored === 'string' ? { ok: true, method: stored } : { ok: true };
    panel.clearLine();
  } catch (e) {
    body = { ok: false, error: describeFailure(e) };
  }
  if (nonce && !(seenInStatus && body.ok)) {
    await requestAPI<void>('result', app.serviceManager.serverSettings, {
      method: 'POST',
      body: JSON.stringify({ nonce, ...body })
    });
  }
  await panel.refresh();
}

/**
 * Dismiss the unlock and set-up notifications in this tab that nothing waits for, and
 * say whether one is left. A notification goes when `status` shows the vault unlocked,
 * or for a set-up shows a vault, and its read began at `since`, after the notification
 * came: a read begun earlier can predate the lock that raised it. It also goes when the
 * wait of the CLI that raised it has run out. The CLI names its command and that wait
 * in the notification's data (`_trigger` in cli.py).
 */
export function dismissStale(status: IStatus | null, since = 0): boolean {
  let left = false;
  for (const n of Notification.manager.notifications) {
    const data = (n.options.data ?? {}) as {
      command?: unknown;
      seconds?: unknown;
    };
    let reached: boolean | undefined;
    if (data.command === UNLOCK_COMMAND) {
      reached = status?.unlocked;
    } else if (data.command === SETUP_COMMAND) {
      reached = status?.initialized;
    } else {
      continue;
    }
    const over =
      typeof data.seconds === 'number' &&
      Date.now() - n.createdAt >= data.seconds * 1000;
    if (over || (reached && since > n.createdAt)) {
      Notification.dismiss(n.id);
    } else {
      left = true;
    }
  }
  return left;
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
    const {
      askProof,
      registerWithProof,
      sentence,
      setupVault,
      unlockWithChoice
    } = await import('./dialogs');
    const {
      describeFailure,
      ipAddressAdvice,
      isIpAddress,
      matchingSlots,
      passkeyPrf,
      shareUnlock
    } = await import('./webauthn');
    setTranslator(translator);
    const api = new VaultApi(app.serviceManager.serverSettings);
    // While an unlock or set-up notification is in this tab, the state is read every
    // REFRESH_MS, with the panel hidden too, so the notification goes once nothing
    // waits for it. A hidden tab reads when it is shown again, as the panel's own poll
    // does.
    let timer: number | null = null;
    const watch = (status: IStatus | null = null, since = 0): void => {
      const left = dismissStale(status, since);
      if (left && timer === null) {
        timer = window.setInterval(read, REFRESH_MS);
        document.addEventListener('visibilitychange', read);
      } else if (!left && timer !== null) {
        window.clearInterval(timer);
        timer = null;
        document.removeEventListener('visibilitychange', read);
      }
    };
    const read = (): void => void panel.poll().then(() => watch());
    const panel = new VaultPanel({
      api,
      openSettings: () =>
        void app.commands.execute('settingeditor:open', {
          // The title in schema/vault.json, which the Settings Editor searches.
          query: 'Passkey Vault'
        }),
      onRead: watch
    });
    // An added one starts the poll; the last one gone, by a press or a dismissal, stops it.
    Notification.manager.changed.connect(() => watch());
    // One that came before this plugin started.
    watch();
    // Read the state now: the sidebar icon shows whether a vault exists, and a vault
    // notification that came before this plugin started goes if nothing waits for it.
    void panel.refresh();
    // A press on a vault notification reads the state before it asks anything, so one
    // left from an unlock done another way asks nothing. Safari may refuse a passkey
    // request that follows this read. A failed read asks nothing: it is the failure.
    const readOnPress = async (): Promise<IStatus> => {
      try {
        return await api.status();
      } catch (e) {
        const line = `the vault state could not be read (${describeFailure(e)}) - run the command again`;
        panel.fail(sentence(line), false);
        throw new VaultError(0, line);
      }
    };
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
                'Names the relay a failure is posted to; a success shows in vault status. With none, nothing is posted.'
            },
            method: {
              type: 'string',
              enum: ['passkey', 'choose'],
              description:
                'How to unlock: a passkey (default), or a choice of a passkey, the password and a code, Password and passkey, or the recovery passphrase.'
            }
          }
        }
      },
      execute: args =>
        answerCli(
          app,
          args.nonce as string | undefined,
          () =>
            shareUnlock(async () => {
              const host = location.hostname;
              // As the panel's failure notification: one at a time, and the next
              // action or a CLI step done in this tab dismisses it.
              const fail = (text: string): void => panel.fail(text, false);
              const status = await readOnPress();
              if (status.unlocked) {
                return status;
              }
              // The chooser asked for, or no passkey this tab can use: every way in.
              if (
                (args.method as string | undefined) === 'choose' ||
                isIpAddress(host) ||
                matchingSlots(status.slots, host).length === 0
              ) {
                return unlockWithChoice(api, status, host, fail);
              }
              let passkey: { credId: string; prf: string };
              try {
                passkey = await passkeyPrf(status, host);
              } catch (e) {
                // A VaultError comes after the passkey answered with no PRF, and the
                // chooser would only ask for it again.
                if (e instanceof VaultError) {
                  throw e;
                }
                // The slot matches, but its passkey is on another machine or was
                // deleted: offer every way in instead of failing the unlock.
                return unlockWithChoice(api, status, host, fail);
              }
              // Outside the try for the same reason: the passkey has answered, so a
              // refusal reaches the CLI as its one line.
              return api.unlockPasskey(passkey.credId, passkey.prf);
            }),
          panel,
          true
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
            const proof = await askProof(
              api,
              status,
              host,
              'Add passkey',
              true
            );
            const label = (args.label as string) ?? '';
            const stored =
              proof !== null &&
              (await registerWithProof(api, proof, label, host));
            if (!stored) {
              throw new VaultError(0, 'adding the passkey was cancelled');
            }
            return stored;
          },
          panel
        )
    });

    app.commands.addCommand(SETUP_COMMAND, {
      label: trans.__('Set Up Vault'),
      describedBy: {
        args: {
          type: 'object',
          properties: {
            nonce: {
              type: 'string',
              description:
                'Names the relay a failure is posted to; a success shows in vault status. With none, nothing is posted.'
            }
          }
        }
      },
      execute: args =>
        answerCli(
          app,
          args.nonce as string | undefined,
          async () => setupVault(api, await readOnPress(), location.hostname),
          panel,
          true
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
