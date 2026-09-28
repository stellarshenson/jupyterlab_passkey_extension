import { URLExt } from '@jupyterlab/coreutils';

import { ServerConnection } from '@jupyterlab/services';

/** What the key holder protects on this host - see vault/holders.py. */
export interface ICapabilities {
  locked_memory: boolean;
  no_core_dump: boolean;
  holder_ttl: boolean;
  locks_on_restart: boolean;
  container_isolated: boolean;
}

export interface IHolder {
  name: string;
  /** What the holder is, for a reader who does not know the name. */
  about: string;
  summary: 'strong' | 'reduced' | 'basic';
  /** What the summary counts: the protections it has or lacks. */
  protection: string;
  capabilities: ICapabilities;
  /** Each capability's label and the explanation of its current value, in order. */
  details: { key: keyof ICapabilities; label: string; text: string }[];
  notice: string | null;
}

export interface ISlot {
  type: 'recovery' | 'passkey';
  cred_id?: string;
  rp_id?: string;
  prf_salt?: string;
  label?: string;
  created?: string;
}

export interface IStatus {
  initialized: boolean;
  unlocked: boolean;
  remaining: number | null;
  holder: IHolder;
  slots: ISlot[];
  settings: { unlock_minutes: number };
  path: string;
  /** Changes whenever the entries do; absent with no vault. */
  revision?: string;
}

export interface IEntry {
  name: string;
  username: string;
  url: string;
  category: string;
  notes: string;
  created: string;
  updated: string;
}

export interface IEntryFields {
  username?: string;
  password?: string;
  url?: string;
  category?: string;
  notes?: string;
}

export interface IPasskeySlot {
  cred_id: string;
  rp_id: string;
  prf_salt: string;
  prf: string;
  label: string;
}

/**
 * What the server asks before it adds a passkey or replaces the recovery passphrase:
 * the current recovery passphrase, or a passkey's PRF.
 */
export type Proof = { current: string } | { cred_id: string; prf: string };

/**
 * A vault request that did not succeed: the vault's own `error`, the text `_call` gives
 * an answer that is not the vault's, or, with status 0, a refusal the page makes
 * before any request. A lost answer is `NoAnswer`; a registration stopped after the
 * browser created the passkey, whatever the cause, is `Unused` (webauthn.ts).
 */
export class VaultError extends Error {
  constructor(
    readonly status: number,
    message: string
  ) {
    super(message);
  }
}

/** No answer came: the request may or may not have reached the server. */
export class NoAnswer extends VaultError {
  constructor() {
    super(0, 'cannot reach the Jupyter server');
  }
}

/** The vault REST API: `<base>/jupyterlab-passkey-extension/vault/<action>`. */
export class VaultApi {
  constructor(private readonly _settings: ServerConnection.ISettings) {}

  status(): Promise<IStatus> {
    return this._call<IStatus>('status', 'GET');
  }

  setConfig(unlockMinutes: number): Promise<void> {
    return this._call('config', 'POST', { unlock_minutes: unlockMinutes });
  }

  init(recovery: string): Promise<void> {
    return this._call('init', 'POST', { recovery });
  }

  unlockRecovery(recovery: string): Promise<IStatus> {
    return this._call<IStatus>('unlock', 'POST', { recovery });
  }

  unlockPasskey(credId: string, prf: string): Promise<IStatus> {
    return this._call<IStatus>('unlock', 'POST', { cred_id: credId, prf });
  }

  lock(): Promise<void> {
    return this._call('lock', 'POST');
  }

  async entries(): Promise<IEntry[]> {
    return (await this._call<{ entries: IEntry[] }>('entries', 'GET')).entries;
  }

  add(name: string, fields: IEntryFields): Promise<void> {
    return this._call('entries', 'POST', { name, fields });
  }

  edit(name: string, fields: IEntryFields): Promise<void> {
    return this._call('entries', 'PATCH', { name, fields });
  }

  remove(name: string): Promise<void> {
    return this._call('delete', 'POST', { name });
  }

  /** The password of `name`; the server answers 403 unless the PRF opens a passkey slot. */
  async revealPassword(
    name: string,
    credId: string,
    prf: string
  ): Promise<string> {
    return (
      await this._call<{ value: string }>('reveal', 'POST', {
        name,
        cred_id: credId,
        prf
      })
    ).value;
  }

  async generate(): Promise<string> {
    return (await this._call<{ value: string }>('generate', 'GET')).value;
  }

  /** The server adds the slot only with a proof. */
  addPasskey(slot: IPasskeySlot, proof: Proof): Promise<void> {
    return this._call('passkeys', 'POST', { ...slot, proof });
  }

  removePasskey(credId: string): Promise<void> {
    return this._call('passkeys-remove', 'POST', { cred_id: credId });
  }

  /** The server replaces it only with a proof. */
  replaceRecovery(recovery: string, proof: Proof): Promise<void> {
    return this._call('recovery', 'POST', { recovery, proof });
  }

  private async _call<T = void>(
    action: string,
    method: string,
    body?: unknown
  ): Promise<T> {
    const url = URLExt.join(
      this._settings.baseUrl,
      'jupyterlab-passkey-extension',
      'vault',
      action
    );
    // Asked for JSON, JupyterHub answers a read for a stopped server with JSON, not a
    // page.
    const init: RequestInit = {
      method,
      headers: { Accept: 'application/json' }
    };
    if (method !== 'GET') {
      init.body = JSON.stringify(body ?? {});
    }
    let response: Response;
    let text: string;
    try {
      response = await ServerConnection.makeRequest(url, init, this._settings);
      text = await response.text();
    } catch {
      throw new NoAnswer();
    }
    let data: any = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = null;
      }
    }
    // The vault answers with JSON or nothing: a page is never its answer (JupyterHub's
    // 403 for an action on a stopped server, or its sign-in page).
    if (!response.ok || (text && data === null)) {
      throw new VaultError(
        response.status,
        // A 424's `message` is JupyterHub's for a stopped server, naming where to start
        // it. A 404 without the vault's `error`: the server runs without the vault's
        // routes, as after an install into a running server. Any other answer without
        // it is not the vault's (the Jupyter server's "Forbidden" after a hub logout,
        // the hub's pages).
        data?.error ??
          (response.status === 424 ? data?.message : undefined) ??
          (response.status === 404
            ? 'the vault is not loaded on this Jupyter server - restart the server'
            : `the vault did not answer (HTTP ${response.status}) - reload the page to sign in again or start the server`)
      );
    }
    return data as T;
  }
}
