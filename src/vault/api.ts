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
  type: 'recovery' | 'passkey' | 'password' | 'password-passkey';
  /** The key derivation of a typed slot: argon2id today, scrypt in older slots. */
  kdf?: string;
  cred_id?: string;
  rp_id?: string;
  prf_salt?: string;
  label?: string;
  created?: string;
  /** The exact origin a Password and passkey slot was added at. */
  origin?: string;
}

/** The data key's age and rotation state, as the server reports them. */
export interface IRotation {
  /** The creation date; null for a version-1 vault, which gets a data key at its next unlock. */
  created: string | null;
  /** Whole days since `created`; null with none. */
  age_days: number | null;
  /** Days between rotations; 0 turns automatic rotation off. */
  period_days: number;
  due: boolean;
}

export interface IStatus {
  initialized: boolean;
  unlocked: boolean;
  remaining: number | null;
  holder: IHolder;
  slots: ISlot[];
  /** The registered authenticator app; null with none, absent with no vault. */
  authenticator?: { created: string } | null;
  /** The data key's state; absent with no vault. */
  rotation?: IRotation;
  settings: {
    unlock_minutes: number;
    password_min_length: number;
    /** How long an unlock or a proof in this tab shows a password with no other proof. */
    reveal_seconds: number;
    /** The rotation period in days; 0 turns automatic rotation off. */
    rotate_days: number;
  };
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
  used?: string;
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
 * A passkey's answer to a server challenge, each field base64url: the server checks
 * the signature with the public key the vault holds for Password and passkey.
 */
export interface IAssertion {
  cred_id: string;
  client_data: string;
  authenticator_data: string;
  signature: string;
}

/**
 * A passkey's answer to `navigator.credentials.create`, each field base64url: the
 * server runs the WebAuthn registration steps on it and takes the public key from it.
 */
export interface IRegistration {
  client_data: string;
  attestation_object: string;
}

/** A new Password and passkey. */
export interface IPairSlot {
  password: string;
  cred_id: string;
  rp_id: string;
  registration: IRegistration;
  label: string;
  assertion: IAssertion;
}

/**
 * What the server asks before it adds an unlock method, replaces the recovery
 * passphrase or shows a password to the panel: the current recovery passphrase, a
 * passkey's PRF, or - on an unlocked vault only - a code of the authenticator app or
 * a signature of the passkey of Password and passkey. The unlock password alone is a
 * proof for showing a password on an unlocked vault and for nothing else.
 */
export type Proof =
  | { current: string }
  | { cred_id: string; prf: string }
  | { code: string }
  | { assertion: IAssertion }
  | { password: string };

/**
 * A vault request that did not succeed: the vault's own `error`, the text `_call` gives
 * an answer that is not the vault's, or, with status 0, a refusal the page makes
 * before any request. A lost answer is `NoAnswer`. A registration stopped after the
 * browser created the passkey is `Unused` (webauthn.ts) when no request stored the
 * method, and `MaybeAdded` after a 5xx or a lost answer to that request. `short`
 * is the panel's notification text, which `fit` (webauthn.ts) cuts where a clause
 * must stay whole; the CLI gets `message`.
 */
export class VaultError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly short = message
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

  /**
   * True for the reveal window after this tab unlocked the vault or had a proof
   * accepted: the person at the screen has just proven, so the entry popup's eye asks
   * no second proof. The window is the `reveal_seconds` setting, read from the server's
   * status; 0 means every reveal asks for a proof. Kept by the tab, as the eye's proof
   * is asked by the tab: the server reads a password for any request on an unlocked
   * vault (`vault get`). A lock in this tab and a reload of the page end it. While the
   * system clock reads earlier than that proof, it is false.
   */
  get proven(): boolean {
    const since = Date.now() - this._provenAt;
    return since >= 0 && since < this._revealMs;
  }

  status(): Promise<IStatus> {
    return this._status(this._call<IStatus>('status', 'GET'));
  }

  /**
   * Rotate the data key now: the entries, the authenticator secret and the public key
   * of Password and passkey are re-sealed under a new key. The server takes a passkey
   * with PRF or the recovery passphrase (a code alone and a passkey with no PRF alone
   * hold no key) and needs an unlocked vault.
   */
  rotate(proof: Proof): Promise<void> {
    return this._proving(this._call('rotate', 'POST', { proof }));
  }

  init(recovery: string): Promise<void> {
    return this._call('init', 'POST', { recovery });
  }

  unlockRecovery(recovery: string): Promise<IStatus> {
    return this._proving(
      this._status(this._call<IStatus>('unlock', 'POST', { recovery }))
    );
  }

  /**
   * The unlock password and a code of the authenticator app: the two are one unlock
   * method. A vault written by 1.1.28 to 1.1.31 can hold a password and no app, and
   * takes no code.
   */
  unlockPassword(password: string, code?: string): Promise<IStatus> {
    return this._proving(
      this._status(this._call<IStatus>('unlock', 'POST', { password, code }))
    );
  }

  unlockPasskey(credId: string, prf: string): Promise<IStatus> {
    return this._proving(
      this._status(
        this._call<IStatus>('unlock', 'POST', { cred_id: credId, prf })
      )
    );
  }

  /**
   * Password and passkey: the password, and the passkey's signature over the challenge
   * `challenge()` gave. The server keeps the key only when the signature verifies.
   */
  unlockPair(password: string, assertion: IAssertion): Promise<IStatus> {
    return this._proving(
      this._status(
        this._call<IStatus>('unlock', 'POST', { password, assertion })
      )
    );
  }

  /** A one-use challenge for the passkey of Password and passkey to sign. */
  async challenge(): Promise<string> {
    return (await this._call<{ challenge: string }>('challenge', 'POST'))
      .challenge;
  }

  lock(): Promise<void> {
    this._provenAt = 0;
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

  /**
   * The password of `name`. With a proof the server answers 403 unless it holds. With
   * none it is the plain read of an unlocked vault, which the panel asks only while
   * `proven`.
   */
  async revealPassword(name: string, proof?: Proof): Promise<string> {
    const request = this._call<{ value: string }>('reveal', 'POST', {
      name,
      ...proof
    });
    return (await (proof ? this._proving(request) : request)).value;
  }

  async generate(): Promise<string> {
    return (await this._call<{ value: string }>('generate', 'GET')).value;
  }

  /**
   * Refuse a wrong recovery passphrase before the steps a proof guards. It changes
   * nothing and starts no reveal window: the request that acts carries the proof
   * again, and that request is the accepted proof.
   */
  checkRecovery(current: string): Promise<void> {
    return this._call('proof-check', 'POST', { current });
  }

  /** The server adds the slot only with a proof. */
  addPasskey(slot: IPasskeySlot, proof: Proof): Promise<void> {
    return this._proving(this._call('passkeys', 'POST', { ...slot, proof }));
  }

  /**
   * Add Password and passkey. The server stores it only for a registration and a
   * signature of the new passkey, both over the live challenge, and a proof.
   */
  addPair(slot: IPairSlot, proof: Proof): Promise<void> {
    return this._proving(
      this._call('password-passkey', 'POST', { ...slot, proof })
    );
  }

  /** Remove a passkey; the cred_id of Password and passkey removes that method. */
  removePasskey(credId: string): Promise<void> {
    return this._call('passkeys-remove', 'POST', { cred_id: credId });
  }

  /**
   * Add the unlock password and the authenticator app that was given `setupKey`, as
   * one unlock method. The server stores them only for the code the app shows now
   * and a proof.
   */
  addMfa(
    password: string,
    setupKey: string,
    code: string,
    proof: Proof
  ): Promise<void> {
    return this._proving(
      this._call('mfa', 'POST', { password, secret: setupKey, code, proof })
    );
  }

  /** Remove the unlock password and the authenticator app. */
  removeMfa(): Promise<void> {
    return this._call('mfa-remove', 'POST');
  }

  /** The server replaces it only with a proof. */
  replaceRecovery(recovery: string, proof: Proof): Promise<void> {
    return this._proving(this._call('recovery', 'POST', { recovery, proof }));
  }

  /** When this tab last unlocked or had a proof accepted; 0 before and after a lock. */
  private _provenAt = 0;

  /** The reveal window, from the `reveal_seconds` setting; the server default until read. */
  private _revealMs = 60000;

  /** `request`, whose answer is the state: its settings set the reveal window. */
  private async _status<T extends IStatus>(request: Promise<T>): Promise<T> {
    const result = await request;
    this._revealMs = result.settings.reveal_seconds * 1000;
    return result;
  }

  /** `request`, whose success is an unlock or an accepted proof of this tab. */
  private async _proving<T>(request: Promise<T>): Promise<T> {
    const result = await request;
    this._provenAt = Date.now();
    return result;
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
            ? 'the vault is not loaded - restart the Jupyter server'
            : `the vault did not answer (HTTP ${response.status}) - reload or restart`)
      );
    }
    return data as T;
  }
}
