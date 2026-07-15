import { expect, test } from '@jupyterlab/galata';
import * as fs from 'fs';
import * as path from 'path';

/**
 * The test server (jupyter_server_test_config.py) points the extension's relay
 * dir here, so this Node test process can read back the one-shot file the server
 * writes - proving the full command -> WebAuthn ceremony -> POST -> server-write
 * chain end to end, not just that a request was sent.
 */
const RELAY_DIR = path.resolve(__dirname, '..', '.tmp-passkey-relay');

/** A 32-byte PRF salt as url-safe base64 (43 chars). */
const PRF_SALT = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

/** A base64url user handle for create ceremonies. */
const USER = {
  id: Buffer.from('passkey-e2e-user').toString('base64url'),
  name: 'e2e',
  displayName: 'Passkey E2E'
};

interface IRelay {
  nonce: string;
  ok: boolean;
  cred_id?: string;
  prf?: string;
  prf_enabled?: boolean;
  error?: string;
}

/**
 * Don't load JupyterLab before the tests run so we can capture every console
 * log message (required by the activation test below).
 */
test.use({ autoGoto: false });

/**
 * Attach a Chromium CDP virtual authenticator so the WebAuthn ceremony completes
 * headlessly with no real security key and no user gesture. `hasPrf` toggles the
 * CTAP2 hmac-secret feature the bridge's PRF flow depends on.
 */
async function addAuthenticator(page: any, hasPrf: boolean): Promise<void> {
  // galata's `page` is a proxy; the raw Playwright Page (needed by CDP) is page.page.
  const raw = page.page;
  const client = await raw.context().newCDPSession(raw);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      hasPrf,
      automaticPresenceSimulation: true,
      isUserVerified: true,
      defaultBackupEligibility: true,
      defaultBackupState: true
    }
  });
}

/**
 * Execute passkey:run in the page and return the relay file the server writes.
 * rp_id defaults to the page's own hostname so the ceremony's RP matches origin.
 */
async function runPasskey(
  page: any,
  args: Record<string, unknown>
): Promise<IRelay> {
  const nonce = args.nonce as string;
  const relayFile = path.join(RELAY_DIR, `${nonce}.json`);
  fs.rmSync(relayFile, { force: true });

  await page.evaluate(a => {
    const full = { rp_id: location.hostname, ...a };
    return (window as any).jupyterapp.commands.execute('passkey:run', full);
  }, args);

  await expect
    .poll(() => fs.existsSync(relayFile), { timeout: 15000 })
    .toBeTruthy();
  return JSON.parse(fs.readFileSync(relayFile, 'utf-8')) as IRelay;
}

test('should emit an activation console message', async ({ page }) => {
  const logs: string[] = [];

  page.on('console', message => {
    logs.push(message.text());
  });

  await page.goto();

  expect(
    logs.filter(
      s =>
        s === 'JupyterLab extension jupyterlab_passkey_extension is activated!'
    )
  ).toHaveLength(1);
});

test('create registers a credential, reports prf_enabled, and writes a 0600 relay', async ({
  page
}) => {
  await addAuthenticator(page, true);
  await page.goto();

  const nonce = 'testcreateprf0123456789';
  const relay = await runPasskey(page, { op: 'create', nonce, user: USER });

  expect(relay.nonce).toBe(nonce);
  expect(relay.ok).toBe(true);
  expect(typeof relay.cred_id).toBe('string');
  expect(relay.cred_id!.length).toBeGreaterThan(0);
  expect(relay.prf_enabled).toBe(true);

  // The one-shot relay file must be created 0600.
  const mode = fs.statSync(path.join(RELAY_DIR, `${nonce}.json`)).mode & 0o777;
  expect(mode).toBe(0o600);
});

test('get returns a PRF value for the registered credential', async ({
  page
}) => {
  await addAuthenticator(page, true);
  await page.goto();

  const created = await runPasskey(page, {
    op: 'create',
    nonce: 'testgetsetup0123456789',
    user: USER
  });
  expect(created.ok).toBe(true);
  const cred_id = created.cred_id!;

  const relay = await runPasskey(page, {
    op: 'get',
    nonce: 'testgetprf0123456789',
    cred_id,
    prf_salt: PRF_SALT
  });

  expect(relay.ok).toBe(true);
  expect(relay.cred_id).toBe(cred_id);
  expect(typeof relay.prf).toBe('string');
  // 32 PRF bytes encode to 43 url-safe base64 chars.
  expect(relay.prf!.length).toBeGreaterThanOrEqual(43);
});

test('create succeeds on a non-PRF authenticator without rejecting', async ({
  page
}) => {
  await addAuthenticator(page, false);
  await page.goto();

  // New contract: a created credential is a success even without PRF. The bridge
  // returns cred_id + prf_enabled:false and lets the caller decide - it does not
  // reject (Windows Hello reports enabled:false at register yet may yield PRF at
  // assertion, so the reject belongs to the caller's follow-up get, not here).
  const created = await runPasskey(page, {
    op: 'create',
    nonce: 'testnoprfcreate0123456789',
    user: USER
  });
  expect(created.ok).toBe(true);
  expect(typeof created.cred_id).toBe('string');
  expect(created.prf_enabled).toBe(false);

  // The follow-up get is where PRF absence is authoritatively reported.
  const got = await runPasskey(page, {
    op: 'get',
    nonce: 'testnoprfget0123456789',
    cred_id: created.cred_id!,
    prf_salt: PRF_SALT
  });
  expect(got.ok).toBe(false);
  expect(got.error).toBe('no-prf');
});

test('get with an unknown credential relays a not-allowed error', async ({
  page
}) => {
  await addAuthenticator(page, true);
  await page.goto();

  const relay = await runPasskey(page, {
    op: 'get',
    nonce: 'testunknown0123456789',
    cred_id: Buffer.from('no-such-credential').toString('base64url')
  });

  expect(relay.ok).toBe(false);
  expect(relay.error).toBe('not-allowed');
});
