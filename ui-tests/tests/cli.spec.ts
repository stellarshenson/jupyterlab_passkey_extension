import { expect, test } from '@jupyterlab/galata';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Functional tests for the shipped `jupyterlab-passkey` binary.
 *
 * Every other CLI test mocks both of the CLI's ends - it stubs the trigger AND writes
 * the relay itself - so the suite plays browser and server and proves only that the
 * CLI talks to its own mocks. That is how a CLI whose ingest endpoint 404s for every
 * `pip install` user shipped with a fully green suite.
 *
 * These tests mock nothing. They spawn the real console script, let it POST to the
 * real notifications endpoint, click the real toast button (the WebAuthn user gesture),
 * let the real ceremony run against a CDP virtual authenticator, and assert on the
 * process's real stdout. This is the only rung that can fail when the packaging is
 * wrong rather than the code.
 */

/** Must match jupyter_server_test_config.py - the server writes relays here. */
const RELAY_DIR = path.resolve(__dirname, '..', '.tmp-passkey-relay');

/** Must match playwright.config.js - the one knob that moves the server and its URL. */
const PORT = process.env.JUPYTER_TEST_PORT || '8888';
const BASE_URL = `http://localhost:${PORT}`;
const NOTIFICATIONS_URL = `${BASE_URL}/jupyterlab-notifications-extension/notifications`;

/**
 * The RP ID must be the page's own hostname or WebAuthn rejects the ceremony. Read off
 * BASE_URL so the two cannot drift apart; today that is always 'localhost', since the
 * host half of BASE_URL is fixed and only the port moves.
 */
const RP_ID = new URL(BASE_URL).hostname;

/** A 32-byte PRF salt as url-safe base64 (43 chars). */
const PRF_SALT = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

/**
 * The CLI must give up before Playwright does, or its diagnostic never prints and the
 * failure surfaces as an opaque test timeout instead of the CLI's own message.
 */
const CLI_TIMEOUT = '20';

interface IResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

test.use({ autoGoto: false });
test.setTimeout(90000);

/**
 * Empty the server's notification queue.
 *
 * The ingest handler appends every notification to a process-global store and only a
 * GET drains it. A notification left queued by an earlier test is replayed into the
 * next test's fresh page at activation, where it renders as a stale toast that looks
 * exactly like the one this test is waiting for. Draining first is what makes the
 * toast this test sees provably its own.
 */
test.beforeEach(async () => {
  await fetch(NOTIFICATIONS_URL).catch(() => undefined);
});

async function addAuthenticator(page: any, hasPrf: boolean): Promise<void> {
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
 * The credentials cli.py would reach for when `jupyter server list` comes back empty.
 *
 * Subtracted from the child's environment, because the private JUPYTER_RUNTIME_DIR does
 * not isolate on its own - it EMPTIES the server list, which is precisely the condition
 * that arms cli.py's env fallback. Inherited on a JupyterHub box that fallback resolves
 * to the developer's own lab, with a live token, and a test meant to be hermetic posts
 * an authenticated trigger into a real tab.
 */
const DISCOVERY_ENV = [
  'JUPYTERHUB_API_TOKEN',
  'JPY_API_TOKEN',
  'JUPYTER_TOKEN',
  'JUPYTERHUB_SERVICE_PREFIX'
];

/**
 * Spawn the real binary.
 *
 * JLAB_PASSKEY_RELAY_DIR is passed explicitly and deliberately: the test config sets it
 * inside the *server* process only, so a subprocess spawned from Playwright would
 * otherwise poll /dev/shm while the server writes here, and hang until the timeout.
 *
 * Returned unresolved - the CLI does not exit until the button is clicked, so awaiting
 * it before clicking would deadlock.
 */
function runCli(args: string[]): Promise<IResult> {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    JLAB_PASSKEY_RELAY_DIR: RELAY_DIR,
    // Pointed at the suite's own port rather than deleted. cli.py's fallback defaults to
    // 8888 when JUPYTER_PORT is absent, which is the single likeliest port for the
    // developer's real lab - and a tokenless lab there would ACCEPT the ingest and pop
    // the toast in their tab. Setting it makes a discovery miss die on connection
    // refused against our own port, structurally unable to reach anything else.
    JUPYTER_PORT: PORT
  };
  for (const name of DISCOVERY_ENV) {
    delete env[name];
  }

  const child = spawn(
    'jupyterlab-passkey',
    [...args, '--timeout', CLI_TIMEOUT],
    { env }
  );

  return new Promise<IResult>(resolve => {
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => (stdout += d.toString()));
    child.stderr.on('data', d => (stderr += d.toString()));
    // Without this, a missing binary - the packaging break this file exists to catch -
    // raises an unhandled 'error' and takes the worker down with an ENOENT stack
    // instead of reporting that jupyterlab-passkey was not on PATH.
    child.on('error', e =>
      resolve({ code: null, stdout, stderr: `${stderr}spawn failed: ${e}` })
    );
    child.on('close', code => resolve({ code, stdout, stderr }));
  });
}

/**
 * Click the toast raised by THIS invocation - the WebAuthn user gesture - and return
 * only once the screen is clear again.
 *
 * The trailing wait for zero is load-bearing. Toasts do NOT accumulate: clicking the
 * action dismisses the toast. So correlating by "the count grew past what was on screen
 * before" succeeds on a test's first invocation and then hangs forever on its second,
 * which records 1, watches the first toast leave as the second arrives, and waits out
 * its timeout for a 2 that never comes. Ending every call with an empty screen is what
 * makes the next call's wait unambiguous without any bookkeeping.
 *
 * The CLI's exit is raced against the wait. On the likeliest failure of all - the
 * trigger POST rejected, so no toast is ever raised - the CLI dies in about a second
 * with a precise message. Polling on regardless would bury that and report a bare
 * "count > 0" timeout instead: the harness hiding the one diagnostic worth reading,
 * which is the exact failure mode this file was written to end.
 */
async function clickToast(page: any, cli: Promise<IResult>): Promise<void> {
  const buttons = page.locator('.jp-toast-button');
  // Promise.race subscribes to both, so this rejection is always observed - it cannot
  // surface later as an unhandled rejection once the poll has won.
  const diedEarly = cli.then((r: IResult) => {
    throw new Error(
      `CLI exited before any toast appeared (code ${r.code})\nstderr: ${r.stderr}`
    );
  });
  // 45s, not 30: the toast normally arrives on a WebSocket push, and the notifications
  // extension's 30s poll is the only rescue when that push is missed. Waiting exactly
  // one poll interval is a dead heat with the thing meant to save us.
  await Promise.race([
    expect.poll(() => buttons.count(), { timeout: 45000 }).toBeGreaterThan(0),
    diedEarly
  ]);
  // `first()`, not `last()`: JupyterLab builds its ToastContainer with newestOnTop, and
  // react-toastify reverses the render order to honour it - so the newest toast is the
  // FIRST in the DOM. `last()` reaches for the oldest, which is precisely the stale one
  // the beforeEach drain exists to rule out.
  await buttons.first().click();
  await expect.poll(() => buttons.count(), { timeout: 15000 }).toBe(0);
}

test('create drives a real ceremony through the notification and prints a cred_id', async ({
  page
}) => {
  await addAuthenticator(page, true);
  await page.goto();

  const done = runCli(['create', '--rp-id', RP_ID]);
  await clickToast(page, done);
  const { code, stdout, stderr } = await done;

  expect(code, `stderr: ${stderr}`).toBe(0);
  // A real credential id, minted by the browser and round-tripped through the relay.
  expect(stdout.trim()).toMatch(/^[A-Za-z0-9_-]+$/);
});

test('get prints the PRF the authenticator actually returned', async ({
  page
}) => {
  await addAuthenticator(page, true);
  await page.goto();

  const created = runCli(['create', '--rp-id', RP_ID]);
  await clickToast(page, created);
  const credId = (await created).stdout.trim();
  expect(credId.length).toBeGreaterThan(0);

  const got = runCli([
    'get',
    '--rp-id',
    RP_ID,
    '--cred-id',
    credId,
    '--prf-salt',
    PRF_SALT
  ]);
  await clickToast(page, got);
  const { code, stdout, stderr } = await got;

  expect(code, `stderr: ${stderr}`).toBe(0);
  // 32 PRF bytes encode to at least 43 url-safe base64 chars.
  expect(stdout.trim().length).toBeGreaterThanOrEqual(43);
  expect(stdout.trim()).toMatch(/^[A-Za-z0-9_-]+$/);
});

test('the PRF is deterministic across two separate CLI invocations', async ({
  page
}) => {
  // This is the property a keystore stakes its key material on: same credential, same
  // salt, same 32 bytes - across processes, not just within one.
  await addAuthenticator(page, true);
  await page.goto();

  const created = runCli(['create', '--rp-id', RP_ID]);
  await clickToast(page, created);
  const credId = (await created).stdout.trim();

  const args = [
    'get',
    '--rp-id',
    RP_ID,
    '--cred-id',
    credId,
    '--prf-salt',
    PRF_SALT
  ];

  const first = runCli(args);
  await clickToast(page, first);
  const prf1 = (await first).stdout.trim();

  const second = runCli(args);
  await clickToast(page, second);
  const prf2 = (await second).stdout.trim();

  expect(prf1.length).toBeGreaterThanOrEqual(43);
  expect(prf2).toBe(prf1);
});

test('a failed ceremony exits non-zero and prints nothing to stdout', async ({
  page
}) => {
  // A caller pipes stdout into key derivation. On failure it must get an empty capture
  // and a non-zero status, never a diagnostic that would be mistaken for a secret.
  await addAuthenticator(page, true);
  await page.goto();

  const done = runCli([
    'get',
    '--rp-id',
    RP_ID,
    '--cred-id',
    Buffer.from('no-such-credential').toString('base64url')
  ]);
  await clickToast(page, done);
  const { code, stdout, stderr } = await done;

  expect(code).not.toBe(0);
  expect(stdout.trim()).toBe('');
  expect(stderr).toContain('not-allowed');
});

test('passphrase relays the typed value to a raw 0600 file and prints only its path', async ({
  page
}) => {
  await page.goto();
  const PASSPHRASE = 'correct horse battery staple';

  const done = runCli(['passphrase', '--prompt', 'Recovery passphrase']);
  await clickToast(page, done);

  await page.waitForSelector('.jp-PassphraseDialog-body');
  const inputs = page.locator('.jp-PassphraseDialog-input');
  await inputs.nth(0).fill(PASSPHRASE);
  await inputs.nth(1).fill(PASSPHRASE);
  await page.click('.jp-Dialog-button.jp-mod-accept');

  const { code, stdout, stderr } = await done;
  expect(code, `stderr: ${stderr}`).toBe(0);

  const relayPath = stdout.trim();
  expect(relayPath.endsWith('.pass')).toBe(true);
  // The secret must never transit the terminal - only its path may.
  expect(stdout).not.toContain(PASSPHRASE);
  expect(stderr).not.toContain(PASSPHRASE);

  expect(fs.readFileSync(relayPath, 'utf-8')).toBe(PASSPHRASE);
  expect(fs.statSync(relayPath).mode & 0o777).toBe(0o600);
  fs.rmSync(relayPath, { force: true });
});
