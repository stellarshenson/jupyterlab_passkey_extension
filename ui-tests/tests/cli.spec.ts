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
 * Spawn the real binary for `copy`, feeding it a secret on stdin.
 *
 * Separate from runCli because runCli appends --timeout to every call, and `copy`
 * rejects one unless --block makes it mean something - so the shared helper cannot
 * spawn this command at all. Callers that want a timeout pass both flags themselves.
 *
 * Mind which contract you are testing. Without --block this promise resolves BEFORE
 * the click, so awaiting it first is correct rather than a deadlock; with --block it
 * resolves only once the browser has collected the secret, so awaiting it before
 * clicking deadlocks until the CLI's own timeout.
 */
function runCopy(secret: string, args: string[] = []): Promise<IResult> {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    JLAB_PASSKEY_RELAY_DIR: RELAY_DIR,
    JUPYTER_PORT: PORT
  };
  for (const name of DISCOVERY_ENV) {
    delete env[name];
  }

  const child = spawn('jupyterlab-passkey', ['copy', ...args], { env });

  return new Promise<IResult>(resolve => {
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => (stdout += d.toString()));
    child.stderr.on('data', d => (stderr += d.toString()));
    child.on('error', e =>
      resolve({ code: null, stdout, stderr: `${stderr}spawn failed: ${e}` })
    );
    child.on('close', code => resolve({ code, stdout, stderr }));
    // No trailing newline: the CLI strips exactly one, and this way the test
    // asserts on the bytes it actually handed over.
    child.stdin.write(secret);
    child.stdin.end();
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

test('copy hands a piped secret to the clipboard through the real binary', async ({
  page
}) => {
  // The rung that mocks nothing: the shipped console script stages the relay itself,
  // the real ingest raises the real toast, the real click runs passkey:copy, and the
  // secret lands on a real clipboard. Every other copy test stubs one of those ends.
  await page.page
    .context()
    .grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto();

  const SECRET = 'ghp_real_binary_token_value';

  // Unlike every other subcommand this returns before the click - copy is fire and
  // forget, so awaiting it first is the correct order, not a deadlock.
  const { code, stdout, stderr } = await runCopy(SECRET, [
    '--label',
    'GitHub token'
  ]);
  expect(code, `stderr: ${stderr}`).toBe(0);
  // Nothing but the path-free confirmation may reach the terminal.
  expect(stdout).not.toContain(SECRET);
  expect(stderr).not.toContain(SECRET);

  // Wait for the toast before reading it. The CLI has already exited by here -
  // that is what fire-and-forget means - but the notification still has to reach
  // the page over the WebSocket, so asserting on its text first finds nothing.
  const buttons = page.locator('.jp-toast-button');
  await expect
    .poll(() => buttons.count(), { timeout: 45000 })
    .toBeGreaterThan(0);

  // The label is the only thing telling two staged secrets apart.
  await expect(page.locator('.jp-toast-message').first()).toContainText(
    'GitHub token'
  );
  await buttons.first().click();

  await expect
    .poll(() => page.evaluate(() => navigator.clipboard.readText()), {
      timeout: 15000
    })
    .toBe(SECRET);

  // One shot: collected means spent, so nothing outlives the click.
  expect(stagedSecrets()).toEqual([]);
});

test('copy --block stays alive until the browser collects the secret', async ({
  page
}) => {
  // The only rung that can prove --block: every unit test stubs either _wait_gone or
  // the collection, so none of them watches a real process stay alive across a real
  // click and then exit on a relay a real server unlinked.
  await page.page
    .context()
    .grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto();

  const SECRET = 'ghp_blocking_token_value';

  // NOT awaited: with --block the CLI is still running, waiting for the click that
  // this test is about to perform. Awaiting first would deadlock until its timeout.
  const cli = runCopy(SECRET, ['--block', '--timeout', CLI_TIMEOUT]);

  // Still staged and still waiting: the whole point of the flag.
  await expect.poll(() => stagedSecrets().length, { timeout: 15000 }).toBe(1);

  // clickToast races the CLI's exit, which under --block is exactly right: a CLI that
  // dies before the click means --block failed, and that is the message worth reading.
  await clickToast(page, cli);

  const { code, stdout, stderr } = await cli;
  expect(code, `stderr: ${stderr}`).toBe(0);
  expect(stdout).not.toContain(SECRET);
  expect(stderr).not.toContain(SECRET);

  await expect
    .poll(() => page.evaluate(() => navigator.clipboard.readText()), {
      timeout: 15000
    })
    .toBe(SECRET);

  // The server unlinked it as it read; --block's exit is what says so.
  expect(stagedSecrets()).toEqual([]);
});

test('copy --block shreds the secret it gave up on', async ({ page }) => {
  // A timeout means nobody collected it. Leaving it staged would hand a live button to
  // whoever clicks next, long after the caller was told the secret never landed.
  await page.goto();

  // Deliberately never clicked. 3s rather than CLI_TIMEOUT: this test waits out the
  // whole timeout on purpose, so the shorter the better.
  const { code, stderr } = await runCopy('ghp_abandoned_token', [
    '--block',
    '--timeout',
    '3'
  ]);

  expect(code).toBe(1);
  expect(stderr).toContain('not copied after 3s');
  expect(stagedSecrets()).toEqual([]);
});

test('copy rejects a --timeout that would do nothing', async () => {
  // Without --block nothing waits, so accepting --timeout and ignoring it would tell a
  // caller they had bounded something they had not.
  const { code, stderr } = await runCopy('ghp_token', ['--timeout', '5']);

  expect(code).toBe(1);
  expect(stderr).toContain('--timeout only applies with --block');
  expect(stagedSecrets()).toEqual([]);
});

/** The .secret relays currently staged, tolerating a relay dir nothing has made yet. */
function stagedSecrets(): string[] {
  if (!fs.existsSync(RELAY_DIR)) {
    return [];
  }
  return fs.readdirSync(RELAY_DIR).filter((f: string) => f.endsWith('.secret'));
}

test('copy stages nothing when the trigger cannot reach a server', async () => {
  // The bug this whole flow nearly shipped with: the secret is staged BEFORE the
  // trigger, so a trigger that dies leaves a plaintext secret whose nonce died with
  // the process - uncollectable, not merely uncollected, and one more copy per
  // retry. Driven through the real binary against a port with nothing on it.
  const before = stagedSecrets();

  // An EMPTY runtime dir, not the suite's own: the test server registers itself in
  // that one, so `jupyter server list` finds it and JUPYTER_PORT is never consulted.
  // Emptying the list is what arms cli.py's env fallback, and only then does
  // pointing it at a dead port actually fail the trigger.
  const emptyRuntime = path.resolve(__dirname, '..', '.tmp-runtime-empty');
  fs.mkdirSync(emptyRuntime, { recursive: true });

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    JLAB_PASSKEY_RELAY_DIR: RELAY_DIR,
    JUPYTER_RUNTIME_DIR: emptyRuntime,
    // Nothing listens here, so the trigger POST dies on connection refused.
    JUPYTER_PORT: '1'
  };
  for (const name of DISCOVERY_ENV) {
    delete env[name];
  }

  const child = spawn('jupyterlab-passkey', ['copy'], { env });
  const result = await new Promise<IResult>(resolve => {
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => (stdout += d.toString()));
    child.stderr.on('data', d => (stderr += d.toString()));
    child.on('error', e =>
      resolve({ code: null, stdout, stderr: `${stderr}spawn failed: ${e}` })
    );
    child.on('close', code => resolve({ code, stdout, stderr }));
    child.stdin.write('a-secret-nobody-can-ever-collect');
    child.stdin.end();
  });

  expect(result.code).not.toBe(0);
  expect(result.stderr).toContain('cannot reach');
  expect(stagedSecrets()).toEqual(before);
});
