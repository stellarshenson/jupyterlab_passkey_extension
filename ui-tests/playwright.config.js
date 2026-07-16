/**
 * Configuration for Playwright using default from @jupyterlab/galata
 */
const path = require('path');
const baseConfig = require('@jupyterlab/galata/lib/playwright-config');

// Galata pins the test server to 8888 (with port_retries=0, so it dies rather than
// move) and defaults its own baseURL to match. This knob moves both together, so the
// suite can run beside a lab already holding 8888 - the only thing that ever made it
// unrunnable on a developer box. CI leaves it at the default.
const PORT = process.env.JUPYTER_TEST_PORT || '8888';
const BASE_URL = `http://localhost:${PORT}`;

// `jupyter server list` is how the CLI finds the server to post its trigger to, and it
// scans the Jupyter runtime directory. Point it at a private one so the suite's own
// server is the only one listed: with the shared default a developer's own lab is listed
// too, and the CLI would raise its toast in that real tab while the test waits here.
// Set at module scope because the webServer and every worker-spawned CLI inherit it.
//
// This is only half the isolation, and on its own it is worse than none: emptying the
// list is exactly what arms cli.py's env-based fallback onto a real lab. cli.spec.ts's
// DISCOVERY_ENV subtraction is the other half - neither is sufficient alone.
// Deliberately not `||`-overridable: an inherited JUPYTER_RUNTIME_DIR pointing at a
// developer's real runtime is the precise thing this exists to prevent.
process.env.JUPYTER_RUNTIME_DIR = path.join(__dirname, '.tmp-runtime');

module.exports = {
  ...baseConfig,
  use: { ...baseConfig.use, baseURL: BASE_URL },
  // Clears the ceremony output and server records the run leaves behind. The matching
  // pre-run sweep is chained into webServer.command below, NOT here as a globalSetup:
  // Playwright starts the webServer before globalSetup runs, so a sweep here would
  // delete the record the live server just wrote. See sweep-scratch.js.
  globalTeardown: require.resolve('./sweep-scratch.js'),
  // Both spec files drive ONE server, and they share its process-global state: the
  // notification queue and the relay directory. Run them in parallel and whichever page
  // polls first drains the queue for everyone, so a toast meant for one test is
  // rendered - and clicked - in another. Serialise them.
  workers: 1,
  fullyParallel: false,
  webServer: {
    // Sweep, THEN start - the only point genuinely before the server writes its runtime
    // record, so an interrupted run's leftover ceremony residue is cleared without ever
    // touching this run's record. Node rather than `rm -rf`, to keep one definition of
    // what gets swept and stay off a POSIX-only shell.
    command: 'node sweep-scratch.js && jlpm start',
    url: `${BASE_URL}/lab`,
    timeout: 120 * 1000,
    // Never adopt a server we did not start, not even locally. Reuse adopts whatever
    // answers on the port, and this suite does not merely read a page - it drives a
    // WebAuthn ceremony and posts notifications through a CLI. Adopting a developer's
    // own lab on the default 8888 fires a real toast into their tab, which is the exact
    // harm the runtime-dir and DISCOVERY_ENV isolation exists to prevent, reached by a
    // route neither of them guards. A taken port now fails loudly instead: set
    // JUPYTER_TEST_PORT and the suite moves.
    reuseExistingServer: false
  }
};
