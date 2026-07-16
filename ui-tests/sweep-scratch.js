/**
 * Empty the suite's scratch directories: `.tmp-passkey-relay` and `.tmp-runtime`.
 *
 * Wired as `globalTeardown` in playwright.config.js, and chained ahead of the server in
 * `webServer.command` for the pre-run half.
 *
 * NOT a globalSetup, and that is the load-bearing fact about this file. Playwright starts
 * the webServer - a plugin - BEFORE globalSetup runs, so a sweep there deletes the
 * runtime record the live server has just written. `jupyter server list` is then empty
 * for the whole run and the CLI under test silently falls back to its env guess instead
 * of discovering anything, so the suite goes green having stopped exercising discovery
 * at all. Chaining the sweep into webServer.command is what puts it genuinely before the
 * record exists. Do not re-wire it as globalSetup.
 *
 * What it is for: `.tmp-passkey-relay` accumulates real ceremony output - PRF values and
 * a plaintext passphrase - and `.tmp-runtime` accumulates server records and a cookie
 * secret. All of it is gitignored, and none of it is anyone's real key since the
 * ceremonies run against a CDP virtual authenticator. It still gets swept: the suite
 * deliberately moves this material off /dev/shm (tmpfs, gone at reboot) and onto disk
 * inside a checkout, so without this it is secret-shaped residue piling up run after run.
 *
 * The pre-run half is about that residue, not about stale server records - jupyter's own
 * `list_running_servers` unlinks any record whose pid no longer answers `check_pid`, so
 * an interrupted run does not misroute the next one by itself. Nor does this rescue a
 * run whose server is still listening: Playwright refuses to start on a used port before
 * ever running the command, which is the intended loud failure rather than adopting an
 * orphan.
 */
const fs = require('fs');
const path = require('path');

const sweep = async () => {
  for (const dir of ['.tmp-passkey-relay', '.tmp-runtime']) {
    fs.rmSync(path.join(__dirname, dir), { recursive: true, force: true });
  }
};

module.exports = sweep;

// Runnable as a script, which is how webServer.command invokes the pre-run sweep. Guarded
// so that requiring it as globalTeardown never sweeps on import.
if (require.main === module) {
  sweep();
}
