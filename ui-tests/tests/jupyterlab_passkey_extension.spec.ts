import { expect, test } from '@jupyterlab/galata';

/**
 * Don't load JupyterLab webpage before running the tests.
 * This is required to ensure we capture all log messages.
 */
test.use({ autoGoto: false });

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

test('should relay a passkey ceremony result to the server', async ({
  page
}) => {
  // Drive a Chromium CDP virtual authenticator so the WebAuthn ceremony can
  // complete headlessly with no real security key and no user gesture.
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send(
    'WebAuthn.addVirtualAuthenticator',
    {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        hasPrf: true,
        automaticPresenceSimulation: true,
        isUserVerified: true
      }
    }
  );

  await page.goto();

  // We request a PRF-capable virtual authenticator (hasPrf), but not every
  // Chromium build honours it, so the assertion below tolerates either the
  // PRF-enabled (ok:true + cred_id) or prf-unsupported (ok:false) outcome - this
  // test verifies the ceremony + relay round-trip, not a real 32-byte PRF value.
  const resultRequest = page.waitForRequest(
    request =>
      request.url().includes('/jupyterlab-passkey-extension/result') &&
      request.method() === 'POST'
  );

  await page.evaluate(() =>
    (window as any).jupyterapp.commands.execute('passkey:run', {
      op: 'create',
      nonce: 'testnonce0123456789',
      rp_id: location.hostname,
      user: { id: btoa('u').replace(/=/g, ''), name: 'u', displayName: 'u' }
    })
  );

  const request = await resultRequest;
  const body = JSON.parse(request.postData() ?? '{}');
  expect(body.nonce).toBe('testnonce0123456789');
  expect(typeof body.ok).toBe('boolean');
  if (body.ok) {
    expect(typeof body.cred_id).toBe('string');
    expect(body.cred_id.length).toBeGreaterThan(0);
  } else {
    expect(typeof body.error).toBe('string');
  }
});
