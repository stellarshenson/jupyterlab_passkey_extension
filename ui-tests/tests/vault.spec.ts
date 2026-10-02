import { expect, test } from '@jupyterlab/galata';
import * as fs from 'fs';
import * as path from 'path';

/**
 * The vault panel end to end: a real server with a throwaway vault (see
 * jupyter_server_test_config.py), and a CDP virtual authenticator with PRF standing in
 * for the passkey. Every test starts from no vault, because each page gets a fresh
 * authenticator and a vault is only openable by the passkeys registered with it.
 */

const VAULT_DIR = path.resolve(__dirname, '..', '.tmp-passkey-vault');
const PANEL_ID = 'jp-passkey-vault';
const RECOVERY = 'correct horse battery staple';

test.use({ autoGoto: false });

async function addAuthenticator(page: any): Promise<void> {
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
      hasPrf: true,
      automaticPresenceSimulation: true,
      isUserVerified: true
    }
  });
}

function panel(page: any) {
  return page.locator(`#${PANEL_ID}`);
}

function state(page: any) {
  return panel(page).locator('.jp-PasskeyVaultPanel-stateText');
}

/** A lab with no vault, a virtual authenticator, and the vault panel open. */
async function openVault(page: any): Promise<void> {
  fs.rmSync(VAULT_DIR, { recursive: true, force: true });
  await page.goto();
  await addAuthenticator(page);
  await page.sidebar.openTab(PANEL_ID);
  // The first read can queue behind the lab's own start-up requests - seconds in a
  // lab with many extensions installed - so it gets more than the default 5 s.
  await expect(state(page)).toHaveText('No vault', { timeout: 20000 });
}

async function submitSecret(page: any, value: string, twice: boolean) {
  const dialog = page.locator('.jp-Dialog');
  // Typing starts in the passphrase field, not on the Submit button.
  await expect(dialog.locator('input[type="password"]').nth(0)).toBeFocused();
  await dialog.locator('input[type="password"]').nth(0).fill(value);
  if (twice) {
    await dialog.locator('input[type="password"]').nth(1).fill(value);
  }
  await dialog.getByRole('button', { name: 'Submit' }).click();
}

/** The two registration dialogs: name the passkey, then confirm it once created. */
async function nameAndConfirmPasskey(page: any, name = '') {
  const dialog = page.locator('.jp-Dialog');
  const create = dialog.getByRole('button', { name: 'Create passkey' });
  // Create vault first waits for the server to create the vault, which took about
  // 5 s in this suite - longer than an expect's default wait.
  await create.waitFor({ timeout: 20000 });
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(
    'Name the new passkey'
  );
  // Typing starts in the name field, not on the button.
  const field = dialog.getByLabel('Name', { exact: true });
  await expect(field).toBeFocused();
  await field.fill(name);
  await create.click();
  const confirm = dialog.getByRole('button', { name: 'Confirm passkey' });
  await confirm.waitFor({ timeout: 20000 });
  // The confirm step names the passkey and has nothing to type.
  await expect(dialog.locator('input')).toHaveCount(0);
  await expect(dialog).toContainText(
    `The passkey "${name || 'localhost'}" was created`
  );
  await confirm.click();
}

async function createVault(page: any): Promise<void> {
  await panel(page).getByRole('button', { name: 'Create vault' }).click();
  await submitSecret(page, RECOVERY, true);
  await nameAndConfirmPasskey(page);
  await expect(state(page)).toContainText('Unlocked');
  // A status refresh can show Unlocked while Create still waits on the last passkey
  // request, and the panel ignores a click while an action runs.
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
}

async function openCog(page: any) {
  await panel(page)
    .getByRole('button', { name: 'Vault settings and security' })
    .click();
}

test('the vault panel docks in the right sidebar', async ({ page }) => {
  await openVault(page);
  expect(await page.sidebar.getTabPosition(PANEL_ID)).toBe('right');
});

test('create vault sets the recovery passphrase, registers a passkey and unlocks', async ({
  page
}) => {
  await openVault(page);
  // With no vault the sidebar icon is one shade dimmer than the other icons.
  const tabIcon = page
    .locator(`.lm-TabBar-tab[data-id="${PANEL_ID}"] path`)
    .first();
  await expect(tabIcon).toHaveClass(/jp-icon4/);
  await createVault(page);
  // With a vault it has their colour.
  await expect(tabIcon).toHaveClass(/jp-icon3/);
  const fill = (locator: any) =>
    locator.evaluate((path: Element) => getComputedStyle(path).fill);
  const other = page
    .locator(
      `.jp-SideBar .lm-TabBar-tab:not([data-id="${PANEL_ID}"]) path.jp-icon3`
    )
    .first();
  expect(await fill(tabIcon)).toBe(await fill(other));
  await openCog(page);
  await expect(
    panel(page).locator('.jp-PasskeyVaultPanel-passkey')
  ).toHaveCount(1);
  await expect(panel(page)).toContainText('localhost');
});

test('a hidden panel leaves the settings view', async ({ page }) => {
  await openVault(page);
  await createVault(page);
  await openCog(page);
  const register = panel(page).getByRole('button', {
    name: 'Register new passkey'
  });
  await expect(register).toBeVisible();
  await page.sidebar.close('right');
  await page.sidebar.openTab(PANEL_ID);
  // Shown again, the panel is in its main view.
  await expect(panel(page).getByLabel('Filter by name')).toBeVisible();
  await expect(register).toHaveCount(0);
  await expect(
    panel(page).getByRole('button', { name: 'Vault settings and security' })
  ).not.toHaveClass(/jp-mod-active/);
});

test('lock, then unlock with the passkey', async ({ page }) => {
  await openVault(page);
  await createVault(page);
  // Lock is drawn in the colour of the header's other buttons, not a fainter one.
  const fill = (name: string) =>
    panel(page)
      .getByRole('button', { name })
      .locator('path')
      .first()
      .evaluate(path => getComputedStyle(path).fill);
  expect(await fill('Lock the vault')).toBe(await fill('Refresh'));
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');
  await panel(page)
    .getByRole('button', { name: 'Unlock with passkey' })
    .click();
  await expect(state(page)).toContainText('Unlocked');
});

test('unlock with the recovery passphrase', async ({ page }) => {
  await openVault(page);
  await createVault(page);
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await panel(page)
    .getByRole('button', { name: 'Use recovery passphrase' })
    .click();
  await submitSecret(page, RECOVERY, false);
  await expect(state(page)).toContainText('Unlocked');
});

/** True when `value` is anywhere in the page: its text or any field's value. */
function inPage(page: any, value: string): Promise<boolean> {
  return page.evaluate(
    (v: string) =>
      document.body.innerText.includes(v) ||
      Array.from(
        document.querySelectorAll<HTMLInputElement>('input, textarea')
      ).some(f => f.value.includes(v)),
    value
  );
}

test('an entry opens read-only in a popup, and its password shows only after a passkey', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);

  const SECRET = 'vault-e2e-secret-7Qp';
  await panel(page).getByRole('button', { name: 'Add an entry' }).click();
  const dialog = page.locator('.jp-Dialog');
  await dialog.getByLabel('Name', { exact: true }).fill('github/api');
  await dialog.getByLabel('Username').fill('me');
  await dialog.getByLabel('Password', { exact: true }).fill(SECRET);
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog).toHaveCount(0);

  const row = panel(page).locator('.jp-PasskeyVaultPanel-rowLine', {
    hasText: 'github/api'
  });
  await expect(row).toHaveText('github/apime');
  // The filter box is filled with the panel's background, as the search field of
  // the AI assistants panel, not with the colour of a dialog input.
  expect(
    await panel(page)
      .getByPlaceholder('Filter entries')
      .evaluate(
        (input: HTMLElement) =>
          getComputedStyle(input).backgroundColor ===
          getComputedStyle(input.closest('.jp-PasskeyVaultPanel') as Element)
            .backgroundColor
      )
  ).toBe(true);
  await row.click();
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText('github/api');
  for (const label of ['Name', 'Username', 'Password', 'URL', 'Notes']) {
    await expect(dialog.getByLabel(label, { exact: true })).not.toBeEditable();
  }
  expect(await inPage(page, SECRET)).toBe(false);

  const password = dialog.getByLabel('Password', { exact: true });
  // The eye is joined to the field's right end, as tall as the field, its icon centred.
  const [field, eye, icon] = await password.evaluate(input => {
    const button = input.nextElementSibling as HTMLElement;
    return [input, button, button.querySelector('svg') as Element].map(e =>
      e.getBoundingClientRect().toJSON()
    );
  });
  expect(Math.abs(eye.left - field.right)).toBeLessThanOrEqual(1);
  expect(Math.abs(eye.top - field.top)).toBeLessThanOrEqual(1);
  expect(Math.abs(eye.bottom - field.bottom)).toBeLessThanOrEqual(1);
  const centre = (r: any) => [r.left + r.width / 2, r.top + r.height / 2];
  const [ix, iy] = centre(icon);
  const [ex, ey] = centre(eye);
  expect(Math.abs(ix - ex)).toBeLessThanOrEqual(1);
  expect(Math.abs(iy - ey)).toBeLessThanOrEqual(1);
  await expect(
    dialog.getByRole('button', { name: 'Show password' })
  ).toBeFocused();
  // The icon is the state - crossed while hidden, open while shown - and no border
  // or outline lights up round the eye after the click.
  const eyeIcon = dialog.locator('.jp-PasskeyVaultForm-eye svg');
  await expect(eyeIcon).toHaveAttribute(
    'data-icon',
    'jupyterlab-passkey-extension:eye-off'
  );
  // The reveal is held on its way to the server: until it ends the eye turns a
  // spinner and the line under the field says what is waited for.
  // JupyterLab ends every request URL with a cache-busting query.
  const REVEAL = /\/vault\/reveal(\?|$)/;
  let release = (): void => undefined;
  const held = new Promise<void>(resolve => (release = resolve));
  await page.route(REVEAL, async (route: any) => {
    await held;
    await route.continue();
  });
  const show = dialog.getByRole('button', { name: 'Show password' });
  const spinner = dialog.locator('.jp-PasskeyVaultForm-spinner');
  const waiting = dialog.getByText('Waiting for your passkey');
  // The line's place is kept while it is empty, so the eye stays under the pointer.
  const eyeTop = async () =>
    (await dialog.locator('.jp-PasskeyVaultForm-eye').boundingBox())!.y;
  const before = await eyeTop();
  await show.click();
  await expect(spinner).toBeVisible();
  await expect(waiting).toBeVisible();
  await expect(show).toHaveAttribute('aria-busy', 'true');
  expect(await eyeTop()).toBe(before);
  expect(
    await spinner.evaluate(node => getComputedStyle(node).animationName)
  ).toBe('jp-passkey-vault-spin');
  release();
  await expect(password).toHaveValue(SECRET);
  await expect(spinner).toHaveCount(0);
  await expect(waiting).toHaveCount(0);
  expect(await eyeTop()).toBe(before);
  await page.unroute(REVEAL);
  await expect(password).toHaveAttribute('type', 'text');
  await expect(eyeIcon).toHaveAttribute(
    'data-icon',
    'jupyterlab-passkey-extension:eye'
  );
  await page.mouse.move(0, 0);
  const rim = await password.evaluate(input => {
    const eye = getComputedStyle(input.nextElementSibling as Element);
    const field = getComputedStyle(input);
    return {
      outline: eye.outlineStyle,
      sameBorder: eye.borderTopColor === field.borderTopColor
    };
  });
  expect(rim).toEqual({ outline: 'none', sameBorder: true });
  // A click selects the whole password, symbols and all, for copying - and so does
  // the double-click a user reaches for.
  await password.dblclick();
  expect(
    await password.evaluate((i: HTMLInputElement) =>
      i.value.slice(i.selectionStart!, i.selectionEnd!)
    )
  ).toBe(SECRET);
  await dialog.getByRole('button', { name: 'Hide password' }).click();
  await expect(password).toHaveAttribute('type', 'password');
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toHaveCount(0);
  expect(await inPage(page, SECRET)).toBe(false);

  // Opened from the keyboard, the focused eye fills its box: focus without a rim.
  await row.focus();
  await page.keyboard.press('Enter');
  await expect(
    dialog.getByRole('button', { name: 'Show password' })
  ).toBeFocused();
  const focused = await password.evaluate(input => {
    const eye = getComputedStyle(input.nextElementSibling as Element);
    return {
      outline: eye.outlineStyle,
      filled: eye.backgroundColor !== getComputedStyle(input).backgroundColor
    };
  });
  expect(focused).toEqual({ outline: 'none', filled: true });
  await dialog.getByRole('button', { name: 'Close' }).click();
});

test('the entry dialog is wide with a tall Notes, and Edit shows the same fields as Add', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);

  const labels = () =>
    page.locator('.jp-Dialog .jp-PasskeyVaultForm-label').allInnerTexts();
  await panel(page).getByRole('button', { name: 'Add an entry' }).click();
  const dialog = page.locator('.jp-Dialog');
  const addLabels = await labels();
  const box = await dialog.locator('.jp-Dialog-content').boundingBox();
  expect(box!.width).toBeGreaterThanOrEqual(540);
  const notes = dialog.getByLabel('Notes');
  const lines = await notes.evaluate(
    t => t.clientHeight / (1.2 * parseFloat(getComputedStyle(t).fontSize))
  );
  expect(lines).toBeGreaterThanOrEqual(12);
  // Typing starts in Name, not on the Save button.
  await expect(dialog.getByLabel('Name', { exact: true })).toBeFocused();
  await page.keyboard.type('github/api');
  await dialog.getByRole('button', { name: 'Save' }).click();

  await panel(page)
    .locator('.jp-PasskeyVaultPanel-rowLine', { hasText: 'github/api' })
    .click();
  await dialog.getByRole('button', { name: 'Edit' }).click();
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText('Edit entry');
  expect(await labels()).toEqual(addLabels);
  const name = dialog.getByLabel('Name', { exact: true });
  await expect(name).toHaveValue('github/api');
  await expect(name).not.toBeEditable();
  await expect(dialog.getByLabel('Username')).toBeFocused();
  await dialog.getByRole('button', { name: 'Cancel' }).click();
});

test('the cog view shows the key holder and a row for each capability it shows', async ({
  page
}) => {
  await openVault(page);
  await openCog(page);
  // The row itself, not the header's status line, which also names the holder.
  await expect(
    panel(page).locator('.jp-PasskeyVaultPanel-pair', { hasText: 'Key holder' })
  ).toHaveText('Key holdermemory');
  const rows = panel(page).locator('.jp-PasskeyVaultPanel-capability');
  await expect(rows).toHaveCount(3);
  // A short value in the row, the explanation in its tooltip.
  await expect(rows.first()).toHaveText(/^Never in swap(yes|no)$/);
  await expect(rows.first()).toHaveAttribute('title', /swap/);
  // The memory holder: a restart locks the vault - yes, in the theme's success colour.
  const locks = panel(page).locator('[data-capability="locks_on_restart"]');
  await expect(locks).toHaveText('Locks on server restartyes');
  const [value, success] = await locks
    .locator('.jp-PasskeyVaultPanel-pairValue')
    .evaluate(e => {
      const probe = document.createElement('span');
      probe.style.color = 'var(--jp-success-color1)';
      e.appendChild(probe);
      const colours = [
        getComputedStyle(e).color,
        getComputedStyle(probe).color
      ];
      probe.remove();
      return colours;
    });
  expect(value).toBe(success);
});

test('a passkey is registered with a passkey as the proof, or the recovery passphrase when this host has none', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await openCog(page);
  const register = panel(page).getByRole('button', {
    name: 'Register new passkey'
  });
  // Two button sizes only: a section's action spans the section (8 px each side),
  // a row's action is the small 20 px button. Both widths come from one read, so a
  // re-render between two reads cannot detach the element measured second.
  const [registerWidth, sectionWidth] = await register.evaluate(b => [
    b.getBoundingClientRect().width,
    b.parentElement!.getBoundingClientRect().width
  ]);
  expect(Math.round(registerWidth)).toBe(Math.round(sectionWidth - 16));
  const dialog = page.locator('.jp-Dialog');
  const rows = panel(page).locator('.jp-PasskeyVaultPanel-passkey');
  const remove = async (n: number) => {
    await rows.nth(n).getByRole('button', { name: 'Remove' }).click();
    // A confirming click within half a second of arming is ignored (no double-click
    // deletes), so the second click comes after that.
    await page.waitForTimeout(600);
    await rows.nth(n).getByRole('button', { name: 'Confirm remove' }).click();
  };

  // This host has a passkey: it is the proof, then the user names the new passkey
  // and that click lets the browser create it. No passphrase is asked.
  await register.click();
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(
    'Name the new passkey'
  );
  await expect(dialog.locator('input[type="password"]')).toHaveCount(0);
  await nameAndConfirmPasskey(page, 'Work laptop');
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(1)).toContainText('Work laptop');
  const removeBox = await rows
    .nth(1)
    .getByRole('button', { name: 'Remove' })
    .boundingBox();
  expect(Math.round(removeBox!.height)).toBe(20);
  await remove(1);
  await expect(rows).toHaveCount(1);

  // With no passkey for this host, the recovery passphrase is the proof.
  await remove(0);
  await expect(rows).toHaveCount(0);
  await register.click();
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(
    'Register new passkey'
  );
  await submitSecret(page, RECOVERY, false);
  await nameAndConfirmPasskey(page);
  await expect(rows).toHaveCount(1);
});

test('the recovery passphrase is changed and then opens the vault', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await openCog(page);
  await panel(page)
    .getByRole('button', { name: 'Change recovery passphrase' })
    .click();
  await submitSecret(page, 'a brand new recovery passphrase', true);
  await expect(panel(page)).toContainText('Recovery passphrase changed');

  await openCog(page); // back to the main view
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await panel(page)
    .getByRole('button', { name: 'Use recovery passphrase' })
    .click();
  await submitSecret(page, 'a brand new recovery passphrase', false);
  await expect(state(page)).toContainText('Unlocked');
});
