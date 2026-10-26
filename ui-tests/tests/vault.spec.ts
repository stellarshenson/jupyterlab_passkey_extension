import { expect, test } from '@jupyterlab/galata';
import { spawn } from 'child_process';
import * as crypto from 'crypto';
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
  await page.goto('?reset');
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
  // The panel is busy from the Create click until the action ends; the state text
  // changes only when the passkeys request returns, which can take longer than an
  // expect's default wait.
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true', {
    timeout: 20000
  });
  await expect(state(page)).toContainText('Unlocked');
}

async function openCog(page: any) {
  await panel(page)
    .getByRole('button', { name: 'Vault settings and security' })
    .click();
}

/** An unlock method the cog view adds: a passkey, or the password and authenticator app. */
type Kind = 'passkey' | 'mfa';

/** The cog view's rows of one unlock method. */
function method(page: any, kind: Kind | 'recovery') {
  return panel(page).locator(
    `.jp-PasskeyVaultPanel-method[data-method="${kind}"]`
  );
}

/** Press "Add unlock method" in the cog view and choose a method in its dialog. */
async function addMethod(page: any, kind: Kind) {
  await panel(page).getByRole('button', { name: 'Add unlock method' }).click();
  const dialog = page.locator('.jp-Dialog');
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(
    'Add unlock method'
  );
  await dialog.locator(`button[data-method="${kind}"]`).click();
}

/** Remove an unlock method: two clicks, the second at least half a second later. */
async function removeMethod(page: any, row: any) {
  await row.getByRole('button', { name: 'Remove' }).click();
  // A confirming click within half a second of arming is ignored (no double-click
  // deletes), so the second click comes after that.
  await page.waitForTimeout(600);
  const confirm = row.getByRole('button', { name: 'Confirm remove' });
  // Both words on one line, inside the button, at the width of a sidebar.
  await expect(confirm).toHaveCSS('white-space', 'nowrap');
  await confirm.click();
}

/**
 * The reveal window after a proof ends for the page: the eye asks a proof again.
 * The panel reads the time with Date.now, which answers 61 s later from here on.
 */
async function endProvenMinute(page: any): Promise<void> {
  await page.evaluate(() => {
    const now = Date.now;
    // Kept so a later read of a server-written stamp can use the same clock.
    (window as any).passkeyRealNow = now;
    Date.now = () => now() + 61000;
  });
}

/** The request that reads a password. JupyterLab ends every request URL with a cache-busting query. */
const REVEAL = /\/vault\/reveal(\?|$)/;

/** The code an authenticator app shows for `setupKey` in time step `step` (RFC 6238). */
function appCode(setupKey: string, step: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bits = Array.from(setupKey, c =>
    alphabet.indexOf(c).toString(2).padStart(5, '0')
  ).join('');
  const secret = Buffer.from(
    (bits.match(/.{8}/g) as string[]).map(byte => parseInt(byte, 2))
  );
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = crypto.createHmac('sha1', secret).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const number = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(number % 1000000).padStart(6, '0');
}

test('the vault panel docks in the right sidebar', async ({ page }) => {
  await openVault(page);
  expect(await page.sidebar.getTabPosition(PANEL_ID)).toBe('right');
});

test('the Settings Editor shows the vault icon in the enabled colour', async ({
  page
}) => {
  await page.goto();
  await page.evaluate(() =>
    (window as any).jupyterapp.commands.execute('settingeditor:open')
  );
  const list = page.locator('.jp-PluginList');
  const icon = list
    .locator(
      '.jp-PluginList-entry[data-id="jupyterlab_passkey_extension:vault"]'
    )
    .locator('svg path')
    .first();
  await expect(icon).toBeVisible({ timeout: 20000 });
  const fill = await icon.evaluate(
    (path: Element) => getComputedStyle(path).fill
  );
  // The colour of class jp-icon3 in the same list, read from a temporary path.
  const enabled = await list.evaluate((root: HTMLElement) => {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    const path = document.createElementNS(ns, 'path');
    path.setAttribute('class', 'jp-icon3');
    path.setAttribute('fill', '#616161');
    svg.appendChild(path);
    root.appendChild(svg);
    const value = getComputedStyle(path).fill;
    svg.remove();
    return value;
  });
  expect(fill).toBe(enabled);
});

test('the panel has the geometry of the AI assistants panels', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  const dialog = page.locator('.jp-Dialog');
  await panel(page).getByRole('button', { name: 'Add an entry' }).click();
  await dialog.getByLabel('Name', { exact: true }).fill('github/api');
  await dialog.getByLabel('Username').fill('me');
  await dialog.getByLabel('Password', { exact: true }).fill('s3cret-value');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
  // The filter field is hidden until the header's filter button is pressed; then
  // it takes the typing at once.
  const filterButton = panel(page).getByRole('button', {
    name: 'Filter entries'
  });
  await expect(panel(page).getByLabel('Filter by name')).toHaveCount(0);
  await expect(filterButton).toHaveAttribute('aria-pressed', 'false');
  await filterButton.click();
  await expect(panel(page).getByLabel('Filter by name')).toBeFocused();
  await expect(filterButton).toHaveAttribute('aria-pressed', 'true');

  // For each element: its distance from the panel's left and right border, and its
  // height, in whole pixels.
  const measure = (selectors: string[]) =>
    panel(page).evaluate((root: HTMLElement, list: string[]) => {
      const base = root.getBoundingClientRect();
      return list.map(selector => {
        const r = (
          root.querySelector(selector) as HTMLElement
        ).getBoundingClientRect();
        return [r.left - base.left, base.right - r.right, r.height].map(
          Math.round
        );
      });
    }, selectors);
  const C = '.jp-PasskeyVaultPanel';
  const style = (selector: string, property: string) =>
    panel(page)
      .locator(selector)
      .first()
      .evaluate(
        (node: HTMLElement, name: string) =>
          getComputedStyle(node).getPropertyValue(name),
        property
      );

  // The list view. Text starts 18 px from the border: the title, the state, a
  // category and an entry's name. A field spans from 4 px to 4 px. Header buttons
  // and rows are 24 px high.
  const [
    title,
    stateText,
    filter,
    category,
    caret,
    categoryLabel,
    row,
    name,
    icon
  ] = await measure([
    `${C}-headerTitle`,
    `${C}-stateText`,
    `${C}-filterInput`,
    `${C}-sectionHeader`,
    `${C}-caret`,
    `${C}-sectionLabel`,
    `${C}-rowLine`,
    `${C}-rowName`,
    `${C}-iconButton`
  ]);
  expect([title[0], stateText[0], categoryLabel[0], name[0]]).toEqual([
    18, 18, 18, 18
  ]);
  expect(filter.slice(0, 2)).toEqual([4, 4]);
  expect(category.slice(0, 2)).toEqual([0, 0]);
  expect(row[2]).toBe(24);
  expect(icon[2]).toBe(24);
  // A section header is a band in the header's colour: the caret on the inset, its
  // label in the text column.
  expect(caret[0]).toBe(4);
  expect(await style(`${C}-sectionHeader`, 'background-color')).toBe(
    await style(`${C}-header`, 'background-color')
  );
  expect(await style(`${C}-rowName`, 'font-weight')).toBe('400');
  // The age is small and dim at the right end of the row; the username before it.
  const [user, used] = await measure([`${C}-rowUser`, `${C}-rowAge`]);
  expect(used[1]).toBe(4);
  expect(user[1]).toBeGreaterThan(used[1]);
  expect(await style(`${C}-rowUser`, 'font-size')).toBe(
    await style(`${C}-headerTitle`, 'font-size')
  );
  expect(await style(`${C}-rowAge`, 'font-size')).toBe(
    await style(`${C}-headerTitle`, 'font-size')
  );

  // The cog view: a label and an unlock method's name in the text column, a
  // section's button from 4 px to 4 px.
  await openCog(page);
  const [label, methodName, add] = await measure([
    `${C}-pairLabel`,
    `${C}-method ${C}-rowName`,
    `${C}-section > button`
  ]);
  expect([label[0], methodName[0]]).toEqual([18, 18]);
  expect(add.slice(0, 2)).toEqual([4, 4]);
});

test('create vault sets the recovery passphrase, adds a passkey and unlocks', async ({
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
  await expect(method(page, 'passkey')).toHaveCount(1);
  await expect(panel(page)).toContainText('localhost');
});

test('a hidden panel leaves the settings view', async ({ page }) => {
  await openVault(page);
  await createVault(page);
  await openCog(page);
  const add = panel(page).getByRole('button', { name: 'Add unlock method' });
  await expect(add).toBeVisible();
  await page.sidebar.close('right');
  await page.sidebar.openTab(PANEL_ID);
  // Shown again, the panel is in its main view.
  await expect(
    panel(page).getByRole('button', { name: 'Add an entry' })
  ).toBeVisible();
  await expect(add).toHaveCount(0);
  await expect(
    panel(page).getByRole('button', { name: 'Vault settings and security' })
  ).not.toHaveClass(/jp-mod-active/);
});

test('header icons stay in place and disable themselves when a view does not use them', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await openCog(page);
  const icon = (name: string) => panel(page).getByRole('button', { name });
  for (const name of [
    'Lock the vault',
    'Add an entry',
    'Filter entries',
    'Refresh',
    'Vault settings and security'
  ]) {
    await expect(icon(name)).toBeVisible();
  }
  await expect(icon('Add an entry')).toBeDisabled();
  await expect(icon('Filter entries')).toBeDisabled();
  await expect(icon('Lock the vault')).toBeEnabled();
  await expect(icon('Refresh')).toBeEnabled();
  await expect(icon('Vault settings and security')).toBeEnabled();
  await icon('Vault settings and security').click();
  await expect(icon('Add an entry')).toBeEnabled();
  await expect(icon('Filter entries')).toBeEnabled();
  await icon('Lock the vault').click();
  await expect(state(page)).toHaveText('Locked');
  await expect(icon('Lock the vault')).toBeDisabled();
  await expect(icon('Add an entry')).toBeDisabled();
  await expect(icon('Filter entries')).toBeDisabled();
  await expect(icon('Refresh')).toBeEnabled();
  await expect(icon('Vault settings and security')).toBeEnabled();
});

test('a category collapses from its header and stays collapsed after a reload', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await addEntry(page, 's3cret-value');
  const header = panel(page).getByRole('button', { name: 'Uncategorised (1)' });
  const row = panel(page).locator('.jp-PasskeyVaultPanel-rowName', {
    hasText: 'github/api'
  });
  await expect(header).toHaveAttribute('aria-expanded', 'true');
  await expect(row).toHaveCount(1);
  await header.click();
  await expect(header).toHaveAttribute('aria-expanded', 'false');
  await expect(row).toHaveCount(0);
  // The server keeps the vault unlocked across a reload, and the browser keeps the
  // category collapsed.
  await page.reload();
  await page.sidebar.openTab(PANEL_ID);
  await expect(state(page)).toContainText('Unlocked', { timeout: 20000 });
  await expect(header).toHaveAttribute('aria-expanded', 'false');
  await expect(row).toHaveCount(0);
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
  await expect(row).toHaveText('github/apimenever');
  // The filter box is filled with the panel's background, as the search field of
  // the AI assistants panel, not with the colour of a dialog input.
  await panel(page).getByRole('button', { name: 'Filter entries' }).click();
  expect(
    await panel(page)
      .getByPlaceholder('Filter entries...')
      .evaluate(
        (input: HTMLElement) =>
          getComputedStyle(input).backgroundColor ===
          getComputedStyle(input.closest('.jp-PasskeyVaultPanel') as Element)
            .backgroundColor
      )
  ).toBe(true);
  // Create vault added its first passkey with a proof, which starts the reveal window;
  // here that window is over, so the eye asks a proof.
  await endProvenMinute(page);
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

  // The reveal marked the entry used. The server writes that stamp with its own
  // clock, so undo endProvenMinute's 61 s shift before reading the age back.
  await page.evaluate(() => {
    Date.now = (window as any).passkeyRealNow;
  });
  await panel(page).getByRole('button', { name: 'Refresh' }).click();
  await expect(row.locator('.jp-PasskeyVaultPanel-rowAge')).toHaveText('now');
  await expect(row).toHaveClass(/jp-mod-recentlyActive/);

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

test('the Category field lists the categories in use, and a choice fills the field', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  const dialog = page.locator('.jp-Dialog');
  for (const [name, category] of [
    ['work/one', 'work'],
    ['home/one', 'home']
  ]) {
    await panel(page).getByRole('button', { name: 'Add an entry' }).click();
    await dialog.getByLabel('Name', { exact: true }).fill(name);
    await dialog.getByLabel('Category', { exact: true }).fill(category);
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog).toHaveCount(0);
  }

  await panel(page).getByRole('button', { name: 'Add an entry' }).click();
  const field = dialog.getByLabel('Category', { exact: true });
  await dialog.getByRole('button', { name: 'Existing categories' }).click();
  const menu = page.locator('.jp-PasskeyVaultForm-categoryMenu');
  await expect(menu.locator('.lm-Menu-itemLabel')).toHaveText(['home', 'work']);
  await menu.getByRole('menuitem', { name: 'work' }).click();
  await expect(menu).toHaveCount(0);
  await expect(field).toHaveValue('work');
  await expect(field).toBeEditable();

  // From the keyboard: the keys reach the open list, not the dialog.
  const name = dialog.getByLabel('Name', { exact: true });
  await name.fill('keys/one');
  const toggle = dialog.getByRole('button', { name: 'Existing categories' });
  await toggle.focus();
  await page.keyboard.press('Space');
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  await expect(field).toHaveValue('home');
  await expect(dialog).toHaveCount(1);
  await toggle.focus();
  await page.keyboard.press('Space');
  await page.keyboard.press('Escape');
  await expect(menu).toHaveCount(0);
  await expect(dialog).toHaveCount(1);
  await expect(name).toHaveValue('keys/one');
  // Enter on the arrow opens the list, as Space does.
  await toggle.focus();
  await page.keyboard.press('Enter');
  await expect(menu).toBeVisible();
  await expect(dialog).toHaveCount(1);
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

test('a passkey is added with a passkey as the proof, or the recovery passphrase when this host has none', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await openCog(page);
  const add = panel(page).getByRole('button', { name: 'Add unlock method' });
  // Two button sizes only: a section's action spans the section (4 px each side),
  // a row's action is the small 20 px button. Both widths come from one read, so a
  // re-render between two reads cannot detach the element measured second.
  const [addWidth, sectionWidth] = await add.evaluate(b => [
    b.getBoundingClientRect().width,
    b.parentElement!.getBoundingClientRect().width
  ]);
  expect(Math.round(addWidth)).toBe(Math.round(sectionWidth - 8));
  const dialog = page.locator('.jp-Dialog');
  const rows = method(page, 'passkey');
  const remove = (n: number) => removeMethod(page, rows.nth(n));

  // The dialog offers the two methods as buttons, the first one focused; each button
  // is named by its method and described by the line under the name.
  await add.click();
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(
    'Add unlock method'
  );
  const kinds = dialog.locator('.jp-Dialog-body').getByRole('button');
  await expect(kinds).toHaveCount(2);
  const first = dialog.getByRole('button', { name: 'Passkey', exact: true });
  await expect(first).toBeFocused();
  await expect(first).toHaveAccessibleDescription(
    'Fingerprint, face, PIN or security key.'
  );
  await expect(
    dialog.getByRole('button', {
      name: 'Password and authenticator app',
      exact: true
    })
  ).toHaveAccessibleDescription(
    'A password, then a 6-digit code from your phone.'
  );
  // The two buttons have one width, and the name sits over its line.
  const boxes = await kinds.evaluateAll(buttons =>
    buttons.map(b => {
      const [name, help] = Array.from(b.children).map(c =>
        c.getBoundingClientRect()
      );
      return {
        width: Math.round(b.getBoundingClientRect().width),
        stacked: name.bottom <= help.top && name.left === help.left
      };
    })
  );
  expect(new Set(boxes.map(b => b.width)).size).toBe(1);
  expect(boxes.every(b => b.stacked)).toBe(true);
  // Cancel is the dialog's only button of its own: there is no Continue.
  await expect(
    dialog.locator('.jp-Dialog-footer').getByRole('button')
  ).toHaveText(['Cancel']);
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toHaveCount(0);

  // Enter on the focused method chooses it.
  await add.click();
  await expect(first).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(
    'Name the new passkey'
  );
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');

  // This host has a passkey: it is the proof, then the user names the new passkey
  // and that click lets the browser create it. No passphrase is asked.
  await addMethod(page, 'passkey');
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
  await addMethod(page, 'passkey');
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText('Add passkey');
  await submitSecret(page, RECOVERY, false);
  await nameAndConfirmPasskey(page);
  await expect(rows).toHaveCount(1);
});

const MFA_TITLE = 'Add password and authenticator app';
const UNLOCK_PASSWORD = 'an everyday password';

/** The code field and the Add button of the dialog that shows the app's QR code. */
function appDialog(page: any) {
  const dialog = page.locator('.jp-Dialog');
  return {
    code: dialog.getByLabel('Code from the app'),
    add: dialog.getByRole('button', { name: 'Add', exact: true })
  };
}

/**
 * From the cog view, add the unlock password and the authenticator app up to the
 * dialog that shows the app's setup key: the password twice, then this host's passkey
 * as the proof. Returns the setup key.
 */
async function startMfa(page: any): Promise<string> {
  const dialog = page.locator('.jp-Dialog');
  await addMethod(page, 'mfa');
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(MFA_TITLE);
  const fields = dialog.locator('input[type="password"]');
  await fields.nth(0).fill(UNLOCK_PASSWORD);
  await fields.nth(1).fill(UNLOCK_PASSWORD);
  await dialog.getByRole('button', { name: 'Submit' }).click();
  await appDialog(page).code.waitFor({ timeout: 20000 });
  const shown = await dialog
    .locator('.jp-PasskeyVaultForm-setupKey')
    .innerText();
  return shown.replace(/ /g, '');
}

async function addEntry(page: any, secret: string) {
  const dialog = page.locator('.jp-Dialog');
  await panel(page).getByRole('button', { name: 'Add an entry' }).click();
  await dialog.getByLabel('Name', { exact: true }).fill('github/api');
  await dialog.getByLabel('Password', { exact: true }).fill(secret);
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog).toHaveCount(0);
}

test('a password and an authenticator app are added in one flow, and the two unlock the vault', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  const dialog = page.locator('.jp-Dialog');
  await openCog(page);
  const row = method(page, 'mfa');
  await expect(row).toHaveCount(0);

  // The flow's first step: the password twice. Submit stays off until both fields
  // agree and hold the 12 characters the setting asks.
  await addMethod(page, 'mfa');
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(MFA_TITLE);
  const fields = dialog.locator('input[type="password"]');
  const submit = dialog.getByRole('button', { name: 'Submit' });
  const status = dialog.locator('.jp-PassphraseDialog-status');
  await expect(fields.nth(0)).toHaveAttribute('placeholder', 'Password');
  await expect(fields.nth(1)).toHaveAttribute(
    'placeholder',
    'Confirm password'
  );
  await fields.nth(0).fill('eleven char');
  await fields.nth(1).fill('eleven char');
  await expect(status).toHaveText('Too short: at least 12 characters');
  await expect(submit).toBeDisabled();
  await fields.nth(0).fill(UNLOCK_PASSWORD);
  await fields.nth(1).fill(UNLOCK_PASSWORD);
  await expect(status).toHaveText('Passwords match');
  await submit.click();

  // This host's passkey is the proof. The last step shows the QR code and the setup
  // key, under the same title, and typing starts in the code field.
  const { code, add } = appDialog(page);
  await code.waitFor({ timeout: 20000 });
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(MFA_TITLE);
  await expect(code).toBeFocused();
  // Nothing to send until six digits are typed.
  await expect(add).toBeDisabled();
  const qr = await dialog.locator('.jp-PasskeyVaultForm-qr svg').boundingBox();
  expect([Math.round(qr!.width), Math.round(qr!.height)]).toEqual([180, 180]);
  const shownKey = await dialog
    .locator('.jp-PasskeyVaultForm-setupKey')
    .innerText();
  expect(shownKey).toMatch(/^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);
  const setupKey = shownKey.replace(/ /g, '');
  // A code of another time: the dialog opens again with the same key and says so.
  const step = Math.floor(Date.now() / 30000);
  await code.fill(appCode(setupKey, step + 50));
  await add.click();
  await expect(
    dialog.getByText('Wrong code. Enter the code the app shows now.')
  ).toBeVisible();
  await expect(dialog.locator('.jp-PasskeyVaultForm-setupKey')).toHaveText(
    shownKey
  );
  await code.fill(appCode(setupKey, step));
  await add.click();
  await expect(dialog).toHaveCount(0);
  await expect(panel(page)).toContainText(
    'Password and authenticator app added'
  );
  // One row for the two. Its name is shown whole at the width of a sidebar: it
  // wraps beside Remove and is not cut.
  await expect(row).toContainText('Password and authenticator app');
  await expect(row).toContainText('Added 20');
  const name = row.locator('.jp-PasskeyVaultPanel-rowName');
  expect(await name.evaluate(n => n.scrollWidth <= n.clientWidth)).toBe(true);
  const [rowBox, removeBox] = await Promise.all([
    row.boundingBox(),
    row.getByRole('button', { name: 'Remove' }).boundingBox()
  ]);
  expect(removeBox!.x + removeBox!.width).toBeLessThanOrEqual(
    rowBox!.x + rowBox!.width
  );
  // A vault has one: the dialog says so and the method cannot be chosen.
  await panel(page).getByRole('button', { name: 'Add unlock method' }).click();
  await expect(dialog.locator('button[data-method="mfa"]')).toBeDisabled();
  await expect(dialog).toContainText('Remove it to add another.');
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toHaveCount(0);

  // The locked view offers the two beside the passkey: the password, then the code.
  await openCog(page);
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');
  const unlock = panel(page).getByRole('button', {
    name: 'Unlock with password'
  });
  const unlockCode = dialog.getByLabel(
    'Enter the code the authenticator app shows'
  );
  const send = dialog.getByRole('button', { name: 'Unlock', exact: true });
  // The password with a wrong code opens nothing.
  await unlock.click();
  await submitSecret(page, UNLOCK_PASSWORD, false);
  await expect(unlockCode).toBeFocused();
  await expect(send).toBeDisabled();
  await unlockCode.fill(appCode(setupKey, step + 50));
  await send.click();
  await expect(dialog).toHaveCount(0);
  await expect(panel(page)).toContainText('wrong code');
  await expect(state(page)).toHaveText('Locked');
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
  // The step after the one that added the app: a code is accepted once.
  await unlock.click();
  await submitSecret(page, UNLOCK_PASSWORD, false);
  await unlockCode.fill(appCode(setupKey, step + 1));
  await send.click();
  await expect(state(page)).toContainText('Unlocked');
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');

  // One Remove, in two steps, removes both; the locked view then offers neither.
  await openCog(page);
  await removeMethod(page, row);
  await expect(row).toHaveCount(0);
  await expect(panel(page)).toContainText(
    'Password and authenticator app removed'
  );
  await openCog(page);
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');
  await expect(
    panel(page).getByRole('button', { name: 'Use recovery passphrase' })
  ).toBeVisible();
  await expect(unlock).toHaveCount(0);
});

test('a code, the unlock password or the recovery passphrase shows a password at a hostname with no passkey', async ({
  page
}) => {
  const SECRET = 'vault-e2e-secret-9Wk';
  await openVault(page);
  await createVault(page);
  await addEntry(page, SECRET);
  const dialog = page.locator('.jp-Dialog');
  await openCog(page);
  const setupKey = await startMfa(page);
  // A code is accepted once, so each code here is of a later time step than the one
  // before. The server takes the step before the current one, the current and the next.
  let step = Math.floor(Date.now() / 30000) - 2;
  const nextCode = () => {
    step = Math.max(step + 1, Math.floor(Date.now() / 30000) - 1);
    return appCode(setupKey, step);
  };
  const { code, add } = appDialog(page);
  await code.fill(nextCode());
  await add.click();
  await expect(dialog).toHaveCount(0);
  await expect(method(page, 'mfa')).toContainText('Added 20');

  // With no passkey for this hostname a proof in a dialog is a code. The button for
  // the recovery passphrase works with nothing typed: only Submit waits for six digits.
  await removeMethod(page, method(page, 'passkey'));
  await expect(method(page, 'passkey')).toHaveCount(0);
  await panel(page)
    .getByRole('button', { name: 'Change recovery passphrase' })
    .click();
  await expect(
    dialog.getByLabel('Enter a code of the authenticator app')
  ).toBeFocused();
  await expect(dialog.getByRole('button', { name: 'Submit' })).toBeDisabled();
  await dialog.getByRole('button', { name: 'Use recovery passphrase' }).click();
  await expect(
    dialog.getByText('Enter the current recovery passphrase')
  ).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');

  // Unlock with the password and a code. An unlock starts no reveal window, so the eye
  // asks a proof at once: the app's next code, since a code is accepted once.
  await openCog(page);
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');
  await panel(page)
    .getByRole('button', { name: 'Unlock with password' })
    .click();
  await submitSecret(page, UNLOCK_PASSWORD, false);
  await dialog
    .getByLabel('Enter the code the authenticator app shows')
    .fill(nextCode());
  await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();
  await expect(state(page)).toContainText('Unlocked');
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
  const row = panel(page).locator('.jp-PasskeyVaultPanel-rowLine', {
    hasText: 'github/api'
  });
  const password = dialog.getByLabel('Password', { exact: true });
  const proof = dialog.locator('.jp-PasskeyVaultForm-proof input');
  const show = dialog.getByRole('button', { name: 'Show', exact: true });
  const eye = dialog.getByRole('button', { name: 'Show password' });
  /** Press the eye in the window: the request carries no proof and the popup asks none. */
  const showsAtOnce = async () => {
    await row.click();
    const [request] = await Promise.all([
      page.waitForRequest(REVEAL),
      eye.click()
    ]);
    expect(request.postDataJSON()).toEqual({ name: 'github/api' });
    await expect(password).toHaveValue(SECRET);
    await expect(proof).toHaveCount(0);
    await dialog.getByRole('button', { name: 'Close' }).click();
    await expect(dialog).toHaveCount(0);
  };
  // The unlock opened the vault but started no window: the eye asks a proof.
  await row.click();
  await expect(proof).toHaveCount(0);
  await eye.click();
  await expect(
    dialog.getByText(
      'Enter a code of the authenticator app to show the password.'
    )
  ).toBeVisible();
  // The unlock password proves, so the app's codes are left for the steps below: a
  // code is accepted once, and only the previous, current and next step are taken.
  await dialog.getByRole('button', { name: 'Use the unlock password' }).click();
  await expect(
    dialog.getByText('Enter the unlock password to show the password.')
  ).toBeVisible();
  await proof.fill(UNLOCK_PASSWORD);
  await show.click();
  await expect(password).toHaveValue(SECRET);
  await expect(proof).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toHaveCount(0);
  // That proof starts the reveal window.
  await showsAtOnce();

  // After the window the eye asks the proof in a row of the popup: the app's code first.
  await endProvenMinute(page);
  await row.click();
  // Until the eye is pressed the popup has nothing to type in.
  await expect(proof).toHaveCount(0);
  await eye.click();
  await expect(
    dialog.getByText(
      'Enter a code of the authenticator app to show the password.'
    )
  ).toBeVisible();
  await expect(proof).toBeFocused();
  // Enter on Show presses it and the popup stays.
  await proof.fill(nextCode());
  await show.press('Enter');
  await expect(password).toHaveValue(SECRET);
  await expect(proof).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toHaveCount(0);
  // That proof starts a reveal window of its own.
  await showsAtOnce();

  // The unlock password alone on request, while the vault is unlocked.
  await endProvenMinute(page);
  await row.click();
  await eye.click();
  await dialog.getByRole('button', { name: 'Use the unlock password' }).click();
  await expect(
    dialog.getByText('Enter the unlock password to show the password.')
  ).toBeVisible();
  await expect(proof).toHaveAttribute('type', 'password');
  await proof.fill(UNLOCK_PASSWORD);
  await show.click();
  await expect(password).toHaveValue(SECRET);
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toHaveCount(0);

  // The recovery passphrase after it; Enter in the row sends it and the popup stays.
  await endProvenMinute(page);
  await row.click();
  await eye.click();
  await dialog.getByRole('button', { name: 'Use the unlock password' }).click();
  await dialog
    .getByRole('button', { name: 'Use the recovery passphrase' })
    .click();
  await expect(
    dialog.getByText('Enter the recovery passphrase to show the password.')
  ).toBeVisible();
  await proof.fill('not the passphrase');
  await proof.press('Enter');
  await expect(
    dialog.getByText('The password was not shown: wrong recovery passphrase')
  ).toBeVisible();
  await expect(proof).toHaveValue('');
  await proof.fill(RECOVERY);
  await proof.press('Enter');
  await expect(password).toHaveValue(SECRET);
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toHaveCount(0);

  // With the two removed, the eye asks the recovery passphrase at once.
  await openCog(page);
  await removeMethod(page, method(page, 'mfa'));
  await expect(method(page, 'mfa')).toHaveCount(0);
  await openCog(page);
  await endProvenMinute(page);
  await row.click();
  await eye.click();
  await expect(
    dialog.getByText('Enter the recovery passphrase to show the password.')
  ).toBeVisible();
  await expect(
    dialog.getByRole('button', { name: 'Use the recovery passphrase' })
  ).toHaveCount(0);
  await proof.fill(RECOVERY);
  await show.click();
  await expect(password).toHaveValue(SECRET);
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

test('the data key is rotated with the recovery passphrase as the proof', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await openCog(page);
  // This host's passkey is the first proof the panel uses. Removed, the rotation must
  // ask for the recovery passphrase.
  await removeMethod(page, method(page, 'passkey'));
  await expect(method(page, 'passkey')).toHaveCount(0);
  const vaultFile = path.join(VAULT_DIR, 'vault.json');
  const created = (): string =>
    JSON.parse(fs.readFileSync(vaultFile, 'utf8')).data_key.created;
  const before = created();
  // The date has second precision, so a second's wait keeps the rotated date distinct
  // even when both writes land inside the same minute.
  await page.waitForTimeout(1100);

  await panel(page).getByRole('button', { name: 'Rotate data key' }).click();
  await submitSecret(page, RECOVERY, false);
  await expect(panel(page)).toContainText('Data key rotated');
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
  expect(created()).not.toBe(before);
});

/**
 * Run the vault CLI against this suite's server, the way an agent reads a key: no
 * browser, no panel. The suite's runtime dir is already pinned by playwright.config.js,
 * so the only server `jupyter server list` shows is the test one; the lab's own
 * discovery variables must go, or the CLI would post to the developer's real lab.
 */
function vaultGet(name: string): Promise<{
  code: number | null;
  stdout: string;
  stderr: string;
}> {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    JUPYTER_PORT: process.env.JUPYTER_TEST_PORT || '8888'
  };
  for (const variable of ['JUPYTER_SERVER_URL', 'JUPYTERHUB_SERVICE_PREFIX']) {
    delete env[variable];
  }
  const child = spawn('jupyterlab-passkey', ['vault', 'get', name], { env });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (data: Buffer) => (stdout += data.toString()));
  child.stderr.on('data', (data: Buffer) => (stderr += data.toString()));
  return new Promise(resolve =>
    child.on('close', code => resolve({ code, stdout, stderr }))
  );
}

test('a revealed or externally read entry shows its use without a manual refresh', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);

  const SECRET = 'vault-e2e-secret-7Qp';
  const add = async (name: string) => {
    await panel(page).getByRole('button', { name: 'Add an entry' }).click();
    const form = page.locator('.jp-Dialog');
    await form.getByLabel('Name', { exact: true }).fill(name);
    await form.getByLabel('Username').fill('me');
    await form.getByLabel('Password', { exact: true }).fill(SECRET);
    await form.getByRole('button', { name: 'Save' }).click();
    await expect(form).toHaveCount(0);
    // The panel drops clicks while _busy, which outlasts the dialog close.
    await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
    await expect(
      panel(page).locator('.jp-PasskeyVaultPanel-rowLine', { hasText: name })
    ).toHaveCount(1);
  };
  await add('reveal/one');
  await add('agent/two');

  const row = (name: string) =>
    panel(page).locator('.jp-PasskeyVaultPanel-rowLine', { hasText: name });
  const age = (name: string) =>
    row(name).locator('.jp-PasskeyVaultPanel-rowAge');

  // Both adds are still unused, so they take the stale dim and not the recent class.
  await expect(row('reveal/one')).not.toHaveClass(/jp-mod-recentlyActive/);
  await expect(row('reveal/one')).toHaveClass(/jp-mod-stale/);
  await expect(
    row('reveal/one').locator('.jp-PasskeyVaultPanel-rowName')
  ).toHaveCSS('opacity', '0.65');

  // Create vault sent a proof just now, so the reveal window is open and the eye asks
  // nothing. Nothing below presses Refresh: the row must follow on its own.
  await row('reveal/one').click();
  const dialog = page.locator('.jp-Dialog');
  await dialog.getByRole('button', { name: 'Show password' }).click();
  await expect(dialog.getByLabel('Password', { exact: true })).toHaveValue(
    SECRET
  );
  const revealed = Date.now();
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(age('reveal/one')).toHaveText('now', { timeout: 2000 });
  await expect(row('reveal/one')).toHaveClass(/jp-mod-recentlyActive/);
  await expect(row('reveal/one')).not.toHaveClass(/jp-mod-stale/);
  const revealMs = Date.now() - revealed;

  const got = await vaultGet('agent/two');
  expect(got.code, got.stderr).toBe(0);
  expect(got.stdout.trim()).toBe(SECRET);
  const read = Date.now();
  await expect(age('agent/two')).toHaveText('now', { timeout: 20000 });
  const readMs = Date.now() - read;

  console.log(
    `reveal to row: ${revealMs} ms; CLI get to row: ${readMs} ms (poll 15000 ms)`
  );

  // The age must keep up with the clock while the panel sits open, not stay at the
  // value it was drawn with. Two minutes on, the same row reads 2m ago.
  await page.evaluate(() => {
    const now = Date.now;
    Date.now = () => now() + 120000;
  });
  await expect(age('agent/two')).toHaveText('2m ago', { timeout: 17000 });
});
