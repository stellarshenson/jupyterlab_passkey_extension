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

/** Must match playwright.config.js - the one knob that moves the server and its URL. */
const PORT = process.env.JUPYTER_TEST_PORT || '8888';
const BASE_URL = `http://localhost:${PORT}`;
const NOTIFICATIONS_URL = `${BASE_URL}/jupyterlab-notifications-extension/notifications`;

test.use({ autoGoto: false });

/**
 * Empty the server's notification queue before the test's page opens.
 *
 * The ingest handler appends every notification to a process-global store and only a
 * GET drains it. A notification left queued by an earlier test is replayed into this
 * test's fresh page at activation as a stale toast, and a toast floats over the bottom
 * of the right sidebar, where a category band sits - it swallows the band's click.
 * cli.spec.ts drains the same queue for the same reason.
 */
test.beforeEach(async () => {
  await fetch(NOTIFICATIONS_URL).catch(() => undefined);
});

/** A virtual authenticator; with `hasPrf` false, a passkey that has no PRF. */
async function addAuthenticator(page: any, hasPrf = true): Promise<void> {
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

/**
 * Close every toast on screen.
 *
 * A toast floats over the bottom of the right sidebar, over a category band, and the
 * click aimed at the band lands on the toast instead. This is the second line of
 * defence behind the queue drain: whatever toast is still there goes before the click.
 */
async function dismissToasts(page: any): Promise<void> {
  const close = page.locator('.jp-Notification-Toast-Close');
  await close.evaluateAll((buttons: HTMLElement[]) =>
    buttons.forEach(button => button.click())
  );
  await expect(close).toHaveCount(0);
}

/** A lab with no vault, a virtual authenticator, and the vault panel open. */
async function openVault(page: any, hasPrf = true): Promise<void> {
  fs.rmSync(VAULT_DIR, { recursive: true, force: true });
  await page.goto('?reset');
  await addAuthenticator(page, hasPrf);
  await page.sidebar.openTab(PANEL_ID);
  // The first read can queue behind the lab's own start-up requests - seconds in a
  // lab with many extensions installed - so it gets more than the default 5 s.
  await expect(state(page)).toHaveText('No vault', { timeout: 20000 });
}

async function submitSecret(page: any, value: string, twice: boolean) {
  const dialog = page.locator('.jp-Dialog');
  const fields = dialog.locator('input[type="password"]');
  // Typing starts in the passphrase field, not on the Submit button.
  await expect(fields.nth(0)).toBeFocused();
  // The kind of secret sets the fields: there is nothing for the user to tick.
  await expect(dialog.getByRole('checkbox')).toHaveCount(0);
  await fields.nth(0).fill(value);
  if (twice) {
    await fields.nth(1).fill(value);
  } else {
    await expect(fields.nth(1)).toBeHidden();
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
    `Passkey "${name || 'localhost'}" created - confirm it to derive the vault key`
  );
  await confirm.click();
}

/** Press a button of the choice that follows the recovery passphrase. */
async function chooseAtSetUp(page: any, choice: string): Promise<void> {
  const dialog = page.locator('.jp-Dialog');
  const button = dialog.locator(`button[data-method="${choice}"]`);
  // The choice waits for the server to create the vault; see nameAndConfirmPasskey.
  await button.waitFor({ timeout: 20000 });
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(
    'Add unlock method'
  );
  await button.click();
}

async function createVault(page: any): Promise<void> {
  await panel(page).getByRole('button', { name: 'Create vault' }).click();
  await submitSecret(page, RECOVERY, true);
  await chooseAtSetUp(page, 'passkey');
  await nameAndConfirmPasskey(page);
  // The panel is busy from the Create click until the action ends; the state text
  // changes only when the passkeys request returns, which can take longer than an
  // expect's default wait.
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true', {
    timeout: 20000
  });
  await expect(state(page)).toContainText('Unlocked');
}

/** A success: a notification that closes after 3 s, and no line in the panel. */
async function expectSuccess(page: any, text: string): Promise<void> {
  await expect(
    page.locator('.jp-toast-message', { hasText: text })
  ).toHaveCount(1);
  await expect(panel(page)).not.toContainText(text);
}

async function openCog(page: any) {
  await panel(page)
    .getByRole('button', { name: 'Vault settings and security' })
    .click();
}

/**
 * Press Add, then the kind of entry in the dialog that asks it - Password or Cookies -
 * and wait for its form.
 */
async function pressAdd(
  page: any,
  kind: 'login' | 'cookies' = 'login'
): Promise<void> {
  await panel(page).getByRole('button', { name: 'Add an entry' }).click();
  const dialog = page.locator('.jp-Dialog');
  await dialog.locator(`button[data-method="${kind}"]`).click();
  await expect(dialog.getByLabel('Name', { exact: true })).toBeVisible();
}

/**
 * An unlock method the cog view lists: a passkey, the password and authenticator app,
 * or the password and passkey.
 */
type Kind = 'passkey' | 'mfa' | 'pair';

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
  const confirm = row.getByRole('button', { name: 'Confirm' });
  // The single word on one line, inside the button, at the width of a sidebar.
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
      '.jp-PluginList-entry[data-id="@stellarshenson/jupyterlab-passkey-extension:vault"]'
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
  await pressAdd(page);
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
  // The band and a row's fill are full-bleed, so their corners are square: the
  // core .jp-ThemedContainer button rule would round them to 2px.
  expect(await style(`${C}-sectionHeader`, 'border-top-left-radius')).toBe(
    '0px'
  );
  expect(await style(`${C}-rowLine`, 'border-top-left-radius')).toBe('0px');
  expect(await style(`${C}-rowName`, 'font-weight')).toBe('400');
  // The age is small, dim and level with the status row's holder at the right end
  // of the row; the username before it.
  const [user, used, holder] = await measure([
    `${C}-rowUser`,
    `${C}-rowAge`,
    `${C}-holder`
  ]);
  expect(used[1]).toBe(holder[1]);
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

test('a folded band draws the separator, and the open section none, in both views and both themes', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  const dialog = page.locator('.jp-Dialog');
  // Three categories: the first opens, so the middle and last bands are folded;
  // both draw the separator, and the open first draws none.
  for (const [name, category] of [
    ['extra/one', 'extra'],
    ['home/one', 'home'],
    ['work/one', 'work']
  ]) {
    await pressAdd(page);
    await dialog.getByLabel('Name', { exact: true }).fill(name);
    await dialog.getByLabel('Category', { exact: true }).fill(category);
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog).toHaveCount(0);
  }
  const C = '.jp-PasskeyVaultPanel';
  await expect(panel(page).locator(`${C}-list > ${C}-section`)).toHaveCount(3);
  const filterButton = panel(page).getByRole('button', {
    name: 'Filter entries'
  });

  // Each bottom line as "width style colour", beside the lines the theme's tokens
  // draw on a temporary element: color2 the title band's rule, color3 the status
  // row's general border, layout3 the section band separator; `above` is the row
  // that stands over the first section.
  const read = (above: string) =>
    panel(page).evaluate(
      (root: HTMLElement, [prefix, aboveSelector]: string[]) => {
        const line = (node: Element) => {
          const s = getComputedStyle(node);
          return `${s.borderBottomWidth} ${s.borderBottomStyle} ${s.borderBottomColor}`;
        };
        const token = (color: string) => {
          const probe = document.createElement('div');
          probe.style.borderBottom = `var(--jp-border-width) solid var(${color})`;
          root.appendChild(probe);
          const value = line(probe);
          probe.remove();
          return value;
        };
        const at = (selector: string) =>
          root.querySelector(selector) as HTMLElement;
        const sections = Array.from(root.querySelectorAll(`${prefix}-section`));
        const list = root.querySelector(`${prefix}-list`);
        const edge = root.getBoundingClientRect();
        const row = at(aboveSelector).getBoundingClientRect();
        return {
          color2: token('--jp-border-color2'),
          color3: token('--jp-border-color3'),
          layout3: token('--jp-layout-color3'),
          title: line(at(`${prefix}-header`)),
          titleShadow: getComputedStyle(at(`${prefix}-header`)).boxShadow,
          status: line(at(`${prefix}-status`)),
          row: line(at(aboveSelector)),
          // From the panel's left and right border, and to the first section's top.
          rowEdges: [
            row.left - edge.left,
            edge.right - row.right,
            sections[0].getBoundingClientRect().top - row.bottom
          ].map(Math.round),
          sections: sections.map(line),
          sectionWidths: sections.map(
            s => getComputedStyle(s).borderBottomWidth
          ),
          sectionStyles: sections.map(
            s => getComputedStyle(s).borderBottomStyle
          ),
          sectionTops: sections.map(s => getComputedStyle(s).borderTopStyle),
          sectionShadows: sections.map(s => getComputedStyle(s).boxShadow),
          // The last section's line must sit inside the list, or the list clips it.
          lastOverflow: list
            ? Math.round(
                sections[sections.length - 1].getBoundingClientRect().bottom -
                  list.getBoundingClientRect().bottom
              )
            : null,
          // A band: four border styles and its shadow.
          bands: sections.map(s => {
            const band = getComputedStyle(
              s.querySelector(`${prefix}-sectionHeader`) as Element
            );
            return [
              band.borderTopStyle,
              band.borderRightStyle,
              band.borderBottomStyle,
              band.borderLeftStyle,
              band.boxShadow
            ].join(' ');
          })
        };
      },
      [C, above]
    );
  const check = async (view: string, above: string, list: boolean) => {
    const r = await read(above);
    const every = (value: string) => r.sections.map(() => value);
    expect(r.sections.length, view).toBeGreaterThan(1);
    expect(r.title, view).toBe(r.color2);
    expect(r.titleShadow, view).toBe('none');
    // The status row keeps its general border, and a shown filter box its own; the
    // band separator is drawn under every folded section - between two bands, and
    // under the last band at the panel's bottom edge - so only the open first
    // section draws none. The cog view has no folded viewport, so it draws none there either.
    expect(r.status, view).toBe(r.color3);
    expect(r.row, view).toBe(above === `${C}-filterBox` ? r.layout3 : r.color3);
    expect(r.rowEdges, view).toEqual([0, 0, 0]);
    expect(r.sectionWidths, view).toEqual(
      list ? ['0px', '1px', '1px'] : every('0px')
    );
    expect(r.sectionStyles, view).toEqual(
      list ? ['none', 'solid', 'solid'] : every('none')
    );
    if (list) {
      expect(r.sections[1], view).toBe(r.layout3);
      expect(r.sections[2], view).toBe(r.layout3);
      expect(r.lastOverflow, view).toBeLessThanOrEqual(0);
    }
    // No top line on a section, so two lines never touch.
    expect(r.sectionTops, view).toEqual(every('none'));
    expect(r.sectionShadows, view).toEqual(every('none'));
    expect(r.bands, view).toEqual(every('none none none none none'));
  };

  for (const theme of ['JupyterLab Light', 'JupyterLab Dark']) {
    await page.theme.setTheme(theme);
    await expect(page.locator('body')).toHaveAttribute(
      'data-jp-theme-name',
      theme
    );
    await expect(filterButton).toHaveAttribute('aria-pressed', 'false');
    await expect(panel(page).locator(`${C}-filterBox`)).toHaveCount(0);
    await check(`${theme}, list view`, `${C}-status`, true);
    await filterButton.click();
    await expect(panel(page).locator(`${C}-filterBox`)).toHaveCount(1);
    await check(`${theme}, list view with the filter`, `${C}-filterBox`, true);
    // The filter stays pressed, and the cog view shows no filter box.
    await openCog(page);
    await expect(panel(page).locator(`${C}-filterBox`)).toHaveCount(0);
    await check(`${theme}, cog view`, `${C}-status`, false);
    await openCog(page);
    await filterButton.click();
  }
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

test('set-up offers the methods after the passphrase, says why a step stopped, and Later leaves the vault open', async ({
  page
}) => {
  await openVault(page);
  await panel(page).getByRole('button', { name: 'Create vault' }).click();
  await submitSecret(page, RECOVERY, true);
  const dialog = page.locator('.jp-Dialog');
  const choices = dialog.locator('.jp-PasskeyVaultForm-choice');
  await choices.first().waitFor({ timeout: 20000 });
  await expect(choices).toHaveCount(3);
  await expect(choices.nth(0)).toContainText('Passkey');
  await expect(choices.nth(1)).toContainText('Password and authenticator app');
  await expect(choices.nth(2)).toContainText('Later');
  await expect(dialog.getByRole('button', { name: 'Cancel' })).toHaveCount(0);
  await expect(choices.nth(0)).toBeFocused();

  // A step cancelled at its naming dialog comes back here with its reason, and the
  // passphrase is not asked again.
  await chooseAtSetUp(page, 'passkey');
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog.locator('#jp-PasskeyVaultForm-note')).toHaveText(
    'Adding the passkey was cancelled.'
  );
  await expect(dialog.locator('input')).toHaveCount(0);

  // The arrow keys throw in JupyterLab's Dialog with no footer button unless kept from it.
  const thrown: string[] = [];
  page.on('pageerror', (error: Error) => thrown.push(error.message));
  await page.keyboard.press('ArrowRight');
  expect(thrown).toEqual([]);

  await chooseAtSetUp(page, 'later');
  await expect(dialog).toHaveCount(0);
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true', {
    timeout: 20000
  });
  await expect(state(page)).toContainText('Unlocked');
  await expectSuccess(page, 'Vault created');
  await expect(
    panel(page).locator('.jp-PasskeyVaultPanel-message[data-kind="error"]')
  ).toHaveCount(0);
  await openCog(page);
  await expect(method(page, 'recovery')).toHaveCount(1);
  await expect(method(page, 'passkey')).toHaveCount(0);
  await expect(method(page, 'mfa')).toHaveCount(0);
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

test('one category opens at a time, and the wheel folds to the next at its last entry', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  const dialog = page.locator('.jp-Dialog');
  // Home first, so it is the category left open when work arrives: a category with
  // matches stays open across a redraw.
  for (const [name, category] of [
    ['home/one', 'home'],
    ['work/one', 'work']
  ]) {
    await pressAdd(page);
    await dialog.getByLabel('Name', { exact: true }).fill(name);
    await dialog.getByLabel('Category', { exact: true }).fill(category);
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog).toHaveCount(0);
  }
  const C = '.jp-PasskeyVaultPanel';
  const home = panel(page).getByRole('button', { name: 'home (1)' });
  const work = panel(page).getByRole('button', { name: 'work (1)' });
  const height = async (band: any) =>
    band
      .locator('..')
      .locator(`${C}-viewport`)
      .evaluate((node: HTMLElement) => node.getBoundingClientRect().height);
  // The first category with entries takes the list; the other is its band only.
  await expect(home).toHaveAttribute('aria-expanded', 'true');
  await expect(work).toHaveAttribute('aria-expanded', 'false');
  expect(await height(home)).toBeGreaterThan(100);
  expect(await height(work)).toBe(0);
  // Both bands are inside the list: the last one's divider is not clipped.
  const listBox = (await panel(page).locator(`${C}-list`).boundingBox())!;
  const lastBand = (await work.boundingBox())!;
  expect(lastBand.y + lastBand.height).toBeLessThanOrEqual(
    listBox.y + listBox.height
  );
  // A band click opens its category, and both bands stay on screen.
  await dismissToasts(page);
  await work.click();
  await expect(home).toHaveAttribute('aria-expanded', 'false');
  await expect(work).toHaveAttribute('aria-expanded', 'true');
  expect(await height(home)).toBe(0);
  expect(await height(work)).toBeGreaterThan(100);
  await expect(home).toBeVisible();
  await expect(work).toBeVisible();
  // At the last entry the wheel previews the previous category, and a fresh gesture
  // after the wheel stops folds into it. The wheel anywhere over the panel drives the
  // open category, never the one under the pointer.
  await panel(page).hover();
  await page.mouse.wheel(0, -200);
  await page.waitForTimeout(500);
  await page.mouse.wheel(0, -200);
  await page.waitForTimeout(500);
  await page.mouse.wheel(0, -200);
  await expect(home).toHaveAttribute('aria-expanded', 'true', {
    timeout: 5000
  });
  await expect(work).toHaveAttribute('aria-expanded', 'false');
  expect(await height(home)).toBeGreaterThan(100);
  expect(await height(work)).toBe(0);
  // The open category's rows fit, so the row's right padding must keep its first age
  // level with the status row's holder at the panel's right edge.
  const [ageEdge, holderEdge] = await panel(page).evaluate(
    (root: HTMLElement) => {
      const right = (selector: string) =>
        (root.querySelector(selector) as HTMLElement).getBoundingClientRect()
          .right;
      return [
        right('.jp-PasskeyVaultPanel-rowAge'),
        right('.jp-PasskeyVaultPanel-holder')
      ];
    }
  );
  expect(Math.abs(ageEdge - holderEdge)).toBeLessThanOrEqual(1);
  // A hovered row is three quarters of the band's fill over the row's own fill, as
  // in the AI assistants panel, never the band's colour.
  const firstRow = home.locator('..').locator(`${C}-rowLine`).first();
  await firstRow.hover();
  // With no scrollbar the hovered row's fill reaches the open viewport's right edge.
  const [rowEdge, viewportEdge] = await firstRow.evaluate(
    (node: HTMLElement) => [
      node.getBoundingClientRect().right,
      (node.parentElement as HTMLElement).getBoundingClientRect().right
    ]
  );
  expect(Math.abs(rowEdge - viewportEdge)).toBeLessThanOrEqual(1);
  const hoverColour = await page.evaluate(() => {
    const probe = document.createElement('span');
    probe.style.color =
      'color-mix(in srgb, var(--jp-layout-color2) 75%, var(--jp-layout-color1))';
    document.body.appendChild(probe);
    const colour = getComputedStyle(probe).color;
    probe.remove();
    return colour;
  });
  expect(
    await firstRow.evaluate(
      (node: HTMLElement) => getComputedStyle(node).backgroundColor
    )
  ).toBe(hoverColour);
  // The entry was just added, so its age reads in the active colour.
  await expect(firstRow).toHaveClass(/jp-mod-recentlyActive/);
  const brandColour = await page.evaluate(() => {
    const probe = document.createElement('span');
    probe.style.color = 'var(--jp-brand-color1)';
    document.body.appendChild(probe);
    const colour = getComputedStyle(probe).color;
    probe.remove();
    return colour;
  });
  expect(
    await firstRow
      .locator(`${C}-rowAge`)
      .evaluate((node: HTMLElement) => getComputedStyle(node).color)
  ).toBe(brandColour);
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
  await pressAdd(page);
  const dialog = page.locator('.jp-Dialog');
  await dialog.getByLabel('Name', { exact: true }).fill('github/api');
  await dialog.getByLabel('Username').fill('me');
  await dialog.getByLabel('Password', { exact: true }).fill(SECRET);
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog).toHaveCount(0);

  const row = panel(page).locator('.jp-PasskeyVaultPanel-rowLine', {
    hasText: 'github/api'
  });
  // Adding counts as a use, so a fresh entry is not dimmed as never used.
  await expect(row).toHaveText('github/apimenow');
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
  await pressAdd(page);
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
  // An entry value has one password field, and nothing to tick.
  const password = dialog.getByLabel('Password', { exact: true });
  const save = dialog.getByRole('button', { name: 'Save' });
  await expect(password).toBeVisible();
  await expect(dialog.locator('input[type="password"]')).toHaveCount(1);
  await expect(dialog.getByRole('checkbox')).toHaveCount(0);
  await password.fill('s3cret-value');
  await save.click();

  await panel(page)
    .locator('.jp-PasskeyVaultPanel-rowLine', { hasText: 'github/api' })
    .click();
  await dialog.getByRole('button', { name: 'Edit' }).click();
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText('Edit entry');
  expect(await labels()).toEqual(addLabels);
  const name = dialog.getByLabel('Name', { exact: true });
  await expect(name).toHaveValue('github/api');
  // The name can change, which renames the entry; typing starts there.
  await expect(name).toBeEditable();
  await expect(name).toBeFocused();
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
    await pressAdd(page);
    await dialog.getByLabel('Name', { exact: true }).fill(name);
    await dialog.getByLabel('Category', { exact: true }).fill(category);
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog).toHaveCount(0);
  }

  await pressAdd(page);
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

test('a wrong recovery passphrase opens its dialog again before any browser prompt', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await openCog(page);
  await removeMethod(page, method(page, 'passkey'));
  await expect(method(page, 'passkey')).toHaveCount(0);
  const calls = await countPasskeyCalls(page);

  const dialog = page.locator('.jp-Dialog');
  await addMethod(page, 'passkey');
  await submitSecret(page, `not ${RECOVERY}`, false);
  await expect(dialog.getByText('Wrong recovery passphrase')).toBeVisible();
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText('Add passkey');
  await expect(dialog.locator('input[type="password"]').first()).toHaveValue(
    ''
  );
  expect((await calls()).create).toBe(0);

  await submitSecret(page, RECOVERY, false);
  await nameAndConfirmPasskey(page);
  await expect(method(page, 'passkey')).toHaveCount(1);
  expect((await calls()).create).toBe(1);
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
  await pressAdd(page);
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

  // The flow's first step: two password fields, and nothing to tick.
  // Submit stays off until the pair agrees and holds the 12 characters asked.
  await addMethod(page, 'mfa');
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(MFA_TITLE);
  const fields = dialog.locator('input[type="password"]');
  const submit = dialog.getByRole('button', { name: 'Submit' });
  const status = dialog.locator('.jp-PassphraseDialog-status');
  await expect(fields.nth(0)).toBeVisible();
  await expect(fields.nth(0)).toHaveAttribute('placeholder', 'Password');
  await expect(dialog.getByRole('checkbox')).toHaveCount(0);
  await expect(fields.nth(1)).toBeVisible();
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
  await expectSuccess(page, 'Password and authenticator app added');
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
  // A failure is a notification with no timeout, not a line in the panel.
  const wrong = page.locator('.jp-toast-message', { hasText: 'Wrong code.' });
  await expect(wrong).toHaveCount(1);
  await expect(panel(page)).not.toContainText('rong code');
  await expect(state(page)).toHaveText('Locked');
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
  // The step after the one that added the app: a code is accepted once. The next
  // action dismisses the notification.
  await unlock.click();
  await expect(wrong).toHaveCount(0);
  await submitSecret(page, UNLOCK_PASSWORD, false);
  await unlockCode.fill(appCode(setupKey, step + 1));
  await send.click();
  await expect(state(page)).toContainText('Unlocked');
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');

  // One Remove, in two steps, removes both; the locked view then offers neither.
  await openCog(page);
  await removeMethod(page, row);
  await expect(row).toHaveCount(0);
  await expectSuccess(page, 'Password and authenticator app removed');
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

  // Unlock with the password and a code: the app's next code, since a code is accepted
  // once.
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
  // The unlock started the reveal window, so the eye asks nothing.
  await showsAtOnce();
  // After the window the eye asks a proof.
  await endProvenMinute(page);
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
  await expectSuccess(page, 'Recovery passphrase changed');

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
  await expectSuccess(page, 'Data key rotated');
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
  expect(created()).not.toBe(before);
});

/**
 * Run the vault CLI against this suite's server, the way an agent reads a key: no
 * browser, no panel. The suite's runtime dir is already pinned by playwright.config.js,
 * so the only server `jupyter server list` shows is the test one; the lab's own
 * discovery variables must go, or the CLI would post to the developer's real lab.
 */
function vaultCli(...args: string[]): Promise<{
  code: number | null;
  stdout: string;
  stderr: string;
}> {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    // The relay the server writes: the test config sets it inside the server only.
    JUPYTERLAB_PASSKEY_RELAY_DIR: path.resolve(
      __dirname,
      '..',
      '.tmp-passkey-relay'
    ),
    JUPYTERLAB_PASSKEY_RELAY_BACKEND: 'shm',
    JUPYTER_PORT: process.env.JUPYTER_TEST_PORT || '8888'
  };
  for (const variable of ['JUPYTER_SERVER_URL', 'JUPYTERHUB_SERVICE_PREFIX']) {
    delete env[variable];
  }
  const child = spawn('jupyterlab-passkey', ['vault', ...args], { env });
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
    await pressAdd(page);
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

  // Adding counts as a use, so both rows start recent and undimmed.
  await expect(row('reveal/one')).toHaveClass(/jp-mod-recentlyActive/);
  await expect(row('reveal/one')).not.toHaveClass(/jp-mod-stale/);
  await expect(
    row('reveal/one').locator('.jp-PasskeyVaultPanel-rowName')
  ).toHaveCSS('opacity', '1');

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

  const got = await vaultCli('get', 'agent/two');
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

test('one unlock asks for the passkey once, on a double click and at the eye after it', async ({
  page
}) => {
  const SECRET = 'vault-e2e-secret-4Hs';
  await openVault(page);
  await createVault(page);
  await addEntry(page, SECRET);
  // A lock ends the reveal window that Create vault started.
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');
  const calls = await countPasskeyCalls(page);

  // The button stays in the page during the toast's exit animation, so a double click
  // reaches the command twice.
  const unlock = vaultCli('unlock');
  const press = page.locator('.jp-toast-button', { hasText: 'Unlock vault' });
  await expect(press).toHaveCount(1, { timeout: 45000 });
  await press.dblclick();
  const done = await unlock;
  expect(done.code, done.stderr).toBe(0);
  await expect(state(page)).toContainText('Unlocked', { timeout: 20000 });
  expect((await calls()).get).toBe(1);

  // The eye right after it shows the password with no second prompt.
  const dialog = page.locator('.jp-Dialog');
  await panel(page)
    .locator('.jp-PasskeyVaultPanel-rowLine', { hasText: 'github/api' })
    .click();
  await dialog.getByRole('button', { name: 'Show password' }).click();
  await expect(dialog.getByLabel('Password', { exact: true })).toHaveValue(
    SECRET
  );
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toHaveCount(0);
  expect((await calls()).get).toBe(1);

  // An unlocked vault raises no notification.
  await expect(press).toHaveCount(0, { timeout: 15000 });
  const again = await vaultCli('unlock');
  expect(again.code, again.stderr).toBe(0);
  await expect(press).toHaveCount(0);
  expect((await calls()).get).toBe(1);
});

test('an unlock notification leaves the tab once the vault is opened another way, and a press then asks nothing', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');
  // A hidden panel reads nothing of its own: the tab last read the vault locked.
  await page.sidebar.close('right');
  const calls = await countPasskeyCalls(page);

  // Its own caller: the server's notification queue can still hand this new page the
  // unlock notification of the test before, and only this CLI's own notification shows
  // that the CLI waits on a locked vault before the vault is opened.
  const unlock = vaultCli('unlock', '--caller', 'the opened-elsewhere test');
  const toast = page.locator('.Toastify__toast', {
    hasText: 'the opened-elsewhere test'
  });
  await expect(toast).toHaveCount(1, { timeout: 45000 });
  // Opened through the REST API, as a terminal or another tab would.
  expect(await post(page, 'unlock', { recovery: RECOVERY })).toBe(200);
  const done = await unlock;
  expect(done.code, done.stderr).toBe(0);

  // Within one poll of 15 s it leaves the toast and the notification list.
  await expect(toast).toHaveCount(0, { timeout: 20000 });
  await page.evaluate(() =>
    (window as any).jupyterapp.commands.execute(
      'apputils:display-notifications'
    )
  );
  await expect(page.locator('.jp-Notification-Header')).toBeVisible();
  await expect(
    page.locator('.jp-Notification-List-Item', { hasText: 'Unlock the vault' })
  ).toHaveCount(0);

  // A press now, as from a notification left in another tab, asks nothing.
  await page.evaluate(() =>
    (window as any).jupyterapp.commands.execute('passkey:vault-unlock', {})
  );
  expect(await calls()).toEqual({ create: 0, get: 0 });
  await expect(page.locator('.jp-Dialog')).toHaveCount(0);
});

test('a press on an unlock notification before the tab reads the vault opened another way reads it first and asks nothing', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');
  // A hidden panel reads nothing of its own: only the notification's poll reads.
  await page.sidebar.close('right');
  const calls = await countPasskeyCalls(page);
  const STATUS = /\/vault\/status(\?|$)/;

  const unlock = vaultCli('unlock', '--caller', 'the read-on-press test');
  const toast = page.locator('.Toastify__toast', {
    hasText: 'the read-on-press test'
  });
  await expect(toast).toHaveCount(1, { timeout: 45000 });
  // The poll reads the vault locked; the tab's next read is 15 s after it.
  await page.waitForResponse((r: any) => STATUS.test(r.url()), {
    timeout: 30000
  });
  let reads = 0;
  page.on('request', (r: any) => {
    if (STATUS.test(r.url())) {
      reads++;
    }
  });
  // Opened through the REST API, as a terminal or another tab would.
  expect(await post(page, 'unlock', { recovery: RECOVERY })).toBe(200);
  expect(reads).toBe(0);
  await toast.locator('.jp-toast-button', { hasText: 'Unlock vault' }).click();

  // The press leaves the notification at once, not at the next poll.
  await page.evaluate(() =>
    (window as any).jupyterapp.commands.execute(
      'apputils:display-notifications'
    )
  );
  await expect(page.locator('.jp-Notification-Header')).toBeVisible();
  await expect(
    page.locator('.jp-Notification-List-Item', {
      hasText: 'the read-on-press test'
    })
  ).toHaveCount(0, { timeout: 5000 });
  expect(await calls()).toEqual({ create: 0, get: 0 });
  await expect(page.locator('.jp-Dialog')).toHaveCount(0);
  const done = await unlock;
  expect(done.code, done.stderr).toBe(0);
});

test('an unlock notification answered through the dialog leaves the centre at once', async ({
  page
}) => {
  await openVault(page);
  // A vault with the recovery passphrase alone: the CLI's unlock opens the chooser.
  await panel(page).getByRole('button', { name: 'Create vault' }).click();
  await submitSecret(page, RECOVERY, true);
  await chooseAtSetUp(page, 'later');
  await expect(state(page)).toContainText('Unlocked', { timeout: 20000 });
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');

  const unlock = vaultCli('unlock', '--caller', 'the centre test');
  const toast = page.locator('.Toastify__toast', {
    hasText: 'the centre test'
  });
  await expect(toast).toHaveCount(1, { timeout: 45000 });
  await toast.locator('.jp-toast-button', { hasText: 'Unlock vault' }).click();

  // Answer it the long way: the chooser, then the recovery passphrase.
  const dialog = page.locator('.jp-Dialog');
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText('Unlock vault');
  await dialog.locator('button[data-method="recovery"]').click();
  await submitSecret(page, RECOVERY, false);
  const done = await unlock;
  expect(done.code, done.stderr).toBe(0);
  await expect(dialog).toHaveCount(0);

  // Not at the panel's 15 s poll nor the server's 30 s one: 2 s is all the wait.
  await page.evaluate(() =>
    (window as any).jupyterapp.commands.execute(
      'apputils:display-notifications'
    )
  );
  await expect(page.locator('.jp-Notification-Header')).toBeVisible();
  await expect(
    page.locator('.jp-Notification-List-Item', {
      hasText: 'the centre test'
    })
  ).toHaveCount(0, { timeout: 2000 });
});

test('the Vault unlocked toast leaves no centre row, by its close button or its 3 s autoClose', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');

  // Opened through the REST API, as a terminal or another tab would: the panel's next
  // poll reads the locked -> unlocked edge and raises the toast.
  expect(await post(page, 'unlock', { recovery: RECOVERY })).toBe(200);
  const toast = page.locator('.Toastify__toast', {
    hasText: 'Vault unlocked'
  });
  await expect(toast).toHaveCount(1, { timeout: 30000 });
  // Raised transient with a 3 s autoClose: no press, and gone inside the 5 s check.
  await expect(toast).toHaveCount(0, { timeout: 5000 });

  // A second edge, this time ended by the toast's own close button.
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');
  expect(await post(page, 'unlock', { recovery: RECOVERY })).toBe(200);
  await expect(toast).toHaveCount(1, { timeout: 30000 });
  await toast.locator('.jp-Notification-Toast-Close').click();
  await expect(toast).toHaveCount(0);

  // Either way, the transient row is not in the notification centre.
  await page.evaluate(() =>
    (window as any).jupyterapp.commands.execute(
      'apputils:display-notifications'
    )
  );
  await expect(page.locator('.jp-Notification-Header')).toBeVisible();
  await expect(
    page.locator('.jp-Notification-List-Item', { hasText: 'Vault unlocked' })
  ).toHaveCount(0);
});

/**
 * Count, from now on, the page's toasts whose text holds `text`, each once by its
 * notification id: a toast closes after 3 s, so two raised seconds apart are never on
 * screen together. Run in the page.
 */
function countToasts(text: string): void {
  const seen = new Set<string>();
  (window as any).passkeyToastIds = seen;
  new MutationObserver(() =>
    document.querySelectorAll('.Toastify__toast').forEach(toast => {
      if (toast.textContent?.includes(text)) {
        seen.add(toast.id);
      }
    })
  ).observe(document, { childList: true, subtree: true });
}

function toastCount(tab: any): Promise<number> {
  return tab.evaluate(() => (window as any).passkeyToastIds.size);
}

/**
 * A second tab of the same lab in the page's browser context, counting the toasts that
 * hold `text` from its start, once its notifications stream is connected: a
 * notification posted to the ingest reaches an open tab through that stream.
 */
async function secondTab(page: any, text: string): Promise<any> {
  const tab = await page.context().newPage();
  await tab.addInitScript(countToasts, text);
  const stream = tab.waitForEvent('websocket', (socket: any) =>
    socket.url().includes('jupyterlab-notifications-extension/stream')
  );
  await tab.goto(`${BASE_URL}/lab`);
  await stream;
  await tab
    .locator(`.lm-TabBar-tab[data-id="${PANEL_ID}"]`)
    .waitFor({ timeout: 30000 });
  return tab;
}

test('one unlock shows one Vault unlocked toast in each of two tabs', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');
  const tab = await secondTab(page, 'Vault unlocked');
  const other = tab.locator(`#${PANEL_ID}`);
  if (!(await other.isVisible())) {
    await tab.locator(`.lm-TabBar-tab[data-id="${PANEL_ID}"]`).click();
  }
  const otherState = other.locator('.jp-PasskeyVaultPanel-stateText');
  await expect(otherState).toHaveText('Locked', { timeout: 20000 });
  await page.evaluate(countToasts, 'Vault unlocked');

  await panel(page)
    .getByRole('button', { name: 'Use recovery passphrase' })
    .click();
  await submitSecret(page, RECOVERY, false);
  await expect(state(page)).toContainText('Unlocked');
  // The second tab reads the change at its Refresh, not up to 15 s later at its poll.
  await other.getByRole('button', { name: 'Refresh' }).click();
  await expect(otherState).toContainText('Unlocked');
  await expect.poll(() => toastCount(page)).toBeGreaterThan(0);
  await expect.poll(() => toastCount(tab)).toBeGreaterThan(0);
  // A toast posted by the other tab comes through the stream well inside this wait.
  await page.waitForTimeout(2000);
  // Each tab raises its own from the edge it reads, and shows no other tab's.
  expect(await toastCount(page)).toBe(1);
  expect(await toastCount(tab)).toBe(1);
  await tab.close();
});

test('a panel success shows only in the tab that did it', async ({ page }) => {
  await openVault(page);
  await createVault(page);
  const tab = await secondTab(page, 'Recovery passphrase changed');
  await page.evaluate(countToasts, 'Recovery passphrase changed');

  await openCog(page);
  await panel(page)
    .getByRole('button', { name: 'Change recovery passphrase' })
    .click();
  await submitSecret(page, 'a brand new recovery passphrase', true);
  await expectSuccess(page, 'Recovery passphrase changed');
  // A toast posted to the ingest reaches the other tab through the stream well inside
  // this wait.
  await page.waitForTimeout(2000);
  expect(await toastCount(page)).toBe(1);
  expect(await toastCount(tab)).toBe(0);
  await tab.close();
});

/** Count the page's passkey requests from here on: `create` and `get`. */
async function countPasskeyCalls(page: any): Promise<() => Promise<any>> {
  await page.evaluate(() => {
    const credentials = navigator.credentials;
    const create = credentials.create.bind(credentials);
    const get = credentials.get.bind(credentials);
    const calls = ((window as any).passkeyCalls = { create: 0, get: 0 });
    credentials.create = (options?: CredentialCreationOptions) => {
      calls.create++;
      return create(options);
    };
    credentials.get = (options?: CredentialRequestOptions) => {
      calls.get++;
      return get(options);
    };
  });
  return () => page.evaluate(() => ({ ...(window as any).passkeyCalls }));
}

const PAIR_PASSWORD = 'a password for the passkey';

/** Create the vault with a passkey that has no PRF: the offer of Password and passkey. */
async function createWithNoPrf(page: any): Promise<void> {
  await panel(page).getByRole('button', { name: 'Create vault' }).click();
  await submitSecret(page, RECOVERY, true);
  await chooseAtSetUp(page, 'passkey');
  await nameAndConfirmPasskey(page);
  const dialog = page.locator('.jp-Dialog');
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(
    'Add password and passkey',
    { timeout: 20000 }
  );
  await expect(dialog).toContainText(
    'No PRF: the passkey cannot hold the vault key.'
  );
}

/** A vault request sent by the page itself, outside the panel: its status. */
function post(page: any, action: string, body: unknown): Promise<number> {
  return page.evaluate(
    ({ action, body }: any) =>
      fetch(`/jupyterlab-passkey-extension/vault/${action}`, {
        method: 'POST',
        body: JSON.stringify(body)
      }).then(r => r.status),
    { action, body }
  );
}

test('a passkey with no PRF becomes Password and passkey: one create and one get, an unlock with one get, the eye, and Remove', async ({
  page
}) => {
  const SECRET = 'vault-e2e-secret-pair-3Qz';
  await openVault(page, false);
  const calls = await countPasskeyCalls(page);
  const dialog = page.locator('.jp-Dialog');
  await createWithNoPrf(page);
  await dialog.getByRole('button', { name: 'Continue' }).click();
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(
    'Add password and passkey'
  );
  const [added] = await Promise.all([
    page.waitForRequest(/\/vault\/password-passkey(\?|$)/),
    submitSecret(page, PAIR_PASSWORD, true)
  ]);
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true', {
    timeout: 20000
  });
  await expect(state(page)).toContainText('Unlocked');
  // The get that found no PRF is the signature the server checked: no third prompt.
  expect(await calls()).toEqual({ create: 1, get: 1 });
  // The server ran the registration steps on Chromium's create and took the public
  // key from it: the page sends no key of its own. Both prompts signed one challenge.
  const registered = added.postDataJSON();
  expect(registered).not.toHaveProperty('public_key');
  expect(Object.keys(registered.registration).sort()).toEqual([
    'attestation_object',
    'client_data'
  ]);
  const client = (data: string) =>
    JSON.parse(Buffer.from(data, 'base64url').toString());
  expect(client(registered.registration.client_data).type).toBe(
    'webauthn.create'
  );
  expect(client(registered.registration.client_data).challenge).toBe(
    client(registered.assertion.client_data).challenge
  );
  await openCog(page);
  await expect(method(page, 'pair')).toHaveCount(1);
  await expect(method(page, 'pair')).toContainText('Password and passkey');
  await expect(method(page, 'passkey')).toHaveCount(0);
  await openCog(page);
  await addEntry(page, SECRET);

  // An unlock: the password, then the passkey, in one request with no PRF. The
  // challenge is read before the password dialog, whose Submit leads to the passkey
  // with no dialog between.
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');
  const unlock = panel(page).getByRole('button', {
    name: 'Unlock with password and passkey'
  });
  await Promise.all([
    page.waitForRequest(/\/vault\/challenge(\?|$)/),
    unlock.click()
  ]);
  const [request] = await Promise.all([
    page.waitForRequest(/\/vault\/unlock(\?|$)/),
    submitSecret(page, PAIR_PASSWORD, false)
  ]);
  const sent = request.postDataJSON();
  expect(Object.keys(sent).sort()).toEqual(['assertion', 'password']);
  expect(Object.keys(sent.assertion).sort()).toEqual([
    'authenticator_data',
    'client_data',
    'cred_id',
    'signature'
  ]);
  await expect(state(page)).toContainText('Unlocked');
  expect(await calls()).toEqual({ create: 1, get: 2 });

  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');

  // A wrong password: the passkey is asked, the server refuses, the vault stays locked.
  await unlock.click();
  await submitSecret(page, `not ${PAIR_PASSWORD}`, false);
  // In the panel's line or a notification, whichever reports the failure.
  await expect(page.getByText('wrong unlock password').first()).toBeVisible();
  await expect(state(page)).toHaveText('Locked');

  // After the reveal window of an unlock, the eye proves with this passkey.
  await unlock.click();
  await submitSecret(page, PAIR_PASSWORD, false);
  await expect(state(page)).toContainText('Unlocked');
  await endProvenMinute(page);
  const before = (await calls()).get;
  await panel(page)
    .locator('.jp-PasskeyVaultPanel-rowLine', { hasText: 'github/api' })
    .click();
  const [reveal] = await Promise.all([
    page.waitForRequest(REVEAL),
    dialog.getByRole('button', { name: 'Show password' }).click()
  ]);
  expect(Object.keys(reveal.postDataJSON()).sort()).toEqual([
    'assertion',
    'name'
  ]);
  await expect(dialog.getByLabel('Password', { exact: true })).toHaveValue(
    SECRET
  );
  expect((await calls()).get).toBe(before + 1);
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toHaveCount(0);

  // Remove, in two steps, after a recovery unlock: the button is gone.
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await panel(page)
    .getByRole('button', { name: 'Use recovery passphrase' })
    .click();
  await submitSecret(page, RECOVERY, false);
  await expect(state(page)).toContainText('Unlocked');
  await openCog(page);
  await removeMethod(page, method(page, 'pair'));
  await expect(method(page, 'pair')).toHaveCount(0);
  await panel(page).getByRole('button', { name: 'Lock the vault' }).click();
  await expect(state(page)).toHaveText('Locked');
  await expect(unlock).toHaveCount(0);
});

test('a declined Password and passkey stores nothing, names the ways in, and names the passkey unused where the browser cannot remove it', async ({
  page
}) => {
  await openVault(page, false);
  // A browser with no removal request: the line names the passkey to delete.
  await page.evaluate(() =>
    Object.defineProperty(PublicKeyCredential, 'signalUnknownCredential', {
      value: undefined,
      configurable: true
    })
  );
  const dialog = page.locator('.jp-Dialog');
  await createWithNoPrf(page);
  await dialog.getByRole('button', { name: 'Decline' }).click();
  await expect(dialog.locator('#jp-PasskeyVaultForm-note')).toHaveText(
    /^No PRF - passkey not added; use another passkey or Password and authenticator app; delete the unused passkey dated \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC\.$/,
    { timeout: 20000 }
  );
  await chooseAtSetUp(page, 'later');
  await expect(dialog).toHaveCount(0);
  await openCog(page);
  await expect(method(page, 'pair')).toHaveCount(0);
  await expect(method(page, 'passkey')).toHaveCount(0);
});

test('a passkey with no PRF declined in the cog view is an amber notification that names the ways in, and the browser is asked to remove it', async ({
  page
}) => {
  await openVault(page, false);
  await panel(page).getByRole('button', { name: 'Create vault' }).click();
  await submitSecret(page, RECOVERY, true);
  await chooseAtSetUp(page, 'later');
  const dialog = page.locator('.jp-Dialog');
  await expect(dialog).toHaveCount(0);
  await expect(state(page)).toContainText('Unlocked', { timeout: 20000 });
  // Record each passkey the page creates, and take its removal requests in place of the browser.
  await page.evaluate(() => {
    const record = ((window as any).passkeyRemoval = {
      created: [] as string[],
      asked: [] as unknown[]
    });
    const credentials = navigator.credentials;
    const create = credentials.create.bind(credentials);
    credentials.create = async (options?: CredentialCreationOptions) => {
      const made = (await create(options)) as PublicKeyCredential;
      record.created.push(made.id);
      return made;
    };
    Object.defineProperty(PublicKeyCredential, 'signalUnknownCredential', {
      value: async (request: unknown) => {
        record.asked.push(request);
      },
      configurable: true
    });
  });
  const removal = () => page.evaluate(() => (window as any).passkeyRemoval);

  await openCog(page);
  await addMethod(page, 'passkey');
  // This host has no passkey yet: the recovery passphrase is the proof.
  await submitSecret(page, RECOVERY, false);
  await nameAndConfirmPasskey(page);
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText(
    'Add password and passkey',
    { timeout: 20000 }
  );
  await dialog.getByRole('button', { name: 'Decline' }).click();
  await expect(dialog).toHaveCount(0);

  // The browser took the removal request, so the line names no passkey to delete.
  const toast = page.locator('.Toastify__toast', {
    hasText: 'Passkey not added'
  });
  await expect(toast).toHaveCount(1, { timeout: 20000 });
  await expect(toast).toHaveClass(/jp-Notification-Toast-warning/);
  await expect(toast.locator('.jp-toast-message')).toContainText(
    'No PRF - passkey not added; use another passkey or Password and authenticator app.'
  );
  const { created, asked } = await removal();
  expect(created).toHaveLength(1);
  expect(asked).toEqual([{ rpId: 'localhost', credentialId: created[0] }]);

  // No line in the panel, in the cog view or the list; the notification stays.
  const line = panel(page).locator('.jp-PasskeyVaultPanel-message');
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
  await expect(line).toHaveCount(0);
  await openCog(page);
  await expect(line).toHaveCount(0);
  await panel(page).getByRole('button', { name: 'Refresh' }).click();
  await expect(line).toHaveCount(0);
  await expect(toast).toHaveCount(1);
  await openCog(page);
  await expect(method(page, 'passkey')).toHaveCount(0);
  await expect(method(page, 'pair')).toHaveCount(0);

  // The next action dismisses it.
  await addMethod(page, 'passkey');
  await expect(toast).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toHaveCount(0);
});

// --------------------------------------------------------------------------- //
// cookie entries and rename
// --------------------------------------------------------------------------- //

/** A cookie value no page and no CLI output may show. */
const COOKIE_MARKER = 'fake-sid-7Qp';

/** A Copy as cURL of one request carrying two cookies of shop.example.com. */
const CURL = `curl 'https://shop.example.com/cart' -H 'Cookie: sid=${COOKIE_MARKER}; theme=fake-theme-2Hs'`;

/** A header value no page may show. */
const HEADER_MARKER = 'fake-hdr-9Zk';

/** A Copy as cURL with two cookies, two headers the entry keeps and two of the browser's own. */
const CURL_HEADERS = `curl 'https://app.example.com/api/items' -H 'accept: application/json' -H 'authorization: Bearer ${HEADER_MARKER}' -b 'sid=${COOKIE_MARKER}; tok=fake-tok-2Hs' -H 'user-agent: Mozilla/5.0' -H 'x-csrf-token: ${HEADER_MARKER}-csrf'`;

/** A Copy as cURL with one header the entry keeps and no cookie. */
const CURL_NO_COOKIE = `curl 'https://api.example.com/v1/me' -H 'accept: application/json' -H 'Authorization: Bearer ${HEADER_MARKER}'`;

/** One cookies.txt line: domain, subdomains, path, secure, expiry (0: session), name, value. */
const jarLine = (domain: string, expires: number, name: string) =>
  [
    domain,
    'FALSE',
    '/',
    'FALSE',
    String(expires),
    name,
    `fake-${name}-4Hs`
  ].join('\t');

/** 2100-01-01 and 2001-09-09, in Unix seconds. */
const FUTURE = 4102444800;
const PAST = 1000000000;

/** The entries as GET vault/entries answers them: the type, and per cookie never a value. */
function listed(page: any): Promise<any[]> {
  return page.evaluate(() =>
    fetch('/jupyterlab-passkey-extension/vault/entries')
      .then(r => r.json())
      .then(d => d.entries)
  );
}

/** Add an entry through POST vault/entries, then read the panel again. */
async function addByRest(page: any, name: string, fields: unknown) {
  expect(await post(page, 'entries', { name, fields })).toBe(204);
  await panel(page).getByRole('button', { name: 'Refresh' }).click();
  await expect(
    panel(page).locator('.jp-PasskeyVaultPanel-rowLine', { hasText: name })
  ).toHaveCount(1);
}

function entryRow(page: any, name: string) {
  return panel(page).locator('.jp-PasskeyVaultPanel-rowLine', {
    hasText: name
  });
}

test('Add asks the kind of entry: Password and Cookies with one line each, and Cancel', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await panel(page).getByRole('button', { name: 'Add an entry' }).click();
  const dialog = page.locator('.jp-Dialog');
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText('Add entry');
  const choices = dialog.locator('.jp-PasskeyVaultForm-choice');
  await expect(choices).toHaveCount(2);
  await expect(choices.nth(0)).toHaveAccessibleName('Password');
  await expect(choices.nth(0)).toContainText(
    'A username and a password for a site.'
  );
  await expect(choices.nth(1)).toHaveAccessibleName('Cookies');
  await expect(choices.nth(1)).toContainText(
    'Cookies and request headers of a browser session, pasted.'
  );
  // Cancel is the dialog's only other button.
  await expect(dialog.locator('.jp-Dialog-footer button')).toHaveText([
    'Cancel'
  ]);
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');

  // Password opens the password form, Cookies the paste field.
  await pressAdd(page, 'login');
  await expect(dialog.getByLabel('Password', { exact: true })).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await pressAdd(page, 'cookies');
  await expect(dialog.getByLabel('Cookies', { exact: true })).toBeVisible();
  await expect(dialog.locator('input[type="password"]')).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Cancel' }).click();
});

test('the cookie form reads the paste before Save, shows no value, and saves the entry', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await pressAdd(page, 'cookies');
  const dialog = page.locator('.jp-Dialog');
  expect(
    await dialog.locator('.jp-PasskeyVaultForm-label').allInnerTexts()
  ).toEqual(['Name', 'Username', 'URL', 'Cookies', 'Category', 'Notes']);
  const save = dialog.getByRole('button', { name: 'Save' });
  const paste = dialog.getByLabel('Cookies', { exact: true });
  await dialog.getByLabel('Name', { exact: true }).fill('shop/session');
  await expect(save).toBeDisabled();

  // A Cookie header has no domain without the URL: the reason, and Save stays off.
  await paste.fill(`sid=${COOKIE_MARKER}`);
  await expect(dialog).toContainText(
    "No cookie was read: Cookie header line 1: no domain - give the site's url in the URL field"
  );
  await expect(save).toBeDisabled();
  // The URL gives it the domain: the paste is read again.
  await dialog.getByLabel('URL').fill('https://shop.example.com');
  await expect(dialog).toContainText(
    '1 cookie read, from shop.example.com: sid'
  );
  await expect(save).toBeEnabled();

  // Cookies that have all expired: the line says so, and Save stays off.
  await paste.fill(jarLine('shop.example.com', PAST, 'old'));
  await expect(dialog).toContainText(
    '1 cookie read, all expired - copy the cookies again from the browser'
  );
  await expect(save).toBeDisabled();
  // A copied request with a header to keep and no cookie: Save is on.
  await paste.fill(CURL_NO_COOKIE);
  await expect(dialog).toContainText('0 cookies read; 1 header: Authorization');
  await expect(save).toBeEnabled();
  expect(await dialog.innerHTML()).not.toContain(HEADER_MARKER);

  await paste.fill(CURL);
  await expect(dialog).toContainText(
    '2 cookies read, from shop.example.com: sid, theme'
  );
  await expect(save).toBeEnabled();
  // The paste is the field's value only: no text or attribute of the dialog holds it.
  expect(await dialog.innerHTML()).not.toContain(COOKIE_MARKER);
  await save.click();
  await expect(dialog).toHaveCount(0);
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
  await expect(entryRow(page, 'shop/session')).toHaveCount(1);

  const shop = (await listed(page)).find(e => e.name === 'shop/session');
  expect(shop.type).toBe('cookies');
  expect(shop.url).toBe('https://shop.example.com');
  expect(shop.cookies.map((c: any) => c.name)).toEqual(['sid', 'theme']);
  expect(JSON.stringify(shop)).not.toContain(COOKIE_MARKER);
});

test("a cookie entry's row has the cookie icon, and an expired jar the expired badge", async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await addByRest(page, 'site/login', { password: 'vault-e2e-secret-9Lm' });
  await addByRest(page, 'shop/live', {
    type: 'cookies',
    cookies: [
      jarLine('shop.example.com', FUTURE, 'sid'),
      jarLine('shop.example.com', PAST, 'old')
    ].join('\n')
  });
  // The server refuses a jar whose every cookie has expired: this one expires after
  // it is stored.
  await addByRest(page, 'shop/expired', {
    type: 'cookies',
    cookies: jarLine(
      'old.example.com',
      Math.floor(Date.now() / 1000) + 5,
      'sid'
    )
  });

  const ICON = '.jp-PasskeyVaultPanel-rowIcon';
  const BADGE = '.jp-PasskeyVault-expired';
  await expect(entryRow(page, 'shop/live').locator(ICON)).toHaveCount(1);
  await expect(entryRow(page, 'shop/expired').locator(ICON)).toHaveCount(1);
  await expect(entryRow(page, 'site/login').locator(ICON)).toHaveCount(0);
  // One unexpired cookie is left in the live jar: no badge.
  await expect(entryRow(page, 'shop/live').locator(BADGE)).toHaveCount(0);
  await expect(entryRow(page, 'site/login').locator(BADGE)).toHaveCount(0);
  // A list read draws the rows again, and the badge once the cookie has expired.
  await expect(async () => {
    await panel(page).getByRole('button', { name: 'Refresh' }).click();
    await expect(entryRow(page, 'shop/expired').locator(BADGE)).toHaveText(
      'expired',
      { timeout: 1000 }
    );
  }).toPass({ timeout: 30000 });
  await expect(entryRow(page, 'shop/expired').locator(BADGE)).toHaveCSS(
    'text-transform',
    'uppercase'
  );

  // The icon sits in the status dot's column: every name starts on the 18px text
  // column, and every row keeps its 24px.
  const nameX = async (name: string) =>
    (await entryRow(page, name)
      .locator('.jp-PasskeyVaultPanel-rowName')
      .boundingBox())!.x;
  const panelX = (await panel(page).boundingBox())!.x;
  for (const name of ['site/login', 'shop/live', 'shop/expired']) {
    expect(Math.round((await nameX(name)) - panelX)).toBe(18);
    expect((await entryRow(page, name).boundingBox())!.height).toBe(24);
  }
  const icon = (await entryRow(page, 'shop/live').locator(ICON).boundingBox())!;
  expect(icon.x - panelX).toBeGreaterThanOrEqual(4);
  expect(icon.x + icon.width - panelX).toBeLessThanOrEqual(18);
});

test('the expired tag and the cookie table header keep a 4.5:1 contrast in the Light and the Dark theme', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  // Two cookies past their expiry and one that expires after the jar is stored: the
  // row then has the tag, and so have an odd and an even row of the table.
  await addByRest(page, 'shop/expired', {
    type: 'cookies',
    cookies: [
      jarLine('old.example.com', PAST, 'first'),
      jarLine('old.example.com', PAST, 'second'),
      jarLine('old.example.com', Math.floor(Date.now() / 1000) + 5, 'third')
    ].join('\n')
  });
  const refresh = panel(page).getByRole('button', { name: 'Refresh' });
  const row = entryRow(page, 'shop/expired');
  const tag = row.locator('.jp-PasskeyVault-expired');
  await expect(async () => {
    await refresh.click();
    await expect(tag).toHaveCount(1, { timeout: 1000 });
  }).toPass({ timeout: 30000 });

  /** The WCAG contrast ratio of a node's text colour on what is painted behind it. */
  const contrast = (node: Element): number => {
    // One canvas pixel: white, then every background from the page down to the node,
    // then the text colour. The canvas resolves any CSS colour and blends its alpha.
    const context = document.createElement('canvas').getContext('2d')!;
    const luminance = (colour: string): number => {
      context.fillStyle = colour;
      context.fillRect(0, 0, 1, 1);
      const [r, g, b] = Array.from(context.getImageData(0, 0, 1, 1).data)
        .slice(0, 3)
        .map(value => {
          const c = value / 255;
          return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
        });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const chain: Element[] = [];
    for (let n: Element | null = node; n; n = n.parentElement) {
      chain.unshift(n);
    }
    let behind = luminance('#fff');
    for (const n of chain) {
      behind = luminance(getComputedStyle(n).backgroundColor);
    }
    const text = luminance(getComputedStyle(node).color);
    return (Math.max(text, behind) + 0.05) / (Math.min(text, behind) + 0.05);
  };

  for (const theme of ['JupyterLab Light', 'JupyterLab Dark']) {
    await page.theme.setTheme(theme);
    await expect(page.locator('body')).toHaveAttribute(
      'data-jp-theme-name',
      theme
    );
    // The pointer and the focus are off the row; no read replaces it meanwhile.
    await refresh.hover();
    await refresh.focus();
    expect(
      await tag.evaluate(contrast),
      `${theme}, the tag on a row at rest`
    ).toBeGreaterThanOrEqual(4.5);
    await row.focus();
    expect(
      await tag.evaluate(contrast),
      `${theme}, the tag on the row in focus`
    ).toBeGreaterThanOrEqual(4.5);
    await row.hover();
    expect(
      await tag.evaluate(contrast),
      `${theme}, the tag on a hovered row`
    ).toBeGreaterThanOrEqual(4.5);

    await row.click();
    const dialog = page.locator('.jp-Dialog');
    const tags = dialog.locator('table .jp-PasskeyVault-expired');
    await expect(tags).toHaveCount(3);
    for (const index of [0, 1]) {
      expect(
        await tags.nth(index).evaluate(contrast),
        `${theme}, the tag in table row ${index + 1}`
      ).toBeGreaterThanOrEqual(4.5);
    }
    expect(
      await dialog.locator('table th').first().evaluate(contrast),
      `${theme}, the table header`
    ).toBeGreaterThanOrEqual(4.5);
    await dialog.getByRole('button', { name: 'Close' }).click();
    await expect(dialog).toHaveCount(0);
  }
});

test('a cookie entry opens with a table of domain, name and expiry, no value and no eye', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await addByRest(page, 'shop/session', {
    type: 'cookies',
    url: 'https://shop.example.com',
    cookies: [
      jarLine('shop.example.com', 0, 'sid'),
      jarLine('example.com', FUTURE, 'theme'),
      jarLine('example.com', PAST, 'old')
    ].join('\n')
  });
  await entryRow(page, 'shop/session').click();
  const dialog = page.locator('.jp-Dialog');
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText('shop/session');
  await expect(dialog.locator('table th')).toHaveText([
    'Domain',
    'Name',
    'Expires'
  ]);
  const rows = dialog.locator('table tbody tr');
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(0).locator('td')).toHaveText([
    'shop.example.com',
    'sid',
    'session'
  ]);
  await expect(rows.nth(1).locator('td')).toHaveText([
    'example.com',
    'theme',
    '2100-01-01 00:00 UTC'
  ]);
  await expect(rows.nth(2).locator('td')).toHaveText([
    'example.com',
    'old',
    '2001-09-09 01:46 UTC expired'
  ]);
  await expect(rows.nth(2).locator('.jp-PasskeyVault-expired')).toHaveCount(1);
  await expect(rows.nth(1).locator('.jp-PasskeyVault-expired')).toHaveCount(0);
  // The panel's 24px rows.
  expect((await rows.nth(0).boundingBox())!.height).toBe(24);
  // No eye, no password field, no value.
  await expect(dialog.locator('.jp-PasskeyVaultForm-eye')).toHaveCount(0);
  await expect(
    dialog.getByRole('button', { name: 'Show password' })
  ).toHaveCount(0);
  await expect(dialog.locator('input[type="password"]')).toHaveCount(0);
  expect(await dialog.innerHTML()).not.toContain('fake-');
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toHaveCount(0);
});

test('the cookie form names the kept headers beside the cookies, never a value, and saves a copy with a header and no cookie', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await pressAdd(page, 'cookies');
  const dialog = page.locator('.jp-Dialog');
  const save = dialog.getByRole('button', { name: 'Save' });
  const paste = dialog.getByLabel('Cookies', { exact: true });
  await dialog.getByLabel('Name', { exact: true }).fill('api/token');

  // The count and the names of the headers kept, after the cookie summary; the
  // browser's own headers are not among them.
  await paste.fill(CURL_HEADERS);
  await expect(dialog).toContainText(
    '2 cookies read, from app.example.com: sid, tok; 2 headers: authorization, x-csrf-token'
  );
  await expect(save).toBeEnabled();
  // The paste is the field's value only: no text or attribute of the dialog holds it.
  expect(await dialog.innerHTML()).not.toContain(HEADER_MARKER);
  expect(await dialog.innerHTML()).not.toContain(COOKIE_MARKER);

  // A header and no cookie: Save is on, and the entry is stored with no cookie.
  await paste.fill(CURL_NO_COOKIE);
  await expect(dialog).toContainText('0 cookies read; 1 header: Authorization');
  await expect(save).toBeEnabled();
  expect(await dialog.innerHTML()).not.toContain(HEADER_MARKER);
  await save.click();
  await expect(dialog).toHaveCount(0);
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
  await expect(entryRow(page, 'api/token')).toHaveCount(1);

  const token = (await listed(page)).find(e => e.name === 'api/token');
  expect(token.type).toBe('cookies');
  // The URL field was empty: the entry has the origin of the copied request.
  expect(token.url).toBe('https://api.example.com/');
  expect(token.cookies).toEqual([]);
  expect(token.headers).toEqual(['Authorization']);
  expect(JSON.stringify(token)).not.toContain(HEADER_MARKER);
  expect(await inPage(page, HEADER_MARKER)).toBe(false);
});

test('a cookie entry opens with the kept header names under the cookie table, no value and no eye; one with no cookie has no cookie table and no expired badge', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await addByRest(page, 'app/session', {
    type: 'cookies',
    cookies: CURL_HEADERS
  });
  await addByRest(page, 'api/token', {
    type: 'cookies',
    cookies: CURL_NO_COOKIE
  });
  const dialog = page.locator('.jp-Dialog');
  const tables = dialog.locator('table');
  const headers = dialog.getByRole('table', { name: 'Headers' });
  const noValue = async () => {
    await expect(dialog.locator('.jp-PasskeyVaultForm-eye')).toHaveCount(0);
    await expect(
      dialog.getByRole('button', { name: 'Show password' })
    ).toHaveCount(0);
    await expect(dialog.locator('input[type="password"]')).toHaveCount(0);
    expect(await dialog.innerHTML()).not.toContain('fake-');
    expect(await inPage(page, HEADER_MARKER)).toBe(false);
  };

  await entryRow(page, 'app/session').click();
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText('app/session');
  expect(
    await dialog.locator('.jp-PasskeyVaultForm-label').allInnerTexts()
  ).toEqual([
    'Name',
    'Username',
    'URL',
    'Cookies',
    'Headers',
    'Category',
    'Notes'
  ]);
  // The header table is the second one, under the cookie table.
  await expect(tables).toHaveCount(2);
  await expect(tables.nth(0)).toHaveAttribute('aria-label', 'Cookies');
  await expect(tables.nth(1)).toHaveAttribute('aria-label', 'Headers');
  await expect(headers.locator('th')).toHaveText(['Name']);
  await expect(headers.locator('tbody td')).toHaveText([
    'authorization',
    'x-csrf-token'
  ]);
  // The cookie table's look: the panel's 24px rows and the text colour of its cells.
  const headerCell = headers.locator('tbody td').nth(0);
  const cookieCell = tables.nth(0).locator('tbody td').nth(0);
  expect((await headers.locator('tbody tr').nth(0).boundingBox())!.height).toBe(
    24
  );
  for (const property of ['color', 'font-size', 'padding-left']) {
    const value = await cookieCell.evaluate(
      (node: Element, p: string) => getComputedStyle(node).getPropertyValue(p),
      property
    );
    await expect(headerCell).toHaveCSS(property, value);
  }
  await noValue();
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toHaveCount(0);

  // No cookie: the cookie icon of the type, no expired badge, and no cookie table.
  const row = entryRow(page, 'api/token');
  await expect(row.locator('.jp-PasskeyVaultPanel-rowIcon')).toHaveCount(1);
  await expect(row.locator('.jp-PasskeyVault-expired')).toHaveCount(0);
  await expect(row).toHaveAttribute(
    'aria-label',
    /^api\/token, cookies, (last|never) used/
  );
  await row.click();
  await expect(dialog.locator('.jp-Dialog-header')).toHaveText('api/token');
  expect(
    await dialog.locator('.jp-PasskeyVaultForm-label').allInnerTexts()
  ).toEqual(['Name', 'Username', 'URL', 'Headers', 'Category', 'Notes']);
  await expect(tables).toHaveCount(1);
  await expect(headers.locator('tbody td')).toHaveText(['Authorization']);
  await expect(dialog.locator('.jp-PasskeyVault-expired')).toHaveCount(0);
  await noValue();
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toHaveCount(0);
});

test('Edit of a cookie entry keeps the jar with an empty paste, and a paste that reads replaces it', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await addByRest(page, 'shop/session', {
    type: 'cookies',
    url: 'https://shop.example.com',
    cookies: [
      jarLine('shop.example.com', FUTURE, 'sid'),
      jarLine('shop.example.com', FUTURE, 'theme')
    ].join('\n')
  });
  const dialog = page.locator('.jp-Dialog');
  const edit = async () => {
    await entryRow(page, 'shop/session').click();
    await dialog.getByRole('button', { name: 'Edit' }).click();
    await expect(dialog.locator('.jp-Dialog-header')).toHaveText('Edit entry');
  };
  const save = dialog.getByRole('button', { name: 'Save' });

  // The URL only: the two cookies stay.
  await edit();
  await expect(dialog).toContainText('Leave empty to keep the 2 cookies');
  await expect(save).toBeEnabled();
  await dialog.getByLabel('URL').fill('https://shop.example.com/v2');
  await save.click();
  await expect(dialog).toHaveCount(0);
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
  let shop = (await listed(page)).find(e => e.name === 'shop/session');
  expect(shop.url).toBe('https://shop.example.com/v2');
  expect(shop.cookies.map((c: any) => c.name)).toEqual(['sid', 'theme']);

  // A paste that reads replaces the whole jar.
  await edit();
  await dialog
    .getByLabel('Cookies', { exact: true })
    .fill(
      `curl 'https://shop.example.com/' -H 'Cookie: only=${COOKIE_MARKER}'`
    );
  await expect(dialog).toContainText(
    '1 cookie read, from shop.example.com: only. Save replaces the current cookies'
  );
  await save.click();
  await expect(dialog).toHaveCount(0);
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
  shop = (await listed(page)).find(e => e.name === 'shop/session');
  expect(shop.cookies.map((c: any) => c.name)).toEqual(['only']);
});

test('Edit renames an entry, and a name in use is refused under the field', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  const SECRET = 'vault-e2e-secret-3Rn';
  await addByRest(page, 'site/one', { username: 'me', password: SECRET });
  await addByRest(page, 'site/two', { password: 'vault-e2e-other-8Qw' });
  await entryRow(page, 'site/one').click();
  const dialog = page.locator('.jp-Dialog');
  await dialog.getByRole('button', { name: 'Edit' }).click();
  const name = dialog.getByLabel('Name', { exact: true });
  const save = dialog.getByRole('button', { name: 'Save' });
  await expect(name).toBeEditable();

  await name.fill('site/two');
  // The help line of the Name field, matched inside the field.
  const help = dialog
    .locator('.jp-PasskeyVaultForm-field', {
      has: page.getByLabel('Name', { exact: true })
    })
    .locator('.jp-PasskeyVaultForm-help');
  await expect(help).toHaveText('An entry named site/two already exists');
  await expect(save).toBeDisabled();

  await name.fill('site/renamed');
  await expect(help).toHaveText('');
  await expect(save).toBeEnabled();
  await save.click();
  await expect(dialog).toHaveCount(0);
  await expect(panel(page)).not.toHaveAttribute('aria-busy', 'true');
  await expect(entryRow(page, 'site/renamed')).toHaveCount(1);
  await expect(entryRow(page, 'site/one')).toHaveCount(0);
  // Every other field is kept: the username, and the password the CLI reads.
  const renamed = (await listed(page)).find(e => e.name === 'site/renamed');
  expect(renamed.username).toBe('me');
  const got = await vaultCli('get', 'site/renamed');
  expect(got.code, got.stderr).toBe(0);
  expect(got.stdout.trim()).toBe(SECRET);
});

test('vault add --cookies --in-browser asks one paste field: Submit adds the entry, Cancel exits 1', async ({
  page
}) => {
  await openVault(page);
  await createVault(page);
  await dismissToasts(page);
  // The CLI's notification; its button opens the paste dialog.
  const toast = page.locator('.jp-toast-button', { hasText: 'Enter secret' });
  const dialog = page.locator('.jp-Dialog');
  const paste = dialog.locator('textarea.jp-PassphraseDialog-paste');

  const added = vaultCli(
    'add',
    'shop/cli',
    '--cookies',
    '--in-browser',
    '--json',
    '--timeout',
    '30'
  );
  // The notification comes on a WebSocket push, or on the 30 s poll when that is missed.
  await toast.first().click({ timeout: 45000 });
  // The click dismisses the notification.
  await expect(toast).toHaveCount(0, { timeout: 15000 });
  await expect(dialog).toContainText('Cookies for shop/cli');
  // One multi-line field, not masked, where typing starts.
  await expect(paste).toBeFocused();
  await expect(dialog.locator('input:visible')).toHaveCount(0);
  const submit = dialog.getByRole('button', { name: 'Submit' });
  await expect(submit).toBeDisabled();
  await paste.fill(CURL);
  await expect(submit).toBeEnabled();
  await submit.click();
  const result = await added;
  expect(result.code, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout).result).toEqual({
    added: 'shop/cli',
    count: 2,
    domains: ['shop.example.com'],
    names: ['sid', 'theme'],
    expired: 0,
    headers: []
  });
  expect(result.stdout + result.stderr).not.toContain(COOKIE_MARKER);
  await expect(entryRow(page, 'shop/cli')).toHaveCount(1, { timeout: 20000 });

  const cancelled = vaultCli(
    'add',
    'shop/cancelled',
    '--cookies',
    '--in-browser',
    '--timeout',
    '30'
  );
  await toast.first().click({ timeout: 45000 });
  await expect(paste).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  const refused = await cancelled;
  expect(refused.code).toBe(1);
  expect(refused.stderr).toContain('cancelled');
  expect((await listed(page)).map(e => e.name)).not.toContain('shop/cancelled');
});
