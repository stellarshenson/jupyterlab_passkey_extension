/// <reference types="node" />
/**
 * Every visible line of the page is at most 60 characters, or a reason here says
 * why it cannot be shorter. The texts are read from the product source, so a new
 * or reworded literal is measured as it ships.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';

const ROOT = path.resolve(__dirname, '..', '..');

/** The page files whose text the user reads. */
const FILES = [
  'src/vault/panel.ts',
  'src/vault/dialogs.ts',
  'src/vault/plugin.ts',
  'src/vault/webauthn.ts',
  'src/vault/api.ts',
  'src/index.ts',
  'src/copy.ts',
  'src/show.ts'
];

/** A visible line longer than 60 characters, with the fact that keeps it long. */
const LONGER: Record<string, string> = {
  'no PRF - passkey not added; use another passkey or Password and authenticator app':
    'names the two methods that work after a declined passkey',
  'No PRF: the passkey cannot hold the vault key. A new unlock password decrypts the vault and the server checks the passkey; a copy of the vault opens with the password alone.':
    'each clause is a safety fact: no key in the passkey, the password decrypts, the copy opens alone',
  'Choose a recovery passphrase and store it offline - it opens the vault when no other method can':
    'names where to keep it and that it is the last way in',
  'A password vault the Jupyter server keeps, unlocked by passkey, password and code, or recovery passphrase':
    'names all three unlock methods in the settings description',
  'The relay a failure is posted to; success shows in vault status':
    'names both what the relay carries and where success shows',
  'the server did not confirm the method - it may have been added; check the cog':
    'states that the method may have landed and where to check',
  'an IP address cannot hold a passkey - open by hostname over HTTPS, or at localhost':
    'names both addresses that work',
  'Capture browser passkeys for the API and CLI, so vaults and secrets use the passkey of the browser or operating system':
    'the package description names what is captured and why'
};

/** A literal that is not a visible line: markup, a CSS class list or a debug line. */
function notVisible(text: string): boolean {
  return (
    text.startsWith('<svg') ||
    text.startsWith('[passkey:') ||
    text.includes('jp-PasskeyVaultForm-') ||
    text.includes('is activated!')
  );
}

/** Every string the page shows, one entry per literal or template part. */
function visibleTexts(): Set<string> {
  const texts = new Set<string>();
  for (const file of FILES) {
    const source = fs.readFileSync(path.join(ROOT, file), 'utf8');
    const tree = ts.createSourceFile(
      file,
      source,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TS
    );
    const visit = (node: ts.Node): void => {
      let text: string | undefined;
      if (
        ts.isStringLiteral(node) ||
        ts.isNoSubstitutionTemplateLiteral(node) ||
        ts.isTemplateHead(node) ||
        ts.isTemplateMiddle(node) ||
        ts.isTemplateTail(node)
      ) {
        text = node.text;
      }
      if (text !== undefined && text.length > 0 && !notVisible(text)) {
        texts.add(text);
      }
      ts.forEachChild(node, visit);
    };
    visit(tree);
  }
  return texts;
}

it('keeps every visible page line within 60 characters, or records why not', () => {
  const tooLong = Array.from(visibleTexts())
    .filter(text => text.length > 60 && !(text in LONGER))
    .map(text => `${text.length}: ${JSON.stringify(text)}`);
  expect(tooLong).toEqual([]);
});

it('records a reason only for a line the page still has', () => {
  const texts = visibleTexts();
  expect(Object.keys(LONGER).filter(text => !texts.has(text))).toEqual([]);
});
