/**
 * Unit tests for the plugin wiring in src/index. runPasskey is mocked, so these
 * assert only that activation registers the command, delegates correctly, and
 * tolerates a missing command palette.
 */

jest.mock('../passkey');
jest.mock('../copy');
jest.mock('../show');
// Stub the heavy @jupyterlab modules so index.ts loads without pulling their
// untransformed ESM graph into jest (apputils is a real value use of the
// ICommandPalette token).
jest.mock('@jupyterlab/application', () => ({}));
jest.mock('@jupyterlab/apputils', () => ({
  ICommandPalette: 'ICommandPalette'
}));
import { runPasskey } from '../passkey';
import { runCopy } from '../copy';
import { runShow } from '../show';
// The vault plugin has its own tests (vault.spec.ts); stubbed here so this file keeps
// testing only the bridge plugin's wiring.
jest.mock('../vault/plugin', () => ({
  vaultPlugin: { id: 'jupyterlab_passkey_extension:vault' }
}));
import { ITranslator } from '@jupyterlab/translation';
import plugins from '../index';

const plugin = plugins[0];

it('exports the bridge plugin and the vault plugin', () => {
  expect(plugins.map(p => p.id)).toEqual([
    'jupyterlab_passkey_extension:plugin',
    'jupyterlab_passkey_extension:vault'
  ]);
});

const mockRun = runPasskey as jest.MockedFunction<typeof runPasskey>;
const mockCopy = runCopy as jest.MockedFunction<typeof runCopy>;
const mockShow = runShow as jest.MockedFunction<typeof runShow>;

function fakeApp(): { app: any; addCommand: jest.Mock; serverSettings: any } {
  const addCommand = jest.fn();
  const serverSettings = { fake: true };
  return {
    app: { commands: { addCommand }, serviceManager: { serverSettings } },
    addCommand,
    serverSettings
  };
}

describe('plugin activation', () => {
  beforeEach(() => {
    mockRun.mockReset();
    mockCopy.mockReset();
    mockShow.mockReset();
  });

  it('registers the passkey:run command and adds a palette item', () => {
    const { app, addCommand } = fakeApp();
    const palette = { addItem: jest.fn() } as any;

    plugin.activate!(app, palette);

    expect(addCommand).toHaveBeenCalledWith(
      'passkey:run',
      expect.objectContaining({
        label: expect.any(String),
        execute: expect.any(Function)
      })
    );
    expect(palette.addItem).toHaveBeenCalledWith({
      command: 'passkey:run',
      category: 'Passkey'
    });
  });

  it('execute splits op from the rest and forwards the server settings', () => {
    const { app, addCommand, serverSettings } = fakeApp();

    plugin.activate!(app, null);
    const config = addCommand.mock.calls[0][1];
    config.execute({
      op: 'get',
      nonce: 'unit_nonce_0123456789',
      rp_id: 'example.com',
      cred_id: 'AAAA'
    });

    expect(mockRun).toHaveBeenCalledWith(
      'get',
      { nonce: 'unit_nonce_0123456789', rp_id: 'example.com', cred_id: 'AAAA' },
      serverSettings
    );
  });

  it('forwards a create ceremony with its args', () => {
    const { app, addCommand, serverSettings } = fakeApp();

    plugin.activate!(app, null);
    const config = addCommand.mock.calls[0][1];
    const args = {
      nonce: 'unit_nonce_0123456789',
      rp_id: 'example.com',
      user: { id: 'AA', name: 'n', displayName: 'd' }
    };
    config.execute({ op: 'create', ...args });

    expect(mockRun).toHaveBeenCalledWith('create', args, serverSettings);
  });

  it('registers passkey:copy, forwarding the nonce and adding a palette item', () => {
    const { app, addCommand, serverSettings } = fakeApp();
    const palette = { addItem: jest.fn() } as any;

    plugin.activate!(app, palette);

    const call = addCommand.mock.calls.find(c => c[0] === 'passkey:copy');
    expect(call).toBeDefined();
    call![1].execute({ nonce: 'unit_nonce_0123456789' });

    expect(mockCopy).toHaveBeenCalledWith(
      { nonce: 'unit_nonce_0123456789' },
      serverSettings
    );
    expect(palette.addItem).toHaveBeenCalledWith({
      command: 'passkey:copy',
      category: 'Passkey'
    });
  });

  it('registers passkey:show, forwarding the nonce and adding a palette item', async () => {
    const { app, addCommand, serverSettings } = fakeApp();
    const palette = { addItem: jest.fn() } as any;

    plugin.activate!(app, palette);

    const call = addCommand.mock.calls.find(c => c[0] === 'passkey:show');
    expect(call).toBeDefined();
    await call![1].execute({
      nonce: 'unit_nonce_0123456789',
      label: 'Auth code'
    });

    expect(mockShow).toHaveBeenCalledWith(
      { nonce: 'unit_nonce_0123456789', label: 'Auth code' },
      serverSettings
    );
    expect(palette.addItem).toHaveBeenCalledWith({
      command: 'passkey:show',
      category: 'Passkey'
    });
  });

  it('activates without a command palette', () => {
    const { app } = fakeApp();
    expect(() => plugin.activate!(app, null)).not.toThrow();
  });

  it('labels the commands through the lab translator and describes their arguments', () => {
    const { app, addCommand } = fakeApp();
    const translator = { load: () => ({ __: (s: string) => `<${s}>` }) } as any;

    plugin.activate!(app, null, translator);

    const commands = new Map<string, any>(addCommand.mock.calls as any);
    expect(
      Array.from(commands, ([id, options]) => [id, options.label])
    ).toEqual([
      ['passkey:run', '<Run Passkey Ceremony>'],
      ['passkey:passphrase', '<Enter Passphrase>'],
      ['passkey:copy', '<Copy Secret To Clipboard>'],
      ['passkey:show', '<Show Code>']
    ]);
    // Each command says what arguments it takes, as a JSON schema.
    for (const options of commands.values()) {
      expect(options.describedBy.args.type).toBe('object');
      expect(options.describedBy.args.required).toContain('nonce');
      expect(options.describedBy.args.properties.nonce.type).toBe('string');
    }
    expect(commands.get('passkey:run').describedBy.args.required).toEqual([
      'op',
      'nonce',
      'rp_id'
    ]);
    expect(
      Object.keys(
        commands.get('passkey:passphrase').describedBy.args.properties
      )
    ).toEqual(['nonce', 'prompt', 'once']);

    // A lab with no translator: each label is returned as written.
    const plain = fakeApp();
    plugin.activate!(plain.app, null, null);
    expect(plain.addCommand.mock.calls[0][1].label).toBe(
      'Run Passkey Ceremony'
    );
  });

  it('declares the translator optional', () => {
    expect(plugin.optional).toContain(ITranslator);
    expect(plugin.requires ?? []).not.toContain(ITranslator);
  });

  it('declares the palette optional and auto-starts (DI wiring)', () => {
    // A regression moving ICommandPalette into `requires` would fail to load in
    // real JupyterLab when no palette is present; pin the optional wiring.
    expect(plugin.id).toBe('jupyterlab_passkey_extension:plugin');
    expect(plugin.autoStart).toBe(true);
    expect(plugin.optional).toContain('ICommandPalette');
    expect(plugin.requires ?? []).not.toContain('ICommandPalette');
  });
});
