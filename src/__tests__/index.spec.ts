/**
 * Unit tests for the plugin wiring in src/index. runPasskey is mocked, so these
 * assert only that activation registers the command, delegates correctly, and
 * tolerates a missing command palette.
 */

jest.mock('../passkey');
// Stub the heavy @jupyterlab modules so index.ts loads without pulling their
// untransformed ESM graph into jest (apputils is a real value use of the
// ICommandPalette token).
jest.mock('@jupyterlab/application', () => ({}));
jest.mock('@jupyterlab/apputils', () => ({
  ICommandPalette: 'ICommandPalette'
}));
import { runPasskey } from '../passkey';
import plugin from '../index';

const mockRun = runPasskey as jest.MockedFunction<typeof runPasskey>;

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
  beforeEach(() => mockRun.mockReset());

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

  it('activates without a command palette', () => {
    const { app } = fakeApp();
    expect(() => plugin.activate!(app, null)).not.toThrow();
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
