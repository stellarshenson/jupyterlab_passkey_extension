/**
 * Unit tests for runCopy (src/copy). The server POST and the clipboard are both
 * mocked, so the collect-then-write order, the nonce-only request body and the
 * two failure paths are exercised without a browser.
 */

import { ServerConnection } from '@jupyterlab/services';

jest.mock('@jupyterlab/services', () => ({ ServerConnection: {} }));
jest.mock('@jupyterlab/apputils', () => ({
  Notification: { emit: jest.fn() }
}));
jest.mock('../request');

import { Notification } from '@jupyterlab/apputils';
import { requestAPI } from '../request';
import { runCopy } from '../copy';

const mockEmit = Notification.emit as jest.MockedFunction<
  typeof Notification.emit
>;

const mockRequestAPI = requestAPI as jest.MockedFunction<typeof requestAPI>;

const serverSettings = {} as ServerConnection.ISettings;
const NONCE = 'unit_nonce_0123456789';
const SECRET = 's3cr3t-token-value';

const writeText = jest.fn();

beforeAll(() => {
  // jsdom ships no clipboard, and a real one would be a global side effect.
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText },
    configurable: true
  });
});

beforeEach(() => {
  mockRequestAPI.mockReset();
  mockEmit.mockReset();
  writeText.mockReset();
  writeText.mockResolvedValue(undefined);
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
});

afterEach(() => {
  // The hasFocus spy must not leak into the next test's focus assumptions.
  jest.restoreAllMocks();
});

describe('runCopy', () => {
  it('collects the secret against the nonce and puts it on the clipboard', async () => {
    mockRequestAPI.mockResolvedValue({ value: SECRET } as any);

    await runCopy({ nonce: NONCE }, serverSettings);

    const [endpoint, settings, init] = mockRequestAPI.mock.calls[0];
    expect(endpoint).toBe('secret');
    expect(settings).toBe(serverSettings);
    // POST, not GET: the read is destructive, and a query string would put the
    // nonce in the server's access log.
    expect(init?.method).toBe('POST');
    expect(JSON.parse(init!.body as string)).toEqual({ nonce: NONCE });
    expect(writeText).toHaveBeenCalledWith(SECRET);
  });

  it('leaves the clipboard alone when there is no secret to collect', async () => {
    // An expired or already-collected relay 404s. Overwriting whatever the user
    // had on their clipboard with nothing would be a real loss.
    mockRequestAPI.mockRejectedValue(new Error('404'));

    await expect(runCopy({ nonce: NONCE }, serverSettings)).rejects.toThrow();
    expect(writeText).not.toHaveBeenCalled();
  });

  it('retries the write when focus returns, so a focus blip does not eat the secret', async () => {
    // Chrome refuses writeText while the document is unfocused (DevTools, another
    // window). The value is one-shot - already consumed from the relay - so the
    // refusal must not be the end of it. Observed live: the click collected the
    // relay, the clipboard stayed empty, and the secret was gone.
    mockRequestAPI.mockResolvedValue({ value: SECRET } as any);
    writeText
      .mockRejectedValueOnce(new Error('Document is not focused'))
      .mockResolvedValueOnce(undefined);

    const run = runCopy({ nonce: NONCE }, serverSettings);
    // Let the refusal land and the focus listener attach before focus returns.
    await new Promise(resolve => setTimeout(resolve, 0));
    window.dispatchEvent(new Event('focus'));

    await run;
    expect(writeText).toHaveBeenCalledTimes(2);
    expect(writeText).toHaveBeenLastCalledWith(SECRET);
  });

  it('keeps retrying past a second refusal - one retry was observed to lose a secret', async () => {
    // The live failure the single-retry version shipped with: the first retry
    // met another transient refusal and gave up, and the secret was gone.
    mockRequestAPI.mockResolvedValue({ value: SECRET } as any);
    writeText
      .mockRejectedValueOnce(new Error('Document is not focused'))
      .mockRejectedValueOnce(new Error('Document is not focused'))
      .mockResolvedValueOnce(undefined);

    const run = runCopy({ nonce: NONCE }, serverSettings);
    await new Promise(resolve => setTimeout(resolve, 0));
    window.dispatchEvent(new Event('focus'));
    await new Promise(resolve => setTimeout(resolve, 0));
    window.dispatchEvent(new Event('focus'));

    await run;
    expect(writeText).toHaveBeenCalledTimes(3);
    expect(writeText).toHaveBeenLastCalledWith(SECRET);
  });

  it('retries on the tick without a focus event, and succeeds when the refusal clears', async () => {
    jest.useFakeTimers();
    try {
      mockRequestAPI.mockResolvedValue({ value: SECRET } as any);
      writeText
        .mockRejectedValueOnce(new Error('transient refusal'))
        .mockResolvedValueOnce(undefined);

      const run = runCopy({ nonce: NONCE }, serverSettings);
      await jest.advanceTimersByTimeAsync(2000);
      await run;
      expect(writeText).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it('offers a recovery click once retries are exhausted - the secret is never dropped', async () => {
    // Chrome honours a clipboard write for only ~5s past the last user
    // gesture, so once the click's activation is gone no background retry can
    // ever land it - observed live as a long absence eating the secret. The
    // rung below the retries is a NEW notification whose button click IS a
    // fresh gesture.
    jest.useFakeTimers();
    try {
      mockRequestAPI.mockResolvedValue({ value: SECRET } as any);
      writeText.mockRejectedValue(new Error('Document is not focused'));

      const run = runCopy(
        { nonce: NONCE, label: 'DB password' },
        serverSettings
      );
      await jest.advanceTimersByTimeAsync(20000);
      // Resolves rather than rejects: the flow continues through the button.
      await run;

      expect(mockEmit).toHaveBeenCalledTimes(1);
      const [message, type, options] = mockEmit.mock.calls[0];
      expect(message).toContain('DB password');
      expect(message).not.toContain(SECRET);
      expect(type).toBe('warning');
      expect((options as any).autoClose).toBe(false);

      // The button's click writes the held value under its fresh gesture.
      writeText.mockClear();
      writeText.mockResolvedValue(undefined);
      (options as any).actions[0].callback();
      await Promise.resolve();
      expect(writeText).toHaveBeenCalledWith(SECRET);
    } finally {
      jest.useRealTimers();
    }
  });

  it('re-offers the recovery click if even the fresh click is refused', async () => {
    jest.useFakeTimers();
    try {
      mockRequestAPI.mockResolvedValue({ value: SECRET } as any);
      writeText.mockRejectedValue(new Error('Document is not focused'));

      const run = runCopy({ nonce: NONCE }, serverSettings);
      await jest.advanceTimersByTimeAsync(20000);
      await run;
      expect(mockEmit).toHaveBeenCalledTimes(1);

      // The recovery click's own write is refused: the offer must come back -
      // below this rung there is nothing, so it cannot fail silently.
      (mockEmit.mock.calls[0][2] as any).actions[0].callback();
      await jest.advanceTimersByTimeAsync(0);
      expect(mockEmit).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });
});
