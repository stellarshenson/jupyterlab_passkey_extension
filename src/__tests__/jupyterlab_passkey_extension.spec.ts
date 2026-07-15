/**
 * Unit tests for the pure passkey helpers in src/passkey-util. These need no
 * browser or navigator - only the jsdom globals btoa/atob/DOMException that the
 * @jupyterlab/testutils jest environment provides.
 */

import { b64urlEncode, b64urlToBuf, mapCeremonyError } from '../passkey-util';

function bufFrom(bytes: number[]): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

function toArray(buf: ArrayBuffer): number[] {
  return Array.from(new Uint8Array(buf));
}

describe('b64urlEncode / b64urlToBuf round-trip', () => {
  it('round-trips empty bytes', () => {
    const buf = bufFrom([]);
    expect(b64urlEncode(buf)).toEqual('');
    expect(toArray(b64urlToBuf(b64urlEncode(buf)))).toEqual([]);
  });

  it('round-trips a small fixed array', () => {
    const bytes = [0, 1, 2, 3, 4, 5, 250, 255];
    const buf = bufFrom(bytes);
    expect(toArray(b64urlToBuf(b64urlEncode(buf)))).toEqual(bytes);
  });

  it('round-trips 32 random bytes', () => {
    const bytes = Array.from({ length: 32 }, () =>
      Math.floor(Math.random() * 256)
    );
    const buf = bufFrom(bytes);
    expect(toArray(b64urlToBuf(b64urlEncode(buf)))).toEqual(bytes);
  });
});

describe('b64urlEncode alphabet', () => {
  it('emits only url-safe characters (no +, /, =)', () => {
    // Bytes [251, 255] encode to "+/8=" in standard base64, exercising the
    // '+' -> '-', '/' -> '_' substitutions and the '=' padding strip.
    const encoded = b64urlEncode(bufFrom([251, 255]));
    expect(encoded).not.toMatch(/[+/=]/);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
  });
});

describe('mapCeremonyError', () => {
  it('maps a NotAllowedError DOMException to not-allowed', () => {
    expect(
      mapCeremonyError(new DOMException('cancelled', 'NotAllowedError'))
    ).toEqual('not-allowed');
  });

  it('maps another DOMException name to error', () => {
    expect(mapCeremonyError(new DOMException('boom', 'AbortError'))).toEqual(
      'error'
    );
  });

  it('maps a generic Error to error', () => {
    expect(mapCeremonyError(new Error('nope'))).toEqual('error');
  });

  it('maps a non-DOMException NotAllowedError-shaped object to error', () => {
    // The contract's not-allowed code is reserved for real DOMExceptions; a
    // duck-typed object must not be mistaken for one.
    expect(mapCeremonyError({ name: 'NotAllowedError' })).toEqual('error');
  });
});
