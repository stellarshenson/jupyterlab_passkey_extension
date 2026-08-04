/**
 * Pure, framework-free helpers for the passkey ceremony. Kept free of any
 * @jupyterlab imports so they can be unit-tested in isolation.
 */

/** Encode an ArrayBuffer as url-safe base64 without padding. */
export function b64urlEncode(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Decode a url-safe base64 string (tolerant of missing padding) to an ArrayBuffer. */
export function b64urlToBuf(s: string): ArrayBuffer {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/** Map a ceremony exception to one of the contract's honest error codes. */
export function mapCeremonyError(e: unknown): string {
  // WebAuthn deliberately conflates user-cancel / no-matching-credential /
  // wrong-rp into NotAllowedError for privacy, so we cannot distinguish them
  // and emit one honest code.
  if (e instanceof DOMException && e.name === 'NotAllowedError') {
    return 'not-allowed';
  }
  // A SecurityError is thrown synchronously, before any authenticator interaction,
  // when rpId is not a registrable domain suffix of (nor equal to) the tab's origin -
  // i.e. the --rp-id does not match the URL the JupyterLab tab is open at. It is a
  // caller misconfiguration, not a privacy-conflated outcome, so naming it distinctly
  // leaks nothing and is the difference between a fixable message and a blank "error".
  if (e instanceof DOMException && e.name === 'SecurityError') {
    return 'rp-id-mismatch';
  }
  // Never collapse an unexpected failure to a bare "error": pass the exception name
  // through so the CLI prints something a caller can act on rather than a dead end.
  if (e instanceof DOMException) {
    return `error: ${e.name}`;
  }
  return 'error';
}
