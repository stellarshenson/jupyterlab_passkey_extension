import qrcode from 'qrcode-generator';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** A new secret for an authenticator app, as the setup key the app takes: base32. */
export function newSetupKey(): string {
  // 160 bits, what authenticator apps create themselves.
  const secret = new Uint8Array(20);
  crypto.getRandomValues(secret);
  let bits = '';
  for (const byte of secret) {
    bits += byte.toString(2).padStart(8, '0');
  }
  let key = '';
  for (let at = 0; at < bits.length; at += 5) {
    key += BASE32[parseInt(bits.slice(at, at + 5), 2)];
  }
  return key;
}

/** The address an authenticator app reads from the QR code: the key and its names. */
export function otpauthUri(setupKey: string, host: string): string {
  const issuer = 'JupyterLab vault';
  return `otpauth://totp/${encodeURIComponent(`${issuer}:${host}`)}?secret=${setupKey}&issuer=${encodeURIComponent(issuer)}`;
}

/** `text` as a QR code: dark modules on white with the quiet zone a scanner needs. */
export function qrSvg(text: string): SVGSVGElement {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const count = qr.getModuleCount();
  const quiet = 4;
  const size = count + 2 * quiet;
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
  svg.setAttribute('shape-rendering', 'crispEdges');
  const background = document.createElementNS(ns, 'rect');
  background.setAttribute('width', String(size));
  background.setAttribute('height', String(size));
  background.setAttribute('fill', '#fff');
  let d = '';
  for (let row = 0; row < count; row++) {
    for (let col = 0; col < count; col++) {
      if (qr.isDark(row, col)) {
        d += `M${col + quiet} ${row + quiet}h1v1h-1z`;
      }
    }
  }
  const modules = document.createElementNS(ns, 'path');
  modules.setAttribute('d', d);
  modules.setAttribute('fill', '#000');
  svg.append(background, modules);
  return svg;
}
