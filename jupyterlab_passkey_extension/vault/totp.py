"""The codes of an authenticator app: RFC 6238 with the parameters every app supports -
HMAC-SHA-1, 6 digits, a new code every 30 seconds.

A code is a proof that the person holds the phone, checked against a secret the app and
the vault share. It holds no key: it cannot open a locked vault.
"""

import base64
import hashlib
import hmac
import struct
import time

DIGITS = 6
STEP = 30
# The step before and the step after the current one are accepted, for a phone clock
# that is off and a code typed as it changes.
WINDOW = 1
# RFC 4226 asks for at least 128 bits of secret; apps create 160.
MIN_SECRET, MAX_SECRET = 16, 64


def decode_secret(setup_key):
    """The secret behind a setup key (base32 as apps show it), or None when it is none."""
    if not isinstance(setup_key, str):
        return None
    text = setup_key.replace(" ", "").upper()
    try:
        secret = base64.b32decode(text + "=" * (-len(text) % 8))
    except ValueError:
        return None
    return secret if MIN_SECRET <= len(secret) <= MAX_SECRET else None


def code(secret, counter):
    """The code of time step `counter` (RFC 4226 section 5.3)."""
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**DIGITS).zfill(DIGITS)


def matching_step(secret, typed, now=None):
    """The time step whose code is `typed`, within the window around now, or None."""
    if not isinstance(typed, str):
        return None
    typed = typed.replace(" ", "")
    if len(typed) != DIGITS or not (typed.isascii() and typed.isdigit()):
        return None
    current = int(time.time() if now is None else now) // STEP
    found = None
    # Every step is compared, so the time taken does not tell which one matched.
    for step in range(current - WINDOW, current + WINDOW + 1):
        if hmac.compare_digest(code(secret, step), typed):
            found = step
    return found
