"""The check of a passkey with no PRF, with Yubico's `fido2` library: its registration,
and a WebAuthn assertion over a challenge the server issued, verified against the
public key the vault holds.

At registration the library runs the registration steps of the WebAuthn
specification on the `create`: the type, the challenge, the origin, the relying party
hash, user presence and user verification; the public key the vault keeps is the COSE
key of its attested credential data, as CBOR bytes, the form the library takes back to
check a signature. The attestation statement is not verified (attestation `none`), so the
assertion of the `get` that follows proves the page holds that key. At each check the
library runs the verification steps: the type, the challenge, the origin, the
relying party hash, user presence, user verification, the credential and the
signature. The origin is one exact value, the one stored when the method was added.
The steps the library leaves to the caller are made here: a cross-origin request is
refused, a registration's credential id must be the one sent and its key of an
algorithm the page asks for, and a sign count that did not rise is refused.

The registration arrives from the page as base64url fields: `client_data` (the client
data JSON of the `create`) and `attestation_object`. The assertion: `cred_id`,
`client_data`, `authenticator_data` and `signature`.
"""

from urllib.parse import urlparse

from fido2 import cbor
from fido2.cose import ES256, RS256, CoseKey
from fido2.rpid import verify_rp_id
from fido2.server import Fido2Server
from fido2.utils import websafe_decode
from fido2.webauthn import (Aaguid, AttestationObject, AttestedCredentialData,
                            AuthenticationResponse, AuthenticatorAssertionResponse,
                            AuthenticatorAttestationResponse, AuthenticatorData,
                            CollectedClientData, RegistrationResponse,
                            UserVerificationRequirement)


class Refused(Exception):
    """A registration or an assertion that does not verify. The reason is for the tests
    and the log of a developer; a client is told one text for every refusal."""


def load_key(cose):
    """The `fido2` key of COSE key bytes, as the vault holds them: ES256 on P-256, or RS256
    of 2048 bits or more, the two algorithms the page asks for."""
    try:
        key = CoseKey.parse(cbor.decode(cose))
        alg = key.get(3)
        if alg == ES256.ALGORITHM and key.get(-1) == 1:
            return key
        if alg == RS256.ALGORITHM and int.from_bytes(key[-1], "big").bit_length() >= 2048:
            return key
    except Exception:
        raise Refused("no COSE key")
    raise Refused("a key of an algorithm the page does not ask for")


def origin_of(assertion, rp_id):
    """The origin the browser wrote into the client data of `assertion`, a registration
    response, when it is a WebAuthn origin for `rp_id` whose hostname is `rp_id` itself."""
    try:
        origin = CollectedClientData(websafe_decode(assertion["client_data"])).origin
        if verify_rp_id(rp_id, origin) and urlparse(origin).hostname == rp_id:
            return origin
    except Exception:
        raise Refused("a malformed assertion")
    raise Refused("another relying party")


def registered_key(registration, cred_id, rp_id, origin, challenge):
    """The COSE key bytes of credential `cred_id`, which `registration` created
    over `challenge` (as the server sent it, base64url) from exactly `origin` for
    `rp_id`, with user verification: the registration steps, run by `fido2`'s
    `register_complete`. The key comes from the attested credential data."""
    # As in `verify`: any exception from a body the page sent is a refusal.
    try:
        raw = websafe_decode(cred_id)
        client = CollectedClientData(websafe_decode(registration["client_data"]))
        made = Fido2Server({"id": rp_id, "name": rp_id}, attestation="none",
                           verify_origin=lambda o: o == origin).register_complete(
            {"challenge": challenge, "user_verification": UserVerificationRequirement.REQUIRED},
            RegistrationResponse(
                raw_id=raw,
                response=AuthenticatorAttestationResponse(
                    client_data=client,
                    attestation_object=AttestationObject(
                        websafe_decode(registration["attestation_object"]))))).credential_data
        cross = client.cross_origin
        same = made.credential_id == raw
        # The attested credential data holds `cbor.encode` of this key (fido2 webauthn.py:138).
        cose = cbor.encode(made.public_key)
        load_key(cose)
    except Refused:
        raise
    except Exception as e:
        raise Refused(str(e) or type(e).__name__)
    if cross:
        raise Refused("a cross-origin request")
    if not same:
        raise Refused("another credential")
    return cose


def verify(assertion, cose, cred_id, rp_id, origin, challenge, count=0):
    """Raise Refused unless `assertion` answers `challenge` (as the server sent it,
    base64url) from exactly `origin` for `rp_id`, signed by credential `cred_id` with
    the key in `cose`, COSE key bytes. Returns the authenticator's sign count: when it or
    `count`, the count stored, is not 0, it must be higher than `count`."""
    key = load_key(cose)
    # Any exception from parsing or checking a body the page sent is a refusal: the
    # library names no closed list of them, and a check that cannot finish passes nothing.
    try:
        raw = websafe_decode(cred_id)
        client = CollectedClientData(websafe_decode(assertion["client_data"]))
        data = AuthenticatorData(websafe_decode(assertion["authenticator_data"]))
        Fido2Server({"id": rp_id, "name": rp_id}, attestation="none",
                    verify_origin=lambda o: o == origin).authenticate_complete(
            {"challenge": challenge, "user_verification": UserVerificationRequirement.REQUIRED},
            [AttestedCredentialData.create(Aaguid.NONE, raw, key)],
            AuthenticationResponse(
                raw_id=websafe_decode(assertion["cred_id"]),
                response=AuthenticatorAssertionResponse(
                    client_data=client, authenticator_data=data,
                    signature=websafe_decode(assertion["signature"]))))
        cross = client.cross_origin
        seen = data.counter
        rose = not (seen or count) or seen > count
    except Exception as e:
        raise Refused(str(e) or type(e).__name__)
    if cross:
        raise Refused("a cross-origin request")
    if not rose:
        raise Refused("a sign count that did not rise")
    return seen
