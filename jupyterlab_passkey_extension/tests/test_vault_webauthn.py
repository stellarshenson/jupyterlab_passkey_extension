"""Password and passkey: an unlock password with a passkey that has no PRF.

Every assertion here carries a real signature, made with `cryptography` the way an
authenticator makes it: over the authenticator data and the SHA-256 of the client data
JSON. A forged assertion is one signed by another key. Every registration carries an
attestation object of format `none`, as a browser sends it, whose authenticator data
holds the credential id and the COSE public key.
"""

import base64
import hashlib
import json
import os
import struct

import pytest
import tornado.httpclient
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fido2 import cbor
from fido2.cose import ES256, ES384, RS256, EdDSA
from fido2.webauthn import Aaguid, AttestationObject, AttestedCredentialData, AuthenticatorData

from jupyterlab_passkey_extension.vault import handlers, service as vault_service, store, totp, webauthn

from .test_vault_routes import _version_one_vault_held_by_its_root

PASS = "correct horse battery staple"
PAIR_PASSWORD = "a password for the passkey"
RP = "lab.example"
ORIGIN = "https://lab.example:8443"
CRED = "cred-pair"
SECRET = "pw-MUST-NOT-LEAK-pair"
APP = bytes(range(40, 60))
APP_KEY = base64.b32encode(APP).decode()
UNLOCK = "an everyday password"
CHECK_FAILED = (403, "the passkey check failed or expired - try again")
PRF = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Authenticator:
    """A passkey with no PRF: it signs what a browser asks with its own private key."""

    def __init__(self, kind="es256", cred=CRED):
        if kind == "es256":
            self.key = ec.generate_private_key(ec.SECP256R1())
        else:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.cred = cred
        self.count = 0

    @property
    def public_key(self):
        return b64u(self.key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))

    @property
    def cose(self):
        """The COSE key this authenticator attests at registration."""
        public = self.key.public_key()
        return (RS256 if isinstance(public, rsa.RSAPublicKey) else ES256).from_cryptography_key(public)

    def sign(self, data):
        if isinstance(self.key, rsa.RSAPrivateKey):
            return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return self.key.sign(data, ec.ECDSA(hashes.SHA256()))

    def assertion(self, challenge, *, type="webauthn.get", origin=ORIGIN, rp_id=RP, flags=0x05,
                  count=None, signer=None, client=None, auth=None, **extra):
        client = client if client is not None else json.dumps(
            {"type": type, "challenge": challenge, "origin": origin, **extra}).encode()
        if auth is None:
            if count is None:
                count = self.count
            auth = hashlib.sha256(rp_id.encode()).digest() + struct.pack(">BI", flags, count)
        signature = (signer or self).sign(auth + hashlib.sha256(client).digest())
        return {"cred_id": b64u(self.cred.encode()), "client_data": b64u(client),
                "authenticator_data": b64u(auth), "signature": b64u(signature)}

    def registration(self, challenge, *, type="webauthn.create", origin=ORIGIN, rp_id=RP,
                     flags=0x45, cred=None, cose=None, **extra):
        """What `navigator.credentials.create` answers with attestation `none`: the
        client data JSON, and the attestation object whose authenticator data holds the
        credential id and the COSE public key (flag 0x40). `cose` replaces that key."""
        client = json.dumps({"type": type, "challenge": challenge, "origin": origin,
                             **extra}).encode()
        if cose is None:
            cose = self.cose
        attested = AttestedCredentialData.create(
            Aaguid.NONE, (cred or self.cred).encode(), cose) if flags & 0x40 else b""
        auth = AuthenticatorData.create(hashlib.sha256(rp_id.encode()).digest(), flags, 0,
                                        attested)
        return {"client_data": b64u(client),
                "attestation_object": b64u(AttestationObject.create("none", auth, {}))}


@pytest.fixture
def svc(vault_env):
    s = handlers._service
    s.init(PASS)
    return s


def der_of(authenticator):
    return store.b64url_decode(authenticator.public_key)


def cose_of(authenticator):
    """The COSE key bytes the registration's attested credential data holds."""
    return cbor.encode(authenticator.cose)


def add_pair(svc, authenticator=None, proof=None, password=PAIR_PASSWORD, origin=ORIGIN, rp_id=RP):
    authenticator = authenticator or Authenticator()
    challenge = svc.challenge()["challenge"]
    svc.add_pair(password, b64u(authenticator.cred.encode()), rp_id,
                 authenticator.registration(challenge, origin=origin, rp_id=rp_id), "laptop",
                 authenticator.assertion(challenge, origin=origin, rp_id=rp_id),
                 proof or {"current": PASS})
    return authenticator


def unlock_pair(svc, authenticator, password=PAIR_PASSWORD, **kw):
    challenge = svc.challenge()["challenge"]
    svc.unlock_pair(password, authenticator.assertion(challenge, **kw))


def pair_proof(svc, authenticator, **kw):
    return {"assertion": authenticator.assertion(svc.challenge()["challenge"], **kw)}


def vault_doc():
    return store.load(store.vault_path())


def pair_slot():
    return next(s for s in vault_doc()["slots"] if s["type"] == store.PAIR)


def write_doc(doc):
    with open(store.vault_path(), "w") as f:
        json.dump(doc, f)


def is_locked(svc):
    return svc.holder().get(svc._vault_id()) is None


@pytest.fixture
def clock(monkeypatch):
    """The clock codes are checked against, stopped at a step start."""
    class Clock:
        now = 1_700_000_010.0

        def time(self):
            return self.now

        def code(self, steps=0):
            return totp.code(APP, int(self.now) // totp.STEP + steps)

        def advance(self, steps):
            self.now += steps * totp.STEP

    stopped = Clock()
    monkeypatch.setattr(totp, "time", stopped)
    return stopped


def add_app(svc, clock):
    svc.add_mfa(UNLOCK, APP_KEY, clock.code(), {"current": PASS})
    clock.advance(1)


# --------------------------------------------------------------------------- #
# webauthn.verify, with real signatures
# --------------------------------------------------------------------------- #

CHALLENGE = b64u(os.urandom(32))


@pytest.mark.parametrize("kind", ["es256", "rs256"])
def test_verify_accepts_a_real_signature(kind):
    a = Authenticator(kind)
    assert webauthn.verify(a.assertion(CHALLENGE), cose_of(a), b64u(CRED.encode()), RP, ORIGIN,
                           CHALLENGE) == 0


def flip(field, at):
    def change(assertion):
        raw = bytearray(store.b64url_decode(assertion[field]))
        raw[at] ^= 0x01
        return {**assertion, field: b64u(bytes(raw))}
    return change


REFUSED = {
    "a registration's client data": dict(type="webauthn.create"),
    "another challenge": dict(challenge=b64u(os.urandom(32))),
    "another port": dict(origin="https://lab.example:9443"),
    "another scheme": dict(origin="http://lab.example:8443"),
    "a cross-origin request": dict(crossOrigin=True),
    "another relying party": dict(rp_id="other.example"),
    "no user presence": dict(flags=0x04),
    "no user verification": dict(flags=0x01),
    "short authenticator data": dict(auth=hashlib.sha256(RP.encode()).digest() + b"\x05"),
    "a signature of another key": dict(signer=Authenticator()),
}


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_verify_refuses_each_check(case):
    a = Authenticator()
    kw = dict(REFUSED[case])
    challenge = kw.pop("challenge", CHALLENGE)
    with pytest.raises(webauthn.Refused):
        webauthn.verify(a.assertion(challenge, **kw), cose_of(a), b64u(CRED.encode()), RP, ORIGIN,
                        CHALLENGE)


@pytest.mark.parametrize("change", [
    flip("client_data", 10), flip("authenticator_data", 0), flip("authenticator_data", 34),
    flip("signature", 20),
    lambda x: {**x, "cred_id": b64u(b"another credential")},
    lambda x: {k: v for k, v in x.items() if k != "signature"},
    lambda x: {**x, "client_data": "!!"},
    lambda x: {**x, "signature": None},
    lambda x: "not an object",
], ids=["client data", "rp hash", "sign count", "signature", "another credential",
        "no signature", "not base64", "a null field", "not an object"])
def test_verify_refuses_a_changed_or_malformed_assertion(change):
    a = Authenticator()
    with pytest.raises(webauthn.Refused):
        webauthn.verify(change(a.assertion(CHALLENGE)), cose_of(a), b64u(CRED.encode()), RP, ORIGIN,
                        CHALLENGE)


@pytest.mark.parametrize("client", [
    b'{"type": "webauthn.get", "challenge": "\\ud800", "origin": "https://lab.example:8443"}',
    b'["webauthn.get"]', b'"webauthn.get"', b"7", b"\xff\xfe",
], ids=["lone surrogate", "list", "string", "number", "not utf-8"])
def test_verify_refuses_malformed_client_data(client):
    a = Authenticator()
    with pytest.raises(webauthn.Refused):
        webauthn.verify(a.assertion(CHALLENGE, client=client), cose_of(a), b64u(CRED.encode()), RP,
                        ORIGIN, CHALLENGE)


def test_a_sign_count_must_rise_once_either_count_is_not_zero():
    a = Authenticator()
    cred = b64u(CRED.encode())
    check = lambda seen, stored: webauthn.verify(  # noqa: E731
        a.assertion(CHALLENGE, count=seen), cose_of(a), cred, RP, ORIGIN, CHALLENGE, stored)
    assert check(0, 0) == 0 and check(0, 0) == 0
    assert check(8, 7) == 8
    for seen, stored in ((0, 7), (7, 7), (6, 7)):
        with pytest.raises(webauthn.Refused, match="sign count"):
            check(seen, stored)
    with pytest.raises(webauthn.Refused):
        check(8, "7")


@pytest.mark.parametrize("cose", [
    lambda: cbor.encode(EdDSA.from_cryptography_key(ed25519.Ed25519PrivateKey.generate().public_key())),
    lambda: cbor.encode(ES384.from_cryptography_key(ec.generate_private_key(ec.SECP384R1()).public_key())),
    lambda: cbor.encode({**Authenticator().cose, -1: 2}),
    lambda: cbor.encode(RS256.from_cryptography_key(
        rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key())),
    lambda: der_of(Authenticator()),
    lambda: b"no key at all",
], ids=["Ed25519", "P-384", "ES256 on another curve", "RSA 1024", "SPKI DER of a P-256 key",
        "no key"])
def test_load_key_refuses_every_key_the_page_does_not_ask_for(cose):
    with pytest.raises(webauthn.Refused):
        webauthn.load_key(cose())


@pytest.mark.parametrize("kind", ["es256", "rs256"])
def test_a_der_key_verifies_nothing(kind):
    # The form this method stored before its key was COSE: no reader for it is kept.
    a = Authenticator(kind)
    with pytest.raises(webauthn.Refused, match="no COSE key"):
        webauthn.verify(a.assertion(CHALLENGE), der_of(a), b64u(CRED.encode()), RP, ORIGIN,
                        CHALLENGE)


# --------------------------------------------------------------------------- #
# webauthn.registered_key: the registration steps on the create
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("kind", ["es256", "rs256"])
def test_registration_gives_the_key_the_authenticator_attested(kind):
    a = Authenticator(kind)
    registration = a.registration(CHALLENGE)
    cose = webauthn.registered_key(registration, b64u(CRED.encode()), RP, ORIGIN, CHALLENGE)
    # The COSE key bytes of the attested credential data, which fido2 reads back as this key.
    attested = AttestationObject(store.b64url_decode(
        registration["attestation_object"])).auth_data.credential_data
    assert cose == cose_of(a) and bytes(attested).endswith(cose)
    assert webauthn.load_key(cose) == a.cose and type(webauthn.load_key(cose)) is type(a.cose)


REGISTRATION_REFUSED = {
    "an assertion's client data": dict(type="webauthn.get"),
    "another challenge": dict(challenge=b64u(os.urandom(32))),
    "another port": dict(origin="https://lab.example:9443"),
    "another scheme": dict(origin="http://lab.example:8443"),
    "a cross-origin request": dict(crossOrigin=True),
    "another relying party": dict(rp_id="other.example"),
    "no user presence": dict(flags=0x44),
    "no user verification": dict(flags=0x41),
    "no attested credential": dict(flags=0x05),
    "another credential id": dict(cred="another credential"),
    "an Ed25519 key": dict(cose=EdDSA.from_cryptography_key(
        ed25519.Ed25519PrivateKey.generate().public_key())),
    "a P-384 key": dict(cose=ES384.from_cryptography_key(
        ec.generate_private_key(ec.SECP384R1()).public_key())),
    "an RSA key of 1024 bits": dict(cose=RS256.from_cryptography_key(
        rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key())),
}


@pytest.mark.parametrize("case", sorted(REGISTRATION_REFUSED))
def test_registration_refuses_each_check(case):
    a = Authenticator()
    kw = dict(REGISTRATION_REFUSED[case])
    challenge = kw.pop("challenge", CHALLENGE)
    with pytest.raises(webauthn.Refused):
        webauthn.registered_key(a.registration(challenge, **kw), b64u(CRED.encode()), RP, ORIGIN,
                                CHALLENGE)


@pytest.mark.parametrize("change", [
    lambda x: None, lambda x: "not an object", lambda x: {},
    lambda x: {**x, "client_data": "!!"},
    lambda x: {**x, "attestation_object": b64u(b"\xa0")},
    lambda x: {k: v for k, v in x.items() if k != "attestation_object"},
], ids=["null", "a string", "empty", "not base64", "an empty CBOR map", "no attestation object"])
def test_registration_refuses_a_malformed_body(change):
    a = Authenticator()
    with pytest.raises(webauthn.Refused):
        webauthn.registered_key(change(a.registration(CHALLENGE)), b64u(CRED.encode()), RP,
                                ORIGIN, CHALLENGE)


@pytest.mark.parametrize("origin, ok", [
    (ORIGIN, True), ("http://localhost:8888", False), ("https://sub.lab.example", False),
    ("http://lab.example", False), ("https://example", False),
])
def test_the_origin_at_registration_is_a_webauthn_origin_of_the_hostname(origin, ok):
    a = Authenticator()
    registration = a.registration(CHALLENGE, origin=origin)
    if ok:
        assert webauthn.origin_of(registration, RP) == origin
    else:
        with pytest.raises(webauthn.Refused):
            webauthn.origin_of(registration, RP)
    assert webauthn.origin_of(a.registration(CHALLENGE, origin="http://localhost:8888"),
                              "localhost") == "http://localhost:8888"


# --------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------- #


def test_the_method_is_one_slot_with_its_own_password_and_a_sealed_public_key(svc, clock):
    add_app(svc, clock)
    before = vault_doc()
    password_slot = next(s for s in before["slots"] if s["type"] == "password")
    a = add_pair(svc)
    doc = vault_doc()
    slot = pair_slot()
    assert [s["type"] for s in doc["slots"]] == ["recovery", "password", store.PAIR]
    assert next(s for s in doc["slots"] if s["type"] == "password") == password_slot
    assert doc["authenticator"] == before["authenticator"]
    assert slot["salt"] != password_slot["salt"] and slot["kdf"] == "argon2id"
    assert slot["origin"] == ORIGIN and slot["rp_id"] == RP and slot["label"] == "laptop"
    # The password alone unwraps the root: no key comes from the passkey.
    root = store.unwrap_pair(doc, PAIR_PASSWORD)
    assert root == store.unwrap_recovery(doc, PASS)
    dek = store.open_data_key(doc, root)
    # The public key is the COSE key of the registration, sealed under the data key
    # with the slot's fields bound, in a field named for it.
    assert "public_key" not in slot
    assert store._open(dek, slot["cose_key"], store._slot_aad(slot)) == cose_of(a)
    for form in (b64u(cose_of(a)), base64.b64encode(cose_of(a)).decode(), a.public_key):
        assert form not in json.dumps(doc)
    assert doc["version"] == 2


def test_status_carries_no_public_key_wrapped_key_or_salt(svc):
    add_pair(svc)
    row = next(s for s in svc.status()["slots"] if s["type"] == store.PAIR)
    assert not {"cose_key", "wrapped", "salt"} & set(row)
    assert row["origin"] == ORIGIN and row["cred_id"] == b64u(CRED.encode())


def test_a_password_alone_is_refused_on_a_vault_with_the_method(svc, clock):
    add_pair(svc)
    svc.lock()
    with pytest.raises(store.VaultError, match="this unlock password goes with a passkey - run "
                       "jupyterlab-passkey vault unlock and use the browser tab"):
        svc.unlock_password(PAIR_PASSWORD)
    assert is_locked(svc)
    # With an app pair as well, the request reads the app's password slot only.
    svc.unlock_recovery(PASS)
    add_app(svc, clock)
    svc.lock()
    with pytest.raises(store.VaultError, match="wrong unlock password"):
        svc.unlock_password(PAIR_PASSWORD, clock.code())
    assert is_locked(svc)


def test_rotation_reseals_the_public_key_and_the_method_still_unlocks(svc):
    a = add_pair(svc)
    old = vault_doc()
    old_slot = pair_slot()
    svc.rotate({"current": PASS})
    slot = pair_slot()
    assert slot["cose_key"] != old_slot["cose_key"] and slot["wrapped"] == old_slot["wrapped"]
    svc.lock()
    unlock_pair(svc, a)
    assert not is_locked(svc)
    # The old seal does not open under the new data key.
    doc = vault_doc()
    dek = store.open_data_key(doc, store.unwrap_pair(doc, PAIR_PASSWORD))
    with pytest.raises(Exception):
        store._open(dek, old_slot["cose_key"], store._slot_aad(old_slot))
    assert old["data_key"] != doc["data_key"]


def test_a_restored_slot_proves_until_the_next_rotation(svc):
    a = add_pair(svc)
    copy = pair_slot()
    # The named limit: with no rotation, a slot written back after Remove proves again.
    svc.remove_passkey(copy["cred_id"])
    doc = vault_doc()
    doc["slots"].append(copy)
    write_doc(doc)
    svc.add_passkey("c1", RP, "c2FsdA", PRF, None, pair_proof(svc, a))
    # After Remove and a rotation the restored slot does not decrypt.
    svc.remove_passkey(copy["cred_id"])
    svc.rotate({"current": PASS})
    doc = vault_doc()
    doc["slots"].append(copy)
    write_doc(doc)
    with pytest.raises(store.VaultError, match="does not decrypt"):
        svc.add_passkey("c2", RP, "c2FsdA", PRF, None, pair_proof(svc, a))


def test_adding_and_removing_the_method_leaves_the_app_pair_and_the_reverse(svc, clock):
    add_app(svc, clock)
    add_pair(svc)
    svc.lock()
    svc.unlock_password(UNLOCK, clock.code())
    clock.advance(1)
    svc.remove_passkey(pair_slot()["cred_id"])
    svc.lock()
    svc.unlock_password(UNLOCK, clock.code())
    clock.advance(1)
    a = add_pair(svc, Authenticator(cred="second"))
    svc.remove_mfa()
    svc.lock()
    unlock_pair(svc, a)
    assert not is_locked(svc)
    assert [s["type"] for s in vault_doc()["slots"]] == ["recovery", store.PAIR]


# --------------------------------------------------------------------------- #
# file edits by a person with no password
# --------------------------------------------------------------------------- #


def edit_slot(**fields):
    doc = vault_doc()
    slot = next(s for s in doc["slots"] if s["type"] == store.PAIR)
    slot.update(fields)
    write_doc(doc)


def test_a_swapped_public_key_does_not_decrypt_at_unlock_or_as_a_proof(svc):
    add_pair(svc)
    other = Authenticator()
    slot = pair_slot()
    # Sealed under another data key with the same fields: what a writer can produce.
    edit_slot(cose_key=store._seal(os.urandom(32), cose_of(other), store._slot_aad(slot)))
    with pytest.raises(store.VaultError, match="does not decrypt"):
        svc.add_passkey("c1", RP, "c2FsdA", PRF, None, pair_proof(svc, other))
    svc.lock()
    with pytest.raises(store.VaultError, match="does not decrypt"):
        unlock_pair(svc, other)
    assert is_locked(svc)


def old_form(slot, dek, der):
    """The slot as this method wrote it before its key was COSE: an SPKI DER key in
    `public_key`, a field the wrap did not bind."""
    old = {k: v for k, v in slot.items() if k != "cose_key"}
    old["public_key"] = store._seal(dek, der, store._slot_aad(old))
    return old


@pytest.mark.parametrize("form", ["a DER key in cose_key", "the old public_key field"])
def test_a_slot_written_with_a_der_key_is_not_accepted(svc, form):
    a = add_pair(svc)
    doc = vault_doc()
    dek = store.open_data_key(doc, store.unwrap_recovery(doc, PASS))
    slot = pair_slot()
    if form == "a DER key in cose_key":
        # Sealed under the right data key with the slot's fields: only the form is wrong.
        edit_slot(cose_key=store._seal(dek, der_of(a), store._slot_aad(slot)))
        as_proof = as_unlock = (vault_service.Denied, "the passkey check failed")
    else:
        doc["slots"] = [old_form(s, dek, der_of(a)) if s["type"] == store.PAIR else s
                        for s in doc["slots"]]
        write_doc(doc)
        # No reader for the old form: the wrap now binds `public_key`, and no `cose_key` is there.
        as_proof = (store.VaultError, "public key does not decrypt")
        as_unlock = (store.VaultError, "wrong unlock password")
    with pytest.raises(as_proof[0], match=as_proof[1]):
        svc.add_passkey("c1", RP, "c2FsdA", PRF, None, pair_proof(svc, a))
    svc.lock()
    with pytest.raises(as_unlock[0], match=as_unlock[1]):
        unlock_pair(svc, a)
    assert is_locked(svc)
    assert [s["type"] for s in vault_doc()["slots"]] == ["recovery", store.PAIR]


@pytest.mark.parametrize("field, value", [("cred_id", b64u(b"forged")), ("rp_id", "evil.example"),
                                          ("origin", "https://evil.example")])
def test_an_edited_clear_field_fails_at_unlock_and_as_a_proof(svc, field, value):
    a = add_pair(svc)
    edit_slot(**{field: value})
    with pytest.raises(store.VaultError, match="does not decrypt"):
        svc.add_passkey("c1", RP, "c2FsdA", PRF, None, pair_proof(svc, a))
    svc.lock()
    with pytest.raises(store.VaultError, match="wrong unlock password"):
        unlock_pair(svc, a)
    assert is_locked(svc)


def test_a_slot_retyped_as_password_does_not_open(svc):
    add_pair(svc)
    edit_slot(type="password")
    svc.lock()
    with pytest.raises(store.VaultError, match="wrong unlock password"):
        svc.unlock_password(PAIR_PASSWORD)
    assert is_locked(svc)


def test_a_raised_sign_count_stops_this_method_alone_and_counts_nothing(svc, clock):
    add_app(svc, clock)
    a = add_pair(svc)
    edit_slot(sign_count=2**31)
    svc.lock()
    for _ in range(6):
        with pytest.raises(vault_service.Denied, match="the passkey check failed"):
            unlock_pair(svc, a)
    assert svc._wrong_codes == 0 and is_locked(svc)
    svc.unlock_password(UNLOCK, clock.code())
    assert not is_locked(svc)


def test_five_wrong_codes_stop_no_passkey_check(svc, clock):
    add_app(svc, clock)
    a = add_pair(svc)
    svc.lock()
    for _ in range(vault_service.MAX_WRONG_CODES):
        with pytest.raises(vault_service.Denied, match="^wrong code$"):
            svc.unlock_password(UNLOCK, "000000")
    # The rule of wrong codes is unchanged: a right code is now refused.
    with pytest.raises(vault_service.Denied, match="^too many wrong codes"):
        svc.unlock_password(UNLOCK, clock.code())
    unlock_pair(svc, a)
    assert not is_locked(svc) and svc._wrong_codes == 0


# --------------------------------------------------------------------------- #
# the challenge and the unlock
# --------------------------------------------------------------------------- #


def test_a_challenge_is_32_random_bytes_kept_only_in_memory(svc):
    first, second = svc.challenge()["challenge"], svc.challenge()["challenge"]
    assert len(first) == 43 and len(store.b64url_decode(first)) == 32 and first != second
    assert first not in json.dumps(vault_doc()) and second not in json.dumps(vault_doc())
    assert svc._challenge[0] == second


def test_the_sign_count_is_written_back_and_a_failed_write_fails_no_unlock(svc, monkeypatch, caplog):
    a = add_pair(svc)
    svc.lock()
    unlock_pair(svc, a, count=5)
    assert pair_slot()["sign_count"] == 5
    svc.lock()
    monkeypatch.setattr(store, "set_sign_count", lambda *x: (_ for _ in ()).throw(OSError("full")))
    unlock_pair(svc, a, count=6)
    assert not is_locked(svc)
    assert "could not record the passkey's sign count" in caplog.text
    assert pair_slot()["sign_count"] == 5


def test_a_request_with_no_live_challenge_reaches_no_argon2id(svc, monkeypatch):
    a = add_pair(svc)
    svc.lock()
    assertion = a.assertion(svc.challenge()["challenge"])
    svc._take_challenge()

    def kek(*args):
        raise AssertionError("Argon2id ran for a request with no live challenge")

    monkeypatch.setattr(store, "_kek", kek)
    with pytest.raises(vault_service.Denied, match="the passkey check failed"):
        svc.unlock_pair(PAIR_PASSWORD, assertion)


def test_a_forged_check_leaves_the_vault_locked_and_runs_no_unlock_step(svc, monkeypatch):
    add_pair(svc)
    svc.lock()
    finished = []
    monkeypatch.setattr(svc, "_finish_unlock", lambda *x: finished.append(x))
    with pytest.raises(vault_service.Denied):
        unlock_pair(svc, Authenticator())
    assert finished == [] and is_locked(svc)


def test_a_refused_request_uses_its_challenge_up(svc):
    a = add_pair(svc)
    svc.lock()
    # A signature of another key, then the right signature over the same challenge.
    c = svc.challenge()["challenge"]
    with pytest.raises(vault_service.Denied, match="the passkey check failed"):
        svc.unlock_pair(PAIR_PASSWORD, a.assertion(c, signer=Authenticator()))
    with pytest.raises(vault_service.Denied, match="the passkey check failed"):
        svc.unlock_pair(PAIR_PASSWORD, a.assertion(c))
    assert is_locked(svc)
    # A wrong password, then the right password with the same assertion: one passkey
    # touch tries one password.
    good = a.assertion(svc.challenge()["challenge"])
    with pytest.raises(store.VaultError, match="wrong unlock password"):
        svc.unlock_pair("wrong", good)
    with pytest.raises(vault_service.Denied, match="the passkey check failed"):
        svc.unlock_pair(PAIR_PASSWORD, good)
    assert is_locked(svc)


# --------------------------------------------------------------------------- #
# the proof
# --------------------------------------------------------------------------- #


def test_a_verified_assertion_proves_an_add_a_pair_a_recovery_change_and_a_reveal(svc, clock):
    a = add_pair(svc)
    svc.add("github/api", {"password": SECRET})
    svc.add_passkey("c1", RP, "c2FsdA", PRF, None, pair_proof(svc, a))
    svc.add_mfa(UNLOCK, APP_KEY, clock.code(), pair_proof(svc, a))
    clock.advance(1)
    svc.replace_recovery("a new recovery passphrase", pair_proof(svc, a))
    assert svc.reveal_proven("github/api", pair_proof(svc, a)) == SECRET
    types = [s["type"] for s in vault_doc()["slots"]]
    assert types == ["recovery", store.PAIR, "passkey", "password"]
    svc.lock()
    svc.unlock_recovery("a new recovery passphrase")


def test_rotation_refuses_a_passkey_with_no_prf(svc):
    a = add_pair(svc)
    before = vault_doc()["data_key"]
    with pytest.raises(vault_service.Denied, match=r"^a passkey with no PRF is no proof for this - "
                       r"use a passkey with PRF or the recovery passphrase$"):
        svc.rotate(pair_proof(svc, a))
    assert vault_doc()["data_key"] == before


def test_on_a_locked_vault_the_proof_answers_locked_and_keeps_the_challenge(svc):
    a = add_pair(svc)
    svc.lock()
    proof = pair_proof(svc, a)
    live = svc._challenge
    with pytest.raises(vault_service.Locked):
        svc.add_passkey("c1", RP, "c2FsdA", PRF, None, proof)
    assert svc._challenge == live


def test_this_methods_password_alone_is_no_proof_and_shows_nothing(svc, clock):
    add_pair(svc)
    svc.add("github/api", {"password": SECRET})
    proof = {"password": PAIR_PASSWORD}
    with pytest.raises(vault_service.Denied):
        svc.reveal_proven("github/api", proof)
    with pytest.raises(vault_service.Denied):
        svc.add_passkey("c1", RP, "c2FsdA", PRF, None, proof)
    # With an app pair too, the reveal reads the app's password slot, not this one.
    add_app(svc, clock)
    with pytest.raises(vault_service.Denied, match="wrong unlock password"):
        svc.reveal_proven("github/api", {"password": PAIR_PASSWORD})


def test_the_app_pair_proves_as_before_with_the_method_present(svc, clock):
    # ACC-UNLOCK-219 and the 409 of ACC-UNLOCK-218 hold with Password and passkey present.
    add_pair(svc)
    add_app(svc, clock)
    svc.add("github/api", {"password": SECRET})
    assert svc.reveal_proven("github/api", {"code": clock.code()}) == SECRET
    clock.advance(1)
    svc.add_passkey("c1", RP, "c2FsdA", PRF, None, {"code": clock.code()})
    clock.advance(1)
    svc.replace_recovery("a new recovery passphrase", {"code": clock.code()})
    clock.advance(1)
    assert svc.reveal_proven("github/api", {"password": UNLOCK}) == SECRET
    with pytest.raises(vault_service.Denied):
        svc.add_passkey("c2", RP, "c2FsdA", PRF, None, {"password": UNLOCK})
    with pytest.raises(vault_service.Conflict, match="already has a password and authenticator app"):
        svc.add_mfa(UNLOCK + "x", APP_KEY, clock.code(), {"current": "a new recovery passphrase"})
    assert [s["type"] for s in vault_doc()["slots"]] == ["recovery", store.PAIR, "password", "passkey"]


# --------------------------------------------------------------------------- #
# adding the method
# --------------------------------------------------------------------------- #


def test_a_second_method_answers_conflict_and_the_file_stays(svc):
    add_pair(svc)
    before = open(store.vault_path()).read()
    with pytest.raises(vault_service.Conflict, match="already has a password and passkey"):
        add_pair(svc, Authenticator(cred="second"))
    assert open(store.vault_path()).read() == before


@pytest.mark.parametrize("proof, error", [
    ({"current": PASS + "x"}, "wrong recovery passphrase"),
    (None, "this needs a proof"),
])
def test_a_wrong_proof_or_a_short_password_adds_nothing(svc, proof, error):
    before = open(store.vault_path()).read()
    a = Authenticator()
    challenge = svc.challenge()["challenge"]
    with pytest.raises(vault_service.Denied, match=error):
        svc.add_pair(PAIR_PASSWORD, b64u(a.cred.encode()), RP, a.registration(challenge), None,
                     a.assertion(challenge), proof)
    with pytest.raises(store.VaultError, match="at least 12 characters"):
        add_pair(svc, password="short")
    assert open(store.vault_path()).read() == before


ADD_REFUSED = {
    "a signature of another key than the attested one": (dict(), dict(signer=Authenticator())),
    "a registration over another challenge": (dict(challenge=b64u(os.urandom(32))), dict()),
    "a registration with no user verification": (dict(flags=0x41), dict()),
    "a registration of another credential id": (dict(cred="another credential"), dict()),
    "a registration of a P-384 key": (dict(cose=ES384.from_cryptography_key(
        ec.generate_private_key(ec.SECP384R1()).public_key())), dict()),
    "a registration at another origin than the signature":
        (dict(origin="https://lab.example:9443"), dict()),
    "a public key in place of a registration": (None, dict()),
}


@pytest.mark.parametrize("case", sorted(ADD_REFUSED))
def test_an_add_whose_registration_or_signature_does_not_verify_stores_nothing(svc, case):
    before = open(store.vault_path()).read()
    a = Authenticator()
    created, signed = ADD_REFUSED[case]
    challenge = svc.challenge()["challenge"]
    created = None if created is None else dict(created)
    registration = a.public_key if created is None else a.registration(
        created.pop("challenge", challenge), **created)
    with pytest.raises(vault_service.Denied, match="the passkey check failed"):
        svc.add_pair(PAIR_PASSWORD, b64u(a.cred.encode()), RP, registration, None,
                     a.assertion(challenge, **signed), {"current": PASS})
    assert open(store.vault_path()).read() == before


def test_an_assertion_proof_does_not_add_the_method(svc):
    a = Authenticator()
    challenge = svc.challenge()["challenge"]
    with pytest.raises(vault_service.Denied):
        svc.add_pair(PAIR_PASSWORD, b64u(a.cred.encode()), RP, a.registration(challenge), None,
                     a.assertion(challenge), {"assertion": a.assertion(challenge)})
    assert [s["type"] for s in vault_doc()["slots"]] == ["recovery"]


def test_a_version_one_vault_is_adopted_before_the_slot_is_added(vault_env):
    path = vault_env / "vault" / "vault.json"
    _version_one_vault_held_by_its_root(vault_env)
    svc = handlers._service
    a = add_pair(svc)
    after = store.load(str(path))
    assert after["version"] == 2 and [s["type"] for s in after["slots"]][-1] == store.PAIR
    assert svc.read("fixture-entry") == "fixture-password"
    svc.lock()
    unlock_pair(svc, a)
    assert svc.read("fixture-entry") == "fixture-password"


# --------------------------------------------------------------------------- #
# through the REST API
# --------------------------------------------------------------------------- #


async def call(jp_fetch, action, body=None, method="POST", **kw):
    args = {"method": method, **kw}
    if method != "GET":
        args["body"] = json.dumps(body if body is not None else {})
    r = await jp_fetch("jupyterlab-passkey-extension", "vault", action, **args)
    return json.loads(r.body) if r.body else None


async def fails(jp_fetch, action, body=None, **kw):
    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await call(jp_fetch, action, body, **kw)
    body = exc.value.response.body
    return exc.value.code, (json.loads(body).get("error") if body else None)


async def challenge(jp_fetch):
    return (await call(jp_fetch, "challenge"))["challenge"]


async def rest_pair(jp_fetch, a, proof=None):
    c = await challenge(jp_fetch)
    await call(jp_fetch, "password-passkey", {
        "password": PAIR_PASSWORD, "cred_id": b64u(a.cred.encode()), "rp_id": RP,
        "registration": a.registration(c), "label": "laptop", "assertion": a.assertion(c),
        "proof": proof or {"current": PASS}})


async def test_the_rest_unlock_answers_each_refusal_with_its_status(jp_fetch, vault_env):
    await call(jp_fetch, "init", {"recovery": PASS})
    a = Authenticator()
    await rest_pair(jp_fetch, a)
    await call(jp_fetch, "lock")
    unlock = lambda c, password=PAIR_PASSWORD, **kw: {  # noqa: E731
        "password": password, "assertion": a.assertion(c, **kw)}
    # A wrong password: 400, as with the app pair.
    assert await fails(jp_fetch, "unlock", unlock(await challenge(jp_fetch), "wrong")) == (
        400, "wrong unlock password")
    # A forged signature with the right password: 403, locked.
    c = await challenge(jp_fetch)
    assert await fails(jp_fetch, "unlock", unlock(c, signer=Authenticator())) == CHECK_FAILED
    # A superseded challenge: the request uses up the live one too.
    first = await challenge(jp_fetch)
    await challenge(jp_fetch)
    assert await fails(jp_fetch, "unlock", unlock(first)) == CHECK_FAILED
    assert handlers._service._wrong_codes == 0
    # Malformed client data answers 403, never 500.
    for client in (b'{"challenge": "\\ud800"}', b"[1]", b'"s"', b"5"):
        c = await challenge(jp_fetch)
        assert await fails(jp_fetch, "unlock", {"password": PAIR_PASSWORD,
                                                "assertion": a.assertion(c, client=client)}) == CHECK_FAILED
    assert (await call(jp_fetch, "status", method="GET"))["unlocked"] is False
    # A replay of a good assertion: the first use unlocks, the second is refused.
    good = unlock(await challenge(jp_fetch))
    assert (await call(jp_fetch, "unlock", good))["unlocked"] is True
    await call(jp_fetch, "lock")
    assert await fails(jp_fetch, "unlock", good) == CHECK_FAILED
    # A third, fresh challenge unlocks.
    assert (await call(jp_fetch, "unlock", unlock(await challenge(jp_fetch))))["unlocked"] is True


async def test_an_expired_challenge_is_refused(jp_fetch, vault_env, monkeypatch):
    await call(jp_fetch, "init", {"recovery": PASS})
    a = Authenticator()
    await rest_pair(jp_fetch, a)
    await call(jp_fetch, "lock")

    class Stopped:
        now = 1000.0

        def monotonic(self):
            return self.now

    stopped = Stopped()
    monkeypatch.setattr(vault_service, "time", stopped)
    c = await challenge(jp_fetch)
    # The lifetime is 600 s, written here as a number so a changed constant fails.
    stopped.now += 600
    assert await fails(jp_fetch, "unlock", {"password": PAIR_PASSWORD,
                                            "assertion": a.assertion(c)}) == CHECK_FAILED
    c = await challenge(jp_fetch)
    stopped.now += 599
    assert (await call(jp_fetch, "unlock", {"password": PAIR_PASSWORD,
                                            "assertion": a.assertion(c)}))["unlocked"] is True


async def test_six_forged_checks_count_nothing_and_the_app_pair_still_opens(jp_fetch, vault_env, clock):
    await call(jp_fetch, "init", {"recovery": PASS})
    await call(jp_fetch, "mfa", {"password": UNLOCK, "secret": APP_KEY, "code": clock.code(),
                                 "proof": {"current": PASS}})
    clock.advance(1)
    a = Authenticator()
    await rest_pair(jp_fetch, a)
    await call(jp_fetch, "lock")
    for _ in range(6):
        c = await challenge(jp_fetch)
        assert await fails(jp_fetch, "unlock", {"password": PAIR_PASSWORD,
                                                "assertion": a.assertion(c, signer=Authenticator())}) == CHECK_FAILED
    assert handlers._service._wrong_codes == 0
    for body in ({"password": PAIR_PASSWORD}, {"password": UNLOCK}):
        code, _ = await fails(jp_fetch, "unlock", body)
        assert code in (400, 403)
    assert (await call(jp_fetch, "status", method="GET"))["unlocked"] is False
    s = await call(jp_fetch, "unlock", {"password": UNLOCK, "code": clock.code()})
    assert s["unlocked"] is True


async def test_the_origin_is_the_stored_one_whatever_the_request_headers_say(jp_fetch, vault_env):
    await call(jp_fetch, "init", {"recovery": PASS})
    a = Authenticator()
    await rest_pair(jp_fetch, a)
    await call(jp_fetch, "lock")
    c = await challenge(jp_fetch)
    other = "https://lab.example:9443"
    assert await fails(jp_fetch, "unlock", {"password": PAIR_PASSWORD,
                                            "assertion": a.assertion(c, origin=other)},
                       headers={"X-Forwarded-Host": "lab.example:9443",
                                "Origin": other}) == CHECK_FAILED


async def test_the_rest_add_and_remove(jp_fetch, vault_env):
    await call(jp_fetch, "init", {"recovery": PASS})
    a = Authenticator()
    # A public key the page states, with no registration to take it from: 403, never 500.
    c = await challenge(jp_fetch)
    assert await fails(jp_fetch, "password-passkey", {
        "password": PAIR_PASSWORD, "cred_id": b64u(a.cred.encode()), "rp_id": RP,
        "public_key": a.public_key, "assertion": a.assertion(c),
        "proof": {"current": PASS}}) == CHECK_FAILED
    await rest_pair(jp_fetch, a)
    other = Authenticator(cred="other")
    c = await challenge(jp_fetch)
    assert await fails(jp_fetch, "password-passkey", {
        "password": PAIR_PASSWORD, "cred_id": b64u(b"other"), "rp_id": RP,
        "registration": other.registration(c), "assertion": other.assertion(c),
        "proof": {"current": PASS}}) == (409, "the vault already has a password and passkey - "
                                              "remove them first")
    s = await call(jp_fetch, "status", method="GET")
    row = [x for x in s["slots"] if x["type"] == store.PAIR]
    assert len(row) == 1 and not {"cose_key", "wrapped", "salt"} & set(row[0])
    await call(jp_fetch, "passkeys-remove", {"cred_id": row[0]["cred_id"]})
    s = await call(jp_fetch, "status", method="GET")
    assert [x["type"] for x in s["slots"]] == ["recovery"]


async def test_a_rest_reveal_takes_the_assertion_as_its_proof(jp_fetch, vault_env):
    await call(jp_fetch, "init", {"recovery": PASS})
    a = Authenticator()
    await rest_pair(jp_fetch, a)
    await call(jp_fetch, "entries", {"name": "github/api", "fields": {"password": SECRET}})
    c = await challenge(jp_fetch)
    assert (await call(jp_fetch, "reveal", {"name": "github/api",
                                            "assertion": a.assertion(c)}))["value"] == SECRET
    c = await challenge(jp_fetch)
    assert await fails(jp_fetch, "reveal", {"name": "github/api",
                                            "assertion": a.assertion(c, signer=Authenticator())}) == CHECK_FAILED
