import json
import logging
import os
import stat

import pytest
import tornado.httpclient
from jupyter_server.utils import url_path_join

from jupyterlab_passkey_extension.routes import ensure_relay_dir, write_relay

# A nonce that satisfies the handler's ^[A-Za-z0-9_-]{16,128}$ guard.
VALID_NONCE = "test_nonce_ABCDEF0123456789-_"


@pytest.fixture
def relay_dir(tmp_path, monkeypatch):
    """Point the handler's relay directory at a fresh path under tmp_path."""
    d = tmp_path / "relay"
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(d))
    return d


async def test_result_valid_post_writes_relay_file(jp_fetch, relay_dir):
    body = {
        "nonce": VALID_NONCE,
        "ok": True,
        "cred_id": "Y3JlZF9pZA",
        "prf": "cHJmX3ZhbHVl",
    }

    response = await jp_fetch(
        "jupyterlab-passkey-extension", "result",
        method="POST", body=json.dumps(body),
    )

    assert response.code == 204
    relay_file = relay_dir / f"{VALID_NONCE}.json"
    assert relay_file.exists()
    assert stat.S_IMODE(os.stat(relay_file).st_mode) == 0o600
    assert json.loads(relay_file.read_text()) == body


# "../" + 16 valid chars has a >=16-char valid RUN, so a re.fullmatch -> re.search
# regression (or a widened char class) would accept it while fullmatch rejects the
# leading "../" - the short inputs alone would not catch that.
@pytest.mark.parametrize(
    "bad_nonce", ["../../etc/evil", "a/b", "../aaaaaaaaaaaaaaaa", "aaaaaaaa aaaaaaaa"]
)
async def test_result_rejects_traversal_nonce(jp_fetch, relay_dir, bad_nonce):
    body = {"nonce": bad_nonce, "ok": True, "cred_id": "Y3JlZF9pZA"}

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch(
            "jupyterlab-passkey-extension", "result",
            method="POST", body=json.dumps(body),
        )

    assert exc.value.code == 400
    # Validation happens before makedirs, so the relay dir is never created
    # and no file is written anywhere (in tmp or outside it).
    assert not relay_dir.exists()


async def test_result_rejects_short_nonce(jp_fetch, relay_dir):
    body = {"nonce": "short", "ok": True, "cred_id": "Y3JlZF9pZA"}

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch(
            "jupyterlab-passkey-extension", "result",
            method="POST", body=json.dumps(body),
        )

    assert exc.value.code == 400
    assert not relay_dir.exists()


async def test_result_rejects_trailing_newline_nonce(jp_fetch, relay_dir):
    # re.fullmatch (not `$`) must reject a nonce with a trailing newline, which
    # Python's `$` anchor would otherwise accept.
    body = {"nonce": VALID_NONCE + "\n", "ok": True, "cred_id": "Y3JlZF9pZA"}

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch(
            "jupyterlab-passkey-extension", "result",
            method="POST", body=json.dumps(body),
        )

    assert exc.value.code == 400
    assert not relay_dir.exists()


async def test_health_ok(jp_fetch):
    response = await jp_fetch("jupyterlab-passkey-extension", "health")

    assert response.code == 200
    assert json.loads(response.body) == {"ok": True}


async def test_prf_not_logged(jp_fetch, relay_dir, caplog):
    prf_secret = "PRF_SECRET_MUST_NOT_BE_LOGGED_ZZZ"
    body = {"nonce": VALID_NONCE, "ok": True, "cred_id": "Y3JlZF9pZA", "prf": prf_secret}

    # Capture at DEBUG on the root logger so a future body-logging regression at
    # any level (not just INFO) trips this guard on the extension's central
    # secret-protection invariant.
    with caplog.at_level(logging.DEBUG):
        response = await jp_fetch(
            "jupyterlab-passkey-extension", "result",
            method="POST", body=json.dumps(body),
        )

    assert response.code == 204
    assert prf_secret not in caplog.text


async def test_unauthenticated_post_forbidden(http_server_client, jp_base_url, relay_dir):
    # http_server_client hits 127.0.0.1:<port> with NO auth token, so the
    # @authenticated + XSRF protection must reject the POST.
    path = url_path_join(jp_base_url, "jupyterlab-passkey-extension", "result")
    body = {"nonce": VALID_NONCE, "ok": True, "cred_id": "Y3JlZF9pZA"}

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await http_server_client.fetch(path, method="POST", body=json.dumps(body))

    assert exc.value.code == 403
    assert not relay_dir.exists()


@pytest.mark.parametrize("body", ["[1, 2, 3]", '"a string"', "null"])
async def test_result_rejects_non_dict_body(jp_fetch, relay_dir, body):
    # Valid JSON that is not an object has no nonce -> 400, nothing written.
    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch(
            "jupyterlab-passkey-extension", "result", method="POST", body=body,
        )

    assert exc.value.code == 400
    assert not relay_dir.exists()


async def test_result_rejects_missing_nonce(jp_fetch, relay_dir):
    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch(
            "jupyterlab-passkey-extension", "result",
            method="POST", body=json.dumps({"ok": True}),
        )

    assert exc.value.code == 400
    assert not relay_dir.exists()


async def test_result_accepts_max_length_nonce(jp_fetch, relay_dir):
    nonce = "a" * 128  # upper bound of {16,128}
    response = await jp_fetch(
        "jupyterlab-passkey-extension", "result",
        method="POST", body=json.dumps({"nonce": nonce, "ok": True}),
    )

    assert response.code == 204
    assert (relay_dir / f"{nonce}.json").exists()


async def test_result_accepts_min_length_nonce(jp_fetch, relay_dir):
    nonce = "a" * 16  # lower bound of {16,128}
    response = await jp_fetch(
        "jupyterlab-passkey-extension", "result",
        method="POST", body=json.dumps({"nonce": nonce, "ok": True}),
    )

    assert response.code == 204
    assert (relay_dir / f"{nonce}.json").exists()


async def test_result_rejects_15_char_nonce(jp_fetch, relay_dir):
    nonce = "a" * 15  # one below the {16,128} lower bound
    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch(
            "jupyterlab-passkey-extension", "result",
            method="POST", body=json.dumps({"nonce": nonce, "ok": True}),
        )

    assert exc.value.code == 400
    assert not relay_dir.exists()


async def test_result_rejects_overlong_nonce(jp_fetch, relay_dir):
    nonce = "a" * 129  # one past the {16,128} bound
    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch(
            "jupyterlab-passkey-extension", "result",
            method="POST", body=json.dumps({"nonce": nonce, "ok": True}),
        )

    assert exc.value.code == 400
    assert not relay_dir.exists()


async def test_result_relay_is_one_shot_overwrite(jp_fetch, relay_dir):
    # Two POSTs on the same nonce: os.replace overwrites atomically, so only the
    # latest body survives (the relay is one-shot, never appended).
    first = {"nonce": VALID_NONCE, "ok": False, "error": "not-allowed"}
    second = {"nonce": VALID_NONCE, "ok": True, "cred_id": "Y3JlZF9pZA"}

    r1 = await jp_fetch(
        "jupyterlab-passkey-extension", "result", method="POST", body=json.dumps(first),
    )
    r2 = await jp_fetch(
        "jupyterlab-passkey-extension", "result", method="POST", body=json.dumps(second),
    )

    assert r1.code == 204 and r2.code == 204
    relay_file = relay_dir / f"{VALID_NONCE}.json"
    assert json.loads(relay_file.read_text()) == second
    # The rewritten relay must still be 0600 - a 0644-on-overwrite regression
    # would leak the secret-bearing file to other users sharing the box.
    assert stat.S_IMODE(os.stat(relay_file).st_mode) == 0o600


async def test_relay_dir_is_private(jp_fetch, relay_dir):
    await jp_fetch(
        "jupyterlab-passkey-extension", "result",
        method="POST", body=json.dumps({"nonce": VALID_NONCE, "ok": True}),
    )

    assert stat.S_IMODE(os.stat(relay_dir).st_mode) == 0o700


async def test_health_requires_auth(http_server_client, jp_base_url):
    # health is @authenticated too - an unauthenticated GET must be refused.
    path = url_path_join(jp_base_url, "jupyterlab-passkey-extension", "health")

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await http_server_client.fetch(path)

    assert exc.value.code == 403


PASSPHRASE = "correct horse battery staple"


async def test_passphrase_writes_raw_relay_file(jp_fetch, relay_dir):
    body = {"nonce": VALID_NONCE, "passphrase": PASSPHRASE}

    response = await jp_fetch(
        "jupyterlab-passkey-extension", "passphrase",
        method="POST", body=json.dumps(body),
    )

    assert response.code == 204
    relay_file = relay_dir / f"{VALID_NONCE}.pass"
    assert relay_file.exists()
    assert stat.S_IMODE(os.stat(relay_file).st_mode) == 0o600
    # Written raw: no JSON envelope and no trailing newline, so a consumer can
    # use the file directly as PASS_RECOVERY_FILE.
    assert relay_file.read_text() == PASSPHRASE


async def test_passphrase_preserves_exact_bytes(jp_fetch, relay_dir):
    # Whitespace and unicode must survive byte-for-byte - a passphrase that is
    # silently trimmed or re-encoded would derive the wrong key.
    tricky = "  leading and trailing  \t spaces éü \n embedded"
    await jp_fetch(
        "jupyterlab-passkey-extension", "passphrase",
        method="POST", body=json.dumps({"nonce": VALID_NONCE, "passphrase": tricky}),
    )

    assert (relay_dir / f"{VALID_NONCE}.pass").read_text() == tricky


@pytest.mark.parametrize(
    "bad_nonce", ["../../etc/evil", "a/b", "../aaaaaaaaaaaaaaaa", "aaaaaaaa aaaaaaaa"]
)
async def test_passphrase_rejects_traversal_nonce(jp_fetch, relay_dir, bad_nonce):
    body = {"nonce": bad_nonce, "passphrase": PASSPHRASE}

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch(
            "jupyterlab-passkey-extension", "passphrase",
            method="POST", body=json.dumps(body),
        )

    assert exc.value.code == 400
    assert not relay_dir.exists()


@pytest.mark.parametrize("passphrase", ["", None, 123, ["a"]])
async def test_passphrase_rejects_missing_or_non_string(
    jp_fetch, relay_dir, passphrase
):
    # An empty or non-string passphrase is a client bug, not a valid secret.
    body = {"nonce": VALID_NONCE, "passphrase": passphrase}

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch(
            "jupyterlab-passkey-extension", "passphrase",
            method="POST", body=json.dumps(body),
        )

    assert exc.value.code == 400
    assert not relay_dir.exists()


async def test_passphrase_requires_auth(http_server_client, jp_base_url, relay_dir):
    path = url_path_join(jp_base_url, "jupyterlab-passkey-extension", "passphrase")
    body = {"nonce": VALID_NONCE, "passphrase": PASSPHRASE}

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await http_server_client.fetch(path, method="POST", body=json.dumps(body))

    assert exc.value.code == 403
    assert not relay_dir.exists()


async def test_passphrase_not_logged(jp_fetch, relay_dir, caplog):
    secret = "PASSPHRASE_MUST_NOT_BE_LOGGED_ZZZ"
    body = {"nonce": VALID_NONCE, "passphrase": secret}

    with caplog.at_level(logging.DEBUG):
        response = await jp_fetch(
            "jupyterlab-passkey-extension", "passphrase",
            method="POST", body=json.dumps(body),
        )

    assert response.code == 204
    assert secret not in caplog.text


async def test_write_relay_leaves_no_partial_secret_when_the_write_fails(relay_dir, monkeypatch):
    # A full /dev/shm would otherwise leave the mkstemp temp behind holding a PARTIAL
    # secret at 0600 - under a dot-name nothing collects and nothing cleans. Guarded
    # in relay.write_relay, and without this the guard could be deleted tomorrow
    # with every other test still green.
    import jupyterlab_passkey_extension.relay as relay_mod

    def boom(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(relay_mod.os, "replace", boom)

    with pytest.raises(OSError):
        write_relay(VALID_NONCE, f"{VALID_NONCE}.secret", "a-partial-secret")

    assert os.listdir(relay_dir) == []


async def test_result_handler_answers_a_relay_failure_with_a_clean_500(jp_fetch, monkeypatch):
    # A keyctl quota, a missing keyctl binary, or a squatted shm dir raises OSError out
    # of stage. The CLI turns that into a one-line message; the server must answer with
    # a handled 500, not a Tornado traceback in the Jupyter log.
    import jupyterlab_passkey_extension.relay as relay_mod

    def boom(*a, **k):
        raise OSError("relay backend down")

    monkeypatch.setattr(relay_mod, "stage", boom)

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch(
            "jupyterlab-passkey-extension", "result",
            method="POST", body=json.dumps({"nonce": VALID_NONCE, "ok": True}),
        )
    assert exc.value.code == 500
    # The HANDLED body, which an unhandled exception's default 500 page would not carry -
    # this is what distinguishes a caught failure from a Tornado traceback. The detail
    # (and certainly no secret) is never in it.
    body = exc.value.response.body.decode()
    assert "relay backend unavailable" in body
    assert "relay backend down" not in body


async def test_secret_handler_answers_a_relay_failure_with_a_clean_500(jp_fetch, monkeypatch):
    import jupyterlab_passkey_extension.relay as relay_mod

    def boom(*a, **k):
        raise OSError("relay backend down")

    monkeypatch.setattr(relay_mod, "collect", boom)

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch(
            "jupyterlab-passkey-extension", "secret",
            method="POST", body=json.dumps({"nonce": VALID_NONCE}),
        )
    assert exc.value.code == 500
    body = exc.value.response.body.decode()
    assert "relay backend unavailable" in body
    assert "relay backend down" not in body


async def test_passphrase_handler_answers_a_relay_failure_with_a_clean_500(jp_fetch, monkeypatch):
    # The third staging handler, guarded identically: a forced-but-broken keyctl (or a
    # quota / squatted dir) raising OSError out of stage must answer with the handled
    # 500, never a Tornado traceback carrying the passphrase.
    import jupyterlab_passkey_extension.relay as relay_mod

    def boom(*a, **k):
        raise OSError("relay backend down")

    monkeypatch.setattr(relay_mod, "stage", boom)

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await jp_fetch(
            "jupyterlab-passkey-extension", "passphrase",
            method="POST", body=json.dumps({"nonce": VALID_NONCE, "passphrase": PASSPHRASE}),
        )
    assert exc.value.code == 500
    body = exc.value.response.body.decode()
    assert "relay backend unavailable" in body
    assert "relay backend down" not in body
    assert PASSPHRASE not in body


# --- secret: the one handler that reads a relay out rather than writing one in ---

SECRET_VALUE = "s3cr3t-token-value"


def _stage(nonce, value):
    """Put a secret where `jupyterlab-passkey copy` would have staged it."""
    write_relay(nonce, f"{nonce}.secret", value)


async def _collect(jp_fetch, nonce):
    return await jp_fetch(
        "jupyterlab-passkey-extension", "secret",
        method="POST", body=json.dumps({"nonce": nonce}),
    )


async def test_secret_is_handed_over_once_and_then_gone(jp_fetch, relay_dir):
    _stage(VALID_NONCE, SECRET_VALUE)

    response = await _collect(jp_fetch, VALID_NONCE)

    assert response.code == 200
    assert json.loads(response.body)["value"] == SECRET_VALUE
    # Collected means spent: nothing is left for a second collector to find, which is
    # what keeps an uncollected secret from outliving the click that wanted it.
    assert not (relay_dir / f"{VALID_NONCE}.secret").exists()

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await _collect(jp_fetch, VALID_NONCE)
    assert exc.value.code == 404


async def test_secret_preserves_exact_bytes(jp_fetch, relay_dir):
    # A token is opaque - trailing spaces, tabs and non-ASCII are all somebody's key.
    tricky = "  lead & trail\ttab\nnewline\néé中  "
    _stage(VALID_NONCE, tricky)

    response = await _collect(jp_fetch, VALID_NONCE)

    assert json.loads(response.body)["value"] == tricky


async def test_secret_404s_when_nothing_was_staged(jp_fetch, relay_dir):
    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await _collect(jp_fetch, VALID_NONCE)

    assert exc.value.code == 404


@pytest.mark.parametrize(
    "bad_nonce", ["../../etc/passwd", "a/b", "../aaaaaaaaaaaaaaaa", "aaaaaaaa aaaaaaaa"]
)
async def test_secret_rejects_traversal_nonce(jp_fetch, relay_dir, bad_nonce):
    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await _collect(jp_fetch, bad_nonce)

    assert exc.value.code == 400


async def test_secret_traversal_neither_reads_nor_unlinks_an_outside_file(
    jp_fetch, relay_dir, tmp_path
):
    # This is the only handler that turns a nonce into a path it READS and then
    # UNLINKS. A guard regression here would not merely write a stray file, it would
    # hand out an arbitrary one and delete it on the way. Prove both halves are out
    # of reach, not just the status code.
    outside = tmp_path / "outside_aaaaaaaaaaaa.secret"
    outside.write_text("NOT_YOURS")

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await _collect(jp_fetch, "../outside_aaaaaaaaaaaa")

    assert exc.value.code == 400
    assert outside.read_text() == "NOT_YOURS"


async def test_secret_requires_auth(http_server_client, jp_base_url, relay_dir):
    _stage(VALID_NONCE, SECRET_VALUE)
    path = url_path_join(jp_base_url, "jupyterlab-passkey-extension", "secret")

    with pytest.raises(tornado.httpclient.HTTPClientError) as exc:
        await http_server_client.fetch(
            path, method="POST", body=json.dumps({"nonce": VALID_NONCE})
        )

    assert exc.value.code == 403
    # A rejected caller must not consume it either - the secret is still there for
    # the click that is entitled to it.
    assert (relay_dir / f"{VALID_NONCE}.secret").read_text() == SECRET_VALUE


async def test_secret_not_logged(jp_fetch, relay_dir, caplog):
    secret = "SECRET_MUST_NOT_BE_LOGGED_ZZZ"
    _stage(VALID_NONCE, secret)

    with caplog.at_level(logging.DEBUG):
        response = await _collect(jp_fetch, VALID_NONCE)

    assert response.code == 200
    assert secret not in caplog.text


def test_ensure_relay_dir_refuses_a_symlinked_relay_path(tmp_path, monkeypatch):
    """A co-tenant who gets to the predictable path first must not receive our secrets.

    /dev/shm is 1777, so pre-creating /dev/shm/jlab-passkey-<uid> as a symlink is
    something any local user can do. `makedirs(exist_ok=True)` follows it without a
    word, and every .pass and .secret then lands in the attacker's directory - which
    is exactly what this used to do.
    """
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    squatted = tmp_path / "relay"
    squatted.symlink_to(attacker)
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(squatted))

    with pytest.raises(PermissionError, match="squatting the relay path"):
        ensure_relay_dir()

    # The point of the check, not a side effect: nothing may reach the attacker.
    with pytest.raises(PermissionError):
        write_relay(VALID_NONCE, f"{VALID_NONCE}.secret", "hunter2")
    assert list(attacker.iterdir()) == []


def test_ensure_relay_dir_refuses_a_dangling_symlink_with_the_same_diagnosis(tmp_path, monkeypatch):
    """A symlink to nothing is the same squat and deserves the same sentence.

    It takes a different branch: makedirs' exist_ok check asks isdir(), which follows
    the link to a missing target and re-raises a bare "[Errno 17] File exists". Safe
    either way - nothing is written - but the errno diagnoses nothing.
    """
    squatted = tmp_path / "relay"
    squatted.symlink_to(tmp_path / "nowhere")
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(squatted))

    with pytest.raises(PermissionError, match="squatting the relay path"):
        ensure_relay_dir()


def test_ensure_relay_dir_refuses_a_directory_owned_by_someone_else(tmp_path, monkeypatch):
    """Owning the DIRECTORY is enough to attack us, even though relays are 0600.

    An attacker cannot read a 0600 file we wrote, but a directory they own lets them
    unlink it and drop their own <nonce>.json - whose `prf` the CLI hands to a keystore
    that derives a key from it. Root is not available here, so the foreign uid is
    faked; what is under test is the branch, which is the part that used to be missing
    entirely (the chmod that would have failed was swallowed).
    """
    d = tmp_path / "relay"
    d.mkdir(mode=0o700)
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(d))

    real_lstat = os.lstat

    def foreign(path, *a, **kw):
        st = real_lstat(path, *a, **kw)
        if str(path) == str(d):
            return os.stat_result(tuple(st)[:4] + (st.st_uid + 1,) + tuple(st)[5:])
        return st

    monkeypatch.setattr(os, "lstat", foreign)

    with pytest.raises(PermissionError, match="somebody else controls the relay directory"):
        ensure_relay_dir()


def test_ensure_relay_dir_tightens_a_loose_directory_of_our_own(tmp_path, monkeypatch):
    """Ours but loose (an older release's 0755, an inherited umask) is fixable, not fatal.

    The distinction matters: refusing here would break a working install over something
    we have the authority to correct, and correcting a directory somebody else owns is
    the thing we cannot do.
    """
    d = tmp_path / "relay"
    d.mkdir(mode=0o755)
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(d))

    assert ensure_relay_dir() == str(d)
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


def test_ensure_relay_dir_creates_a_private_directory_when_absent(tmp_path, monkeypatch):
    d = tmp_path / "relay"
    monkeypatch.setenv("JLAB_PASSKEY_RELAY_DIR", str(d))

    assert ensure_relay_dir() == str(d)
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
