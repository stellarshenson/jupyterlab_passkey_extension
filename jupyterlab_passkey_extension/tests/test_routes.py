import json
import logging
import os
import stat

import pytest
import tornado.httpclient
from jupyter_server.utils import url_path_join

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
