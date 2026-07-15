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


@pytest.mark.parametrize("bad_nonce", ["../../etc/evil", "a/b"])
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

    with caplog.at_level(logging.INFO):
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
