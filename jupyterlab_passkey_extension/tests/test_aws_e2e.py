"""The AWS CLI's `credential_process` end to end.

The real `aws s3 ls` runs the profile's `credential_process`, the installed
`aws-credential-jupyterlab-passkey`, which reads vault entry `aws/jlab-test` over the
server's vault routes - the same HTTP bridge `test_vault_git` uses for git. A local S3
stub answers ListBuckets and records the Authorization header, so the test proves the
access key id the CLI signed with is the one the vault holds.

Everything stateful lives under `tmp_path`: HOME, AWS_CONFIG_FILE and
AWS_SHARED_CREDENTIALS_FILE are temporary, so the real `~/.aws` is never read.
"""

import contextlib
import http.server
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import threading
import urllib.parse

import pytest

from jupyterlab_passkey_extension.vault import handlers, service
from jupyterlab_passkey_extension.vault.store import VaultError

PROFILE = "jlab-test"
ENTRY = f"aws/{PROFILE}"
HELPER = "aws-credential-jupyterlab-passkey"
# AKIA plus 16 uppercase characters, the shape AWS documents for an access key id.
KEY_ID = "AKIAJLABTESTFAKE0001"
KEY_ID_NEW = "AKIAJLABTESTFAKE0002"
SECRET_KEY = "fake-secret-key-jlab-MUST-NOT-LEAK"
PASS = "correct horse battery staple"
ROOT = pathlib.Path(__file__).resolve().parents[2]
TIMEOUT = 60
BUCKETS_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<Owner><ID>stub</ID><DisplayName>stub</DisplayName></Owner>"
    b"<Buckets></Buckets>"
    b"</ListAllMyBucketsResult>"
)


class _VaultHTTP(http.server.BaseHTTPRequestHandler):
    """The vault's action tables over HTTP, for the helper in another process."""

    svc = None

    def log_message(self, *args):
        pass

    def _answer(self, status, result):
        payload = b"" if result is None else json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _serve(self, method):
        split = urllib.parse.urlsplit(self.path)
        action = split.path.rstrip("/").rsplit("/", 1)[-1]
        args = dict(urllib.parse.parse_qsl(split.query))
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = json.loads(raw) if raw else {}
        try:
            table = {"GET": handlers._GET, "POST": handlers._POST,
                     "PATCH": handlers._PATCH}[method]
            result = table[action](self.svc, args if method == "GET" else body)
        except service.Locked as e:
            return self._answer(423, {"error": str(e)})
        except VaultError as e:
            return self._answer(400, {"error": str(e)})
        self._answer(204 if result is None else 200, result)

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")

    def do_PATCH(self):
        self._serve("PATCH")


class _S3Stub(http.server.BaseHTTPRequestHandler):
    """ListBuckets for every GET, and a record of every Authorization header.

    A stub accepts any syntactically valid SigV4: the signature is not verified, only
    that one was sent and which access key id it names.
    """

    requests = None

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.requests.append(
            {"path": self.path, "authorization": self.headers.get("Authorization", "")})
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(BUCKETS_XML)))
        self.end_headers()
        self.wfile.write(BUCKETS_XML)


@contextlib.contextmanager
def _serve(handler_class):
    """Serve `handler_class` on 127.0.0.1:0 and yield its port."""
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


@pytest.fixture
def vault(vault_env):
    """The test vault, unlocked, holding the profile's entry."""
    svc = handlers._service
    svc.init(PASS)
    svc.add(ENTRY, {"username": KEY_ID, "password": SECRET_KEY})
    return svc


@pytest.fixture
def vault_http(vault):
    _VaultHTTP.svc = vault
    with _serve(_VaultHTTP) as port:
        yield port


@pytest.fixture
def s3_stub():
    """The stub's port and its request log, one log per test."""
    _S3Stub.requests = []
    with _serve(_S3Stub) as port:
        yield port, _S3Stub.requests


def _tools():
    """The real aws CLI and the installed helper, or a skip naming the one missing."""
    found = {}
    for tool in ("aws", HELPER):
        path = shutil.which(tool)
        if path is None:
            pytest.skip(f"{tool} not on PATH - cannot run the AWS credential_process "
                        f"end to end")
        found[tool] = path
    return found["aws"], found[HELPER]


def _aws_env(tmp_path, helper, vault_port, s3_port):
    """A temporary HOME and AWS config; the real ~/.aws is out of reach."""
    aws_dir = tmp_path / "home" / ".aws"
    aws_dir.mkdir(parents=True)
    config = aws_dir / "config"
    config.write_text(
        f"[profile {PROFILE}]\n"
        "region = us-east-1\n"
        f"endpoint_url = http://127.0.0.1:{s3_port}\n"
        f"credential_process = {shlex.quote(helper)} {PROFILE}\n"
    )
    # A fake `jupyter` on PATH: `jupyter server list` must report no server, and
    # JUPYTER_PORT names the test vault's bridge, as in test_vault_git.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "jupyter"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    return {
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(tmp_path / "home"),
        "PYTHONPATH": os.pathsep.join(
            p for p in (str(ROOT), os.environ.get("PYTHONPATH")) if p),
        "JUPYTER_PORT": str(vault_port),
        "AWS_CONFIG_FILE": str(config),
        "AWS_SHARED_CREDENTIALS_FILE": str(aws_dir / "credentials"),
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_MAX_ATTEMPTS": "1",
        "AWS_PAGER": "",
    }


def _aws_s3_ls(env, s3_port):
    """The real aws CLI listing buckets against the stub, through the profile."""
    return subprocess.run(
        ["aws", "s3", "ls", "--endpoint-url", f"http://127.0.0.1:{s3_port}",
         "--profile", PROFILE],
        env=env, text=True, capture_output=True, timeout=TIMEOUT)


def _signed_headers(requests):
    """The Authorization header of every request the stub saw."""
    return [r["authorization"] for r in requests]


def test_the_aws_cli_signs_with_the_vaults_access_key_id(tmp_path, vault_http, s3_stub):
    _, helper = _tools()
    s3_port, requests = s3_stub
    done = _aws_s3_ls(_aws_env(tmp_path, helper, vault_http, s3_port), s3_port)
    assert done.returncode == 0, done.stderr
    headers = _signed_headers(requests)
    assert headers, done.stderr
    assert all(f"Credential={KEY_ID}/" in header for header in headers)
    assert all("Signature=" in header for header in headers)
    assert all(SECRET_KEY not in header for header in headers)
    assert SECRET_KEY not in done.stdout
    assert SECRET_KEY not in done.stderr
    assert done.stderr == ""


def test_the_signed_key_follows_the_vault_entry(tmp_path, vault, vault_http, s3_stub):
    """The same profile and environment sign with a new id only after the vault changes,
    so a cached or default credential cannot pass."""
    _, helper = _tools()
    s3_port, requests = s3_stub
    env = _aws_env(tmp_path, helper, vault_http, s3_port)
    first = _aws_s3_ls(env, s3_port)
    assert first.returncode == 0, first.stderr
    assert requests
    assert all(f"Credential={KEY_ID}/" in header for header in _signed_headers(requests))
    requests.clear()
    vault.edit(ENTRY, {"username": KEY_ID_NEW})
    second = _aws_s3_ls(env, s3_port)
    assert second.returncode == 0, second.stderr
    assert requests, second.stderr
    assert all(f"Credential={KEY_ID_NEW}/" in header
               for header in _signed_headers(requests))
