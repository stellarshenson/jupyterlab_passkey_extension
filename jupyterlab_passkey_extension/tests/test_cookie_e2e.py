"""Cookie entries end to end.

The real `curl` runs under `jupyterlab-passkey vault exec --env`, a separate CLI
process that reads cookie entry `site/local` over the vault's routes - the HTTP bridge
test_aws_e2e uses - and hands the command the Cookie header in its environment. `wget`
reads the cookies.txt of `vault get`. `requests` sends the jar of
`Vault().cookies(name)`. A stdlib http.server records the Cookie header of each request,
so the tests prove the cookies the vault holds are the ones sent. The kept request
headers of entry `site/web` go the same ways: `vault get --format headers` into
`curl -H @-`, and `Vault().headers(name)` into `requests`.

HOME is temporary; the test asserts no file under /tmp, /dev/shm or HOME holds a cookie
value afterwards, and no value reaches stdout or stderr.
"""

import contextlib
import http.server
import json
import os
import shutil
import subprocess
import sys

import pytest

from jupyterlab_passkey_extension import cli
from jupyterlab_passkey_extension.vault import client, handlers

from .test_aws_e2e import PASS, ROOT, TIMEOUT, _serve, _VaultHTTP

MARKER = "MARKER-cookie-e2e-5b1d"
ENTRY = "site/local"
# Where a cookie value could land on this host besides the temporary HOME.
SHARED = ("/tmp", "/dev/shm")


class CookieStub(http.server.BaseHTTPRequestHandler):
    """204 for every GET, and a record of the Cookie header each request carried and of
    all its headers."""

    seen = None
    requests = None

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.seen.append(self.headers.get("Cookie"))
        self.requests.append(self.headers)
        self.send_response(204)
        self.end_headers()


@contextlib.contextmanager
def cookie_stub():
    """The stub's url and its record of Cookie headers."""
    CookieStub.seen, CookieStub.requests = [], []
    with _serve(CookieStub) as port:
        yield f"http://127.0.0.1:{port}/", CookieStub.seen


@pytest.fixture
def stub():
    with cookie_stub() as served:
        yield served


@pytest.fixture
def vault_port(vault_env, stub):
    """The test vault over HTTP, unlocked, holding a cookie entry for the stub's host."""
    url, _ = stub
    svc = _VaultHTTP.svc = handlers._service
    svc.init(PASS)
    svc.add(ENTRY, {"type": "cookies", "url": url, "cookies": f"sid={MARKER}-sid; tok={MARKER}-tok"})
    with _serve(_VaultHTTP) as port:
        yield port


def _files(roots):
    """Every file path under `roots` that can be listed."""
    found = set()
    for root in roots:
        for top, _, names in os.walk(root, onerror=lambda e: None):
            found.update(os.path.join(top, name) for name in names)
    return found


def _holding(paths, marker):
    """The regular files among `paths` whose bytes hold `marker`."""
    holding = []
    for path in paths:
        try:
            if os.path.isfile(path) and not os.path.islink(path):
                with open(path, "rb") as f:
                    if marker.encode() in f.read():
                        holding.append(path)
        except OSError:
            pass
    return holding


def _cli_env(tmp_path, vault_port):
    """A temporary HOME, and a fake `jupyter` whose server list is empty, so JUPYTER_PORT
    names the test vault's bridge, as in test_aws_e2e."""
    home = tmp_path / "home"
    home.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "jupyter"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    return {
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(home),
        "PYTHONPATH": os.pathsep.join(p for p in (str(ROOT), os.environ.get("PYTHONPATH")) if p),
        "JUPYTER_PORT": str(vault_port),
    }


def _sent(seen):
    """The cookies of each request the stub got; a tool orders them its own way."""
    return [sorted(header.split("; ")) for header in seen]


COOKIES = [f"sid={MARKER}-sid", f"tok={MARKER}-tok"]


# The command line `vault exec --help` and docs/cli-reference.md show: curl reads the
# header from standard input, so the cookie values are in no command line.
TOOL = 'printf "Cookie: %s\\n" "$C" | curl -sS -H @-'


def test_a_tool_under_exec_env_sends_the_cookies_and_leaves_no_file(tmp_path, vault_port, stub):
    if shutil.which("curl") is None:
        pytest.skip("curl not on PATH - cannot run vault exec --env end to end")
    url, seen = stub
    env = _cli_env(tmp_path, vault_port)
    before = _files(SHARED)
    done = subprocess.run(
        [sys.executable, "-m", "jupyterlab_passkey_extension.cli", "vault", "exec",
         "--env", f"C={ENTRY}", "--", "sh", "-c", f"{TOOL} {url}"],
        env=env, cwd=tmp_path, capture_output=True, text=True, timeout=TIMEOUT)
    assert done.returncode == 0, done.stderr
    assert _sent(seen) == [COOKIES]
    assert MARKER not in done.stdout + done.stderr
    assert _holding(_files(SHARED) - before, MARKER) == []
    # HOME and the working directory of the command are under tmp_path.
    assert _holding(_files([tmp_path]), MARKER) == []


def test_wget_loads_the_cookies_txt_of_vault_get_through_a_process_substitution(tmp_path, vault_port, stub):
    if shutil.which("wget") is None or shutil.which("bash") is None:
        pytest.skip("wget or bash not on PATH - cannot load the cookies.txt of vault get")
    url, seen = stub
    env = _cli_env(tmp_path, vault_port)
    before = _files(SHARED)
    done = subprocess.run(
        ["bash", "-c", f'wget -qO- --load-cookies <("$0" -m jupyterlab_passkey_extension.cli vault get {ENTRY}) {url}',
         sys.executable],
        env=env, cwd=tmp_path, capture_output=True, text=True, timeout=TIMEOUT)
    assert done.returncode == 0, done.stderr
    assert _sent(seen) == [COOKIES]
    assert MARKER not in done.stdout + done.stderr
    assert _holding(_files(SHARED) - before, MARKER) == []
    # HOME and the working directory of the command are under tmp_path.
    assert _holding(_files([tmp_path]), MARKER) == []


# The headers a copied request keeps: a value with a space, and one with double quotes, %20
# and a backslash.
WEB = "site/web"
KEPT = {"authorization": f"Bearer {MARKER}-auth", "x-app-client": f"web 1.2 {MARKER}-client",
        "x-csrf-token": f'c"s%20r\\f={MARKER}-csrf "q"'}


@pytest.fixture
def web(vault_port, stub):
    """Cookie entry site/web: a Copy as cURL of a request to the stub, with two cookies, the
    headers of KEPT and three of the browser's own."""
    url, _ = stub
    kept = " ".join(f"-H '{name}: {value}'" for name, value in KEPT.items())
    handlers._service.add(WEB, {"type": "cookies", "cookies": (
        f"curl '{url}api' -H 'accept: */*' {kept} -b 'sid={MARKER}-sid; tok={MARKER}-tok' "
        "-H 'user-agent: Mozilla/5.0' -H 'sec-fetch-mode: cors' --compressed")})
    return vault_port


def _kept(request):
    """The headers of KEPT as the stub got them, and whether one of the browser's own came."""
    return {name: request.get(name) for name in KEPT}, request.get("sec-fetch-mode")


def test_curl_reads_the_lines_of_get_format_headers_from_standard_input(tmp_path, web, stub):
    if shutil.which("curl") is None:
        pytest.skip("curl not on PATH - cannot run `vault get --format headers | curl -H @-` end to end")
    url, seen = stub
    env = _cli_env(tmp_path, web)
    before = _files(SHARED)
    # The line `vault get --help` and docs/cli-reference.md show; $0 is this Python.
    argv = ["sh", "-c", f'"$0" -m jupyterlab_passkey_extension.cli vault get {WEB} --format headers '
                        f"| curl -sS -H @- {url}api", sys.executable]
    done = subprocess.run(argv, env=env, cwd=tmp_path, capture_output=True, text=True, timeout=TIMEOUT)
    assert (done.returncode, done.stdout, done.stderr) == (0, "", "")
    assert _sent(seen) == [COOKIES]
    # Each kept header arrives byte for byte, and none of the browser's own was stored.
    assert _kept(CookieStub.requests[0]) == (KEPT, None)
    # No value is in a command line, a file the run left or the pipeline's output.
    assert MARKER not in " ".join(argv)
    assert _holding(_files(SHARED) - before, MARKER) == []
    assert _holding(_files([tmp_path]), MARKER) == []


def test_requests_sends_the_jar_and_the_headers_of_a_cookie_entry(web, stub, monkeypatch):
    requests = pytest.importorskip("requests", reason="requests not installed - cannot send "
                                                      "Vault().headers(name) through it")
    url, seen = stub
    monkeypatch.setattr(cli, "_found", (f"http://127.0.0.1:{web}", None))
    session = requests.Session()
    # The proxy of the environment, if any, must not stand between the test and the stub.
    session.trust_env = False
    vault = client.Vault()
    assert vault.headers(WEB) == KEPT
    assert session.get(url, cookies=vault.cookies(WEB), headers=vault.headers(WEB),
                       timeout=TIMEOUT).status_code == 204
    assert seen == [f"sid={MARKER}-sid; tok={MARKER}-tok"]
    assert _kept(CookieStub.requests[0]) == (KEPT, None)


def test_exec_json_reports_the_exit_of_the_command_in_a_cli_started_with_sigchld_ignored(tmp_path, vault_port):
    # An ignored SIGCHLD survives exec. The kernel then collects an ended child itself,
    # and Python reports status 0 for a child whose status it cannot read.
    launcher = ("import os, signal, sys; signal.signal(signal.SIGCHLD, signal.SIG_IGN); "
                "os.execv(sys.executable, [sys.executable, '-m', 'jupyterlab_passkey_extension.cli', *sys.argv[1:]])")
    done = subprocess.run(
        [sys.executable, "-c", launcher, "vault", "exec", "--json", "--env", f"T={ENTRY}", "--",
         "sh", "-c", "exit 3"],
        env=_cli_env(tmp_path, vault_port), cwd=tmp_path, capture_output=True, text=True, timeout=TIMEOUT)
    assert (done.returncode, json.loads(done.stdout)["result"]["exit"], done.stderr) == (3, 3, "")


def test_requests_sends_the_jar_of_vault_cookies(vault_port, stub, monkeypatch):
    requests = pytest.importorskip("requests", reason="requests not installed - cannot send "
                                                      "Vault().cookies(name) through it")
    url, seen = stub
    monkeypatch.setattr(cli, "_found", (f"http://127.0.0.1:{vault_port}", None))
    session = requests.Session()
    # The proxy of the environment, if any, must not stand between the test and the stub.
    session.trust_env = False
    assert session.get(url, cookies=client.Vault().cookies(ENTRY), timeout=TIMEOUT).status_code == 204
    assert seen == [f"sid={MARKER}-sid; tok={MARKER}-tok"]
