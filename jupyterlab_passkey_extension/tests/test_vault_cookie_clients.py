"""The clients of cookie entries and of the entry operations: `vault add|edit --cookies`,
`vault get --format`, `vault list`, `vault exec --env`, `vault copy|show` on a
cookie entry, `vault rename`, and the Python Vault's methods; and the request headers a
cookie entry keeps, through each of them.

Every command runs against a real vault through the handlers' action tables (the
`server` fixture of test_vault_cli). The paste dialog of --in-browser is simulated as the
frontend answers it: the click stages, through the relay, what the passphrase route
stages - the pasted text, or the cancel marker.
"""

import http.cookiejar
import json
import os
import pty
import re
import sys
import urllib.request

import pytest

from jupyterlab_passkey_extension import cli, relay
from jupyterlab_passkey_extension.vault import client, cookies, service, store
from jupyterlab_passkey_extension.vault import cli as vcli

from .test_cookie_e2e import cookie_stub
from .test_vault_cli import SECRET, _fake_exec, _help, _one, ready, run, server  # noqa: F401 - fixtures
from .test_vault_cookies import HEADER_MARKER, ONLY, VALUES, StoppedClock, fixture, marked, netscape
from .test_vault_routes import vault_file

MARKER = "MARKER-cookie-c11e"
# A browser's Copy as cURL of one request, with two cookies holding the marker.
CURL = (f"curl 'https://app.example.com/api/me' -H 'accept: application/json' "
        f"-H 'cookie: sid={MARKER}-1; tok={MARKER}-2' --compressed")
Y2100 = 4102444800
SITE = netscape(("#HttpOnly_app.example.com", "FALSE", "/api", "TRUE", Y2100, "sid", MARKER + "-sid"),
                (".example.com", "TRUE", "/", "FALSE", Y2100, "pref", MARKER + "-pref"),
                ("app.example.com", "FALSE", "/", "FALSE", 0, "plain", MARKER + "-plain"),
                (".other.test", "TRUE", "/", "FALSE", 0, "else", MARKER + "-else"))


@pytest.fixture
def site(ready, monkeypatch, capsys):
    """`ready` and cookie entry site/app: a host-only secure HttpOnly cookie under /api, a
    domain cookie, a host-only session cookie and a session cookie of another domain."""
    assert run(monkeypatch, "vault", "add", "site/app", "--cookies",
               "--url", "https://app.example.com/api", stdin=SITE) == 0
    capsys.readouterr()
    return ready


@pytest.fixture
def web(ready, monkeypatch, capsys):
    """`ready`, cookie entry site/app from a Copy as cURL with two cookies and three kept
    headers, and api/only from a copy with one kept header and no cookie."""
    assert run(monkeypatch, "vault", "add", "site/app", "--cookies", stdin=marked()[0]) == 0
    assert run(monkeypatch, "vault", "add", "api/only", "--cookies", stdin=fixture("curl-headers-only.txt")) == 0
    capsys.readouterr()
    return ready


# What a client says of api/only wherever its cookies are asked for.
NO_COOKIE = ("'api/only' stores no cookie - read its headers with "
             "`jupyterlab-passkey vault get api/only --format headers`")
# The values of the kept headers and the cookies of site/app in `web`.
HEADER_VALUES = (HEADER_MARKER, "web 1.2", "s%20r", VALUES["sid"], VALUES["tok"], "hdr.fake-only")


def lines(kept):
    return "".join(f"{name}: {value}\n" for name, value in kept)


def stored(svc, name):
    """The entry as the vault file holds it, values included."""
    return next(e for e in svc._entries() if e["name"] == name)


def _paste_dialog(monkeypatch, answer):
    """The click on the paste dialog's notification: Submit stages `answer` as `pass`, as
    the passphrase route does; None is Cancel, which stages the cancel marker."""
    seen = []

    def trigger(command, args, label, message):
        seen.append((command, args))
        if answer is None:
            relay.stage(args["nonce"], "cancel", "1")
        else:
            relay.stage(args["nonce"], "pass", answer)

    monkeypatch.setattr(vcli._cli, "_trigger", trigger)
    return seen


# --------------------------------------------------------------------------- #
# add and edit
# --------------------------------------------------------------------------- #


def test_add_cookies_from_a_pipe_prints_the_summary_never_a_value(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "add", "site/app", "--cookies", "-u", "me",
               "--url", "https://app.example.com", "-c", "web", "--notes", "n", stdin=CURL + "\n") == 0
    out, err = capsys.readouterr()
    assert "added site/app - cookies: 2, expired: 0, domains: app.example.com; names: sid, tok" in err
    assert MARKER not in out + err
    entry = stored(ready, "site/app")
    assert (entry["type"], entry["username"], entry["url"], entry["category"], entry["notes"]) == (
        "cookies", "me", "https://app.example.com", "web", "n")
    assert [c["value"] for c in entry["cookies"]] == [f"{MARKER}-1", f"{MARKER}-2"]
    assert run(monkeypatch, "vault", "add", "site/two", "--cookies", "--json", stdin=CURL) == 0
    obj = _one(capsys)
    assert obj["result"] == {"added": "site/two", "count": 2, "domains": ["app.example.com"],
                             "names": ["sid", "tok"], "expired": 0, "headers": []}
    assert MARKER not in json.dumps(obj)


def test_add_cookies_under_a_name_with_spaces_around_it_reads_the_stored_name(ready, monkeypatch, capsys):
    # The server stores the name stripped; the summary finds the entry by that name.
    assert run(monkeypatch, "vault", "add", "--json", "site/sp ", "--cookies",
               "--url", "https://a.example.com", stdin=f"a={MARKER}-a") == 0
    assert _one(capsys)["result"] == {"added": "site/sp ", "count": 1, "domains": ["a.example.com"],
                                      "names": ["a"], "expired": 0, "headers": []}


@pytest.mark.parametrize("argv, verb", [(["add", "site/new"], "added"), (["edit", "site/app"], "updated")])
def test_a_cookie_write_reports_the_keys_of_cookies_parse_with_the_expired_count(site, monkeypatch, capsys,
                                                                                 argv, verb):
    # One cookie past its expiry beside a session cookie and one that expires in 2100.
    paste = netscape(("app.example.com", "FALSE", "/", "TRUE", 1_000_000_000, "old", MARKER + "-old"),
                     (".example.com", "TRUE", "/", "FALSE", 0, "session", MARKER + "-session"),
                     ("app.example.com", "FALSE", "/", "FALSE", Y2100, "late", MARKER + "-late"))
    assert run(monkeypatch, "vault", *argv, "--cookies", stdin=paste) == 0
    out, err = capsys.readouterr()
    assert (f"{verb} {argv[1]} - cookies: 3, expired: 1, domains: app.example.com, example.com; "
            "names: old, session, late") in err
    assert MARKER not in out + err
    assert run(monkeypatch, "vault", "edit", argv[1], "--cookies", "--json", stdin=paste) == 0
    result = _one(capsys)["result"]
    assert result == {"updated": argv[1], **site.parse_cookies(paste)}
    assert list(result)[1:] == ["count", "domains", "names", "expired", "headers"] and result["expired"] == 1


def test_add_cookies_in_the_browser_asks_one_multi_line_paste_field(ready, monkeypatch, capsys):
    seen = _paste_dialog(monkeypatch, CURL)
    assert run(monkeypatch, "vault", "add", "site/app", "--cookies", "--in-browser") == 0
    [(command, args)] = seen
    assert command == cli.PASSPHRASE_COMMAND
    assert {k: v for k, v in args.items() if k != "nonce"} == {
        "prompt": "Cookies for site/app", "twice": False, "multiline": True}
    out, err = capsys.readouterr()
    assert "cookies: 2" in err and MARKER not in out + err
    assert len(ready.read("site/app")) == 2


def test_a_cancelled_paste_dialog_exits_1_and_writes_nothing(ready, monkeypatch, capsys):
    _paste_dialog(monkeypatch, None)
    with pytest.raises(SystemExit, match="^cancelled$"):
        run(monkeypatch, "vault", "add", "site/app", "--cookies", "--in-browser")
    assert run(monkeypatch, "vault", "add", "site/app", "--cookies", "--in-browser", "--json") == 1
    assert _one(capsys)["error"] == "cancelled"
    assert [e["name"] for e in ready.list_entries()] == ["github/api"]


@pytest.mark.parametrize("copy, lacks", [
    # Accept is the browser's own header: the copy has no cookie and no header to keep.
    ("curl 'https://app.example.com/api/me' -H 'accept: application/json'", "no cookie and no header to keep"),
    (fixture("chrome-fetch.txt"), "no cookie"),
], ids=["curl", "fetch"])
def test_a_copy_with_no_cookie_is_refused_at_add_and_nothing_is_written(ready, monkeypatch, vault_env, copy, lacks):
    before = vault_file(vault_env)
    with pytest.raises(SystemExit, match=rf"carries {lacks} - copy it with Copy as cURL or Copy as fetch \(Node\.js\)"):
        run(monkeypatch, "vault", "add", "site/app", "--cookies", stdin=copy)
    assert vault_file(vault_env) == before
    assert [e["name"] for e in ready.list_entries()] == ["github/api"]


@pytest.mark.parametrize("argv", [["add", "site/new", "--cookies"], ["edit", "site/txt", "--cookies"]],
                         ids=["add", "edit"])
def test_a_cookie_header_with_no_url_is_refused_and_nothing_is_written(ready, monkeypatch, vault_env, argv):
    # site/txt has no url: a cookies.txt carries its own domains.
    assert run(monkeypatch, "vault", "add", "site/txt", "--cookies", stdin=SITE) == 0
    assert stored(ready, "site/txt")["url"] == ""
    entries, before = ready._entries(), vault_file(vault_env)
    with pytest.raises(SystemExit, match="Cookie header line 1: no domain - give the site's url with --url"):
        run(monkeypatch, "vault", *argv, stdin=f"Cookie: a={MARKER}-a; b={MARKER}-b")
    assert vault_file(vault_env) == before
    assert ready._entries() == entries


@pytest.mark.parametrize("argv", [["add", "site/old", "--cookies"], ["edit", "site/app", "--cookies"]],
                         ids=["add", "edit"])
def test_a_paste_whose_every_cookie_has_expired_is_refused_with_code_expired(site, monkeypatch, capsys,
                                                                             vault_env, argv):
    entries, before = site._entries(), vault_file(vault_env)
    paste = netscape(("app.example.com", "FALSE", "/", "TRUE", 1_000_000_000, "sid", MARKER))
    assert run(monkeypatch, "vault", *argv, "--json", stdin=paste) == 1
    assert _one(capsys) == {
        "ok": False, "command": f"vault {argv[0]}", "code": "expired",
        "error": "every cookie in the paste has expired - copy the cookies again from the browser"}
    assert vault_file(vault_env) == before
    assert site._entries() == entries


@pytest.mark.parametrize("argv", [["add", "site/app", "--cookies"], ["edit", "site/app", "--cookies"]])
def test_cookies_from_a_terminal_are_refused_naming_a_pipe_and_in_browser(site, monkeypatch, argv):
    before = site._entries()
    master, slave = pty.openpty()
    with open(master, "rb"), open(slave) as terminal:
        monkeypatch.setattr(sys, "stdin", terminal)
        with pytest.raises(SystemExit, match="^--cookies reads a pipe or --in-browser, not a terminal$"):
            run(monkeypatch, "vault", *argv)
    assert site._entries() == before


def test_edit_cookies_replaces_the_jar_keeps_the_url_and_sets_updated(site, monkeypatch, capsys):
    before = stored(site, "site/app")
    monkeypatch.setattr(store, "_now", lambda: "2099-01-01T00:00:00Z")
    assert run(monkeypatch, "vault", "edit", "site/app", "--cookies", stdin=CURL) == 0
    out, err = capsys.readouterr()
    assert "updated site/app - cookies: 2, expired: 0, domains: app.example.com; names: sid, tok" in err
    assert MARKER not in out + err
    after = stored(site, "site/app")
    assert [(c["name"], c["value"]) for c in after["cookies"]] == [("sid", f"{MARKER}-1"), ("tok", f"{MARKER}-2")]
    assert after["url"] == before["url"] == "https://app.example.com/api"
    assert after["updated"] == "2099-01-01T00:00:00Z" > before["updated"]


def test_edit_cookies_in_the_browser_asks_one_multi_line_paste_field_and_replaces_the_jar(site, monkeypatch,
                                                                                         capsys):
    seen = _paste_dialog(monkeypatch, CURL)
    assert run(monkeypatch, "vault", "edit", "site/app", "--cookies", "--in-browser") == 0
    [(command, args)] = seen
    assert command == cli.PASSPHRASE_COMMAND
    assert {k: v for k, v in args.items() if k != "nonce"} == {
        "prompt": "Cookies for site/app", "twice": False, "multiline": True}
    out, err = capsys.readouterr()
    assert "updated site/app - cookies: 2" in err and MARKER not in out + err
    assert [(c["name"], c["value"]) for c in stored(site, "site/app")["cookies"]] == [
        ("sid", f"{MARKER}-1"), ("tok", f"{MARKER}-2")]


def test_a_curl_or_fetch_copy_on_an_entry_with_no_url_stores_the_copy_origin(ready, monkeypatch, capsys):
    # The origin only: the copy's path and query, which can carry a token, are not stored.
    assert run(monkeypatch, "vault", "add", "site/ff", "--cookies", stdin=fixture("firefox-curl.txt")) == 0
    assert stored(ready, "site/ff")["url"] == "https://app.example.com/"
    capsys.readouterr()
    assert run(monkeypatch, "vault", "get", "site/ff", "--format", "header") == 0
    assert _pairs(capsys.readouterr().out) == {f"{k}={v}" for k, v in VALUES.items()}
    assert run(monkeypatch, "vault", "add", "site/fetch", "--cookies", stdin=fixture("chrome-fetch-node.txt")) == 0
    assert stored(ready, "site/fetch")["url"] == "https://app.example.com/"
    assert run(monkeypatch, "vault", "add", "site/given", "--cookies", "--url", "https://app.example.com/api",
               stdin=CURL) == 0
    assert stored(ready, "site/given")["url"] == "https://app.example.com/api"
    assert run(monkeypatch, "vault", "add", "site/txt", "--cookies", stdin=SITE) == 0
    assert stored(ready, "site/txt")["url"] == ""
    assert run(monkeypatch, "vault", "edit", "site/txt", "--cookies", stdin=CURL) == 0
    assert stored(ready, "site/txt")["url"] == "https://app.example.com/"


@pytest.mark.parametrize("copy, origin", [
    (f"curl 'https://intranet.example.com:8443/api/x?token=abc' -H 'Cookie: sid={MARKER}'",
     "https://intranet.example.com:8443/"),
    (f"curl 'http://[::1]:8080/x' -H 'Cookie: sid={MARKER}'", "http://[::1]:8080/"),
    (f"curl 'https://user:pw@App.Example.com/x' -H 'Cookie: sid={MARKER}'", "https://app.example.com/"),
    (f'fetch("https://app.example.com:444/x", {{"headers": {{"cookie": "sid={MARKER}"}}}});',
     "https://app.example.com:444/"),
], ids=["port", "ipv6", "userinfo", "fetch"])
def test_the_stored_origin_keeps_the_port_and_drops_the_userinfo(ready, monkeypatch, capsys, copy, origin):
    assert run(monkeypatch, "vault", "add", "site/app", "--cookies", stdin=copy) == 0
    assert stored(ready, "site/app")["url"] == origin
    capsys.readouterr()
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "header") == 0
    assert capsys.readouterr().out == f"sid={MARKER}\n"


def test_a_json_export_with_a_bracketed_ipv6_domain_is_sent_to_that_host(ready, monkeypatch, capsys):
    export = json.dumps([{"name": "sid", "value": MARKER, "domain": "[::1]", "hostOnly": True, "path": "/",
                          "secure": False, "httpOnly": False, "session": True}])
    assert run(monkeypatch, "vault", "add", "site/app", "--cookies", "--url", "http://[::1]:8080/",
               stdin=export) == 0
    capsys.readouterr()
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "header") == 0
    assert capsys.readouterr().out == f"sid={MARKER}\n"
    request = urllib.request.Request("http://[::1]:8080/")
    client.Vault().cookies("site/app").add_cookie_header(request)
    assert request.get_header("Cookie") == f"sid={MARKER}"


@pytest.mark.parametrize("paste, url", [
    (json.dumps([{"name": "sid", "value": MARKER, "domain": "[::1]", "hostOnly": True, "path": "/",
                  "secure": False, "httpOnly": False, "session": True}]), "http://[::1]:8080/"),
    (f"Set-Cookie: sid={MARKER}", "http://[::1]:8080/"),
    (f"curl 'http://[::1]:8080/x' -H 'Cookie: sid={MARKER}'", None),
], ids=["json", "set-cookie", "curl"])
def test_an_ipv6_domain_is_stored_and_written_bare_from_every_form(ready, monkeypatch, capsys, paste, url):
    # curl -b matches the bare ::1 of a cookies.txt line, and sends nothing for [::1].
    assert run(monkeypatch, "vault", "add", "site/app", "--cookies", *(["--url", url] if url else []),
               stdin=paste) == 0
    assert [c["domain"] for c in stored(ready, "site/app")["cookies"]] == ["::1"]
    capsys.readouterr()
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "netscape") == 0
    assert capsys.readouterr().out.splitlines()[1:] == [f"::1\tFALSE\t/\tFALSE\t0\tsid\t{MARKER}"]


@pytest.mark.parametrize("argv, stdin, kind", [
    (["edit", "site/app", "--password"], "new-password\n", "cookies"),
    (["edit", "site/app", "--generate"], None, "cookies"),
    (["edit", "github/api", "--cookies"], CURL, "login"),
])
def test_an_option_of_the_other_type_is_refused_naming_the_type(site, monkeypatch, argv, stdin, kind):
    before = site._entries()
    # Refused before any prompt or dialog asks for the secret, or the server generates one.
    monkeypatch.setattr(vcli, "_read_secret", lambda *a, **k: pytest.fail("asked for a secret"))
    sent = []
    request = vcli.request

    def recorded(method, action, *args, **kwargs):
        sent.append(action)
        return request(method, action, *args, **kwargs)

    monkeypatch.setattr(vcli, "request", recorded)
    with pytest.raises(SystemExit, match=f"is a {kind} entry"):
        run(monkeypatch, "vault", *argv, stdin=stdin)
    assert "generate" not in sent
    assert site._entries() == before


def test_edit_of_a_password_reaches_the_server_when_the_list_names_no_type(ready, monkeypatch):
    # A Jupyter server still running the code from before cookie entries lists no type.
    # The type is unknown, so the server decides.
    listed = client.Vault.list
    monkeypatch.setattr(client.Vault, "list", lambda self: [
        {k: v for k, v in e.items() if k != "type"} for e in listed(self)])
    assert run(monkeypatch, "vault", "edit", "github/api", "--password", stdin="new-password\n") == 0
    assert ready.read("github/api") == "new-password"


@pytest.mark.parametrize("option, stdin", [("--password", "new-password\n"), ("--cookies", CURL)])
def test_edit_of_a_missing_entry_is_refused_before_a_secret_is_asked(site, monkeypatch, capsys, option, stdin):
    # The server's sentence and code for a missing entry, as `vault rm` of it gets them.
    monkeypatch.setattr(vcli, "_read_secret", lambda *a, **k: pytest.fail("asked for a secret"))
    assert run(monkeypatch, "vault", "rm", "missing/entry", "--json") == 1
    missing = _one(capsys)
    assert missing["code"] == "entry-not-found" and "vault list --json" in missing["error"]
    assert run(monkeypatch, "vault", "edit", "missing/entry", option, "--json", stdin=stdin) == 1
    assert _one(capsys) == {**missing, "command": "vault edit"}
    assert sys.stdin.read() == stdin


def test_a_cookie_entry_takes_no_generated_password_at_add(ready, monkeypatch):
    with pytest.raises(SystemExit) as e:
        run(monkeypatch, "vault", "add", "site/app", "--cookies", "--generate")
    assert e.value.code == 2


# --------------------------------------------------------------------------- #
# list and get
# --------------------------------------------------------------------------- #


def test_list_prints_the_count_the_expired_count_and_the_domains(site, monkeypatch, capsys):
    # Past 2100: the two cookies with an expiry have expired, the session cookies stay.
    monkeypatch.setattr(vcli, "time", StoppedClock(Y2100 + 1))
    assert run(monkeypatch, "vault", "list") == 0
    out, err = capsys.readouterr()
    assert ("site/app\t\t\thttps://app.example.com/api\tcookies: 4, expired: 2, "
            "domains: app.example.com, example.com, other.test; headers: 0\n") in out
    assert "github/api\tme\tinfra\thttps://github.com\n" in out
    assert MARKER not in out + err


def test_a_cookie_write_and_the_list_name_the_kept_headers_never_a_value(ready, monkeypatch, capsys):
    text, kept = marked()
    names = [name for name, _ in kept]
    assert run(monkeypatch, "vault", "add", "site/app", "--cookies", stdin=text) == 0
    out, err = capsys.readouterr()
    assert ("added site/app - cookies: 2, expired: 0, domains: app.example.com; names: sid, tok; "
            "headers: authorization, x-app-client, x-csrf-token\n") in err
    assert not any(value in out + err for value in HEADER_VALUES)
    assert run(monkeypatch, "vault", "add", "site/two", "--cookies", "--json", stdin=text) == 0
    obj = _one(capsys)
    assert obj["result"] == {"added": "site/two", "count": 2, "domains": ["app.example.com"],
                             "names": ["sid", "tok"], "expired": 0, "headers": names}
    assert not any(value in json.dumps(obj) for value in HEADER_VALUES)
    # A copy with a header and no cookie, then a copy with cookies and no header to keep.
    assert run(monkeypatch, "vault", "edit", "site/two", "--cookies", stdin=fixture("curl-headers-only.txt")) == 0
    out, err = capsys.readouterr()
    assert "updated site/two - cookies: 0; headers: Authorization\n" in err
    assert not any(value in out + err for value in HEADER_VALUES)
    assert run(monkeypatch, "vault", "edit", "site/two", "--cookies", "--json",
               stdin=fixture("curl-headers-only.txt")) == 0
    assert _one(capsys)["result"] == {"updated": "site/two", "count": 0, "domains": [], "names": [],
                                      "expired": 0, "headers": ["Authorization"]}
    assert run(monkeypatch, "vault", "add", "site/plain", "--cookies", stdin=CURL) == 0
    assert capsys.readouterr().err.endswith(
        "added site/plain - cookies: 2, expired: 0, domains: app.example.com; names: sid, tok\n")
    assert run(monkeypatch, "vault", "list") == 0
    out, err = capsys.readouterr()
    assert ("site/app\t\t\thttps://app.example.com/\tcookies: 2, expired: 0, domains: app.example.com; "
            "headers: 3\n") in out
    assert "site/two\t\t\thttps://app.example.com/\tcookies: 0; headers: 1\n" in out
    assert ("site/plain\t\t\thttps://app.example.com/\tcookies: 2, expired: 0, domains: app.example.com; "
            "headers: 0\n") in out
    assert "github/api\tme\tinfra\thttps://github.com\n" in out
    assert not any(value in out + err for value in (*HEADER_VALUES, MARKER))
    assert run(monkeypatch, "vault", "list", "--json") == 0
    out = capsys.readouterr().out
    listed = {e["name"]: e.get("headers") for e in json.loads(out)["result"]["entries"]}
    assert listed == {"github/api": None, "site/app": names, "site/plain": [], "site/two": ["Authorization"]}
    assert not any(value in out for value in (*HEADER_VALUES, MARKER))


def test_get_prints_a_cookies_txt_with_every_line_and_flag(site, monkeypatch, capsys):
    # 0 is a session cookie's expiry, as curl, wget and yt-dlp read it.
    assert run(monkeypatch, "vault", "get", "site/app") == 0
    out = capsys.readouterr().out
    assert out == (
        "# Netscape HTTP Cookie File\n"
        f"app.example.com\tFALSE\t/api\tTRUE\t{Y2100}\tsid\t{MARKER}-sid\n"
        f".example.com\tTRUE\t/\tFALSE\t{Y2100}\tpref\t{MARKER}-pref\n"
        f"app.example.com\tFALSE\t/\tFALSE\t0\tplain\t{MARKER}-plain\n"
        f".other.test\tTRUE\t/\tFALSE\t0\telse\t{MARKER}-else\n")
    assert run(monkeypatch, "vault", "get", "site/app", "--json") == 0
    assert _one(capsys)["result"] == {"name": "site/app", "field": "cookies", "value": out}


def _pairs(header):
    return set(header.strip("\n").split("; ")) if header.strip("\n") else set()


def test_get_format_header_matches_domain_path_and_secure_and_json_is_the_list(site, monkeypatch, capsys):
    # http: the secure cookie stays out; another domain never matches.
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "header",
               "--url", "http://app.example.com/api/x") == 0
    assert _pairs(capsys.readouterr().out) == {f"pref={MARKER}-pref", f"plain={MARKER}-plain"}
    # The entry's url by default: https and under /api, so the secure cookie too.
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "header") == 0
    assert _pairs(capsys.readouterr().out) == {f"sid={MARKER}-sid", f"pref={MARKER}-pref",
                                               f"plain={MARKER}-plain"}
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "header",
               "--url", "https://other.test/") == 0
    assert _pairs(capsys.readouterr().out) == {f"else={MARKER}-else"}
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "json") == 0
    assert json.loads(capsys.readouterr().out) == site.read("site/app")
    with pytest.raises(SystemExit, match="for a cookie entry; github/api is a login entry"):
        run(monkeypatch, "vault", "get", "github/api", "--format", "header")
    with pytest.raises(SystemExit, match="^--format and --url are for the cookies field; url is text$"):
        run(monkeypatch, "vault", "get", "site/app", "--field", "url", "--format", "header")


def test_get_format_header_with_no_url_anywhere_is_refused_naming_url(ready, monkeypatch):
    assert run(monkeypatch, "vault", "add", "site/bare", "--cookies", stdin=SITE) == 0
    with pytest.raises(SystemExit, match="site/bare has no url - give the site's url with --url"):
        run(monkeypatch, "vault", "get", "site/bare", "--format", "header")


def test_get_format_header_with_no_cookie_for_the_url_is_refused_naming_the_domains(site, monkeypatch, capsys):
    # An empty header with exit 0 would let curl send the request with no cookie.
    argv = ("vault", "get", "site/app", "--format", "header", "--url", "https://elsewhere.test/")
    refusal = "no cookie matches the domain, path and scheme of the url - its cookies are for"
    # The refusal ends with what gives `get` another url.
    hint = "; give the site's url with --url"
    with pytest.raises(SystemExit, match=f"^site/app: {refusal} app.example.com, example.com, other.test{hint}$"):
        run(monkeypatch, *argv)
    assert capsys.readouterr().out == ""
    assert run(monkeypatch, *argv, "--json") == 1
    obj = _one(capsys)
    assert obj["ok"] is False and refusal in obj["error"] and obj["error"].endswith(hint)
    # The domain matches; the path and the Secure flag are what the url fails.
    only = netscape(("only.test", "FALSE", "/account", "TRUE", Y2100, "sid", MARKER + "-only"))
    assert run(monkeypatch, "vault", "add", "site/only", "--cookies", "--url", "https://only.test/account",
               stdin=only) == 0
    with pytest.raises(SystemExit, match=f"^site/only: {refusal} only.test{hint}$"):
        run(monkeypatch, "vault", "get", "site/only", "--format", "header", "--url", "http://only.test/")


def test_get_format_header_reads_a_url_with_no_scheme_as_a_host(site, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "add", "site/bare", "--cookies", "--url", "app.example.com",
               stdin=f"a={MARKER}-a; b={MARKER}-b") == 0
    capsys.readouterr()
    assert run(monkeypatch, "vault", "get", "site/bare", "--format", "header") == 0
    assert _pairs(capsys.readouterr().out) == {f"a={MARKER}-a", f"b={MARKER}-b"}
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "header", "--url", "app.example.com") == 0
    assert _pairs(capsys.readouterr().out) == {f"pref={MARKER}-pref", f"plain={MARKER}-plain"}
    # A bare host reads as https, so the Secure cookies of a browser's copy match it.
    assert run(monkeypatch, "vault", "add", "site/copy", "--cookies", "--url", "app.example.com",
               stdin=CURL + "\n") == 0
    capsys.readouterr()
    assert run(monkeypatch, "vault", "get", "site/copy", "--format", "header") == 0
    assert _pairs(capsys.readouterr().out) == {f"sid={MARKER}-1", f"tok={MARKER}-2"}
    # A url with no host is refused naming --url; --json answers an object.
    assert run(monkeypatch, "vault", "get", "--json", "site/app", "--format", "header", "--url", "/x") == 1
    obj = _one(capsys)
    assert obj["ok"] is False and "site/app: the url has no host" in obj["error"] and "--url" in obj["error"]


def test_get_format_headers_prints_the_cookie_line_then_each_kept_header(web, monkeypatch, capsys):
    kept = marked()[1]
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "header") == 0
    header = capsys.readouterr().out
    assert _pairs(header) == {f"sid={VALUES['sid']}", f"tok={VALUES['tok']}"}
    # One line per header: the Cookie header of --format header, then the kept ones as stored.
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "headers") == 0
    out = capsys.readouterr().out
    assert out == "Cookie: " + header + lines(kept)
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "headers",
               "--url", "https://app.example.com/other/page") == 0
    assert capsys.readouterr().out == out
    assert run(monkeypatch, "vault", "get", "--json", "site/app", "--format", "headers") == 0
    assert _one(capsys)["result"] == {"name": "site/app", "field": "headers", "value": out}
    # The Cookie line has the refusals of --format header: no line is printed without it.
    refusal = ("site/app: no cookie matches the domain, path and scheme of the url - its cookies are for "
               "app.example.com; give the site's url with --url")
    with pytest.raises(SystemExit, match=f"^{re.escape(refusal)}$"):
        run(monkeypatch, "vault", "get", "site/app", "--format", "headers", "--url", "https://elsewhere.test/")
    assert capsys.readouterr().out == ""
    # A cookie entry that keeps no header prints its Cookie line alone.
    assert run(monkeypatch, "vault", "add", "site/plain", "--cookies", stdin=CURL) == 0
    capsys.readouterr()
    assert run(monkeypatch, "vault", "get", "site/plain", "--format", "headers") == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and _pairs(out.removeprefix("Cookie: ")) == {f"sid={MARKER}-1", f"tok={MARKER}-2"}
    with pytest.raises(SystemExit, match="^--format and --url are for the cookies field; url is text$"):
        run(monkeypatch, "vault", "get", "site/app", "--field", "url", "--format", "headers")


def test_get_format_headers_of_an_entry_whose_cookies_all_expired_is_code_expired(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "add", "site/app", "--cookies", stdin=marked()[0]) == 0
    capsys.readouterr()

    # No copy with headers carries an expiry, so the stored cookies get one.
    def change(entries):
        for cookie in next(e for e in entries if e["name"] == "site/app")["cookies"]:
            cookie["expires"] = 1_000_000_000

    store.update_entries(store.vault_path(), ready._dek(), change)
    for argv in (["get", "site/app", "--format", "headers"], ["exec", "--env", "H=site/app:headers", "--", "true"]):
        assert run(monkeypatch, "vault", argv[0], "--json", *argv[1:]) == 1
        obj = _one(capsys)
        assert obj["code"] == "expired" and "vault edit site/app --cookies" in obj["error"]
    with pytest.raises(client.VaultClientError) as e:
        client.Vault().headers("site/app")
    assert e.value.code == "expired"


def test_every_cookie_read_of_an_entry_with_no_cookie_is_code_invalid_naming_format_headers(
        web, monkeypatch, capsys, vault_env):
    raised = []
    monkeypatch.setattr(cli, "_trigger", lambda *a: raised.append(a))
    seen = _fake_exec(monkeypatch)
    for argv in (["get", "api/only"], ["get", "api/only", "--format", "netscape"],
                 ["get", "api/only", "--format", "header"], ["get", "api/only", "--format", "json"],
                 ["get", "api/only", "--format", "header", "--url", "https://api.example.com/"],
                 ["exec", "--env", "C=api/only", "--", "true"], ["copy", "api/only"]):
        assert run(monkeypatch, "vault", argv[0], "--json", *argv[1:]) == 1
        assert _one(capsys) == {"ok": False, "command": f"vault {argv[0]}", "error": NO_COOKIE, "code": "invalid"}
    vault = client.Vault()
    for call in (vault.get, vault.cookies, vault.copy):
        with pytest.raises(client.VaultClientError) as e:
            call("api/only")
        assert (e.value.code, str(e.value)) == ("invalid", NO_COOKIE)
    # No command ran, no notification was raised and nothing is staged.
    assert all(len(call) == 2 for call in seen) and raised == [] and not list((vault_env / "relay").glob("*"))
    # Its headers print with no Cookie line, also when the entry has no url.
    assert run(monkeypatch, "vault", "get", "api/only", "--format", "headers") == 0
    assert capsys.readouterr().out == lines(ONLY)
    assert run(monkeypatch, "vault", "edit", "api/only", "--url", "") == 0
    assert stored(web, "api/only")["url"] == ""
    capsys.readouterr()
    assert run(monkeypatch, "vault", "get", "api/only", "--format", "headers") == 0
    assert capsys.readouterr().out == lines(ONLY)
    assert run(monkeypatch, "vault", "get", "--json", "api/only", "--format", "headers") == 0
    assert _one(capsys)["result"] == {"name": "api/only", "field": "headers", "value": lines(ONLY)}


def test_a_read_with_no_cookie_left_is_code_expired_in_every_client(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "add", "site/old", "--cookies", stdin=netscape(
        ("app.example.com", "FALSE", "/", "TRUE", Y2100, "sid", MARKER))) == 0
    capsys.readouterr()
    # The cookie was unexpired at the write; the clock the service reads is past it now.
    monkeypatch.setattr(service, "time", StoppedClock(Y2100 + 1))
    for argv in (["get", "site/old"], ["exec", "--env", "C=site/old", "--", "true"]):
        assert run(monkeypatch, "vault", *argv[:1], "--json", *argv[1:]) == 1
        obj = _one(capsys)
        assert obj["code"] == "expired" and "vault edit site/old --cookies" in obj["error"]
    for call in (client.Vault().get, client.Vault().cookies):
        with pytest.raises(client.VaultClientError) as e:
            call("site/old")
        assert e.value.code == "expired"


def test_reading_the_password_of_a_cookie_entry_is_code_invalid_in_every_client(site, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "get", "--json", "site/app", "--field", "password") == 1
    obj = _one(capsys)
    assert obj["code"] == "invalid" and "cookies entry" in obj["error"] and MARKER not in obj["error"]
    with pytest.raises(client.VaultClientError) as e:
        client.Vault().get("site/app", field="password")
    assert e.value.code == "invalid" and str(e.value) == obj["error"]


# --------------------------------------------------------------------------- #
# exec, copy and show
# --------------------------------------------------------------------------- #


def test_exec_env_sets_the_cookie_header_of_a_cookie_entry_never_in_argv(site, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "header") == 0
    header = capsys.readouterr().out.rstrip("\n")
    seen = _fake_exec(monkeypatch)
    with pytest.raises(SystemExit):
        run(monkeypatch, "vault", "exec", "--env", "C=site/app", "--", "curl", "-b", "$C")
    _, argv, env = seen[-1]
    # The text `get --format header` prints: the cookies that match the entry's url.
    assert env["C"] == header
    assert _pairs(header) == {f"sid={MARKER}-sid", f"pref={MARKER}-pref", f"plain={MARKER}-plain"}
    # The command line is the one given: the value is in the environment only.
    assert argv == ["curl", "-b", "$C"]


def test_exec_env_name_headers_sets_the_text_of_get_format_headers_never_in_argv(web, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "headers") == 0
    text = capsys.readouterr().out
    assert run(monkeypatch, "vault", "get", "site/app", "--format", "header") == 0
    header = capsys.readouterr().out.rstrip("\n")
    seen = _fake_exec(monkeypatch)
    with pytest.raises(SystemExit):
        run(monkeypatch, "vault", "exec", "--env", "H=site/app:headers", "--env", "C=site/app",
            "--env", "O=api/only:headers", "--env", "U=site/app:url", "--", "curl", "-H", "@-")
    _, argv, env = seen[-1]
    # The text `get --format headers` prints, for the entry's url: four lines here.
    assert env["H"] == text == f"Cookie: {header}\n" + lines(marked()[1])
    assert env["O"] == lines(ONLY)
    # --env VAR=NAME stays the Cookie header, and NAME:FIELD a field.
    assert (env["C"], env["U"]) == (header, "https://app.example.com/")
    # The command line is the one given, and the variables are the command's only.
    assert argv == ["curl", "-H", "@-"]
    assert not {"H", "C", "O", "U"} & set(os.environ)


def test_exec_env_name_headers_refuses_as_get_format_headers_does(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "add", "site/bare", "--cookies", stdin=SITE) == 0
    capsys.readouterr()
    seen = _fake_exec(monkeypatch)
    # exec has no --url, so the refusal names the command that gives the entry one.
    no_url = "site/bare has no url - give the site's url with `vault edit site/bare --url URL`"
    no_headers = "'github/api' is a login entry; it has no headers"
    for name, refusal, code in (("site/bare", no_url, "usage"), ("github/api", no_headers, "invalid")):
        assert run(monkeypatch, "vault", "exec", "--json", "--env", f"H={name}:headers", "--", "true") == 1
        assert _one(capsys) == {"ok": False, "command": "vault exec", "code": code, "error": refusal}
    with pytest.raises(SystemExit, match="^site/bare has no url - give the site's url with --url$"):
        run(monkeypatch, "vault", "get", "site/bare", "--format", "headers")
    # No command ran: _fake_exec records an exec as three values, a signal as two.
    assert all(len(call) == 2 for call in seen)


def test_exec_json_returns_the_result_of_a_command_given_a_cookie_entry(site, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "edit", "site/app", "-u", "me") == 0
    capsys.readouterr()
    # The command prints the count of cookies it was given, never a value, and a field.
    script = "import os, sys; print(len(os.environ['C'].split('; ')), os.environ['U']); sys.exit(3)"
    assert run(monkeypatch, "vault", "exec", "--json", "--env", "C=site/app", "--env", "U=site/app:username",
               "--", sys.executable, "-c", script) == 3
    assert _one(capsys) == {"ok": True, "command": "vault exec",
                            "result": {"exit": 3, "stdout": "3 me\n", "stderr": ""}}
    assert run(monkeypatch, "vault", "exec", "--json", "--env", "U=site/app:url", "--",
               sys.executable, "-c", "import os; print(os.environ['U'])") == 0
    assert _one(capsys)["result"]["stdout"] == "https://app.example.com/api\n"


def test_exec_env_refuses_a_cookie_entry_as_get_format_header_does(ready, monkeypatch, capsys):
    assert run(monkeypatch, "vault", "add", "site/bare", "--cookies", stdin=SITE) == 0
    assert run(monkeypatch, "vault", "add", "site/off", "--cookies", "--url", "https://elsewhere.test/",
               stdin=SITE) == 0
    capsys.readouterr()
    seen = _fake_exec(monkeypatch)
    # exec has no --url, so the refusal names the command that gives the entry one.
    no_url = "site/bare has no url - give the site's url with `vault edit site/bare --url URL`"
    no_match = ("site/off: no cookie matches the domain, path and scheme of the url - its cookies are for "
                "app.example.com, example.com, other.test; give the site's url with "
                "`vault edit site/off --url URL`")
    for name, refusal in (("site/bare", no_url), ("site/off", no_match)):
        with pytest.raises(SystemExit, match=f"^{re.escape(refusal)}$"):
            run(monkeypatch, "vault", "exec", "--env", f"C={name}", "--", "true")
        capsys.readouterr()
        # The refusal names the command, never its argv, which can hold anything.
        assert run(monkeypatch, "vault", "exec", "--json", "--env", f"C={name}", "--", "true", MARKER) == 1
        refused = _one(capsys)
        assert refused == {"ok": False, "command": "vault exec", "code": "usage", "error": refusal}
        # The code is the one `get --format header` gives the same refusal.
        assert run(monkeypatch, "vault", "get", "--json", name, "--format", "header") == 1
        assert _one(capsys)["code"] == refused["code"]
    # No command ran: _fake_exec records an exec as three values, a signal as two.
    assert all(len(call) == 2 for call in seen)


def test_cookie_file_is_no_option_of_exec(site, monkeypatch, capsys):
    seen = _fake_exec(monkeypatch)
    with pytest.raises(SystemExit) as exit_:
        run(monkeypatch, "vault", "exec", "--cookie-file", "C=site/app", "--", "true")
    assert exit_.value.code == 2 and all(len(call) == 2 for call in seen)
    assert "unrecognized arguments: --cookie-file" in capsys.readouterr().err


def test_copy_stages_the_cookies_txt_and_show_is_refused_naming_copy(site, monkeypatch, capsys, vault_env):
    seen = []
    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: seen.append((c, a)))
    assert run(monkeypatch, "vault", "copy", "site/app") == 0
    [(command, args)] = seen
    assert command == cli.COPY_COMMAND
    staged = (vault_env / "relay" / f"{args['nonce']}.secret").read_text()
    assert staged == cookies.to_netscape(site.read("site/app"))
    with pytest.raises(SystemExit, match="is a cookies entry - show draws a short value; copy its "
                                         "cookies.txt with `jupyterlab-passkey vault copy site/app`"):
        run(monkeypatch, "vault", "show", "site/app")
    assert len(seen) == 1 and not list((vault_env / "relay").glob("*.code"))
    out, err = capsys.readouterr()
    assert MARKER not in out + err


@pytest.mark.keyctl
@pytest.mark.skipif(not relay._keyctl_probe(), reason="keyctl not functional on this host")
def test_copy_of_a_cookies_txt_over_a_user_key_reaches_the_relay_on_keyctl(ready, monkeypatch, capsys, vault_env):
    # A kernel user key holds at most 32767 bytes. The auto backend stages a bigger
    # value in the file relay, which a keyctl reader collects; a small one stays a key.
    monkeypatch.setenv("JUPYTERLAB_PASSKEY_RELAY_BACKEND", "auto")
    monkeypatch.setattr(relay, "_backend_cache", None)
    jar = "; ".join(f"c{n}={MARKER}-" + "v" * 3500 for n in range(10))
    assert run(monkeypatch, "vault", "add", "site/big", "--cookies", "--url", "https://app.example.com/",
               stdin=jar) == 0
    seen = []
    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: seen.append(a["nonce"]))
    assert run(monkeypatch, "vault", "copy", "site/big") == 0
    assert run(monkeypatch, "vault", "copy", "github/api") == 0
    big, small = seen
    expected = cookies.to_netscape(ready.read("site/big"))
    assert relay.backend() == "keyctl" and len(expected.encode()) > 32767
    assert relay.collect(big, "secret") == expected
    assert relay._keyctl_exists(small, "secret") and not list((vault_env / "relay").glob("*.secret"))
    assert relay.collect(small, "secret") == SECRET
    # A pinned keyctl backend refuses what the keyring cannot hold.
    monkeypatch.setenv("JUPYTERLAB_PASSKEY_RELAY_BACKEND", "keyctl")
    monkeypatch.setattr(relay, "_backend_cache", None)
    with pytest.raises(OSError, match="keyctl padd failed"):
        relay.stage(big, "secret", expected)
    out, err = capsys.readouterr()
    assert MARKER not in out + err


@pytest.mark.keyctl
@pytest.mark.skipif(not relay._keyctl_probe(), reason="keyctl not functional on this host")
def test_a_paste_over_a_user_key_taken_in_the_browser_reaches_the_cli_through_the_file_relay(
        ready, monkeypatch, capsys, vault_env):
    # The other direction of the test above. The passphrase route stages the paste; the
    # keyring refuses it, so it is a relay file, which the keyctl reader's wait sees and
    # its collect reads.
    monkeypatch.setenv("JUPYTERLAB_PASSKEY_RELAY_BACKEND", "auto")
    monkeypatch.setattr(relay, "_backend_cache", None)
    jar = "; ".join(f"c{n}={MARKER}-" + "v" * 3500 for n in range(10))
    staged = []

    def click(command, args, label, message):
        relay.stage(args["nonce"], "pass", jar)
        staged.append((relay._keyctl_exists(args["nonce"], "pass"),
                       (vault_env / "relay" / f"{args['nonce']}.pass").exists()))

    monkeypatch.setattr(vcli._cli, "_trigger", click)
    assert run(monkeypatch, "vault", "add", "site/big", "--cookies", "--in-browser",
               "--url", "https://app.example.com/") == 0
    assert relay.backend() == "keyctl" and len(jar.encode()) > 32767
    assert staged == [(False, True)]
    assert "; ".join(f"{c['name']}={c['value']}" for c in stored(ready, "site/big")["cookies"]) == jar
    assert not list((vault_env / "relay").glob("*.pass"))
    out, err = capsys.readouterr()
    assert MARKER not in out + err


# --------------------------------------------------------------------------- #
# rename
# --------------------------------------------------------------------------- #


def test_rename_unlocks_first_and_keeps_the_entry(site, monkeypatch, capsys):
    run(monkeypatch, "vault", "lock")
    site.calls.clear()
    assert run(monkeypatch, "vault", "rename", "site/app", "site/web") == 0
    assert site.calls == [client.UNLOCK_COMMAND]
    assert "renamed site/app to site/web" in capsys.readouterr().err
    assert [e["name"] for e in site.list_entries()] == ["github/api", "site/web"]
    assert len(site.read("site/web")) == 4
    assert run(monkeypatch, "vault", "rename", "site/web", "site/app", "--json") == 0
    assert _one(capsys)["result"] == {"renamed": "site/web", "to": "site/app"}


@pytest.mark.parametrize("argv, code", [
    (["site/app", "github/api"], "conflict"),
    (["missing/entry", "missing/other"], "entry-not-found"),
    (["site/app", "site/app"], "invalid"),
])
def test_rename_refusals_carry_their_json_codes(site, monkeypatch, capsys, argv, code):
    assert run(monkeypatch, "vault", "rename", *argv, "--json") == 1
    obj = _one(capsys)
    assert (obj["command"], obj["code"]) == ("vault rename", code)
    assert [e["name"] for e in site.list_entries()] == ["github/api", "site/app"]


# --------------------------------------------------------------------------- #
# help
# --------------------------------------------------------------------------- #


def test_help_states_the_cookie_forms_format_and_exec_env_with_an_example_each(monkeypatch, capsys):
    def text(*words):
        return " ".join(_help(monkeypatch, capsys, "vault", *words).split())

    add = text("add")
    for form in ("Copy as cURL (bash or cmd)", "Copy as fetch (Node.js)", "Set-Cookie lines",
                 "cookies.txt (Netscape format)", "Cookie-Editor or EditThisCookie JSON export",
                 "Playwright storage state", "Cookie header or name=value"):
        assert form in add
    assert "jupyterlab-passkey vault add site/app --cookies --in-browser" in add
    assert "jupyterlab-passkey vault edit site/app --cookies --in-browser" in text("edit")
    get = text("get")
    assert "--format {netscape,header,json,headers}" in get and "--url URL" in get
    assert "--format headers" in get and "`Name: value`" in get
    assert "jupyterlab-passkey vault get site/app --format headers | curl -H @- https://app.example.com/api" in get
    assert "jupyterlab-passkey vault get site/app --format header --url https://app.example.com/api" in get
    exec_ = text("exec")
    assert "--env VAR=NAME on a cookie entry sets VAR to its Cookie header" in exec_
    assert "`vault edit NAME --url URL`" in exec_ and "code expired" in exec_
    assert "--env VAR=NAME:headers on a cookie entry sets VAR to the text `get NAME --format headers` prints" in exec_
    assert 'printf "%s" "$VAR" | curl -H @- URL' in exec_
    assert "jupyterlab-passkey vault get NAME --format headers | curl -H @- URL" in exec_
    for said in (get, exec_):
        assert "A header has no expiry the vault can read" in said
        # ACC-COOKIE-398: what a refused read does in the pipe, and under exec.
        assert ("when the read is refused, get prints its reason on stderr and curl still sends the request, "
                "without the headers; under `exec --env VAR=NAME:headers` the command does not run") in said
    recipe = 'printf "Cookie: %s\\n" "$C" | curl -H @- https://app.example.com/api'
    assert f"jupyterlab-passkey vault exec --env C=site/app -- sh -c '{recipe}'" in exec_
    # No example gives a tool the cookie variable as an argument: the process list shows it.
    assert '-b "$C"' not in exec_ and '--header "Cookie: $C"' not in exec_
    assert "wget --load-cookies <(jupyterlab-passkey vault get NAME) URL" in exec_
    assert "jupyterlab-passkey vault rename github/api github/token" in text("rename")


# --------------------------------------------------------------------------- #
# the Python Vault
# --------------------------------------------------------------------------- #


def test_vault_add_makes_a_login_a_generated_and_a_cookie_entry(ready):
    vault = client.Vault()
    assert vault.add("db/prod", password="pw-1", username="app", url="https://db.example",
                     category="db", notes="n") is None
    assert vault.add("db/gen", generate=True, length=32) is None
    assert vault.add("site/app", cookies=CURL, url="https://app.example.com") is None
    assert (vault.get("db/prod"), vault.get("db/prod", "username"), vault.get("db/prod", "notes")) == (
        "pw-1", "app", "n")
    assert len(vault.get("db/gen")) == 32
    assert vault.get("site/app") == cookies.to_netscape(ready.read("site/app"))
    assert {e["name"]: e["type"] for e in vault.list()} == {
        "db/gen": "login", "db/prod": "login", "github/api": "login", "site/app": "cookies"}
    with pytest.raises(client.VaultClientError) as e:
        vault.add("db/both", password="pw", generate=True)
    assert e.value.code == "usage"


def test_vault_edit_changes_only_the_fields_given_under_the_type_rules(ready):
    vault = client.Vault()
    vault.edit("github/api", url="https://x.example")
    assert (vault.get("github/api", "url"), vault.get("github/api")) == ("https://x.example", SECRET)
    vault.edit("github/api", generate=True)
    assert len(vault.get("github/api")) == service.GENERATE_LENGTH
    with pytest.raises(client.VaultClientError) as e:
        vault.edit("github/api", cookies=CURL)
    assert e.value.code == "invalid" and "login entry" in str(e.value)
    vault.add("site/app", cookies=CURL)
    vault.edit("site/app", cookies="Set-Cookie: n=1; Domain=example.org")
    assert [c["name"] for c in ready.read("site/app")] == ["n"]
    with pytest.raises(client.VaultClientError) as e:
        vault.edit("site/app", password="pw")
    assert e.value.code == "invalid" and "cookies entry" in str(e.value)
    with pytest.raises(client.VaultClientError) as e:
        vault.edit("site/app")
    assert e.value.code == "usage"


def test_vault_rename_and_delete(ready):
    vault = client.Vault()
    vault.rename("github/api", "github/token")
    assert [e["name"] for e in vault.list()] == ["github/token"]
    assert vault.get("github/token") == SECRET
    vault.delete("github/token")
    assert vault.list() == []
    with pytest.raises(client.VaultClientError) as e:
        vault.delete("github/token")
    assert e.value.code == "entry-not-found"


def test_vault_cookies_is_a_cookie_jar_that_urllib_sends(ready):
    vault = client.Vault()
    with cookie_stub() as (url, seen):
        vault.add("site/local", cookies=f"sid={MARKER}-a; tok={MARKER}-b", url=url)
        jar = vault.cookies("site/local")
        assert isinstance(jar, http.cookiejar.CookieJar)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPCookieProcessor(jar))
        opener.open(url).read()
    assert seen == [f"sid={MARKER}-a; tok={MARKER}-b"]
    with pytest.raises(client.VaultClientError) as e:
        vault.cookies("github/api")
    assert e.value.code == "invalid"


def test_vault_headers_is_a_dict_of_the_kept_headers_with_no_cookie_key(ready):
    vault = client.Vault()
    text, kept = marked()
    # add stores the headers of the copy beside its cookies.
    assert vault.add("site/app", cookies=text) is None
    assert stored(ready, "site/app")["headers"] == kept
    assert [c["name"] for c in stored(ready, "site/app")["cookies"]] == ["sid", "tok"]
    headers = vault.headers("site/app")
    assert type(headers) is dict and headers == dict(kept)
    assert "cookie" not in {name.lower() for name in headers}
    # A name stored twice keeps its last value.
    vault.add("site/twice", cookies="curl 'https://x.example/' -b 'a=1' -H 'x-a: first' -H 'x-b: 2' -H 'x-a: last'")
    assert stored(ready, "site/twice")["headers"] == [["x-a", "first"], ["x-b", "2"], ["x-a", "last"]]
    assert vault.headers("site/twice") == {"x-a": "last", "x-b": "2"}
    # An entry with no cookie, and one with no header.
    vault.add("api/only", cookies=fixture("curl-headers-only.txt"))
    assert vault.headers("api/only") == dict(ONLY)
    vault.add("site/plain", cookies=CURL)
    assert vault.headers("site/plain") == {}
    with pytest.raises(client.VaultClientError) as e:
        vault.headers("github/api")
    assert (e.value.code, str(e.value)) == ("invalid", "'github/api' is a login entry; it has no headers")


def test_vault_get_of_the_field_headers_is_code_invalid_naming_vault_headers(ready, monkeypatch):
    vault = client.Vault()
    # An entry with kept headers, and a cookie entry with none.
    vault.add("site/app", cookies=marked()[0])
    vault.add("site/plain", cookies=CURL)
    asked, request = [], client.request
    monkeypatch.setattr(client, "request", lambda *a, **k: asked.append(a) or request(*a, **k))
    for name in ("site/app", "site/plain"):
        with pytest.raises(client.VaultClientError) as e:
            vault.get(name, "headers")
        assert (e.value.code, str(e.value)) == (
            "invalid", f"get does not read the headers - use `Vault().headers('{name}')`")
    # Refused before any request: no header value reaches the caller.
    assert asked == []


# Each entry command of the CLI and the Vault method with its effect.
PARITY = [
    ("add", lambda v: v.add("db/prod", password="pw", username="app")),
    ("get", lambda v: v.get("db/prod")),
    ("edit", lambda v: v.edit("db/prod", notes="n")),
    ("rename", lambda v: v.rename("db/prod", "db/main")),
    ("list", lambda v: [(e["name"], e["notes"]) for e in v.list()]),
    ("copy", lambda v: v.copy("db/main")),
    ("show", lambda v: v.show("db/main", field="username")),
    ("import", lambda v: v.import_entries([{"name": "imp/one", "password": "p"}])),
    ("generate", lambda v: v.generate(length=16, symbols=False)),
    ("rm", lambda v: v.delete("db/main")),
]


def test_every_entry_command_has_a_vault_method_with_the_same_effect(ready, monkeypatch, capsys, vault_env):
    commands = re.findall(r"^    ([a-z]+) ", _help(monkeypatch, capsys, "vault"), re.M)
    assert {command for command, _ in PARITY} <= set(commands)
    staged = []
    monkeypatch.setattr(cli, "_trigger", lambda c, a, l, m: staged.append((c, a["nonce"])))
    vault = client.Vault()
    result = {command: call(vault) for command, call in PARITY}
    assert result["get"] == "pw"
    assert result["list"] == [("db/main", "n"), ("github/api", "")]
    [(copy, copied), (show, shown)] = staged
    assert (copy, show) == (cli.COPY_COMMAND, cli.SHOW_COMMAND)
    assert (vault_env / "relay" / f"{copied}.secret").read_text() == "pw"
    assert (vault_env / "relay" / f"{shown}.code").read_text() == "app"
    assert result["import"] == {"added": 1, "skipped": []}
    assert len(result["generate"]) == 16 and result["generate"].isalnum()
    assert [e["name"] for e in vault.list()] == ["github/api", "imp/one"]


@pytest.mark.parametrize("call, check", [
    (lambda v: v.add("db/prod", password="pw"), lambda svc: svc.read("db/prod") == "pw"),
    (lambda v: v.add("site/app", cookies=CURL), lambda svc: len(svc.read("site/app")) == 2),
    (lambda v: v.edit("github/api", notes="n"), lambda svc: svc.read("github/api", "notes") == "n"),
    (lambda v: v.rename("github/api", "github/token"), lambda svc: svc.read("github/token") == SECRET),
    (lambda v: v.delete("github/api"), lambda svc: [e["name"] for e in svc.list_entries()] == ["site/jar"]),
    (lambda v: v.import_entries([{"name": "imp/one", "password": "p"}]), lambda svc: svc.read("imp/one") == "p"),
    (lambda v: v.copy("github/api"), lambda svc: True),
    (lambda v: v.show("github/api"), lambda svc: True),
    (lambda v: v.cookies("site/jar"), lambda svc: True),
    (lambda v: v.headers("site/jar"), lambda svc: True),
], ids=["add", "add-cookies", "edit", "rename", "delete", "import", "copy", "show", "cookies", "headers"])
def test_every_vault_method_that_needs_an_open_vault_unlocks_a_locked_one(ready, monkeypatch, call, check):
    monkeypatch.setattr(cli, "_trigger", lambda *a: None)
    vault = client.Vault()
    vault.add("site/jar", cookies=CURL)
    vault.lock()
    ready.calls.clear()
    call(vault)
    assert ready.calls == [client.UNLOCK_COMMAND]
    assert ready.status()["unlocked"] and check(ready)


@pytest.mark.parametrize("call, argv, stdin, code", [
    (lambda v: v.add("github/api", password="x"), ["add", "github/api"], CURL, "conflict"),
    (lambda v: v.rename("github/api", "github/api"), ["rename", "github/api", "github/api"], CURL, "invalid"),
    (lambda v: v.delete("missing/entry"), ["rm", "missing/entry"], CURL, "entry-not-found"),
    (lambda v: v.get("missing/entry"), ["get", "missing/entry"], CURL, "entry-not-found"),
    (lambda v: v.edit("github/api", cookies=CURL), ["edit", "github/api", "--cookies"], CURL, "invalid"),
    (lambda v: v.add("site/n", cookies=""), ["add", "site/n", "--cookies"], "", "usage"),
    (lambda v: v.add("site/n", password=""), ["add", "site/n"], "", "usage"),
    (lambda v: v.add("site/n"), ["add", "site/n"], "", "usage"),
    (lambda v: v.edit("github/api", password=""), ["edit", "github/api", "--password"], "", "usage"),
    (lambda v: v.edit("site/app", cookies=""), ["edit", "site/app", "--cookies"], "", "usage"),
], ids=["conflict", "invalid", "delete-missing", "get-missing", "type", "add-empty-cookies",
        "add-empty-password", "add-no-secret", "edit-empty-password", "edit-empty-cookies"])
def test_a_refused_vault_call_raises_the_clis_json_code(site, monkeypatch, capsys, call, argv, stdin, code):
    before = site._entries()
    with pytest.raises(client.VaultClientError) as e:
        call(client.Vault())
    assert e.value.code == code
    assert run(monkeypatch, "vault", *argv, "--json", stdin=stdin) == 1
    assert _one(capsys) == {"ok": False, "command": f"vault {argv[0]}", "error": str(e.value), "code": code}
    assert site._entries() == before

