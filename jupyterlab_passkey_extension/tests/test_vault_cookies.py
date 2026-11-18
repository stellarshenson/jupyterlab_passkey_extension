"""Cookie entries: the parser of every pasted form, the formatters, and the vault's cookie
entries end to end through a real Jupyter server.

The fixtures under fixtures/cookies are hand-written copies of browser output with fake
values: Chrome's Copy as cURL (bash and cmd) and Copy as fetch (plain and Node.js),
Firefox's Copy as cURL, Set-Cookie lines, a curl cookies.txt, a Cookie-Editor export, an
EditThisCookie export and a Playwright storage state. The `-headers` fixtures are the three
copies of one request that carries an authorization header, a csrf token and a custom
header; curl-headers-only.txt carries a header and no cookie, and chrome-fetch-headers.txt
is a plain Copy as fetch with a custom header, whose cookies the browser keeps to itself.
"""

import inspect
import io
import json
import logging
import os
import sys
import time
import urllib.error

import pytest
import tornado.httpclient

from jupyterlab_passkey_extension import cli, relay
from jupyterlab_passkey_extension.vault import client, cookies, handlers, service as vault_service, store
from jupyterlab_passkey_extension.vault import cli as vcli
from jupyterlab_passkey_extension.vault.store import VaultError

from .test_vault_routes import PASS, call, fails_body, init, vault_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "cookies")
URL = "https://app.example.com/dashboard"
# The three values every form and every output must keep byte for byte.
VALUES = {"sid": "s%3Aab.c%2F", "tok": "eyJhbGc==", "q": '"a b"'}
MARKER = "MARKER-cookie-7f3a"
HEADER_MARKER = "MARKER-header-9c2e"
# The headers the three copies of one request keep, in paste order. The last value holds a
# quote, %20, a backslash and = signs.
KEPT = [["authorization", "Bearer hdr.fake-token=="], ["x-app-client", "web 1.2"],
        ["x-csrf-token", 'c"s%20r\\f=1']]
ONLY = [["Authorization", "Bearer hdr.fake-only=="]]
Y2100 = 4102444800


class StoppedClock:
    """The clock a cookie's expiry is read against, stopped at `now`."""

    def __init__(self, now):
        self.now = now

    def time(self):
        return self.now

    def monotonic(self):
        return time.monotonic()


def fixture(name):
    with open(os.path.join(FIXTURES, name), newline="") as f:
        return f.read()


def by_name(jar):
    return {c["name"]: c for c in jar}


def values(jar):
    return {c["name"]: c["value"] for c in jar}


def netscape(*lines):
    return "# Netscape HTTP Cookie File\n" + "".join("\t".join(map(str, line)) + "\n" for line in lines)


# --------------------------------------------------------------------------- #
# the forms
# --------------------------------------------------------------------------- #


def test_chrome_copy_as_curl_bash_reads_b_with_its_ansi_c_quoting():
    jar = cookies.parse(fixture("chrome-curl-bash.txt"))[0]
    assert values(jar) == {**VALUES, "pref": "it's!"}
    for c in jar:
        assert (c["domain"], c["host_only"], c["path"], c["secure"]) == ("app.example.com", True, "/", True)
        assert c["expires"] is None and c["http_only"] is False


def test_firefox_copy_as_curl_reads_the_cookie_header():
    jar = cookies.parse(fixture("firefox-curl.txt"))[0]
    assert values(jar) == VALUES
    assert {c["domain"] for c in jar} == {"app.example.com"}


def test_curl_reads_cookie_and_a_cookie_header_in_any_case_over_backslash_line_ends():
    text = ("curl 'https://shop.example.org/cart' \\\r\n  --cookie 'a=1' \\\n"
            "  -H 'COOKIE: b=2' -H 'X-Cookie-Note: c=3' --compressed")
    jar = cookies.parse(text)[0]
    assert values(jar) == {"a": "1", "b": "2"}
    assert {c["domain"] for c in jar} == {"shop.example.org"}


def test_cmd_and_bash_copies_of_one_chrome_request_give_equal_jars():
    cmd = fixture("chrome-curl-cmd.txt")
    assert "^%^3A" in cmd and "^\\^\"" in cmd and "\r\n" in cmd
    assert cookies.parse(cmd) == cookies.parse(fixture("chrome-curl-bash.txt"))


@pytest.mark.parametrize("name", ["firefox-curl-windows.txt", "firefox-curl-windows-3parts.txt"])
def test_firefox_copy_as_curl_windows_reads_as_the_cmd_form(name):
    # Firefox names the command curl.exe, and joins more than two parts with ` ^` and a line end.
    text = fixture(name)
    assert text.startswith('curl.exe ^"') and ("^\n" in text) == ("3parts" in name)
    jar = cookies.parse(text)[0]
    assert values(jar) == {"a": "1", "b": 'x"y', "c": "p$q", "d": "50%", "e": "plain"}
    assert {c["domain"] for c in jar} == {"app.example.com"}
    with pytest.raises(VaultError, match=r"^Copy as cURL \(cmd\) line 1: "):
        cookies.parse('curl.exe ^"https://app.example.com/api^"')


@pytest.mark.parametrize("name, want", [
    ("firefox-curl-windows-old.txt", {"a": "1", "b": 'x"y', "c": "p$q", "d": "50%", "e": "plain"}),
    ("firefox-curl-windows-old-3parts.txt",
     {"bs": "a\\b", "bt": "a`b", "dq": 'x"y', "dl": "p$q", "amp": "a&b", "pipe": "a|b", "lt": "a<b",
      "gt": "a>b", "caret": "a^b", "pct": "%41z", "end": "50%"}),
])
def test_firefox_138_copy_as_curl_windows_reads_every_value_byte_for_byte(name, want):
    # Firefox 138 and earlier named the command curl, wrapped an argument in plain quotes
    # and joined the arguments with one space.
    text = fixture(name)
    assert text.startswith('curl "https://app.example.com/api" -H "') and "\n" not in text
    jar = cookies.parse(text)[0]
    assert values(jar) == want
    assert {c["domain"] for c in jar} == {"app.example.com"}
    with pytest.raises(VaultError, match=r"^Copy as cURL \(cmd\) line 1: "):
        # Accept is the browser's own header, so the copy has no cookie and no header to keep.
        cookies.parse(text.replace("Cookie: ", "Accept: "))
    # The arguments joined as Firefox joins them today, with ` ^` and a line end.
    assert values(cookies.parse(text.replace(" -H ", " ^\n  -H "))[0]) == want
    # A hand-written command holds what Firefox did not write, and bash reads it as before.
    for cookie, value in (('"Cookie: a=x\\"y"', 'x"y'), ("'Cookie: a=x\"y'", 'x"y'), ('"Cookie: a=x^y"', "x^y")):
        assert values(cookies.parse(f'curl "https://app.example.com/" -H {cookie}')[0]) == {"a": value}


def test_chrome_copy_as_fetch_node_reads_the_cookie_header():
    jar = cookies.parse(fixture("chrome-fetch-node.txt"))[0]
    assert values(jar) == {**VALUES, "pref": "it's!"}
    assert {(c["domain"], c["host_only"], c["secure"]) for c in jar} == {("app.example.com", True, True)}


def test_an_awaited_fetch_with_the_options_in_another_order_is_read():
    text = ('await fetch("http://intranet.example.net/x", {\n    "method": "GET",\n'
            '    "headers": {\n        "Cookie": "a=1; t=eyJh=="\n    },\n    "mode": "cors"\n});')
    jar = cookies.parse(text)[0]
    assert values(jar) == {"a": "1", "t": "eyJh=="}
    assert {(c["domain"], c["secure"]) for c in jar} == {("intranet.example.net", False)}


@pytest.mark.parametrize("text, where, lacks", [
    (fixture("chrome-fetch.txt"), "Copy as fetch lines 1 to 19", "no cookie"),
    # Accept is the browser's own header: these copies carry no cookie and no header to keep.
    ("curl 'https://app.example.com/api/me' -H 'accept: application/json'", "Copy as cURL line 1",
     "no cookie and no header to keep"),
    ('fetch("https://app.example.com/api/me", {"headers": {"accept": "*/*"}, "method": "GET"});',
     "Copy as fetch line 1", "no cookie and no header to keep"),
    ("curl 'https://app.example.com/api/me'", "Copy as cURL line 1", "no cookie and no header to keep"),
])
def test_a_copy_with_no_cookie_is_refused_naming_the_copies_that_carry_them(text, where, lacks):
    with pytest.raises(VaultError) as e:
        cookies.parse(text)
    assert str(e.value) == (f"{where}: the copied request carries {lacks} - copy it with Copy as cURL "
                            "or Copy as fetch (Node.js), which carry the cookies")


def test_a_cookie_header_reads_as_session_cookies_of_the_url():
    jar = cookies.parse("Cookie: a=1; t=eyJh==", "https://example.com/x")[0]
    assert values(jar) == {"a": "1", "t": "eyJh=="}
    for c in jar:
        assert (c["domain"], c["host_only"], c["path"], c["secure"], c["expires"]) == (
            "example.com", True, "/", True, None)
    [c] = cookies.parse("t=eyJh==", "http://example.com/")[0]
    assert (c["value"], c["secure"]) == ("eyJh==", False)
    assert values(cookies.parse("a = 1 ;  b=2", "https://example.com")[0]) == {"a": "1", "b": "2"}
    assert values(cookies.parse("cart[id]=7", "https://example.com")[0]) == {"cart[id]": "7"}


@pytest.mark.parametrize("text", ["a=1", "Cookie: a=1; b=2"])
def test_a_header_with_no_url_is_refused_naming_url(text):
    with pytest.raises(VaultError, match="--url"):
        cookies.parse(text)


def test_set_cookie_lines_read_their_attributes(monkeypatch):
    monkeypatch.setattr(cookies, "time", StoppedClock(1_800_000_000.0))
    sid, tok = cookies.parse(fixture("set-cookie.txt"), URL)[0]
    assert (sid["name"], sid["value"]) == ("sid", VALUES["sid"])
    assert sid["expires"] == 1_800_000_000 + 3600
    assert (sid["domain"], sid["host_only"], sid["secure"], sid["http_only"]) == (
        "app.example.com", True, True, True)
    assert (tok["value"], tok["domain"], tok["host_only"], tok["expires"]) == (
        VALUES["tok"], "example.com", False, Y2100)
    assert tok["http_only"] is False


def test_a_set_cookie_line_reads_its_path_and_a_line_with_none_gets_the_root():
    deep, root = cookies.parse("Set-Cookie: a=1; Path=/app; Secure\nSet-Cookie: b=2", URL)[0]
    assert (deep["name"], deep["path"]) == ("a", "/app")
    assert (root["name"], root["path"]) == ("b", "/")


def test_a_set_cookie_line_with_no_domain_and_no_url_is_refused():
    with pytest.raises(VaultError, match="Set-Cookie line 1: .*--url"):
        cookies.parse(fixture("set-cookie.txt"))
    assert len(cookies.parse(fixture("set-cookie.txt").splitlines()[1])[0]) == 1


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_cookies_txt_reads_httponly_lines_and_skips_comments(newline):
    text = fixture("cookies.txt").replace("\n", newline)
    sid, tok = cookies.parse(text)[0]
    assert (sid["name"], sid["value"], sid["http_only"], sid["expires"]) == ("sid", VALUES["sid"], True, Y2100)
    assert (sid["domain"], sid["host_only"], sid["secure"]) == ("app.example.com", True, True)
    assert (tok["name"], tok["value"], tok["http_only"], tok["expires"]) == ("tok", VALUES["tok"], False, None)
    assert (tok["domain"], tok["host_only"]) == ("example.com", False)


def test_a_cookie_editor_export_is_read():
    jar = by_name(cookies.parse(fixture("cookie-editor.json"))[0])
    assert values(jar.values()) == VALUES
    assert (jar["tok"]["domain"], jar["tok"]["host_only"], jar["tok"]["expires"]) == ("example.com", False, Y2100)
    assert (jar["tok"]["secure"], jar["tok"]["http_only"]) == (True, False)
    assert (jar["sid"]["domain"], jar["sid"]["host_only"], jar["sid"]["expires"]) == ("app.example.com", True, None)
    assert (jar["sid"]["secure"], jar["sid"]["http_only"]) == (True, True)
    assert jar["q"]["path"] == "/account"


def test_an_editthiscookie_export_is_read():
    text = fixture("editthiscookie.json")
    # EditThisCookie writes Cookie-Editor's keys and an `id` of its own.
    assert all("id" in item for item in json.loads(text))
    assert cookies.parse(text)[0] == [
        cookie("tok", domain="example.com", host_only=False, secure=True, expires=Y2100, value=VALUES["tok"]),
        cookie("sid", domain="app.example.com", path="/app", secure=True, http_only=True, value=VALUES["sid"]),
        cookie("q", domain="app.example.com", path="/account", expires=2_000_000_000, value=VALUES["q"]),
    ]


def test_a_playwright_storage_state_is_read():
    jar = by_name(cookies.parse(fixture("playwright-state.json"))[0])
    assert values(jar.values()) == VALUES
    assert (jar["sid"]["expires"], jar["sid"]["http_only"], jar["sid"]["host_only"]) == (None, True, True)
    assert (jar["tok"]["domain"], jar["tok"]["host_only"], jar["tok"]["expires"]) == ("example.com", False, Y2100)
    assert jar["q"]["secure"] is False


# The fixtures that carry no cookie: the two plain fetch copies, and the copy with headers only.
NO_COOKIES = {"chrome-fetch.txt", "chrome-fetch-headers.txt", "curl-headers-only.txt"}


@pytest.mark.parametrize("name", sorted(set(os.listdir(FIXTURES)) - NO_COOKIES))
def test_every_form_is_told_apart_with_no_form_option(name):
    assert list(inspect.signature(cookies.read).parameters) == ["text", "url"]
    jar = cookies.parse(fixture(name), URL)[0]
    assert jar and all(c["value"] for c in jar)


# Text with `=` that is no Cookie header: a URL, Copy as PowerShell and a raw HTTP request.
NO_FORM = [
    "https://app.example.com/?a=1&b=2",
    '$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession\n'
    '$session.Cookies.Add((New-Object System.Net.Cookie("sid", "1", "/", "app.example.com")))\n'
    'Invoke-WebRequest -UseBasicParsing -Uri "https://app.example.com/" -WebSession $session',
    "GET /dashboard HTTP/1.1\r\nHost: app.example.com\r\nCookie: sid=1; tok=2\r\n\r\n",
]


@pytest.mark.parametrize("text", ["hello world", "", "   \n", *NO_FORM])
def test_text_in_no_form_is_refused_naming_the_forms(text):
    with pytest.raises(VaultError) as e:
        cookies.parse(text, URL)
    for form in ("Copy as cURL", "Copy as fetch (Node.js)", "Set-Cookie", "cookies.txt",
                 "cookie JSON", "Playwright storage state", "Cookie header"):
        assert form in str(e.value)


def test_pasted_text_over_one_mib_is_refused():
    with pytest.raises(VaultError, match="1 MiB"):
        cookies.parse("a=" + "x" * cookies.MAX_PASTE, URL)


@pytest.mark.parametrize("head, quote", [
    ("curl 'https://app.example.com/' -b 'sid=v1' --data-raw ", '"'),
    ("curl 'https://app.example.com/' -b 'sid=v1' --data-raw ", ""),
    ('curl ^"https://app.example.com/^" -b ^"sid=v1^" --data-raw ', '^"'),
    ('curl "https://app.example.com/" -b "sid=v1" --data-raw ', '"'),
], ids=["bash-double-quoted", "bash-unquoted", "cmd", "firefox-138"])
def test_a_one_mib_word_is_parsed_in_under_a_second(head, quote):
    # The parse runs on the server's event loop; a word built a character at a time took 9 s.
    text = head + quote + "x" * (cookies.MAX_PASTE - len(head) - 2 * len(quote)) + quote
    start = time.perf_counter()
    assert values(cookies.parse(text)[0]) == {"sid": "v1"}
    assert time.perf_counter() - start < 1


# Inputs in each form that hold all three values, and the form's own way of writing them.
VERBATIM_INPUTS = {
    "curl bash": "curl 'https://app.example.com/' -b 'sid=s%3Aab.c%2F; tok=eyJhbGc==; q=\"a b\"'",
    "curl bash ansi-c": "curl 'https://app.example.com/' -b $'sid=s%3Aab.c%2F; tok=eyJhbGc==; q=\"a b\"; x=\\''",
    "curl cmd": 'curl ^"https://app.example.com/^" ^\r\n  -b ^"sid=s^%^3Aab.c^%^2F; tok=eyJhbGc==; q=^\\^"a b^\\^"^"',
    "firefox curl": fixture("firefox-curl.txt"),
    "fetch node": fixture("chrome-fetch-node.txt"),
    "set-cookie": "Set-Cookie: sid=s%3Aab.c%2F\nSet-Cookie: tok=eyJhbGc==; Secure\nSet-Cookie: q=\"a b\"; Path=/",
    "cookies.txt": netscape(("app.example.com", "FALSE", "/", "TRUE", 0, "sid", VALUES["sid"]),
                            ("app.example.com", "FALSE", "/", "TRUE", 0, "tok", VALUES["tok"]),
                            ("app.example.com", "FALSE", "/", "TRUE", 0, "q", VALUES["q"])),
    "cookie-editor": fixture("cookie-editor.json"),
    "playwright": fixture("playwright-state.json"),
    "header": "Cookie: sid=s%3Aab.c%2F; tok=eyJhbGc==; q=\"a b\"",
}


@pytest.mark.parametrize("form", sorted(VERBATIM_INPUTS))
def test_values_are_kept_byte_for_byte_through_every_form_and_output(form):
    jar = cookies.parse(VERBATIM_INPUTS[form], "https://app.example.com/")[0]
    got = values(jar)
    assert {k: got[k] for k in VALUES} == VALUES
    sent = [c for c in jar if c["name"] in VALUES]
    # cookies.txt keeps each value as its last field, and reads back the same.
    txt = cookies.to_netscape(sent)
    for c in sent:
        assert txt.count("\t" + c["name"] + "\t" + c["value"] + "\n") == 1
    assert values(cookies.parse(txt)[0]) == values(sent)
    # The Cookie header and the jar carry them as given: no quoting, no decoding.
    header = cookies.to_header(sent, "https://app.example.com/account")
    assert sorted(header.split("; ")) == sorted(f"{c['name']}={c['value']}" for c in sent)
    assert {c.name: c.value for c in cookies.to_jar(sent)} == values(sent)


# --------------------------------------------------------------------------- #
# the request headers of a copy
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", ["chrome-curl-bash-headers.txt", "chrome-curl-cmd-headers.txt"])
def test_a_curl_copy_keeps_every_header_except_the_browsers_own_in_paste_order(name):
    text = fixture(name)
    for own in ("accept", "accept-language", "cache-control", "content-type", "origin", "pragma", "priority",
                "referer", "sec-ch-ua", "sec-fetch-site", "user-agent"):
        assert f"{own}: " in text
    jar, headers = cookies.parse(text)
    assert headers == KEPT
    assert values(jar) == {"sid": "s%3Aab.c%2F", "tok": "eyJhbGc=="}
    assert cookies.read(text) == (jar, "https://app.example.com/", KEPT)


def test_a_fetch_copy_keeps_every_header_except_the_browsers_own_in_paste_order():
    text = fixture("chrome-fetch-node-headers.txt")
    # Chrome's Node.js copy writes Referrer-Policy among the headers; it is left out.
    assert '"Referrer-Policy": ' in text
    jar, headers = cookies.parse(text)
    assert headers == KEPT
    assert values(jar) == {"sid": "s%3Aab.c%2F", "tok": "eyJhbGc=="}


OWN = ["Host", "Cookie", "Content-Length", "Content-Type", "Accept", "Accept-Encoding", "Accept-Language",
       "User-Agent", "Referer", "Origin", "Sec-Fetch-Site", "Sec-CH-UA", "Connection", "Keep-Alive",
       "Cache-Control", "Pragma", "Priority", "If-None-Match", "If-Modified-Since", "TE", "Transfer-Encoding",
       "Upgrade-Insecure-Requests", "DNT", "Referrer-Policy", ":authority"]


@pytest.mark.parametrize("name", OWN)
def test_each_of_the_browsers_own_headers_and_one_with_no_value_is_left_out_in_any_letter_case(name):
    for written in (name, name.lower(), name.upper()):
        text = (f"curl 'https://app.example.com/' -H '{written}: a=1' -H 'X-Kept: 1' -H 'X-Empty;' "
                "-H 'X-None:' -H 'X-Blank: \t'")
        assert cookies.parse(text)[1] == [["X-Kept", "1"]]
        text = 'fetch("https://app.example.com/", ' + json.dumps(
            {"headers": {written: "a=1", "X-Kept": "1", "X-Blank": " \t", "X-Number": 5}}) + ");"
        assert cookies.parse(text)[1] == [["X-Kept", "1"]]


def test_a_name_that_only_starts_as_one_of_the_browsers_own_is_kept():
    names = ["Accepted", "Secret-Key", "Iffy", "Tea", "X-Host", "Hosting", "Cookie2", "Dnt-Mode", "Priority-Id"]
    text = "curl 'https://app.example.com/' " + " ".join(f"-H '{n}: v'" for n in names)
    assert cookies.parse(text)[1] == [[n, "v"] for n in names]


@pytest.mark.parametrize("name", ["set-cookie.txt", "cookies.txt", "cookie-editor.json", "editthiscookie.json",
                                  "playwright-state.json"])
def test_a_form_that_is_no_copied_request_gives_no_header(name):
    assert cookies.parse(fixture(name), URL)[1] == []
    assert cookies.parse("Cookie: a=1; b=2", URL)[1] == []
    assert cookies.read("a=1", URL)[2] == []


def test_a_kept_header_keeps_its_name_as_pasted_and_its_value_byte_for_byte():
    # The same value through the bash, cmd and fetch forms: a quote, %20, a backslash and = signs.
    for name in ("chrome-curl-bash-headers.txt", "chrome-curl-cmd-headers.txt", "chrome-fetch-node-headers.txt"):
        assert dict(cookies.parse(fixture(name))[1])["x-csrf-token"] == 'c"s%20r\\f=1'
    # The value follows the first colon; the spaces and tabs around it go, those in it stay.
    text = ("curl 'https://app.example.com/' -H 'X-Trace-Id: \t a: b  c=d== \t' "
            "-H $'x-q:it\\'s \"q\"' -H 'X-Trace-Id:second'")
    assert cookies.parse(text)[1] == [["X-Trace-Id", "a: b  c=d=="], ["x-q", "it's \"q\""],
                                      ["X-Trace-Id", "second"]]
    text = 'fetch("https://app.example.com/", {"headers": {"X-Api-Key": " k\\u00e9y\\\\1 ", "x-b": "a: b"}});'
    assert cookies.parse(text)[1] == [["X-Api-Key", "kéy\\1"], ["x-b", "a: b"]]


# Copies whose header is refused, each holding the marker in a header value, and the whole
# refusal: the form and the line, never the text.
NOT_A_TOKEN = "a header name is not an HTTP token"
LINE_BREAK = "a header value holds a line break or a NUL"
HEADER_REFUSALS = [
    (f"curl 'https://x.example/' \\\n  -b 'a=1' \\\n  -H $'x-a: {HEADER_MARKER}\\nx-b: 1'",
     f"Copy as cURL line 3: {LINE_BREAK}"),
    (f"curl 'https://x.example/' -H $'x-a: {HEADER_MARKER}\\rx-b: 1'", f"Copy as cURL line 1: {LINE_BREAK}"),
    (f"curl 'https://x.example/' -H $'x-a: {HEADER_MARKER}\\x00'", f"Copy as cURL line 1: {LINE_BREAK}"),
    (f"curl 'https://x.example/' -H 'x-a: {HEADER_MARKER}\nx-b: 1'", f"Copy as cURL line 1: {LINE_BREAK}"),
    (f"curl 'https://x.example/' \\\n  -H 'x a: {HEADER_MARKER}'", f"Copy as cURL line 2: {NOT_A_TOKEN}"),
    (f"curl 'https://x.example/' -H 'x-a : {HEADER_MARKER}'", f"Copy as cURL line 1: {NOT_A_TOKEN}"),
    (f"curl 'https://x.example/' -H $'x-a\\nx-b: {HEADER_MARKER}'", f"Copy as cURL line 1: {NOT_A_TOKEN}"),
    (f'curl ^"https://x.example/^" ^\r\n  -b ^"a=1^" ^\r\n  -H ^"x(a): {HEADER_MARKER}^"',
     f"Copy as cURL (cmd) line 3: {NOT_A_TOKEN}"),
    # Chrome writes a line end in a cmd value as ^ and two line ends.
    (f'curl ^"https://x.example/^" ^\r\n  -H ^"x-a: {HEADER_MARKER}^\r\n\r\nx-b: 1^"',
     f"Copy as cURL (cmd) line 2: {LINE_BREAK}"),
    (f'curl "https://x.example/" -H "x-a: {HEADER_MARKER}"^\n\n"x-b: 1"', f"Copy as cURL (cmd) line 1: {LINE_BREAK}"),
    ('fetch("https://x.example/", {\n  "headers": {\n    "x-a": "1",\n    "x-b": "' + HEADER_MARKER
     + '\\r\\nx-c: 1"\n  }\n});', f"Copy as fetch line 4: {LINE_BREAK}"),
    ('fetch("https://x.example/", {\n  "headers": {"cookie": "a=1",\n  "x-b": "' + HEADER_MARKER + '\\u0000"}});',
     f"Copy as fetch line 3: {LINE_BREAK}"),
    ('fetch("https://x.example/", {"headers": {"x b": "' + HEADER_MARKER + '"}});',
     f"Copy as fetch line 1: {NOT_A_TOKEN}"),
    # A key written with an escape gets the line of the options.
    ('fetch("https://x.example/",\n {"headers": {\n"x\\u0020b": "' + HEADER_MARKER + '"}});',
     f"Copy as fetch line 2: {NOT_A_TOKEN}"),
]


@pytest.mark.parametrize("text, refusal", HEADER_REFUSALS)
def test_a_header_that_is_no_token_or_holds_a_line_break_refuses_the_paste(text, refusal):
    with pytest.raises(VaultError) as e:
        cookies.parse(text)
    assert str(e.value) == refusal
    assert e.value.__cause__ is None


# A lone surrogate, written as a JSON escape: stored, no read could print the value.
NOT_UTF8 = [
    ('fetch("https://x.example/", {\n  "headers": {\n    "cookie": "a=' + MARKER + '\\ud800"\n  }\n});',
     "Copy as fetch line 3, cookie 1: a name, value, domain or path cannot be encoded as UTF-8"),
    ('fetch("https://x.example/", {\n  "headers": {\n    "cookie": "a=1",\n    "x-b": "' + HEADER_MARKER
     + '\\ud800"\n  }\n});', "Copy as fetch line 4: a header value cannot be encoded as UTF-8"),
]


@pytest.mark.parametrize("text, refusal", NOT_UTF8)
def test_a_cookie_or_header_value_that_is_not_utf8_refuses_the_paste(text, refusal):
    with pytest.raises(VaultError) as e:
        cookies.parse(text)
    assert str(e.value) == refusal
    assert e.value.__cause__ is None


async def test_a_paste_that_is_not_utf8_is_refused_at_a_write_and_nothing_is_written(jp_fetch, vault_env):
    await init(jp_fetch)
    await add_cookies(jp_fetch)
    before = vault_file(vault_env)
    for text, refusal in NOT_UTF8:
        for method, name in (("POST", "site/bad"), ("PATCH", "site/app")):
            status, body = await fails_body(jp_fetch, "entries", {"name": name, "fields": cookie_fields(text)},
                                            method=method)
            assert (status, body) == (400, {"code": "invalid", "error": refusal})
    assert vault_file(vault_env) == before
    assert [e["name"] for e in (await call(jp_fetch, "entries", method="GET"))["entries"]] == ["site/app"]


def test_a_plain_copy_as_fetch_with_credentials_include_stays_refused_whatever_its_headers():
    text = fixture("chrome-fetch-headers.txt")
    assert '"credentials": "include"' in text and '"x-app-client": "web 1.2"' in text
    assert "cookie" not in text.lower()
    with pytest.raises(VaultError) as e:
        cookies.parse(text)
    assert str(e.value) == ("Copy as fetch lines 1 to 20: the copied request carries no cookie - copy it "
                            "with Copy as cURL or Copy as fetch (Node.js), which carry the cookies")
    # The refusal is of credentials include: the same headers in a copy without it are read.
    for other in ('"omit"', '"same-origin"'):
        assert cookies.parse(text.replace('"include"', other)) == ([], [["x-app-client", "web 1.2"]])


def test_a_one_mib_copy_of_many_headers_is_parsed_in_under_a_second():
    # The parse runs on the server's event loop; a line counted from the start for each header is not linear.
    count = 70000
    curl = "curl 'https://app.example.com/' " + "\\\n-H 'x-a: b' " * count
    keys = ",\n".join(f'"x-{n}": "\\"v\\""' for n in range(count // 2))
    fetch = 'fetch("https://app.example.com/", {"headers": {' + keys + "}});"
    for text, kept in ((curl, count), (fetch, count // 2)):
        assert len(text) < cookies.MAX_PASTE
        start = time.perf_counter()
        assert len(cookies.parse(text)[1]) == kept
        assert time.perf_counter() - start < 1


# --------------------------------------------------------------------------- #
# the formatters
# --------------------------------------------------------------------------- #


def cookie(name, domain="example.com", host_only=True, path="/", secure=False, http_only=False,
           expires=None, value="v"):
    return {"name": name, "value": value, "domain": domain, "host_only": host_only, "path": path,
            "secure": secure, "http_only": http_only, "expires": expires}


def test_unexpired_keeps_session_and_future_cookies():
    jar = [cookie("s"), cookie("past", expires=999), cookie("future", expires=2001)]
    assert [c["name"] for c in cookies.unexpired(jar, 1000)] == ["s", "future"]


def test_to_netscape_writes_every_cookie_as_a_plain_line():
    # GNU wget 1.x skips a line that begins with #, so an HttpOnly cookie gets no #HttpOnly_.
    jar = [cookie("a", http_only=True, secure=True, expires=Y2100), cookie("b", host_only=False, path="/p")]
    text = cookies.to_netscape(jar)
    assert text.splitlines() == [
        "# Netscape HTTP Cookie File",
        f"example.com\tFALSE\t/\tTRUE\t{Y2100}\ta\tv",
        ".example.com\tTRUE\t/p\tFALSE\t0\tb\tv",
    ]
    assert [line for line in text.splitlines()[1:] if line.startswith("#")] == []
    # Read back, every attribute is kept but the HttpOnly flag, which no tool needs to send a cookie.
    assert cookies.parse(text)[0] == [{**c, "http_only": False} for c in jar]


def test_to_header_matches_domain_path_and_secure_as_http_cookiejar_does():
    jar = [cookie("host"), cookie("dom", host_only=False), cookie("deep", path="/api"),
           cookie("tls", secure=True), cookie("old", expires=1000)]
    assert sorted(cookies.to_header(jar, "http://example.com/").split("; ")) == ["dom=v", "host=v"]
    assert sorted(cookies.to_header(jar, "https://example.com/api/x").split("; ")) == [
        "deep=v", "dom=v", "host=v", "tls=v"]
    assert cookies.to_header(jar, "https://sub.example.com/") == "dom=v"
    assert cookies.to_header(jar, "https://other.example/") == ""


def test_to_jar_sends_a_host_only_cookie_to_a_host_with_no_dot():
    assert cookies.to_header([cookie("a", domain="localhost")], "http://localhost:8000/") == "a=v"
    jar = cookies.to_jar([cookie("a", http_only=True, expires=Y2100)])
    [c] = list(jar)
    assert (c.domain, c.expires, c.has_nonstandard_attr("HttpOnly")) == ("example.com", Y2100, True)


# --------------------------------------------------------------------------- #
# cookie entries in the vault
# --------------------------------------------------------------------------- #


def cookie_fields(text, url=URL, **fields):
    return {"type": "cookies", "url": url, "cookies": text, **fields}


async def add_cookies(jp_fetch, name="site/app", text=None, **fields):
    await call(jp_fetch, "entries", {"name": name, "fields": cookie_fields(
        text if text is not None else fixture("chrome-curl-bash.txt"), **fields)})


def test_an_entry_with_no_type_lists_as_login_and_add_sets_the_type(vault_env):
    svc = handlers._service
    svc.init(PASS)
    # Entries as 1.2.9 wrote them: no type.
    store.update_entries(store.vault_path(), svc._dek(), lambda entries: entries.extend([
        {"name": n, "username": "me", "password": "pw", "url": "", "category": "", "notes": "",
         "created": "2026-11-01T00:00:00Z", "updated": "2026-11-01T00:00:00Z",
         "used": "2026-11-01T00:00:00Z"} for n in ("a/one", "b/two")]))
    before = vault_file(vault_env)
    assert [e["type"] for e in svc.list_entries()] == ["login", "login"]
    assert vault_file(vault_env) == before
    svc.add("c/cookies", cookie_fields("a=1"))
    assert {e["name"]: e["type"] for e in svc.list_entries()} == {
        "a/one": "login", "b/two": "login", "c/cookies": "cookies"}
    with pytest.raises(VaultError, match="never changes the type"):
        svc.edit("a/one", {"type": "cookies"})
    with pytest.raises(VaultError, match="never changes the type"):
        svc.edit("c/cookies", {"type": "login"})
    svc.edit("c/cookies", {"notes": "kept", "cookies": "b=2"})
    [entry] = [e for e in svc.list_entries() if e["name"] == "c/cookies"]
    assert entry["type"] == "cookies" and [c["name"] for c in entry["cookies"]] == ["b"]
    with pytest.raises(VaultError, match="no cookies"):
        svc.edit("a/one", {"cookies": "a=1"})
    with pytest.raises(VaultError, match="no password"):
        svc.edit("c/cookies", {"password": "x"})
    with pytest.raises(VaultError, match="login or cookies"):
        svc.add("d/x", {"type": "card"})


async def test_cookies_are_sealed_and_read_back_with_every_attribute(jp_fetch, vault_env):
    await init(jp_fetch)
    text = netscape(("#HttpOnly_app.example.com", "FALSE", "/api", "TRUE", Y2100, "sid", MARKER),
                    (".example.com", "TRUE", "/", "FALSE", 0, "pref", "dark"))
    await add_cookies(jp_fetch, text=text)
    assert MARKER not in vault_file(vault_env)
    [entry] = [e for e in handlers._service._entries() if e["name"] == "site/app"]
    assert entry["type"] == "cookies"
    expected = [
        {"name": "sid", "value": MARKER, "domain": "app.example.com", "host_only": True,
         "path": "/api", "secure": True, "http_only": True, "expires": Y2100},
        {"name": "pref", "value": "dark", "domain": "example.com", "host_only": False,
         "path": "/", "secure": False, "http_only": False, "expires": None},
    ]
    assert entry["cookies"] == expected
    assert (await call(jp_fetch, "reveal", {"name": "site/app"}))["value"] == expected
    assert (await call(jp_fetch, "reveal", {"name": "site/app", "field": "cookies"}))["value"] == expected


async def test_a_jar_over_the_limit_is_refused_and_nothing_is_written(jp_fetch, vault_env):
    await init(jp_fetch)
    before = vault_file(vault_env)
    text = "; ".join(f"c{n}=" + "x" * 7000 for n in range(10))
    assert 70000 < len(text) < cookies.MAX_PASTE
    status, body = await fails_body(jp_fetch, "entries", {"name": "site/big", "fields": cookie_fields(text)})
    assert (status, body["code"]) == (400, "invalid") and "65536" in body["error"]
    assert vault_file(vault_env) == before
    assert (await call(jp_fetch, "entries", method="GET"))["entries"] == []


async def test_the_list_carries_type_and_cookie_metadata_never_a_value(jp_fetch, vault_env):
    await init(jp_fetch)
    await call(jp_fetch, "entries", {"name": "github/api", "fields": {"password": "pw"}})
    await add_cookies(jp_fetch, text=netscape(
        ("app.example.com", "FALSE", "/", "TRUE", Y2100, "sid", MARKER),
        (".example.com", "TRUE", "/", "TRUE", 0, "tok", MARKER + "-2")))
    r = await jp_fetch("jupyterlab-passkey-extension", "vault", "entries", method="GET")
    assert MARKER not in r.body.decode()
    login, site = json.loads(r.body)["entries"]
    assert login["type"] == "login" and "cookies" not in login
    assert site["type"] == "cookies"
    assert site["cookies"] == [{"domain": "app.example.com", "name": "sid", "expires": Y2100},
                               {"domain": "example.com", "name": "tok", "expires": None}]


@pytest.fixture
def routed(vault_env, monkeypatch):
    """The CLI's requests answered by the real handlers' tables, with their codes."""
    svc = handlers._service

    def request(method, action, body=None, params=None):
        table = {"GET": handlers._GET, "POST": handlers._POST, "PATCH": handlers._PATCH}[method]
        try:
            return table[action](svc, (params or {}) if method == "GET" else (body or {}))
        except vault_service.Locked as e:
            raise client.VaultLocked(str(e), "locked")
        except VaultError as e:
            raise client.VaultClientError(str(e), "invalid")

    for module in (client, vcli):
        monkeypatch.setattr(module, "request", request)
    return svc


@pytest.mark.parametrize("json_flag", [[], ["--json"]])
def test_vault_list_prints_no_cookie_value(routed, monkeypatch, capsys, json_flag):
    routed.init(PASS)
    routed.add("site/app", cookie_fields(f"sid={MARKER}; tok={MARKER}-2"))
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "vault", "list", *json_flag])
    assert cli.main() == 0
    out, err = capsys.readouterr()
    assert "site/app" in out and MARKER not in out + err


def test_expired_cookies_are_left_out_of_every_read(vault_env, monkeypatch):
    svc = handlers._service
    svc.init(PASS)
    svc.add("site/app", cookie_fields(netscape(
        ("app.example.com", "FALSE", "/", "TRUE", 2_000_000_000, "early", "e"),
        ("app.example.com", "FALSE", "/", "TRUE", 3_000_000_000, "late", "l"),
        ("app.example.com", "FALSE", "/", "TRUE", 0, "session", "s"))))
    monkeypatch.setattr(vault_service, "time", StoppedClock(2_000_000_001))
    for field in (None, "cookies"):
        assert [c["name"] for c in svc.read("site/app", field)] == ["late", "session"]
    nonce = svc.stage("site/app", None, "secret")
    staged = relay.collect(nonce, "secret")
    assert "\tlate\tl\n" in staged and "\tsession\ts\n" in staged and "early" not in staged
    assert svc.parse_cookies(netscape(("x.example", "FALSE", "/", "FALSE", 2_000_000_000, "a", "1")))["expired"] == 1


async def test_a_read_with_no_cookie_left_fails_with_code_expired(jp_fetch, vault_env, monkeypatch):
    await init(jp_fetch)
    await add_cookies(jp_fetch, name="site/old", text=netscape(
        ("app.example.com", "FALSE", "/", "TRUE", Y2100, "sid", MARKER)))
    # The cookie was unexpired at the write; the clock the service reads is past it now.
    monkeypatch.setattr(vault_service, "time", StoppedClock(Y2100 + 1))
    for body in ({"name": "site/old"}, {"name": "site/old", "field": "cookies"}):
        status, answer = await fails_body(jp_fetch, "reveal", body)
        assert (status, answer["code"]) == (410, "expired")
        assert "jupyterlab-passkey vault edit site/old --cookies" in answer["error"]
        assert MARKER not in json.dumps(answer)
    status, answer = await fails_body(jp_fetch, "stage", {"name": "site/old", "kind": "secret"})
    assert (status, answer["code"]) == (410, "expired")


EXPIRED = netscape(("app.example.com", "FALSE", "/", "TRUE", 1_000_000_000, "sid", MARKER))
PASTE_EXPIRED = "every cookie in the paste has expired - copy the cookies again from the browser"


def test_a_paste_with_no_unexpired_cookie_is_refused_at_add_and_edit(vault_env):
    svc = handlers._service
    svc.init(PASS)
    svc.add("site/app", cookie_fields("a=1"))
    before = vault_file(vault_env)
    for write in (lambda: svc.add("site/old", cookie_fields(EXPIRED)),
                  lambda: svc.edit("site/app", {"cookies": EXPIRED})):
        with pytest.raises(vault_service.Expired, match=f"^{PASTE_EXPIRED}$"):
            write()
    assert vault_file(vault_env) == before
    # One unexpired cookie beside the expired one, here a session cookie, is stored.
    svc.edit("site/app", {"cookies": EXPIRED + "app.example.com\tFALSE\t/\tTRUE\t0\tkeep\tk\n"})
    assert [c["name"] for c in svc._entries()[0]["cookies"]] == ["sid", "keep"]


async def test_a_rest_write_of_a_paste_with_no_unexpired_cookie_answers_410_expired(jp_fetch, vault_env):
    await init(jp_fetch)
    await add_cookies(jp_fetch)
    before = vault_file(vault_env)
    for method, name in (("POST", "site/old"), ("PATCH", "site/app")):
        status, answer = await fails_body(jp_fetch, "entries",
                                          {"name": name, "fields": cookie_fields(EXPIRED)}, method=method)
        assert (status, answer) == (410, {"error": PASTE_EXPIRED, "code": "expired"})
    assert vault_file(vault_env) == before
    # The preview answers its counts for any jar.
    assert (await call(jp_fetch, "cookies-parse", {"text": EXPIRED}))["expired"] == 1


async def test_the_expired_answer_reaches_the_client_and_json_as_code_expired(jp_fetch, vault_env,
                                                                             monkeypatch, capsys):
    await init(jp_fetch)
    await add_cookies(jp_fetch, name="site/old", text=netscape(
        ("app.example.com", "FALSE", "/", "TRUE", Y2100, "sid", MARKER)))
    monkeypatch.setattr(vault_service, "time", StoppedClock(Y2100 + 1))
    status, answer = await fails_body(jp_fetch, "reveal", {"name": "site/old"})
    unlocked = handlers._service.status()

    def server(req, timeout):
        # The server's own answers: the status, and the refused read captured above.
        if req.full_url.endswith("/status"):
            return io.BytesIO(json.dumps(unlocked).encode())
        raise urllib.error.HTTPError(req.full_url, status, "Gone", {},
                                     io.BytesIO(json.dumps(answer).encode()))

    monkeypatch.setattr(cli, "_found", ("http://127.0.0.1:1", "token"))
    monkeypatch.setattr(cli._LOOPBACK, "open", server)
    with pytest.raises(client.VaultClientError) as caught:
        client.Vault().get("site/old")
    assert caught.value.code == "expired"
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "vault", "get", "site/old", "--json"])
    assert cli.main() == 1
    obj = json.loads(capsys.readouterr().out)
    assert obj["ok"] is False and obj["code"] == "expired"
    assert "vault edit site/old --cookies" in obj["error"]


async def test_a_missing_vault_reaches_the_client_and_json_as_code_no_vault(jp_fetch, vault_env,
                                                                           monkeypatch, capsys):
    # The server's own answers with no vault, replayed through client.request.
    answers = {action: await fails_body(jp_fetch, action, body) for action, body in (
        ("reveal", {"name": "github/api"}),
        ("entries", {"name": "github/api", "fields": {"password": "x"}}),
        ("rename", {"name": "github/api", "new_name": "github/new"}),
        ("delete", {"name": "github/api"}))}
    assert {code for code, _ in answers.values()} == {400}
    status = handlers._service.status()

    def server(req, timeout):
        action = req.full_url.rsplit("/", 1)[1]
        if action == "status":
            return io.BytesIO(json.dumps(status).encode())
        code, answer = answers[action]
        raise urllib.error.HTTPError(req.full_url, code, "Bad Request", {},
                                     io.BytesIO(json.dumps(answer).encode()))

    monkeypatch.setattr(cli, "_found", ("http://127.0.0.1:1", "token"))
    monkeypatch.setattr(cli._LOOPBACK, "open", server)
    vault = client.Vault()
    for refused in (lambda: vault.get("github/api"), lambda: vault.add("github/api", password="x"),
                    lambda: vault.rename("github/api", "github/new"), lambda: vault.delete("github/api")):
        with pytest.raises(client.VaultClientError) as caught:
            refused()
        assert caught.value.code == "no-vault" and str(caught.value).startswith("no vault at ")
    for argv in (["get", "github/api"], ["rename", "github/api", "github/new"], ["rm", "github/api"]):
        monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "vault", *argv, "--json"])
        assert cli.main() == 1
        assert json.loads(capsys.readouterr().out)["code"] == "no-vault"
    # Text mode keeps the server's word.
    monkeypatch.setattr(sys, "argv", ["jupyterlab-passkey", "vault", "get", "github/api"])
    with pytest.raises(SystemExit, match=r"vault init` \[invalid\]$"):
        cli.main()


async def test_a_rest_write_takes_the_type_and_the_pasted_text(jp_fetch, vault_env):
    await init(jp_fetch)
    r = await jp_fetch("jupyterlab-passkey-extension", "vault", "entries", method="POST",
                       body=json.dumps({"name": "site/app", "fields": cookie_fields(fixture("firefox-curl.txt"))}))
    assert r.code == 204
    assert values((await call(jp_fetch, "reveal", {"name": "site/app"}))["value"]) == VALUES
    status, body = await fails_body(jp_fetch, "entries", {"name": "site/bad", "fields": cookie_fields("hello world")})
    assert (status, body["code"]) == (400, "invalid") and "accepted form" in body["error"]
    status, body = await fails_body(jp_fetch, "entries", {"name": "site/none", "fields": cookie_fields("")})
    assert status == 400
    r = await jp_fetch("jupyterlab-passkey-extension", "vault", "entries", method="PATCH",
                       body=json.dumps({"name": "site/app", "fields": {"cookies": "Cookie: n=1", "url": "https://new.example"}}))
    assert r.code == 204
    [c] = (await call(jp_fetch, "reveal", {"name": "site/app"}))["value"]
    assert (c["name"], c["domain"]) == ("n", "new.example")
    assert [e["name"] for e in (await call(jp_fetch, "entries", method="GET"))["entries"]] == ["site/app"]


async def test_cookies_parse_answers_a_summary_and_writes_nothing(jp_fetch, vault_env):
    await init(jp_fetch)
    before = vault_file(vault_env)
    summary = await call(jp_fetch, "cookies-parse", {"text": fixture("cookie-editor.json"), "url": URL})
    assert summary == {"count": 3, "domains": ["app.example.com", "example.com"],
                       "names": ["tok", "sid", "q"], "expired": 0, "headers": []}
    summary = await call(jp_fetch, "cookies-parse", {"text": "a=1; b=2", "url": URL})
    assert (summary["count"], summary["domains"], summary["names"]) == (2, ["app.example.com"], ["a", "b"])
    status, body = await fails_body(jp_fetch, "cookies-parse", {"text": "a=1"})
    assert (status, body["code"]) == (400, "invalid") and "--url" in body["error"]
    assert vault_file(vault_env) == before
    assert (await call(jp_fetch, "entries", method="GET"))["entries"] == []


# Malformed pastes in each form, each holding the marker, and how the refusal starts: the
# form and the line, as the paste numbers its lines.
REFUSALS = [
    (f"curl 'https://x.example/' -b '{MARKER}=1", "Copy as cURL line 1: "),
    (f"curl 'https://x.example/' -b $'a={MARKER}", "Copy as cURL line 1: "),
    (f"curl 'https://x.example/' -b $'a={MARKER}\\U7fffffff'", "Copy as cURL line 1: "),
    (f"curl 'https://x.example/' -H 'accept: {MARKER}'", "Copy as cURL line 1: "),
    ("curl 'https://x.example/' -b", "Copy as cURL line 1: "),
    (f'curl ^"https://x.example/^" -b ^"a={MARKER}', "Copy as cURL (cmd) line 1: "),
    (f'fetch("https://x.example/", {{"headers": {{"cookie": "a={MARKER}"', "Copy as fetch line 1: "),
    (f'[{{"name": "{MARKER}", "value": 5, "domain": "x.example"}}]', "cookie JSON line 1, cookie 1: "),
    (f'[{{"name": "a", "value": "{MARKER}", "domain": "x.example", "expirationDate": "{MARKER}"}}]',
     "cookie JSON line 1, cookie 1: "),
    (f'{{"cookies": "{MARKER}"}}', "Playwright storage state line 1: "),
    (f"[{MARKER}", "cookie JSON line 1: "),
    (f"Set-Cookie: {MARKER}", "Set-Cookie line 1: "),
    (f"Set-Cookie: a={MARKER}\nnot a header {MARKER}", "Set-Cookie line 2: "),
    (f"# Netscape HTTP Cookie File\nx.example\tTRUE\t/\t{MARKER}", "cookies.txt line 2: "),
    (f"# Netscape HTTP Cookie File\n.x.example\tTRUE\t/\tFALSE\t{MARKER}\ta\tb", "cookies.txt line 2: "),
    (f"Cookie: {MARKER}", "line 1: no cookie in an accepted form"),
    (f"a={MARKER}\x01", "Cookie header line 1, cookie 1: "),
    (f"a=1; {MARKER}; b=2", "Cookie header line 1, cookie 2: "),
    # A refusal past the first line names the line the bad cookie is on.
    (fixture("chrome-curl-bash.txt").replace("tok=eyJhbGc==", MARKER), "Copy as cURL line 4, cookie 2: "),
    (fixture("chrome-curl-cmd.txt").replace("tok=eyJhbGc==", MARKER), "Copy as cURL (cmd) line 4, cookie 2: "),
    (fixture("chrome-fetch-node.txt").replace("tok=eyJhbGc==", MARKER), "Copy as fetch line 12, cookie 2: "),
    (fixture("cookie-editor.json").replace('"s%3Aab.c%2F"', f'5, "x": "{MARKER}"'), "cookie JSON line 15, cookie 2: "),
    (fixture("playwright-state.json").replace("4102444800.5", f'"{MARKER}"'),
     "Playwright storage state line 13, cookie 2: "),
    (f"curl \\\n  -b 'a={MARKER}' \\\n  -X GET", "Copy as cURL lines 1 to 3: no URL with a host"),
    # Line ends before the paste count, as the user sees them in what they pasted.
    (f"\n\n# Netscape HTTP Cookie File\n.x.example\tTRUE\t/\tFALSE\t{MARKER}\ta\tb", "cookies.txt line 4: "),
    (f"\r\n\r\n  a=1; {MARKER}; b=2", "Cookie header line 3, cookie 2: "),
    ("\r\n" + fixture("chrome-curl-cmd.txt").replace("tok=eyJhbGc==", MARKER),
     "Copy as cURL (cmd) line 5, cookie 2: "),
]
MALFORMED = [text for text, _ in REFUSALS]


@pytest.mark.parametrize("text, where", REFUSALS)
def test_a_refusal_names_the_form_and_the_line_never_the_text(text, where):
    with pytest.raises(VaultError) as e:
        cookies.parse(text, "https://x.example/")
    assert str(e.value).startswith(where)
    assert MARKER not in str(e.value) and e.value.__cause__ is None


async def test_no_cookie_value_or_pasted_text_reaches_a_log_an_error_or_an_answer(jp_fetch, vault_env, caplog):
    caplog.set_level(logging.DEBUG)
    await init(jp_fetch)
    await add_cookies(jp_fetch, text=f"sid={MARKER}-stored")
    answers, errors = [], []
    for text in [*MALFORMED, f"a={MARKER}"]:
        answers.append(await fails_body(jp_fetch, "cookies-parse", {"text": text}))
        answers.append(await fails_body(jp_fetch, "entries", {"name": "site/new", "fields": cookie_fields(text, url="")}))
        with pytest.raises(VaultError) as e:
            handlers._service.add("site/new", cookie_fields(text, url=""))
        errors.append(str(e.value))
    for text in MALFORMED:
        answers.append(await fails_body(jp_fetch, "entries", {"name": "site/app", "fields": {"cookies": text}},
                                        method="PATCH"))
    await call(jp_fetch, "entries", method="GET")
    await call(jp_fetch, "rename", {"name": "site/app", "new_name": "site/renamed"})
    assert {status for status, _ in answers} == {400}
    assert MARKER not in json.dumps(answers) + json.dumps(errors)
    assert MARKER not in caplog.text
    assert not any(MARKER in str(r.args) for r in caplog.records)


# --------------------------------------------------------------------------- #
# the request headers of a cookie entry
# --------------------------------------------------------------------------- #


def marked(name="chrome-curl-bash-headers.txt"):
    """The fixture with the marker in its authorization header, and the headers it keeps."""
    return (fixture(name).replace("hdr.fake-token==", HEADER_MARKER),
            [["authorization", f"Bearer {HEADER_MARKER}"], *KEPT[1:]])


def without_headers_key(name):
    """Rewrite the entry as it was written before headers were kept."""
    def change(entries):
        [entry] = [e for e in entries if e["name"] == name]
        del entry["headers"]

    store.update_entries(store.vault_path(), handlers._service._dek(), change)


async def test_headers_are_sealed_with_the_entry_and_read_back_in_paste_order(jp_fetch, vault_env):
    await init(jp_fetch)
    text, kept = marked()
    await add_cookies(jp_fetch, text=text)
    sealed = vault_file(vault_env)
    for value in (HEADER_MARKER, "web 1.2", "s%20r"):
        assert value not in sealed
    [entry] = handlers._service._entries()
    assert entry["headers"] == kept and [c["name"] for c in entry["cookies"]] == ["sid", "tok"]
    assert (await call(jp_fetch, "reveal", {"name": "site/app", "field": "headers"}))["value"] == kept
    assert values((await call(jp_fetch, "reveal", {"name": "site/app"}))["value"]) == {
        "sid": "s%3Aab.c%2F", "tok": "eyJhbGc=="}
    # The cmd and the Node.js copies of the request store the same headers.
    await add_cookies(jp_fetch, name="site/cmd", text=marked("chrome-curl-cmd-headers.txt")[0])
    await add_cookies(jp_fetch, name="site/node", text=marked("chrome-fetch-node-headers.txt")[0])
    assert handlers._service.read("site/cmd", "headers") == kept
    assert handlers._service.read("site/node", "headers")[:3] == kept
    assert HEADER_MARKER not in vault_file(vault_env)


async def test_the_list_and_the_preview_give_the_header_names_never_a_value(jp_fetch, vault_env):
    await init(jp_fetch)
    text, kept = marked()
    names = [name for name, _ in kept]
    await call(jp_fetch, "entries", {"name": "github/api", "fields": {"password": "pw"}})
    await add_cookies(jp_fetch, text=text)
    before = vault_file(vault_env)
    r = await jp_fetch("jupyterlab-passkey-extension", "vault", "entries", method="GET")
    login, site = json.loads(r.body)["entries"]
    assert site["headers"] == names and "headers" not in login
    r2 = await jp_fetch("jupyterlab-passkey-extension", "vault", "cookies-parse", method="POST",
                        body=json.dumps({"text": text}))
    assert json.loads(r2.body) == {"count": 2, "domains": ["app.example.com"], "names": ["sid", "tok"],
                                   "expired": 0, "headers": names}
    for body in (r.body, r2.body):
        for value in (HEADER_MARKER, "web 1.2", "s%20r"):
            assert value not in body.decode()
    assert vault_file(vault_env) == before


async def test_a_copy_with_headers_and_no_cookie_is_stored_with_the_copys_origin(jp_fetch, vault_env):
    await init(jp_fetch)
    text = fixture("curl-headers-only.txt")
    assert await call(jp_fetch, "cookies-parse", {"text": text}) == {
        "count": 0, "domains": [], "names": [], "expired": 0, "headers": ["Authorization"]}
    assert (await call(jp_fetch, "entries", method="GET"))["entries"] == []
    await call(jp_fetch, "entries", {"name": "api/me", "fields": {"type": "cookies", "cookies": text}})
    # A url given with the copy stays; a fetch copy with no cookie is stored as the cURL copy is.
    await call(jp_fetch, "entries", {"name": "api/own", "fields": cookie_fields(text, url="https://own.example")})
    await call(jp_fetch, "entries", {"name": "api/node", "fields": {"type": "cookies", "cookies": (
        'fetch("https://api.example.com:8443/v1/me", {"headers": {"authorization": "Bearer hdr.fake-only=="}});')}})
    stored = {e["name"]: e for e in handlers._service._entries()}
    assert {n: (e["type"], e["url"], e["cookies"]) for n, e in stored.items()} == {
        "api/me": ("cookies", "https://api.example.com/", []),
        "api/own": ("cookies", "https://own.example", []),
        "api/node": ("cookies", "https://api.example.com:8443/", [])}
    assert stored["api/me"]["headers"] == stored["api/own"]["headers"] == ONLY
    assert stored["api/node"]["headers"] == [["authorization", "Bearer hdr.fake-only=="]]
    listed = {e["name"]: e for e in (await call(jp_fetch, "entries", method="GET"))["entries"]}
    assert (listed["api/me"]["cookies"], listed["api/me"]["headers"]) == ([], ["Authorization"])
    assert (await call(jp_fetch, "reveal", {"name": "api/me", "field": "headers"}))["value"] == ONLY
    # An edit to a copy with no cookie leaves the entry with its headers and no cookie.
    await add_cookies(jp_fetch)
    await call(jp_fetch, "entries", {"name": "site/app", "fields": {"cookies": text}}, method="PATCH")
    [edited] = [e for e in handlers._service._entries() if e["name"] == "site/app"]
    assert (edited["cookies"], edited["headers"], edited["url"]) == ([], ONLY, URL)


async def test_a_copy_with_no_cookie_and_no_header_to_keep_is_refused_and_nothing_is_written(jp_fetch, vault_env):
    await init(jp_fetch)
    await add_cookies(jp_fetch)
    before = vault_file(vault_env)
    for text in ("curl 'https://app.example.com/api/me' -H 'accept: application/json' -H 'X-Empty;'",
                 'fetch("https://app.example.com/api/me", {"headers": {"accept": "*/*"}});'):
        for method, name in (("POST", "site/none"), ("PATCH", "site/app")):
            status, body = await fails_body(jp_fetch, "entries",
                                            {"name": name, "fields": cookie_fields(text, url="")}, method=method)
            assert (status, body["code"]) == (400, "invalid")
            assert body["error"].endswith(": the copied request carries no cookie and no header to keep - copy it "
                                          "with Copy as cURL or Copy as fetch (Node.js), which carry the cookies")
        status, body = await fails_body(jp_fetch, "cookies-parse", {"text": text})
        assert (status, body["code"]) == (400, "invalid") and "no header to keep" in body["error"]
    assert vault_file(vault_env) == before
    assert [e["name"] for e in (await call(jp_fetch, "entries", method="GET"))["entries"]] == ["site/app"]


async def test_a_plain_copy_as_fetch_is_refused_at_a_write_and_nothing_is_written(jp_fetch, vault_env):
    await init(jp_fetch)
    await add_cookies(jp_fetch, text=fixture("chrome-curl-bash-headers.txt"))
    before = vault_file(vault_env)
    text = fixture("chrome-fetch-headers.txt")
    for method, name in (("POST", "site/plain"), ("PATCH", "site/app")):
        status, body = await fails_body(jp_fetch, "entries", {"name": name, "fields": cookie_fields(text)},
                                        method=method)
        assert (status, body) == (400, {"code": "invalid", "error": (
            "Copy as fetch lines 1 to 20: the copied request carries no cookie - copy it with Copy as cURL "
            "or Copy as fetch (Node.js), which carry the cookies")})
    assert vault_file(vault_env) == before
    assert handlers._service.read("site/app", "headers") == KEPT
    # The same copy without credentials include carries no cookie of the browser's: it is stored.
    await call(jp_fetch, "entries", {"name": "site/omit", "fields": cookie_fields(
        text.replace('"include"', '"omit"'))})
    assert handlers._service.read("site/omit", "headers") == [["x-app-client", "web 1.2"]]


def test_edit_cookies_replaces_the_cookies_and_the_headers_and_other_edits_keep_both(vault_env):
    svc = handlers._service
    svc.init(PASS)
    svc.add("site/app", {"type": "cookies", "cookies": fixture("chrome-curl-bash-headers.txt")})
    jar = svc.read("site/app")
    # An edit of other fields, and an empty paste, keep the cookies and the headers.
    svc.edit("site/app", {"url": "https://app.example.com/x", "notes": "n", "category": "c", "username": "u"})
    svc.edit("site/app", {"cookies": ""})
    svc.rename("site/app", "site/web")
    assert svc.read("site/web", "headers") == KEPT and svc.read("site/web") == jar
    # A new copy replaces both.
    svc.edit("site/web", {"cookies": "curl 'https://app.example.com/' -b 'n=1' -H 'X-New: 2'"})
    assert svc.read("site/web", "headers") == [["X-New", "2"]] and values(svc.read("site/web")) == {"n": "1"}
    # A form that carries no headers leaves the entry with no header.
    svc.edit("site/web", {"cookies": fixture("cookies.txt")})
    [entry] = svc._entries()
    assert entry["headers"] == [] and [c["name"] for c in entry["cookies"]] == ["sid", "tok"]
    assert svc.read("site/web", "headers") == [] and svc.list_entries()[0]["headers"] == []
    # A refused paste keeps both.
    svc.edit("site/web", {"cookies": fixture("chrome-curl-bash-headers.txt")})
    with pytest.raises(VaultError):
        svc.edit("site/web", {"cookies": HEADER_REFUSALS[0][0]})
    assert svc.read("site/web", "headers") == KEPT and svc.read("site/web") == jar


async def test_a_rest_edit_with_a_form_that_carries_no_headers_leaves_no_header(jp_fetch, vault_env):
    await init(jp_fetch)
    await add_cookies(jp_fetch, text=fixture("chrome-curl-bash-headers.txt"))
    await call(jp_fetch, "entries", {"name": "site/app", "fields": {"notes": "kept"}}, method="PATCH")
    assert (await call(jp_fetch, "reveal", {"name": "site/app", "field": "headers"}))["value"] == KEPT
    await call(jp_fetch, "entries", {"name": "site/app", "fields": {"cookies": "Cookie: n=1"}}, method="PATCH")
    assert (await call(jp_fetch, "reveal", {"name": "site/app", "field": "headers"}))["value"] == []
    [listed] = (await call(jp_fetch, "entries", method="GET"))["entries"]
    assert listed["headers"] == [] and [c["name"] for c in listed["cookies"]] == ["n"]


def big_headers(size):
    """A cURL copy with one cookie whose kept headers are `size` characters as stored."""
    text = "curl 'https://app.example.com/' -b 'a=1' -H 'x-a: " + "x" * (size - len('[["x-a", ""]]')) + "'"
    assert len(json.dumps(cookies.parse(text)[1])) == size
    return text


async def test_headers_over_the_limit_are_refused_and_nothing_is_written(jp_fetch, vault_env):
    await init(jp_fetch)
    await add_cookies(jp_fetch)
    before = vault_file(vault_env)
    text = "curl 'https://app.example.com/' -b 'a=1' " + " ".join(
        f"-H 'x-h{n}: {HEADER_MARKER}{'x' * 7000}'" for n in range(10))
    assert 70000 < len(text) < cookies.MAX_PASTE
    answers = [await fails_body(jp_fetch, "entries", {"name": name, "fields": cookie_fields(text)}, method=method)
               for method, name in (("POST", "site/big"), ("PATCH", "site/app"))]
    answers.append(await fails_body(jp_fetch, "cookies-parse", {"text": text}))
    answers.append(await fails_body(jp_fetch, "entries", {"name": "site/big", "fields": cookie_fields(
        big_headers(vault_service.MAX_FIELD + 1))}))
    for status, body in answers:
        assert (status, body["code"]) == (400, "invalid")
        assert body["error"].startswith("the headers are ") and "65536" in body["error"]
        assert HEADER_MARKER not in body["error"]
    assert vault_file(vault_env) == before
    assert [e["name"] for e in (await call(jp_fetch, "entries", method="GET"))["entries"]] == ["site/app"]
    # Headers of the limit's size are stored.
    await call(jp_fetch, "entries", {"name": "site/full", "fields": cookie_fields(big_headers(vault_service.MAX_FIELD))})
    assert len(json.dumps(handlers._service.read("site/full", "headers"))) == vault_service.MAX_FIELD


async def test_the_read_route_answers_the_headers_of_a_cookie_entry_and_refuses_a_login_entry(jp_fetch, vault_env):
    await init(jp_fetch)
    await call(jp_fetch, "entries", {"name": "github/api", "fields": {"password": "pw"}})
    await add_cookies(jp_fetch, text=fixture("chrome-curl-bash-headers.txt"))
    assert (await call(jp_fetch, "reveal", {"name": "site/app", "field": "headers"}))["value"] == KEPT
    status, body = await fails_body(jp_fetch, "reveal", {"name": "github/api", "field": "headers"})
    assert (status, body) == (400, {"error": "'github/api' is a login entry; it has no headers", "code": "invalid"})
    status, body = await fails_body(jp_fetch, "reveal", {"name": "site/app", "field": "header"})
    assert (status, body["code"]) == (400, "invalid") and body["error"].endswith("cookies or headers")
    # An entry written before headers were kept answers an empty list, and reads as before.
    without_headers_key("site/app")
    assert "headers" not in handlers._service._entries()[1]
    assert (await call(jp_fetch, "reveal", {"name": "site/app", "field": "headers"}))["value"] == []
    assert len((await call(jp_fetch, "reveal", {"name": "site/app"}))["value"]) == 2
    listed = (await call(jp_fetch, "entries", method="GET"))["entries"]
    assert listed[1]["headers"] == [] and "headers" not in listed[0]
    # The headers are not copied or shown: the stage route refuses the field.
    status, body = await fails_body(jp_fetch, "stage", {"name": "site/app", "field": "headers", "kind": "secret"})
    assert (status, body["code"]) == (400, "invalid") and "vault get NAME --format headers" in body["error"]


async def test_a_cookie_read_of_an_entry_with_no_cookie_is_refused_naming_format_headers(jp_fetch, vault_env):
    await init(jp_fetch)
    await call(jp_fetch, "entries", {"name": "api/it's me", "fields": {
        "type": "cookies", "cookies": fixture("curl-headers-only.txt")}})
    refusal = {"code": "invalid", "error": ("\"api/it's me\" stores no cookie - read its headers with "
                                            "`jupyterlab-passkey vault get 'api/it'\"'\"'s me' --format headers`")}
    for action, body in (("reveal", {}), ("reveal", {"field": "cookies"}), ("stage", {"kind": "secret"}),
                         ("stage", {"kind": "code"})):
        assert await fails_body(jp_fetch, action, {"name": "api/it's me", **body}) == (400, refusal)
    assert (await call(jp_fetch, "reveal", {"name": "api/it's me", "field": "headers"}))["value"] == ONLY
    assert (await call(jp_fetch, "reveal", {"name": "api/it's me", "field": "url"}))["value"] == "https://api.example.com/"


async def test_the_headers_of_an_entry_whose_cookies_all_expired_fail_with_code_expired(jp_fetch, vault_env,
                                                                                         monkeypatch):
    await init(jp_fetch)
    await add_cookies(jp_fetch, name="site/old", text=marked()[0])

    # A copy's cookies are session cookies; the stored ones here get an expiry, as a later write may give.
    def change(entries):
        for c in entries[0]["cookies"]:
            c["expires"] = Y2100

    store.update_entries(store.vault_path(), handlers._service._dek(), change)
    assert len((await call(jp_fetch, "reveal", {"name": "site/old", "field": "headers"}))["value"]) == 3
    monkeypatch.setattr(vault_service, "time", StoppedClock(Y2100 + 1))
    for body in ({"field": "headers"}, {"field": "cookies"}, {}):
        status, answer = await fails_body(jp_fetch, "reveal", {"name": "site/old", **body})
        assert (status, answer) == (410, {"code": "expired", "error": (
            "every cookie of 'site/old' has expired - paste new ones with "
            "`jupyterlab-passkey vault edit site/old --cookies`")})
    with pytest.raises(vault_service.Expired):
        handlers._service.read("site/old", "headers")
    # The other fields are read as before, and the list still names the headers.
    assert (await call(jp_fetch, "reveal", {"name": "site/old", "field": "url"}))["value"] == URL
    [listed] = (await call(jp_fetch, "entries", method="GET"))["entries"]
    assert listed["headers"] == ["authorization", "x-app-client", "x-csrf-token"]


async def test_no_header_value_reaches_a_log_an_error_or_an_answer(jp_fetch, vault_env, caplog):
    caplog.set_level(logging.DEBUG)
    await init(jp_fetch)
    await call(jp_fetch, "entries", {"name": "github/api", "fields": {"password": "pw"}})
    await add_cookies(jp_fetch, text=f"curl 'https://app.example.com/' -b 'a=1' -H 'authorization: {HEADER_MARKER}-stored'")
    before = vault_file(vault_env)
    header = f"-H 'authorization: Bearer {HEADER_MARKER}'"
    refused = [
        *[text for text, _ in HEADER_REFUSALS],
        # Over the limit, no URL, a quote not closed, a plain fetch copy, and a bad cookie beside the header.
        "curl 'https://x.example/' -b 'a=1' " + f"-H 'x-a: {HEADER_MARKER}{'x' * 70000}'",
        f"curl {header}",
        f"curl 'https://x.example/' {header} -H 'x-b: {HEADER_MARKER}",
        fixture("chrome-fetch-headers.txt").replace("web 1.2", HEADER_MARKER),
        f"curl 'https://x.example/' {header} -b 'a=1; novalue'",
        'fetch("https://x.example/", {"headers": {"authorization": "' + HEADER_MARKER + '"',
    ]
    answers, errors = [], []
    for text in refused:
        answers.append(await fails_body(jp_fetch, "cookies-parse", {"text": text}))
        answers.append(await fails_body(jp_fetch, "entries", {"name": "site/new", "fields": cookie_fields(text, url="")}))
        answers.append(await fails_body(jp_fetch, "entries", {"name": "site/app", "fields": {"cookies": text}},
                                        method="PATCH"))
        with pytest.raises(VaultError) as e:
            handlers._service.add("site/new", cookie_fields(text, url=""))
        errors.append(str(e.value))
        assert e.value.__cause__ is None
    stored = f"curl 'https://x.example/' -b 'a=1' {header}"
    # A copy that would be stored, sent where it is refused: a login entry, a taken name, an unknown entry.
    answers.append(await fails_body(jp_fetch, "entries", {"name": "github/new", "fields": {"cookies": stored}}))
    answers.append(await fails_body(jp_fetch, "entries", {"name": "github/api", "fields": {"cookies": stored}},
                                    method="PATCH"))
    answers.append(await fails_body(jp_fetch, "entries", {"name": "site/app", "fields": cookie_fields(stored)}))
    answers.append(await fails_body(jp_fetch, "entries", {"name": "site/absent", "fields": {"cookies": stored}},
                                    method="PATCH"))
    answers.append(await fails_body(jp_fetch, "reveal", {"name": "github/api", "field": "headers"}))
    answers.append(await fails_body(jp_fetch, "stage", {"name": "site/app", "field": "headers", "kind": "secret"}))
    assert vault_file(vault_env) == before
    assert [e["name"] for e in handlers._service._entries()] == ["github/api", "site/app"]
    assert {status for status, _ in answers} == {400, 404, 409}
    # The answers that carry the names: the preview, the list and a rename.
    shown = [await call(jp_fetch, "cookies-parse", {"text": stored}), await call(jp_fetch, "entries", method="GET")]
    await call(jp_fetch, "rename", {"name": "site/app", "new_name": "site/renamed"})
    assert shown[0]["headers"] == shown[1]["entries"][1]["headers"] == ["authorization"]
    assert HEADER_MARKER not in json.dumps(answers) + json.dumps(errors) + json.dumps(shown)
    assert HEADER_MARKER not in caplog.text
    assert not any(HEADER_MARKER in str(r.args) for r in caplog.records)
    assert HEADER_MARKER not in vault_file(vault_env)
