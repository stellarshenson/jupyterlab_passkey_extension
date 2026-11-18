"""Cookie entries: the parser of every pasted form, and the formatters of the stored list.

A stored cookie is {name, value, domain, host_only, path, secure, http_only, expires}:
the domain has no leading dot, and `expires` is whole Unix seconds, or None for a
session cookie. A value is opaque: it is kept as given, never decoded, re-encoded or
trimmed.

A cURL or fetch copy also carries the request headers. Those kept are stored beside the
cookies as [name, value] pairs in paste order: the name as pasted, the value as it follows
the first colon, with the spaces and tabs around it removed.

The form of pasted text is read from the text itself. A refusal names the form and a
line or cookie number, never the text: the text carries the values.
"""

import http.cookiejar
import json
import math
import re
import time
import urllib.parse
import urllib.request

from .store import VaultError

MAX_PASTE = 1 << 20
FORMS = ("a browser's Copy as cURL or Copy as fetch (Node.js), Set-Cookie lines, a cookies.txt, "
         "a cookie JSON export, a Playwright storage state or a Cookie header")
NO_COOKIE = ("the copied request carries no cookie - copy it with Copy as cURL or Copy as fetch "
             "(Node.js), which carry the cookies")
NOTHING_KEPT = ("the copied request carries no cookie and no header to keep - copy it with Copy as "
                "cURL or Copy as fetch (Node.js), which carry the cookies")
# The browser's own headers, which a copy's kept headers leave out, in any letter case.
_OWN = re.compile(r"host|cookie|content-length|content-type|accept(-.*)?|user-agent|referer|origin"
                  r"|sec-.*|connection|keep-alive|cache-control|pragma|priority|if-.*|te"
                  r"|transfer-encoding|upgrade-insecure-requests|dnt|referrer-policy|:.*", re.I)
# A header name: an HTTP token (RFC 9110 5.6.2).
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
# A string of the JSON in a fetch copy, and the colon after it when it is a key.
_JSON_STRING = re.compile(r'"((?:[^"\\]+|\\.)*)"(\s*:)?')
# The options of a browser's cURL copy that take a value, so the value is not read as the URL.
_CURL_VALUES = {"-H", "--header", "-b", "--cookie", "--url", "-X", "--request", "-d", "--data",
                "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode", "--json",
                "-F", "--form", "-A", "--user-agent", "-e", "--referer", "-u", "--user"}
# bash's $'...' escapes; one not here keeps its backslash, as bash keeps it.
_ANSI_C = {"n": "\n", "r": "\r", "t": "\t", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b",
           "f": "\f", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
# A run of characters that stand for themselves in a shell word, or the one character
# that ends the run; a word grows by runs, so a long one is read in linear time.
_QUOTED = re.compile(r'\\|[^"\\]+')
_BASH_PLAIN = re.compile(r"[^ \t\r\n\\'\"$]+|\$")
_CMD_PLAIN = re.compile(r'\\|[^"\\ \t\r\n]+')
# Firefox 138 and earlier on Windows: a word it left bare, the space between two words (or
# the ^ and line end that joins them), and one piece of a word in quotes - a line end, a
# quote, an escaped character, the ^ it put after a %, a character with the ^ it put before
# it (in ASCII, one outside its class), or a plain run.
_FIREFOX_BARE = re.compile(r"[a-zA-Z.-]*")
_FIREFOX_GAP = re.compile(r"(?:[ \t\r\n]+|\^\r?\n)*")
_FIREFOX_PIECE = re.compile(
    r'("\^\r?\n\r?\n")|""|\\[\\`$]|(?<=%)\^(?=[a-zA-Z0-9_])'
    r'|\^[^a-zA-Z0-9 \t\n\v\f\r_\-:=+~/.\',?;()*$&\\{}"`]|[^"\\^]+')
_ESCAPE = re.compile(r"\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|.)", re.S)


def _line(text, pos):
    return text.count("\n", 0, pos) + 1


def _span(form, text):
    """The form and every line of the text, for a refusal of what the whole text lacks."""
    last = _line(text, len(text.rstrip()))
    return f"{form} line 1" if last == 1 else f"{form} lines 1 to {last}"


def _lines(text):
    """(number, line) of each line, CRLF or LF."""
    return [(n, line[:-1] if line.endswith("\r") else line)
            for n, line in enumerate(text.split("\n"), 1)]


def _site(url):
    """The host and whether the url is https, or None. A bare host reads as a host."""
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        split = urllib.parse.urlsplit(url.strip())
        if not split.netloc:
            split = urllib.parse.urlsplit("//" + url.strip())
        host = split.hostname
    except ValueError:
        return None
    return (host, split.scheme.lower() == "https") if host else None


def _cookie(where, name, value, domain, host_only, path, secure, http_only, expires):
    if not name or not domain:
        raise VaultError(f"{where}: a cookie needs a name and a domain")
    if any(ord(c) < 32 or ord(c) == 127 for c in name + value + domain + path):
        raise VaultError(f"{where}: a name, value, domain or path holds a control character")
    # A lone surrogate, as the escape \ud800 of a copy gives: no read could print it.
    if any("\ud800" <= c <= "\udfff" for c in name + value + domain + path):
        raise VaultError(f"{where}: a name, value, domain or path cannot be encoded as UTF-8")
    if isinstance(expires, float) and not math.isfinite(expires):
        raise VaultError(f"{where}: the expiry is not a number")
    return {"name": name, "value": value, "domain": domain.lstrip(".").strip("[]").lower(),
            "host_only": host_only, "path": path or "/", "secure": secure,
            "http_only": http_only,
            "expires": int(expires) if expires is not None and expires > 0 else None}


def _pairs(form, headers, site):
    """The `name=value` pairs of Cookie headers, each (line, header), as session cookies
    of the site, path /."""
    host, secure = site
    jar = []
    for line, header in headers:
        for pair in header.split(";"):
            pair = pair.strip(" \t")
            if not pair:
                continue
            where = f"{form} line {line}, cookie {len(jar) + 1}"
            name, sep, value = pair.partition("=")
            if not sep:
                raise VaultError(f"{where}: not name=value")
            jar.append(_cookie(where, name.strip(" \t"), value.strip(" \t"), host, True, "/",
                               secure, False, None))
    return jar


def _kept(form, sent):
    """The headers to keep of a copy's (line, name, value), each [name, value]. The browser's
    own and one with no value are left out. A name that is no token, or a value with a line
    break or a NUL, is refused: the lines are fed to `curl -H @-`, where it would add a header."""
    kept = []
    for line, name, value in sent:
        value = value.strip(" \t")
        if not value or _OWN.fullmatch(name.strip(" \t")):
            continue
        if not _TOKEN.fullmatch(name):
            raise VaultError(f"{form} line {line}: a header name is not an HTTP token")
        if any(c in value for c in "\r\n\0"):
            raise VaultError(f"{form} line {line}: a header value holds a line break or a NUL")
        if any("\ud800" <= c <= "\udfff" for c in value):
            raise VaultError(f"{form} line {line}: a header value cannot be encoded as UTF-8")
        kept.append([name, value])
    return kept


def _header(text, site):
    line = _line(text, len(text) - len(text.lstrip()))
    body = text.strip()
    if re.match(r"cookie:", body, re.I):
        body = body[len("cookie:"):]
    # A header is one line of names that are tokens (RFC 6265 4.1.1), so a URL, a command
    # or a request is no header; [ and ] stay, as PHP's array cookie names hold them.
    names = [pair.partition("=")[0].strip(" \t") for pair in body.split(";")]
    if "=" not in body or "\n" in body or any(re.search(r'[ \t"/:?<>@,{}()]', n) for n in names):
        raise VaultError(f"line {line}: no cookie in an accepted form - paste {FORMS}")
    if site is None:
        raise VaultError(f"Cookie header line {line}: no domain - give the site's url with --url")
    return _pairs("Cookie header", [(line, body)], site), None, []


def _set_cookie(text, site):
    jar = []
    for n, line in _lines(text):
        if not line.strip():
            continue
        where = f"Set-Cookie line {n}"
        key, sep, rest = line.partition(":")
        if not sep or key.strip().lower() != "set-cookie":
            raise VaultError(f"{where}: does not start with Set-Cookie:")
        first, *attrs = rest.split(";")
        name, sep, value = first.partition("=")
        if not sep:
            raise VaultError(f"{where}: no name=value")
        domain, path, secure, http_only, expires, max_age = None, "/", False, False, None, None
        for attr in attrs:
            key, _, val = attr.partition("=")
            key, val = key.strip(" \t").lower(), val.strip(" \t")
            if key == "domain" and val.strip("."):
                domain = val
            elif key == "path" and val.startswith("/"):
                path = val
            elif key == "secure":
                secure = True
            elif key == "httponly":
                http_only = True
            elif key == "expires":
                expires = http.cookiejar.http2time(val)
            elif key == "max-age" and re.fullmatch(r"-?\d+", val):
                max_age = int(val)
        if max_age is not None:
            # Max-Age wins over Expires (RFC 6265 5.3); 0 or less is already past.
            expires = max(int(time.time()) + max_age, 1)
        if domain is None and site is None:
            raise VaultError(f"{where}: no Domain, and no url - give the site's url with --url")
        jar.append(_cookie(where, name.strip(" \t"), value.strip(" \t"), domain or site[0],
                           domain is None, path, secure, http_only, expires))
    return jar, None, []


def _netscape(text, site):
    jar = []
    for n, line in _lines(text):
        http_only = line.startswith("#HttpOnly_")
        if http_only:
            line = line[len("#HttpOnly_"):]
        elif line.startswith("#") or not line.strip():
            continue
        where = f"cookies.txt line {n}"
        fields = line.split("\t", 6)
        if len(fields) != 7:
            raise VaultError(f"{where}: not 7 tab-separated fields")
        domain, sub, path, secure, expires, name, value = fields
        if not re.fullmatch(r"-?\d+(\.\d*)?", expires):
            raise VaultError(f"{where}: the expiry is not a number")
        host_only = sub.upper() != "TRUE" and not domain.startswith(".")
        jar.append(_cookie(where, name, value, domain, host_only, path, secure.upper() == "TRUE",
                           http_only, float(expires)))
    return jar, None, []


def _items(text, i):
    """(position, value) of each item of the JSON array or object at text[i], an object's
    keys and values in turn. The text is valid JSON."""
    decoder, gap, items = json.JSONDecoder(), re.compile(r"[\s,:]*"), []
    i = gap.match(text, i + 1).end()
    while text[i] not in "]}":
        value, end = decoder.raw_decode(text, i)
        items.append((i, value))
        i = gap.match(text, end).end()
    return items


def _json(text, site):
    try:
        json.loads(text)
    except ValueError as e:
        raise VaultError(f"cookie JSON line {getattr(e, 'lineno', 1)}: not valid JSON") from None
    start = len(text) - len(text.lstrip())
    form, items = "cookie JSON", _items(text, start)
    if text[start] == "{":
        form = "Playwright storage state"
        # The last "cookies" key is the one json.loads keeps.
        lists = [at for (_, key), (at, _) in zip(items[::2], items[1::2]) if key == "cookies"]
        if not lists or text[lists[-1]] != "[":
            raise VaultError(f"{form} line {_line(text, start)}: no list of cookies")
        items = _items(text, lists[-1])
    jar, line, last = [], 1, 0
    for n, (at, item) in enumerate(items, 1):
        line, last = line + text.count("\n", last, at), at
        where = f"{form} line {line}, cookie {n}"
        if not isinstance(item, dict):
            raise VaultError(f"{where}: not an object")
        name, value, domain = item.get("name"), item.get("value"), item.get("domain")
        path = item.get("path", "/")
        if not all(isinstance(v, str) for v in (name, value, domain, path)):
            raise VaultError(f"{where}: name, value, domain and path must be text")
        # Cookie-Editor and EditThisCookie: expirationDate, none for a session cookie;
        # Playwright: expires, -1 for a session cookie.
        expires = item.get("expirationDate", item.get("expires"))
        if item.get("session") is True:
            expires = None
        if expires is not None and (isinstance(expires, bool) or not isinstance(expires, (int, float))):
            raise VaultError(f"{where}: the expiry is not a number")
        host_only = item["hostOnly"] if isinstance(item.get("hostOnly"), bool) else not domain.startswith(".")
        jar.append(_cookie(where, name, value, domain, host_only, path, item.get("secure") is True,
                           item.get("httpOnly") is True, expires))
    return jar, None, []


def _ansi_c(text, i):
    """The value of a $'...' whose text starts at `i`, and the index after its quote."""
    out = []
    while i < len(text):
        c = text[i]
        if c == "'":
            return "".join(out), i + 1
        match = _ESCAPE.match(text, i) if c == "\\" else None
        if match:
            e = match.group(1)
            if e[0] in "xuU" and len(e) > 1:
                out.append(chr(int(e[1:], 16)))
            elif e[0] in "01234567":
                out.append(chr(int(e, 8)))
            else:
                out.append(_ANSI_C.get(e, "\\" + e))
            i = match.end()
        else:
            out.append(c)
            i += 1
    raise EOFError


def _bash_words(text, form):
    """The words of a POSIX shell line as bash reads them: '...', "...", $'...', backslash
    escapes and backslash line ends. Linear in the text: a paste of up to 1 MiB is read
    on the server's event loop."""
    words, word, first, i = [], None, 0, 0
    while i < len(text):
        c, start = text[i], i
        if c in " \t\r\n":
            if word is not None:
                words.append(("".join(word), first))
            word, i = None, i + 1
            continue
        if c == "\\" and text.startswith(("\n", "\r\n"), i + 1):
            i += 2 if text[i + 1] == "\n" else 3
            continue
        if word is None:
            word, first = [], start
        if c == "\\":
            word.append(text[i + 1:i + 2])
            i += 2
        elif c == "'":
            end = text.find("'", i + 1)
            if end < 0:
                raise VaultError(f"{form} line {_line(text, start)}: a quote is not closed")
            word.append(text[i + 1:end])
            i = end + 1
        elif text.startswith("$'", i):
            try:
                value, i = _ansi_c(text, i + 2)
            except EOFError:
                raise VaultError(f"{form} line {_line(text, start)}: a quote is not closed") from None
            except ValueError:
                raise VaultError(f"{form} line {_line(text, start)}: an escape is not a character") from None
            word.append(value)
        elif c == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                if text[i] == "\\" and text[i + 1:i + 2] in ("$", "`", '"', "\\", "\n"):
                    word.append(text[i + 1] if text[i + 1] != "\n" else "")
                    i += 2
                else:
                    end = _QUOTED.match(text, i).end()
                    word.append(text[i:end])
                    i = end
            if i >= len(text):
                raise VaultError(f"{form} line {_line(text, start)}: a quote is not closed")
            i += 1
        else:
            end = _BASH_PLAIN.match(text, i).end()
            word.append(text[i:end])
            i = end
    if word is not None:
        words.append(("".join(word), first))
    return words


def _cmd_words(text, form):
    """The words of a Windows cmd line as Chrome's Copy as cURL (cmd) writes them: cmd's ^
    escapes first - a ^ at a line end joins the next line and escapes its first character,
    so ^ and two line ends is a line end in a value - then the C runtime's quotes, with \\\\
    and \\" for a backslash and a quote. Linear in the text, as _bash_words."""
    # Each character of the plain text keeps the position of its source, for the line.
    plain, at = [], []
    for m in re.finditer(r"\^(?:\r?\n)?(\r?\n|.)|[^^]+|\^", text):
        if m.group(1):
            plain.append(m.group(1).replace("\r\n", "\n"))
            at.append(m.end() - 1)
        else:
            plain.append(m.group(0))
            at.extend(range(m.start(), m.end()))
    plain = "".join(plain)
    words, word, first, quoted, i = [], None, 0, False, 0
    while i < len(plain):
        c = plain[i]
        if c in " \t\r\n" and not quoted:
            if word is not None:
                words.append(("".join(word), at[first]))
            word, i = None, i + 1
            continue
        if word is None:
            word, first = [], i
        if c == "\\" and plain[i + 1:i + 2] in ("\\", '"'):
            word.append(plain[i + 1])
            i += 2
        elif c == '"':
            quoted, i = not quoted, i + 1
        else:
            end = (_QUOTED if quoted else _CMD_PLAIN).match(plain, i).end()
            word.append(plain[i:end])
            i = end
    if quoted:
        raise VaultError(f"{form} line {_line(text, len(text))}: a quote is not closed")
    if word is not None:
        words.append(("".join(word), at[first]))
    return words


def _firefox_old_words(text):
    """The words of Copy as cURL (Windows) as Firefox 138 and earlier wrote them, the inverse
    of its escapeStringWin: a word of letters and - is bare, any other is in plain quotes
    with \\\\, "", \\` and \\$ for a backslash, a quote, ` and $, ^ before each character it
    escaped, and a quote, ^, two line ends and a quote for a line end. None for text that
    function did not write: a hand-written command, which bash reads. Linear in the text,
    as _bash_words."""
    words, i = [], _FIREFOX_GAP.match(text).end()
    while i < len(text):
        start = i
        if text[i] == '"':
            word, i = [], i + 1
            while piece := _FIREFOX_PIECE.match(text, i):
                run, i = piece.group(), piece.end()
                word.append("\n" if piece.group(1) else run[1:] if run[0] in '"\\^' else run)
            # The pieces end at the closing quote, or at what Firefox did not write.
            if text[i:i + 1] != '"':
                return None
            word, i = "".join(word), i + 1
        else:
            i = _FIREFOX_BARE.match(text, i).end()
            word = text[start:i]
        gap = _FIREFOX_GAP.match(text, i).end()
        if i == start or i == gap < len(text):
            return None
        words.append((word, start))
        i = gap
    return words


def _curl(text, site):
    # A plain quote first is the copy of Firefox 138 and earlier on Windows, or hand-written.
    old = _firefox_old_words(text) if re.match(r'\s*curl(\.exe)?\s+"', text) else None
    cmd = old is not None or re.match(r'\s*curl(\.exe)?\s+\^"', text) is not None
    form = "Copy as cURL (cmd)" if cmd else "Copy as cURL"
    words = old or (_cmd_words if cmd else _bash_words)(text, form)
    target, found, sent, line, last, i = None, [], [], 1, 0, 1
    while i < len(words):
        word, at = words[i]
        if word in _CURL_VALUES:
            if i + 1 == len(words):
                raise VaultError(f"{form} line {_line(text, at)}: {word} has no value")
            value, at = words[i + 1]
            if word in ("-b", "--cookie"):
                found.append((_line(text, at), value))
            elif word in ("-H", "--header"):
                key, sep, rest = value.partition(":")
                if sep and key.strip().lower() == "cookie":
                    found.append((_line(text, at), rest.strip(" \t")))
                elif sep and key:
                    # No name before the colon is a name starting `:`, which is left out.
                    # The words are in the text's order, so the lines are counted once.
                    line, last = line + text.count("\n", last, at), at
                    sent.append((line, key, rest))
            elif word == "--url" and target is None:
                target = words[i + 1]
            i += 2
            continue
        if not word.startswith("-") and target is None:
            target = words[i]
        i += 1
    headers = _kept(form, sent)
    if not found and not headers:
        raise VaultError(f"{_span(form, text)}: {NOTHING_KEPT}")
    site = _site(target[0]) if target else None
    if site is None:
        where = f"{form} line {_line(text, target[1])}" if target else _span(form, text)
        raise VaultError(f"{where}: no URL with a host")
    return _pairs(form, found, site), target[0], headers


def _fetch(text, site):
    form = "Copy as fetch"
    decoder, space = json.JSONDecoder(), re.compile(r"\s*")
    try:
        start = space.match(text, text.index("(") + 1).end()
        url, i = decoder.raw_decode(text, start)
        i = space.match(text, i).end()
        options, at = {}, i
        if text[i] == ",":
            at = space.match(text, i + 1).end()
            options, i = decoder.raw_decode(text, at)
    except (ValueError, IndexError) as e:
        line = getattr(e, "lineno", None) or _line(text, len(text))
        raise VaultError(f"{form} line {line}: not read - paste the copy as the browser gives it") from None
    options = options if isinstance(options, dict) else {}
    headers = options.get("headers")
    # The line of each key as written; a key with an escape in it gets the options' line.
    first = _line(text, at)
    lines, line, last = {}, first, at
    for m in _JSON_STRING.finditer(text, at, i):
        if m.group(2):
            line, last = line + text.count("\n", last, m.start()), m.start()
            lines[m.group(1)] = line
    found, sent = [], []
    for key, value in headers.items() if isinstance(headers, dict) else ():
        if isinstance(value, str):
            where = lines.get(key, first)
            if key.lower() == "cookie":
                found.append((where, value))
            else:
                sent.append((where, key, value))
    headers = _kept(form, sent)
    # A browser's plain copy with credentials include sends cookies that the copy does not
    # carry: its headers alone would make an entry that lacks the session.
    if not found and options.get("credentials") == "include":
        raise VaultError(f"{_span(form, text)}: {NO_COOKIE}")
    if not found and not headers:
        raise VaultError(f"{_span(form, text)}: {NOTHING_KEPT}")
    site = _site(url)
    if site is None:
        raise VaultError(f"{form} line {_line(text, start)}: no URL with a host")
    return _pairs(form, found, site), url, headers


def _reader(body):
    """The form of pasted text and its reader, in the order the forms are told apart."""
    head = body.lower()
    if body[:1] in ("[", "{"):
        return "cookie JSON", _json
    # Firefox's Copy as cURL (Windows) names the command curl.exe.
    if re.match(r"curl(\.exe)?\s", head):
        return "Copy as cURL", _curl
    if head.startswith(("fetch(", "await fetch(")):
        return "Copy as fetch", _fetch
    if head.startswith("set-cookie:"):
        return "Set-Cookie lines", _set_cookie
    if head.startswith(("# netscape http cookie file", "# http cookie file")) \
            or any(line.count("\t") >= 6 for line in body.split("\n")):
        return "cookies.txt", _netscape
    return "Cookie header", _header


def parse(text, url=None):
    """The cookies and the kept headers of pasted text in any accepted form; `url` is the
    entry's, for the forms that carry no domain. Raises VaultError naming the form and a
    line, never the text."""
    jar, _, headers = read(text, url)
    return jar, headers


def read(text, url=None):
    """The cookies of pasted text, the origin of the URL a cURL or fetch copy carries
    (scheme://host[:port]/, never its path or query), or None, and the headers that copy
    keeps, each [name, value]; every other form carries none."""
    if not isinstance(text, str) or not text.strip():
        raise VaultError(f"nothing pasted - paste {FORMS}")
    if len(text) > MAX_PASTE:
        raise VaultError(f"pasted text is at most {MAX_PASTE} characters (1 MiB)")
    body = text.lstrip("﻿ \t\r\n")
    form, reader = _reader(body)
    # The line ends before the first character stay, so a refusal's line is the text's own.
    body = "\n" * text.count("\n", 0, len(text) - len(body)) + body
    try:
        jar, copied, headers = reader(body, _site(url))
    except VaultError:
        raise
    except Exception:
        # A reader's own error can quote the text; this one names only the form and its lines.
        raise VaultError(f"{_span(form, body)}: the text could not be read") from None
    if not jar and not headers:
        raise VaultError(f"{_span(form, body)}: no cookie read - paste {FORMS}")
    if not copied:
        return jar, None, headers
    host, secure = _site(copied)
    # The port and an IPv6 host's brackets stay; the userinfo, path and query go.
    netloc = urllib.parse.urlsplit(copied.strip()).netloc.rpartition("@")[2].lower() or host
    return jar, f"{'https' if secure else 'http'}://{netloc}/", headers


def unexpired(cookies, now):
    """The cookies not past their expiry at `now`; a session cookie stays."""
    return [c for c in cookies if c["expires"] is None or c["expires"] > now]


def to_netscape(cookies):
    """A cookies.txt as curl, wget and yt-dlp read it; 0 is a session cookie's expiry.
    Every cookie is a plain line: GNU wget 1.x skips a `#HttpOnly_` line as a comment, and
    no tool needs the flag to send the cookie."""
    lines = ["# Netscape HTTP Cookie File"]
    for c in cookies:
        domain = c["domain"] if c["host_only"] else "." + c["domain"]
        lines.append("\t".join([domain, "FALSE" if c["host_only"] else "TRUE", c["path"],
                                "TRUE" if c["secure"] else "FALSE", str(c["expires"] or 0),
                                c["name"], c["value"]]))
    return "\n".join(lines) + "\n"


def to_jar(cookies):
    """An http.cookiejar.CookieJar of the cookies. Its policy sends a host-only cookie to
    its own host only, as a browser does: urllib's HTTPCookieProcessor keeps that scope,
    while requests copies the cookies into its own jar and also sends a host-only cookie
    to subdomains."""
    policy = http.cookiejar.DefaultCookiePolicy(
        strict_ns_domain=http.cookiejar.DefaultCookiePolicy.DomainStrictNonDomain)
    jar = http.cookiejar.CookieJar(policy)
    for c in cookies:
        domain = c["domain"] if c["host_only"] else "." + c["domain"]
        if c["host_only"] and ":" in domain:
            # An IPv6 host, which http.cookiejar reads from the url with its brackets.
            domain = f"[{domain}]"
        if c["host_only"] and "." not in domain:
            # http.cookiejar names a host with no dot, such as localhost, host.local.
            domain += ".local"
        jar.set_cookie(http.cookiejar.Cookie(
            0, c["name"], c["value"], None, False, domain, not c["host_only"],
            not c["host_only"], c["path"], True, c["secure"], c["expires"],
            c["expires"] is None, None, None, {"HttpOnly": None} if c["http_only"] else {}))
    return jar


def to_header(cookies, url):
    """`name=value; ...` of the cookies whose domain, path and secure flag match `url`,
    as http.cookiejar matches them. A url with no scheme reads as a host, as _site reads it."""
    if _site(url) is None:
        raise VaultError("the url has no host - give the site's url with --url")
    if not urllib.parse.urlsplit(url.strip()).netloc:
        url = "https://" + url.strip()
    request = urllib.request.Request(url)
    to_jar(cookies).add_cookie_header(request)
    return request.get_header("Cookie", "")
