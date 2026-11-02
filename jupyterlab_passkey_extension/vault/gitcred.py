"""`git-credential-jupyterlab-passkey`: the vault as git's credential helper.

gitcredentials(7): git runs the helper with `get`, `store` or `erase` and writes the
request's attributes to stdin as key=value lines ending in a blank line. `get` writes
the credential it finds on stdout. The vault is the only writer, so `store` and `erase`
refuse and git ignores the helper for them.
"""

import sys
import urllib.parse

from .. import cli as _cli
from . import cli as _vcli
from .client import Vault, VaultClientError

PROGRAM = "git-credential-jupyterlab-passkey"
OPERATIONS = ("get", "store", "erase")


def _attributes(stream):
    """The key=value attributes of one request, up to a blank line or EOF."""
    attrs = {}
    for line in stream:
        line = line.rstrip("\n")
        if not line:
            break
        key, sep, value = line.partition("=")
        if sep:
            attrs[key] = value
    return attrs


def _parts(entry):
    """The scheme, host and path of an entry's url; the host carries the port and no
    userinfo, as git's host attribute does. None for a url urlsplit rejects. A url
    with no scheme and no netloc, such as a bare host, is read as one."""
    url = entry.get("url", "")
    try:
        split = urllib.parse.urlsplit(url)
        if not split.netloc and not split.scheme:
            split = urllib.parse.urlsplit("//" + url)
    except ValueError:
        return None
    return (split.scheme.lower(), split.netloc.rpartition("@")[2].lower(), split.path)


def _segments(path):
    """The non-empty segments of a url path, so '/foo/bar' and 'foo/bar' compare equal."""
    return [segment for segment in path.split("/") if segment]


def _prefix(path, request_path):
    """The entry's path segments are a prefix of the request's on a segment boundary."""
    entry = _segments(path)
    return _segments(request_path)[:len(entry)] == entry


def select(entries, attrs):
    """The entries a request matches, narrowed to the longest path and to its username.

    git only sends `path` after it has applied useHttpPath, generic or per-URL, so a
    path in the request is what turns path scoping on; without one, entry paths are
    ignored.
    """
    protocol = attrs.get("protocol", "").lower()
    host = attrs.get("host", "").lower()
    path = attrs.get("path")
    matched = []
    malformed = []
    for entry in entries:
        parts = _parts(entry)
        if parts is None:
            malformed.append(entry["name"])
            continue
        scheme, entry_host, entry_path = parts
        if entry_host != host or (scheme and scheme != protocol):
            continue
        if path is not None and not _prefix(entry_path, path):
            continue
        matched.append(entry)
    if malformed:
        print(f"{PROGRAM}: invalid url, entry not used: {', '.join(malformed)}", file=sys.stderr)
    if path is not None and matched:
        longest = max(len(_segments(_parts(entry)[2])) for entry in matched)
        matched = [entry for entry in matched if len(_segments(_parts(entry)[2])) == longest]
    username = attrs.get("username", "")
    if username:
        named = [entry for entry in matched if entry.get("username", "") == username]
        if named:
            matched = named
    return matched


def _request(attrs):
    return f"{attrs.get('protocol', '')}://{attrs.get('host', '')}{attrs.get('path', '')}"


def _lookup(attrs):
    """The matched entry's username and password, or None after a line on stderr."""
    vault = Vault(timeout=_cli.CLICK_TIMEOUT)
    if _vcli._terminal():
        # The set-up offer ACC-VAULT-266 added for a command run at a terminal.
        entries = _vcli.ensure_vault(vault, vault.list)
    else:
        # git gives the helper its request on stdin, so there is no terminal to ask
        # at: the page runs the set-up, skipping the steps the vault already has.
        status = vault.status()
        if not status["initialized"] or not any(
                slot["type"] == "passkey" for slot in status["slots"]):
            _vcli.setup_in_browser()
        entries = vault.list()
    matched = select(entries, attrs)
    if len(matched) == 1:
        entry = matched[0]
        return entry.get("username", ""), vault.get(entry["name"])
    if not matched:
        host = attrs.get("host", "").lower()
        names = []
        for entry in entries:
            parts = _parts(entry)
            if parts is not None and parts[1] == host:
                names.append(entry["name"])
        tried = f"; candidates: {', '.join(names)}" if names else ""
        print(f"{PROGRAM}: no vault entry matches {_request(attrs)}{tried}", file=sys.stderr)
    else:
        names = ", ".join(entry["name"] for entry in matched)
        print(f"{PROGRAM}: {len(matched)} vault entries match {_request(attrs)}: {names}",
              file=sys.stderr)
    return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0] not in OPERATIONS:
        print(f"usage: {PROGRAM} {'|'.join(OPERATIONS)}", file=sys.stderr)
        return 1
    attrs = _attributes(sys.stdin)
    if argv[0] != "get":
        # The vault is the only writer: git must never make it store or erase.
        return 1
    try:
        found = _lookup(attrs)
    except (VaultClientError, SystemExit) as e:
        print(f"{PROGRAM}: {e}", file=sys.stderr)
        return 1
    if found is None:
        return 1
    username, password = found
    sys.stdout.write(f"username={username}\npassword={password}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
