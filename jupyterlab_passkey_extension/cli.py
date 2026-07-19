#!/usr/bin/env python3
"""jupyterlab-passkey - drive the browser passkey ceremony from a local process.

A proxy to the extension's JupyterLab commands. WebAuthn needs a user gesture and a
browser; a terminal has neither. So each subcommand posts a notification whose action
button is bound to the command, then (all but `copy`) waits for the relay the server
writes and returns the result - turning a browser ceremony into a blocking call.

    cred_id=$(jupyterlab-passkey create --rp-id lab.example)
    prf=$(jupyterlab-passkey get --rp-id lab.example --cred-id "$cred_id" --prf-salt "$salt")
    pass_ref=$(jupyterlab-passkey passphrase) || exit 1
    PASS_RECOVERY_REF=$pass_ref pass-cli-open --ensure

Secrets move both ways. `passphrase` takes one FROM you in a dialog and stages it in a
relay for a vault or a .env to read; `copy` sends one TO the clipboard of the browser
you are sitting in front of, to paste wherever it is wanted:

    tok_ref=$(jupyterlab-passkey passphrase --once --prompt "GitHub token") || exit 1
    PASS_SECRET_REF=$tok_ref pass-cli-save github/api -u me -c infrastructure

    pass-cli get github/api --field password --quiet --no-clipboard | jupyterlab-passkey copy

`passphrase` prints a scheme-prefixed reference (keyctl:... or file:...), never the
value; the consumer resolves it. Take the `|| exit 1` seriously: a prefix assignment
does not propagate the exit status of a command substitution, so
`PASS_RECOVERY_REF=$(jupyterlab-passkey passphrase) pass-cli-open` would run the consumer
with an EMPTY reference after a timeout or a cancel.

Run it in a terminal on the same Jupyter server, keep a JupyterLab tab open, and click
the button when it pops.
"""

import argparse
import base64
import json
import math
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

from . import relay

INGEST = "jupyterlab-notifications-extension/ingest"
RUN_COMMAND = "passkey:run"
PASSPHRASE_COMMAND = "passkey:passphrase"
COPY_COMMAND = "passkey:copy"

# The trigger POST is a local, non-interactive call - only the click it asks for is slow.
# --timeout governs the wait for the click, never this; without a bound here a wedged
# server event loop hangs the CLI forever, ignoring --timeout entirely.
TRIGGER_TIMEOUT = 10

# How long any subcommand waits for the click, unless --timeout says otherwise. ONE
# definition, fed to argparse and interpolated into the help text below: all four
# commands wait for the same thing - a human noticing a notification and clicking it -
# and a second literal would drift from this one the first time anybody retunes it.
CLICK_TIMEOUT = 120.0

# In --block mode the copy key's TTL is set past the wait deadline by this margin, so
# the key cannot self-destruct while the wait is still running (on keyctl that would
# read as a collection - see cmd_copy). It only has to cover the gap between staging
# the key and the first wait poll, i.e. the trigger POST, so it is generous.
_COPY_BLOCK_TTL_MARGIN = 60

# Upper bound on a --block --timeout. keyctl stores a key timeout in a 32-bit unsigned
# int, so a TTL at or beyond 2**32 wraps to something SHORTER than the wait - the key
# would self-destruct mid-wait and be misread as a collection. This cap sits far below
# that wrap (and far beyond any real click wait), keeping the staged TTL faithful.
_MAX_BLOCK_TIMEOUT = 10**8


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _say(message: str) -> None:
    """Tell the user something on stderr, and never fail the command doing it.

    Catching the write error is not enough on its own. stderr is buffered, so a
    failed write leaves the bytes sitting in it; CPython retries that flush at
    interpreter shutdown - long after main() has returned, where no except can
    reach it - and exits 120 when it fails again. So the whole command reports
    failure because a progress message could not be printed.

    That is not cosmetic here. `copy` answers a failed trigger by destroying the
    secret it staged, precisely so a retry cannot strand another copy; a caller
    that reads 120 as "the trigger failed" retries, and strands one anyway. And
    `passphrase` prints a reference its caller captures with `|| exit 1`, which a 120
    throws away while the relay stays on disk.

    Dropping the stream takes the poisoned buffer with it, so shutdown has nothing
    left to retry.
    """
    stderr = sys.stderr
    # None: print(file=None) falls back to STDOUT, and stdout is load-bearing here -
    # it carries the cred_id, the PRF, the relay path. Chatter must never land there.
    # Closed: an earlier call already dropped it, and printing to a closed stream
    # raises ValueError, which would take the command down over a progress message.
    if stderr is None or getattr(stderr, "closed", False):
        return
    try:
        print(message, file=stderr)
    except (OSError, ValueError):
        try:
            stderr.close()
        except (OSError, ValueError):
            pass


def _server_list() -> dict:
    """The running server's own record: port, base_url, and its token."""
    try:
        out = subprocess.run(
            ["jupyter", "server", "list", "--json"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return json.loads(out.stdout.strip().split("\n")[0])
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return {}


def _base_url(info: dict) -> str:
    """Where the server answers, always on loopback."""
    if info:
        return f"http://127.0.0.1:{info.get('port', 8888)}{info.get('base_url', '/').rstrip('/')}"
    port = os.environ.get("JUPYTER_PORT", "8888")
    return f"http://127.0.0.1:{port}{os.environ.get('JUPYTERHUB_SERVICE_PREFIX', '').rstrip('/')}"


def _token(info: dict) -> str | None:
    """The token that authenticates to that server.

    Order matters and both ends are a real 403:

    - The hub vars win outright. Under JupyterHub the server's own token from
      `jupyter server list` is NOT accepted by its API - only the hub-issued one is.
    - The server list then beats JUPYTER_TOKEN, which is generic and easily stale (an
      old export in a shell rc). Letting a stale env value outrank the token the running
      server just handed us is a 403 that reads like a config error.
    """
    hub = os.environ.get("JUPYTERHUB_API_TOKEN") or os.environ.get("JPY_API_TOKEN")
    if hub:
        return hub
    # `in`, not truthiness: a server reporting token "" is answering "I want none", which
    # is a different thing from having no server record at all. An `or` chain conflates
    # them and lets a stale env var send an Authorization header to a tokenless server.
    if "token" in info:
        return info["token"] or None
    return os.environ.get("JUPYTER_TOKEN") or None


def _server() -> tuple[str, str | None]:
    info = _server_list()
    return _base_url(info), _token(info)


def _trigger(command_id: str, args_obj: dict, label: str, message: str) -> None:
    """Post the notification whose button runs `command_id` with `args_obj`."""
    base, token = _server()
    payload = {
        "message": message,
        "type": "info",
        "autoClose": False,
        "immediate": True,
        "actions": [{
            "label": label,
            "displayType": "default",
            "commandId": command_id,
            "caption": f"Execute: {command_id}",
            "args": args_obj,
        }],
    }
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"token {token}"

    req = urllib.request.Request(
        f"{base}/{INGEST}", data=json.dumps(payload).encode(), headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TRIGGER_TIMEOUT) as r:
            r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise SystemExit(
                f"trigger rejected (404) by {base}/{INGEST} - the notifications extension "
                "is not installed in that lab; the CLI needs it to raise the button"
            )
        raise SystemExit(f"trigger rejected ({e.code} {e.reason}) by {base}/{INGEST}")
    except urllib.error.URLError as e:
        raise SystemExit(f"cannot reach {base} ({e.reason}) - is JupyterLab running?")
    except OSError as e:
        # Must come after URLError, which subclasses OSError. TimeoutError and
        # ConnectionResetError are OSError but NOT URLError, and urlopen raises them
        # bare out of the read phase - so without this the one case TRIGGER_TIMEOUT
        # exists to bound, a server that accepts the connection and then wedges, ends
        # in a traceback instead of the sentence that names the problem.
        raise SystemExit(f"cannot reach {base} ({e}) - is JupyterLab running?")

    # The POST has landed by here and the button is live in the browser, so a broken
    # stderr (a full log volume, a pipe whose reader has gone) must not report the
    # trigger as failed - `copy`'s caller answers that by unstaging the secret the
    # live button is about to ask for. See _say.
    _say(f"click '{label}' in your JupyterLab tab")


def _wait(nonce: str, kind: str, timeout: float, on_timeout: str) -> None:
    """Block until the relay is staged.

    Existence is enough: a relay is staged atomically (the file lands via
    os.replace, the key via a single padd), so what a reader then finds is whole -
    see `relay.stage`. The poll reads nothing, so a squatted shm dir cannot raise
    here; that check fires at collect time.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if relay.relay_exists(nonce, kind):
            return
        time.sleep(0.4)
    # One last look. The final sleep straddles the deadline, so a relay landing in that
    # window would otherwise be declared missing while it is really there - failing a
    # ceremony the user completed in time AND stranding its PRF, since the caller that
    # would have consumed it is the one raising here.
    if relay.relay_exists(nonce, kind):
        return
    raise SystemExit(f"no relay after {timeout:.0f}s - {on_timeout}")


def _wait_gone(nonce: str, kind: str, timeout: float, on_timeout: str) -> None:
    """Block until the relay is consumed.

    The mirror of `_wait`. The `secret` endpoint reads its relay and destroys it in
    the same breath, so the relay DISAPPEARING is the signal - there is nothing else
    to watch. Nothing is posted back from the page, so this is as close to "the
    secret arrived" as the caller can get.

    It is not proof of a clipboard write. The frontend collects the value and only
    then calls navigator.clipboard.writeText, so a browser that refuses the
    clipboard does so after this has already returned. `--block` therefore means
    collected, not pasted.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not relay.relay_exists(nonce, kind):
            return
        time.sleep(0.4)
    # One last look, for the same reason `_wait` takes one: the final sleep straddles
    # the deadline, and a click landing in that window is a success we would
    # otherwise report as a timeout - and then destroy the secret it just delivered.
    if not relay.relay_exists(nonce, kind):
        return
    raise SystemExit(f"not copied after {timeout:.0f}s - {on_timeout}")


def _run(args_obj: dict, label: str, message: str, timeout: float) -> dict:
    """Drive passkey:run and consume its relay, destroying it on every path out of here.

    The relay carries the PRF, so the destroy sits in a finally that also covers the
    timeout - `_wait` is inside the try for exactly that reason. A malformed body, or a
    relay that landed just as we gave up, would otherwise leave key material staged
    precisely when nobody is left to collect it.

    It is best effort and cannot be more: the server writes whenever the ceremony
    finishes, so a click that lands after this process has exited strands a relay no
    matter what we do here. That residue is bounded either way - a keyctl key by its
    TTL, a shm file by the tmpfs it lives in - which is why shredding is documented as
    the consumer's job.
    """
    nonce = args_obj["nonce"]
    _trigger(RUN_COMMAND, args_obj, label, message)
    try:
        _wait(nonce, "json", timeout, "was the button clicked and the prompt approved?")
        # collect destroys the relay as it reads it.
        raw = relay.collect(nonce, "json")
        if raw is None:
            # _wait saw it a tick ago; gone now means it expired or lost a race.
            raise SystemExit("the ceremony relay vanished before it could be read")
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise SystemExit(f"unreadable relay: {e}")
    except OSError as e:
        # A squatted shm dir surfaces here (PermissionError is an OSError) rather
        # than as a traceback out of the guard.
        raise SystemExit(f"cannot read the relay: {e}")
    finally:
        # A relay that landed in the final wait window, or after a timeout, is key
        # material nobody is left to collect - destroy it whichever way we leave. A
        # no-op when collect already took it.
        relay.unstage(nonce, "json")
    if not data.get("ok"):
        raise SystemExit(f"ceremony failed: {data.get('error')}")
    return data


def cmd_create(a) -> int:
    user = {
        "id": b64url(secrets.token_bytes(16)),
        "name": a.user_name,
        "displayName": a.user_name,
    }
    data = _run(
        {"op": "create", "nonce": secrets.token_urlsafe(24), "rp_id": a.rp_id, "user": user},
        "Register passkey", "Register a passkey - click to approve.", a.timeout,
    )
    # .get, not [..]: the server writes any authenticated body verbatim, so an ok:true
    # relay with no cred_id is reachable - and every failure here answers with a line,
    # not a KeyError traceback.
    cred_id = data.get("cred_id")
    if not cred_id:
        raise SystemExit("malformed relay - the ceremony result carries no cred_id")
    print(cred_id)
    return 0


def cmd_get(a) -> int:
    args_obj = {
        "op": "get", "nonce": secrets.token_urlsafe(24),
        "rp_id": a.rp_id, "cred_id": a.cred_id,
    }
    if a.prf_salt:
        args_obj["prf_salt"] = a.prf_salt
    data = _run(args_obj, "Approve passkey", "Approve the passkey request - click to approve.", a.timeout)

    if a.prf_salt:
        if not data.get("prf"):
            raise SystemExit("no PRF returned - the authenticator did not evaluate the salt")
        print(data["prf"])
    else:
        # Same guard as cmd_create: an ok:true relay without the field is a malformed
        # writer, not a KeyError of ours.
        cred_id = data.get("cred_id")
        if not cred_id:
            raise SystemExit("malformed relay - the ceremony result carries no cred_id")
        print(cred_id)
    return 0


def cmd_passphrase(a) -> int:
    """Capture a secret in the browser and stage it for an external consumer.

    Prints a scheme-prefixed REFERENCE, never the value - `keyctl:jlab-passkey:<nonce>.pass`
    when the kernel keyring is live, `file:<path>` on the shm fallback. A keyctl-aware
    consumer branches on the scheme and reads the value itself, so the secret reaches
    a vault, a .env or a keystore without passing through this terminal, the shell
    history, a process argument, or this process at all.

    The prompt is left out of the args unless given, so the frontend can pick a default
    that suits the mode rather than being told "Enter the passphrase twice" about a
    single field.
    """
    nonce = secrets.token_urlsafe(24)
    args_obj = {"nonce": nonce}
    if a.prompt:
        args_obj["prompt"] = a.prompt
    if a.once:
        args_obj["once"] = True
    _trigger(
        PASSPHRASE_COMMAND, args_obj,
        "Enter secret" if a.once else "Enter passphrase",
        "Enter the secret - click to open the dialog." if a.once
        else "Enter the passphrase - click to open the dialog.",
    )
    # The dialog relays nothing on cancel, or on two entries that differ, so a timeout
    # here usually means a deliberate refusal, not an unnoticed button.
    refused = "cancelled or the button was never clicked" if a.once else (
        "cancelled, the two entries differed, or the button was never clicked"
    )
    try:
        _wait(nonce, "pass", a.timeout, refused)
        print(relay.reference(nonce, "pass"))
    except OSError as e:
        # An operator who forced JLAB_PASSKEY_RELAY_BACKEND=keyctl on a host whose
        # keyring is not functional gets a clean line here, not a traceback - the same
        # bar the other commands hold. (A missing/quota'd backend surfaces the same way.)
        raise SystemExit(f"relay backend unavailable: {e}")
    return 0


def cmd_copy(a) -> int:
    """Stage a secret from a file or stdin and offer it to the browser's clipboard.

    The only command that runs outward: the caller already holds the secret and wants
    it in the clipboard of the browser they are sitting in front of, to paste
    somewhere this bridge knows nothing about.

    The value is staged in a 0600 relay and the notification carries only the nonce.
    Putting the secret in the notification instead would be simpler and wrong - the
    notifications extension pushes every payload to every connected socket and parks
    it in an in-memory queue until a client drains it.

    Fire and forget by default: the relay is one-shot, so the click consumes it, but
    nothing here waits for the click. A secret nobody clicks sits in tmpfs until
    reboot - the button is up and the user can see it, which is a different thing
    from the stranded case the unstage below exists to prevent.

    `--block` waits for the relay to be consumed and deletes it if it never is, so an
    agent can sequence work after the secret has actually landed, and nothing is left
    behind when it has not. It means COLLECTED, not pasted: the page fetches the
    value and only then writes the clipboard, so a refused clipboard happens after
    the wait has already returned.
    """
    if a.timeout is not None and not a.block:
        # Without --block nothing here waits, so a --timeout would be accepted and then
        # ignored - and a caller who set it would believe the command had bounded
        # something. Refuse rather than lie.
        raise SystemExit("--timeout only applies with --block - without it, copy waits for nothing")
    timeout = CLICK_TIMEOUT if a.timeout is None else a.timeout
    if a.block and not (0 < timeout <= _MAX_BLOCK_TIMEOUT):
        # argparse(type=float) accepts inf/nan/negatives/huge values; one range test
        # rejects them all (nan/inf fail the comparison too). A non-positive or non-
        # finite deadline is meaningless and would crash the ceil() below or drive the
        # key TTL to 0/negative (`keyctl timeout 0` clears the expiry - a permanent
        # secret key); a value beyond the cap would wrap the 32-bit keyctl TTL below the
        # wait. Refuse before staging so the staged TTL always outlives the wait.
        raise SystemExit(
            f"--timeout must be a positive, finite number of seconds (at most {_MAX_BLOCK_TIMEOUT})"
        )

    if a.file == "-" and sys.stdin.isatty():
        # Reading a terminal echoes the secret onto the screen and into the
        # scrollback, which is the one thing this bridge exists to avoid. Typing a
        # secret is what `passphrase` is for; this command is for piping one.
        raise SystemExit(
            "refusing to read a secret from a terminal - pipe it in or pass a FILE "
            "(to type one, use `jupyterlab-passkey passphrase --once`)"
        )

    source = "stdin" if a.file == "-" else a.file
    try:
        if a.file == "-":
            # .buffer, decoded here rather than sys.stdin.read(): sys.stdin decodes
            # with surrogateescape whatever the locale, so bad bytes would not raise
            # here at all - they would pass through as lone surrogates and blow up
            # later inside the relay write, as a UnicodeEncodeError nothing catches.
            # Strict, at the boundary, is where the error belongs.
            raw = sys.stdin.buffer.read().decode("utf-8")
        else:
            with open(a.file, encoding="utf-8") as f:
                raw = f.read()
    except OSError as e:
        raise SystemExit(f"cannot read {source}: {e}")
    except UnicodeDecodeError:
        raise SystemExit(f"{source} is not text - a clipboard holds text, not bytes")

    # `echo t | ...`, `cat token.txt`, and every here-string end in a newline nobody
    # meant to copy, and a trailing newline pasted into a login field submits it
    # early. Drop exactly one, which is what $(...) would have done anyway - and only
    # one, so a deliberately multi-line secret (a PEM key) survives intact.
    secret = raw[:-1] if raw.endswith("\n") else raw
    if secret == "":
        raise SystemExit("nothing to copy - the input was empty")

    nonce = secrets.token_urlsafe(24)
    message = (
        f"A secret is waiting: {a.label}" if a.label
        else "A secret is waiting - click to copy it to the clipboard."
    )

    # With --block the CLI itself waits for and cleans up the key, but the key must
    # outlive that wait: on keyctl a key that self-destructs at its TTL mid-wait looks
    # exactly like a collection (`keyctl search` fails either way), so --block would
    # report a secret delivered that nobody collected. Give it a TTL past the wait
    # deadline so within the wait it can only vanish by being collected. Without
    # --block the click-whenever default stands; shm files never expire, so this is a
    # no-op there.
    stage_ttl = math.ceil(timeout) + _COPY_BLOCK_TTL_MARGIN if a.block else None
    try:
        relay.stage(nonce, "secret", secret, ttl=stage_ttl)
    except OSError as e:
        # A full /dev/shm or an exhausted keyctl quota is the realistic one. Every
        # other failure here answers with a line; this should not answer with a
        # traceback. A squatted shm dir (PermissionError) also lands here.
        raise SystemExit(f"cannot stage the secret: {e}")

    # The label rides along so the frontend can name the secret if it has to ask
    # for a second click (a clipboard write refused past its retry window).
    command_args = {"nonce": nonce, "label": a.label} if a.label else {"nonce": nonce}
    try:
        _trigger(COPY_COMMAND, command_args, "Copy to clipboard", message)
    except BaseException:
        # The nonce dies with this process, so a relay left behind here is not
        # "uncollected" but uncollectable: no button was ever raised, nothing can
        # ever ask for it, and it would linger to its TTL (or to reboot on shm)
        # while the CLI told the user it had failed. A 404 from a lab without the
        # notifications extension is a first-run failure, not an exotic one, and
        # every retry would strand another copy.
        #
        # BaseException, not Exception: _trigger raises SystemExit, and a Ctrl+C
        # between the stage above and the POST strands the secret identically.
        relay.unstage(nonce, "secret")
        raise

    if a.block:
        try:
            _wait_gone(nonce, "secret", timeout, "was the button clicked?")
        finally:
            # Whatever happened, this secret is ours to clean up: on a timeout nobody
            # collected it, and leaving it would hand a live button to whoever clicks
            # next, long after the caller gave up and moved on. Already gone on the
            # success path, where the unstage is a no-op.
            relay.unstage(nonce, "secret")
        return 0

    # _trigger has just said "click ...", which after every other command is followed
    # by a blocking wait. Here the shell prompt returns underneath it, which reads as
    # done - so say plainly that it is not. Past the unstage window on purpose: the
    # button is live, and a stderr that cannot be written to is no reason to destroy
    # the secret it is about to collect.
    _say("nothing is reported back here - the click is what copies it")
    return 0


# The values these flags carry are base64url, whose alphabet includes "-", so roughly
# one in 64 begins with one. argparse reads ANY leading-dash token as an option, so the
# documented `--cred-id "$cred"` dies with "expected one argument" before the ceremony
# runs - not flakily but for that credential always, which is how it survives a release
# and then strands a passkey that registered perfectly well.
_B64URL_FLAGS = ("--cred-id", "--prf-salt")


def _glue_b64url(argv: list[str]) -> list[str]:
    """Rewrite `--cred-id VALUE` to `--cred-id=VALUE`, the form argparse cannot misread.

    Only the separator changes; the value is passed through untouched. A flag already
    written as `--cred-id=...` never matches and is left alone, and a flag with no value
    left to take is left alone too, so argparse still reports the real mistake.
    """
    out: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] in _B64URL_FLAGS and i + 1 < len(argv):
            out.append(f"{argv[i]}={argv[i + 1]}")
            i += 2
        else:
            out.append(argv[i])
            i += 1
    return out


def _sub(sub, name: str, help_: str, description: str, epilog: str, parents=()):
    """Add a subcommand whose --help is worth reading.

    Every subparser here wants the same three things and argparse defaults to none of
    them: prose under the usage line, examples under the options, and a formatter that
    does not reflow either into one paragraph.
    """
    return sub.add_parser(
        name, parents=list(parents), help=help_,
        description=description.strip("\n"), epilog=epilog.strip("\n"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def main() -> int:
    p = argparse.ArgumentParser(
        prog="jupyterlab-passkey",
        description=__doc__,
        epilog="""
Every subcommand has its own --help with examples: `jupyterlab-passkey copy --help`.

Exit status is the contract: 0 succeeded, 1 refused, timed out, or could not reach the
server (the reason is one line on stderr). Only the result goes to stdout - a cred_id,
a PRF, or a passphrase reference - so `$(...)` captures it clean and progress chatter
cannot contaminate it.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # --timeout hangs off a parent parser so it is accepted after the subcommand, which
    # is where anyone would think to type it. `copy` declares its own instead - see below.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--timeout", type=float, default=CLICK_TIMEOUT,
        metavar="SECONDS",
        help=f"how long to wait for the click before giving up and exiting 1 (default {CLICK_TIMEOUT:.0f})",
    )
    sub = p.add_subparsers(dest="op", required=True, metavar="COMMAND")

    c = _sub(
        sub, "create", "register a passkey; prints its cred_id",
        """
Register a new passkey and print its credential id to stdout.

Keep the cred_id: it is not a secret, but it is the only handle to the credential, and
`get` cannot assert a passkey without it. Store it wherever you store the config for
whatever this passkey unlocks.
""",
        """
example:
  cred_id=$(jupyterlab-passkey create --rp-id lab.example.com) || exit 1
""",
        parents=[common],
    )
    c.add_argument(
        "--rp-id", required=True, metavar="HOSTNAME",
        help="WebAuthn RP ID: your JupyterLab tab's hostname, bare - no scheme, port or path",
    )
    c.add_argument(
        "--user-name", default="jupyterlab-passkey", metavar="NAME",
        help="credential user name, shown in the browser's passkey picker (default jupyterlab-passkey)",
    )
    c.set_defaults(func=cmd_create)

    g = _sub(
        sub, "get", "assert a passkey; prints its PRF (with --prf-salt) or cred_id",
        """
Assert an existing passkey. With --prf-salt, prints the 32-byte PRF the authenticator
derives; without, prints the cred_id back as a liveness check.

The PRF is deterministic - the same credential and the same salt always yield the same
bytes - which is what makes it usable as a key. It goes to stdout, so capture it, do
not let it scroll.
""",
        """
example:
  salt=$(head -c32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')
  prf=$(jupyterlab-passkey get --rp-id lab.example.com --cred-id "$cred_id" \\
          --prf-salt "$salt") || exit 1
""",
        parents=[common],
    )
    g.add_argument(
        "--rp-id", required=True, metavar="HOSTNAME",
        help="WebAuthn RP ID: the same hostname the credential was created with",
    )
    g.add_argument(
        "--cred-id", required=True, metavar="B64URL",
        help="base64url credential id printed by a prior `create`",
    )
    g.add_argument(
        "--prf-salt", metavar="B64URL",
        help="base64url 32-byte salt; prints the PRF it yields instead of the cred_id",
    )
    g.set_defaults(func=cmd_get)

    s = _sub(
        sub, "passphrase", "capture a secret from a dialog; prints a reference to it",
        """
Open a dialog in the browser, take a secret, and print a REFERENCE to it - never the
value. The secret reaches its consumer without passing through this terminal, the shell
history, any process argument, or this CLI itself, which is the point.

The reference is scheme-prefixed so one consumer handles either relay backend:
  keyctl:jlab-passkey:<nonce>.pass   read with: keyctl pipe $(keyctl search @u user <desc>)
  file:<path>                        read the 0600 file at <path>

Use it to get a secret out of a head and into something else: a vault entry, a .env, a
keystore's recovery slot. An AI agent can run this and pipe the reference onward without
the secret ever entering its transcript. The consumer resolves the scheme itself.

The value is entered twice and Submit stays disabled until the two match. --once drops
the confirm field for a secret being pasted rather than typed. Cancelling stages
nothing, so the command times out and exits 1.
""",
        """
examples:
  # a passphrase being set - typed twice, confirmed. The consumer resolves the ref:
  pass_ref=$(jupyterlab-passkey passphrase --prompt "Recovery passphrase") || exit 1
  PASS_RECOVERY_REF="$pass_ref" pass-cli-open --ensure

  # a token being pasted - once is enough
  tok_ref=$(jupyterlab-passkey passphrase --once --prompt "GitHub token") || exit 1

  # resolving a reference by hand, either backend:
  case "$pass_ref" in
    keyctl:*) keyctl pipe "$(keyctl search @u user "${pass_ref#keyctl:}")" ;;
    file:*)   cat "${pass_ref#file:}" ;;
  esac
""",
        parents=[common],
    )
    s.add_argument(
        "--prompt", metavar="TEXT",
        help="dialog prompt text (default: 'Enter the passphrase twice', or 'Enter the secret' with --once)",
    )
    s.add_argument(
        "--once", action="store_true",
        help="ask for the secret once instead of twice - for a value pasted from a password manager",
    )
    s.set_defaults(func=cmd_passphrase)

    # No `common` here: without --block this command waits for nothing, and a --timeout
    # it accepted and then ignored would be a lie about what it does. It declares its
    # own, and refuses it unless --block makes it mean something.
    cp = _sub(
        sub, "copy", "stage a secret from FILE or stdin; a notification button copies it to the clipboard",
        """
Read a secret from FILE or stdin and raise a notification whose button puts it on the
browser's clipboard. The mirror of `passphrase`: that one brings a secret in from the
user, this one sends one out to them, to paste wherever it is wanted.

The secret is never in the notification - it is staged in a 0600 relay and the
notification carries only a nonce, which is useless without the Jupyter token. The
click collects it and the relay is deleted in the same breath, so a second click finds
nothing. An AI agent can hand a user a secret this way without the value appearing in
its transcript or in any file the user has to clean up.

Fire and forget by default: it posts and returns, so exit 0 means POSTED, not copied,
and nothing is reported back. --block instead waits until the browser collects the
secret and deletes it if that never happens - use it to sequence work after the secret
has actually landed. Note it means COLLECTED, not pasted: the page fetches the value
and only then writes the clipboard, so a browser that refuses the clipboard does so
after --block has already returned 0.

Exactly one trailing newline is stripped, as $(...) would; a multi-line secret survives
intact. A stdin that is a terminal is refused - that would echo the secret into the
scrollback; pipe it in, pass a FILE, or use `passphrase --once` to type one.
""",
        """
examples:
  # out of a vault, into the clipboard, ready to paste into a web form
  pass-cli get github/api --field password --quiet --no-clipboard | jupyterlab-passkey copy

  # straight from a file
  jupyterlab-passkey copy ~/.config/some-service/token

  # two in flight - name them, the notifications are otherwise identical
  ... | jupyterlab-passkey copy --label "GitHub token"
  ... | jupyterlab-passkey copy --label "DB password"

  # wait for it to land before moving on, and leave nothing behind if it does not
  ... | jupyterlab-passkey copy --label "DB password" --block || exit 1
""",
    )
    cp.add_argument(
        "file", nargs="?", default="-", metavar="FILE",
        help="file to read the secret from; omit or '-' to read stdin",
    )
    cp.add_argument(
        "--label", metavar="NAME",
        help="name shown in the notification - the only way to tell two staged secrets apart",
    )
    cp.add_argument(
        "--block", action="store_true",
        help="wait until the browser collects the secret; exit 1 and delete it if it never does",
    )
    cp.add_argument(
        "--timeout", type=float, default=None, metavar="SECONDS",
        help=f"with --block: how long to wait before giving up (default {CLICK_TIMEOUT:.0f}); rejected without --block",
    )
    cp.set_defaults(func=cmd_copy)

    argv = _glue_b64url(sys.argv[1:])
    if not argv:
        # argparse answers a bare invocation with a usage line and "the following
        # arguments are required: COMMAND", which tells a first-time caller - or an
        # agent probing what this thing does - nothing at all. The full help is the
        # honest answer to "what are you?". On stderr and still exit 2, because it is
        # still a usage error and stdout carries results, not prose.
        p.print_help(sys.stderr)
        return 2

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
