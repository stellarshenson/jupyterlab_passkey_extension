#!/usr/bin/env python3
"""jupyterlab-passkey - drive the browser passkey ceremony from a local process.

A proxy to the extension's JupyterLab commands. WebAuthn needs a user gesture and a
browser; a terminal has neither. So a subcommand that needs the browser posts a
notification whose action button is bound to the command, then (all but `copy` and
`show`) waits for the relay the server writes and returns the result - turning a
browser ceremony into a blocking call.

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
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

from . import relay
from .relay import _say

INGEST = "jupyterlab-notifications-extension/ingest"
RUN_COMMAND = "passkey:run"
PASSPHRASE_COMMAND = "passkey:passphrase"
COPY_COMMAND = "passkey:copy"
SHOW_COMMAND = "passkey:show"

# The trigger POST is a local, non-interactive call - only the click it asks for is slow.
# --timeout governs the wait for the click, never this; without a bound here a wedged
# server event loop hangs the CLI forever, ignoring --timeout entirely.
TRIGGER_TIMEOUT = 10

# How long a subcommand waits for the click, unless --timeout says otherwise; `vault
# init` and `vault passkey add` wait vault.cli.REGISTER_TIMEOUT instead. ONE
# definition, fed to argparse and interpolated into the help text below: the commands
# that take it wait for the same thing - a human noticing a notification and clicking it -
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


# The SIGHUP disposition this process started with (ignored under nohup), read before
# main() ignores it: `vault exec` hands it on to its command.
STARTED_HANGUP = signal.getsignal(signal.SIGHUP) if hasattr(signal, "SIGHUP") else None


def _ignore_hangup() -> None:
    """Survive the controlling terminal going away, so a detached run still lands.

    A subcommand that raises a browser notification and waits for a human to
    click it - a popup, a passphrase query, a blocking copy - does work that
    outlives the shell that launched it. Backgrounded with a bare `&` and the
    terminal then closed, the default SIGHUP disposition kills the process
    mid-wait; the click afterwards writes (or reads) a relay nobody is left to
    handle, and for `copy` it strands one this process staged and can no
    longer clean up. Ignoring SIGHUP gives every command nohup's behaviour without
    the caller having to remember nohup, so notifications, popups and queries work
    the same whether the process is attached or detached. The command `vault exec`
    runs gets STARTED_HANGUP instead.

    POSIX only - Windows has no SIGHUP. Best-effort: on a non-main thread or a
    platform that refuses, the command still works when launched under nohup/setsid,
    so a failure here is not fatal.
    """
    hup = getattr(signal, "SIGHUP", None)
    if hup is None:
        return
    try:
        signal.signal(hup, signal.SIG_IGN)
    except (ValueError, OSError):
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


# Found once per process: `jupyter server list` takes about a second, and one vault
# command can need the server several times.
_found: tuple[str, str | None] | None = None


def _server() -> tuple[str, str | None]:
    global _found
    if _found is None:
        info = _server_list()
        _found = (_base_url(info), _token(info))
    return _found


def _forget_server() -> None:
    """Look the server up again next time: after a 401/403 (a restarted server has a
    new token) or no answer (it may come back on another port)."""
    global _found
    _found = None


# Requests to the local server bypass any proxy: urlopen follows http_proxy even for
# 127.0.0.1, and would hand the proxy the token and whatever the body carries.
_LOOPBACK = urllib.request.build_opener(urllib.request.ProxyHandler({}))


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
        with _LOOPBACK.open(req, timeout=TRIGGER_TIMEOUT) as r:
            r.read()
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            _forget_server()
        if e.code == 404:
            raise SystemExit(
                f"trigger rejected (404) by {base}/{INGEST} - the notifications extension "
                "is not installed in that lab; the CLI needs it to raise the button"
            )
        raise SystemExit(f"trigger rejected ({e.code} {e.reason}) by {base}/{INGEST}")
    except urllib.error.URLError as e:
        _forget_server()
        raise SystemExit(f"cannot reach {base} ({e.reason}) - is JupyterLab running?")
    except OSError as e:
        # Must come after URLError, which subclasses OSError. TimeoutError and
        # ConnectionResetError are OSError but NOT URLError, and open() raises them
        # bare out of the read phase - so without this the one case TRIGGER_TIMEOUT
        # exists to bound, a server that accepts the connection and then wedges, ends
        # in a traceback instead of the sentence that names the problem.
        _forget_server()
        raise SystemExit(f"cannot reach {base} ({e}) - is JupyterLab running?")

    # The POST has landed by here and the button is live in the browser, so a broken
    # stderr (a full log volume, a pipe whose reader has gone) must not report the
    # trigger as failed - `copy`'s caller answers that by unstaging the secret the
    # live button is about to ask for. See _say.
    _say(f"click '{label}' in your JupyterLab tab")


def _wait(nonce: str, kind: str, timeout: float, on_timeout: str,
          watch_cancel: bool = False) -> None:
    """Block until the relay is staged.

    Existence is enough: a relay is staged atomically (the file lands via
    os.replace, the key via a single padd), so what a reader then finds is whole -
    see `relay.stage`. The poll reads nothing, so a squatted shm dir cannot raise
    here; that check fires at collect time.

    With `watch_cancel`, a `cancel` marker staged by a dismissed dialog ends the wait
    at once. Without it a refusal is indistinguishable from an unclicked button, so
    the user waits out the full timeout to be told what they already decided.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if relay.relay_exists(nonce, kind):
            return
        if watch_cancel and relay.relay_exists(nonce, "cancel"):
            # Consume the marker: it is one-shot like every other relay, and leaving it
            # would strand a key until its TTL for a nonce nothing will use again.
            relay.unstage(nonce, "cancel")
            raise SystemExit("cancelled")
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


def _run(args_obj: dict, label: str, message: str, timeout: float,
         command_id: str = RUN_COMMAND) -> dict:
    """Drive a ceremony command and consume its relay, destroying it on every path out.

    `passkey:run` by default; the vault's unlock and register commands answer through
    the same result relay.

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
    _trigger(command_id, args_obj, label, message)
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
        error = data.get("error")
        if error == "rp-id-mismatch":
            # The one ceremony failure the caller can fix without touching the browser,
            # and the one WebAuthn does NOT hide behind not-allowed: --rp-id must equal
            # the hostname the JupyterLab tab is open at, or a parent domain of it. A
            # bare "rp-id-mismatch" leaves the caller guessing which of the two is wrong.
            raise SystemExit(
                "ceremony failed: rp-id-mismatch - --rp-id does not match the "
                "JupyterLab tab's URL. It must be the tab's hostname, or a parent "
                "domain of it, with no scheme, port or path - and a name: a tab "
                "open at an IP address such as 127.0.0.1 has no valid RP ID, so "
                "open JupyterLab by name - over HTTPS, or at localhost."
            )
        raise SystemExit(f"ceremony failed: {error}")
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
    # A cancel stages a marker that ends the wait at once, and two entries that differ
    # cannot be submitted, so a timeout means the dialog was never finished.
    refused = "the button was never clicked, or the dialog was left open"
    try:
        _wait(nonce, "pass", a.timeout, refused, watch_cancel=True)
        ref = relay.reference(nonce, "pass")
    except OSError as e:
        # An operator who forced JLAB_PASSKEY_RELAY_BACKEND=keyctl on a host whose
        # keyring is not functional gets a clean line here, not a traceback - the same
        # bar the other commands hold. (A missing/quota'd backend surfaces the same way.)
        raise SystemExit(f"relay backend unavailable: {e}")
    # Flushed here, not at shutdown: a caller who cannot receive the reference (stdout
    # closed, its reader gone) would leave the secret staged with nobody to remove it.
    try:
        if sys.stdout is None:
            raise OSError("stdout is closed")
        print(ref, flush=True)
    except (OSError, ValueError) as e:
        relay.unstage(nonce, "pass")
        # Dropped, so shutdown does not retry the flush and exit 120 over this line.
        sys.stdout = None
        raise SystemExit(f"could not write the reference ({e}) - the secret was removed")
    return 0


def _read_stdin_or_file(file_arg, noun, empty_msg, nontext_msg):
    """Read a text value from FILE or stdin, strict utf-8, one trailing newline dropped.

    Shared by `copy`, `show` and the vault's secret and import readers: all read a
    value the same careful way and differ only in the words of their errors. `noun` names the value in the terminal-refusal
    message; `empty_msg` and `nontext_msg` (which may reference `{source}`) are the
    caller's own wording, since copy's strings are pinned by its tests. Keeping the one
    subtle part - strict decode at the boundary, strip exactly one trailing newline -
    in a single place is the point: a fix to it must not have to be remembered twice.
    """
    if file_arg == "-" and sys.stdin.isatty():
        # Reading a terminal echoes the value onto the screen and into the scrollback,
        # the one thing this bridge exists to avoid. Typing one is `passphrase`'s job.
        raise SystemExit(
            f"refusing to read a {noun} from a terminal - pipe it in or pass a FILE "
            "(to type one, use `jupyterlab-passkey passphrase --once`)"
        )
    source = "stdin" if file_arg == "-" else file_arg
    try:
        if file_arg == "-":
            # .buffer, decoded here rather than sys.stdin.read(): sys.stdin decodes with
            # surrogateescape whatever the locale, so bad bytes would not raise here -
            # they would pass through as lone surrogates and blow up later inside the
            # relay write. Strict, at the boundary, is where the error belongs.
            raw = sys.stdin.buffer.read().decode("utf-8")
        else:
            with open(file_arg, encoding="utf-8") as f:
                raw = f.read()
    except OSError as e:
        raise SystemExit(f"cannot read {source}: {e}")
    except UnicodeDecodeError:
        raise SystemExit(nontext_msg.format(source=source))
    # `echo t | ...`, `cat token.txt`, and every here-string end in a newline nobody
    # meant to send, and a trailing one pasted into a field submits it early. Drop
    # exactly one, as $(...) would - and only one, so a multi-line value survives.
    value = raw[:-1] if raw.endswith("\n") else raw
    if value == "":
        raise SystemExit(empty_msg)
    return value


def cmd_copy(a) -> int:
    """Stage a secret from a file or stdin and offer it to the browser's clipboard.

    It runs outward, as `show` does: the caller already holds the secret and wants
    it in the clipboard of the browser they are sitting in front of, to paste
    somewhere this bridge knows nothing about.

    The value is staged in a relay (a kernel key or a 0600 file) and the notification
    carries only the nonce.
    Putting the secret in the notification instead would be simpler and wrong - the
    notifications extension pushes every payload to every connected socket and parks
    it in an in-memory queue until a client drains it.

    Fire and forget by default: the relay is one-shot, so the click consumes it, but
    nothing here waits for the click. A secret nobody clicks self-destructs at its TTL
    on keyctl, and sits in tmpfs until reboot on shm - the button is up and the user can see it, which is a different thing
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

    secret = _read_stdin_or_file(
        a.file,
        "secret",
        "nothing to copy - the input was empty",
        "{source} is not text - a clipboard holds text, not bytes",
    )

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


def cmd_show(a) -> int:
    """Stage a code and show it in the browser as a scraper-resistant image.

    The mirror of `copy` for a value the user must READ rather than paste - a
    one-time authenticator code, a pairing code. The click fetches a rendered PNG
    of the code and shows it in a dialog, so the code never reaches the page as
    text: not the notifications broadcast, not the DOM, not the accessibility tree,
    and an OCR pass on a screenshot still has to beat the distortion.

    Fire and forget, like `copy` without --block: the relay is one-shot, the click
    consumes it by rendering, and nothing here waits. The value never rides the CLI
    beyond the stage call and is never logged.
    """
    code = _read_stdin_or_file(
        a.file,
        "code",
        "nothing to show - the input was empty",
        "{source} is not text",
    )
    if len(code) > relay.MAX_CODE_CHARS:
        # A code is short by definition; a large value is a mistaken `show` of a file,
        # and rendering it would tie up the server. Refuse before staging.
        raise SystemExit(
            f"code too long ({len(code)} chars, max {relay.MAX_CODE_CHARS}) - `show` is "
            "for a short code to read on screen, not a file; did you mean `copy`?"
        )

    nonce = secrets.token_urlsafe(24)
    message = (
        f"A code is waiting: {a.label}" if a.label
        else "A code is waiting - click to show it."
    )
    try:
        relay.stage(nonce, "code", code)
    except OSError as e:
        # A full /dev/shm or an exhausted keyctl quota is the realistic one - a line,
        # not a traceback. A squatted shm dir (PermissionError) lands here too.
        raise SystemExit(f"cannot stage the code: {e}")

    command_args = {"nonce": nonce, "label": a.label} if a.label else {"nonce": nonce}
    try:
        _trigger(SHOW_COMMAND, command_args, "Show the code", message)
    except BaseException:
        # The nonce dies with this process, so a relay left behind here is not
        # uncollected but uncollectable: no button was ever raised. Same reasoning
        # as cmd_copy - BaseException so a SystemExit from _trigger or a Ctrl+C
        # between the stage and the POST cleans up too.
        relay.unstage(nonce, "code")
        raise

    _say("nothing is reported back here - the click is what shows it")
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
    left to take is left alone too, so argparse still reports the real mistake. Nothing
    after a bare `--` is touched: that is another program's command line (`vault exec`).
    """
    out: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--":
            return out + argv[i:]
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
    # Before anything else: a command backgrounded and then orphaned by its terminal
    # must keep waiting for its click, not die on SIGHUP. See _ignore_hangup.
    _ignore_hangup()

    p = argparse.ArgumentParser(
        prog="jupyterlab-passkey",
        description=__doc__,
        epilog="""
Every bridge subcommand has its own --help with examples: `jupyterlab-passkey copy --help`.

Exit status is the contract: 0 succeeded, 1 refused, timed out, or could not reach the
server (the reason is on stderr), 2 an argument the parser rejects; `vault exec`
exits with its command's status. Only the result goes to stdout, so `$(...)` captures it
clean and progress chatter cannot contaminate it.
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
    # --debug rides its own parent so EVERY subcommand takes it, including the ones that
    # want no --timeout. It reports which relay backend was chosen and, when keyctl was
    # rejected, exactly which step the kernel refused - the question that otherwise costs
    # a manual keyctl round-trip to answer. stderr only: stdout carries the result.
    debugp = argparse.ArgumentParser(add_help=False)
    debugp.add_argument(
        "--debug", action="store_true",
        help="report the relay backend and, for vault commands, the key-holder decision on stderr",
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
        parents=[common, debugp],
    )
    c.add_argument(
        "--rp-id", required=True, metavar="HOSTNAME",
        help="WebAuthn RP ID: your JupyterLab tab's hostname, bare - no scheme, port or path; "
             "a name, never an IP address",
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
        parents=[common, debugp],
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
the confirm field for a secret being pasted rather than typed. Cancelling exits 1 at
once.
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
        parents=[common, debugp],
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

The secret is never in the notification - it is staged in a relay (a kernel key or a
0600 file) and the notification carries only a nonce, which is useless without the Jupyter token. The
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
        parents=[debugp],
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

    # No `common` here either: `show` posts and returns like `copy` without --block,
    # so there is nothing for a --timeout to bound.
    sh = _sub(
        sub, "show", "stage a code from FILE or stdin; a notification button shows it as an image",
        """
Read a code from FILE or stdin and raise a notification whose button shows it in a
dialog as a distorted image. For a value the user must READ off the screen and type
somewhere else - a one-time authenticator code, a pairing code - rather than paste.

The code never reaches the page as text. It is staged in a relay (a kernel key or a
0600 file), the notification carries only a nonce, and the click fetches a PNG the server draws from
the relay and consumes in the same breath. So the code is absent from the
notifications broadcast, the DOM, and the accessibility tree; a screen scraper sees
an image, and an OCR pass still has to beat the distortion.

Fire and forget: it posts and returns, and nothing is reported back - the click is
what shows it. Exactly one trailing newline is stripped. A stdin that is a terminal
is refused; pipe it in, pass a FILE, or use `passphrase --once` to type one.
""",
        """
examples:
  # show a TOTP enrolment code the user must type into their authenticator app
  printf '%s' "$totp_secret" | jupyterlab-passkey show --label "Authenticator code"

  # from a file
  jupyterlab-passkey show ~/pairing-code.txt
""",
        parents=[debugp],
    )
    sh.add_argument(
        "file", nargs="?", default="-", metavar="FILE",
        help="file to read the code from; omit or '-' to read stdin",
    )
    sh.add_argument(
        "--label", metavar="NAME",
        help="name shown in the notification and above the code image",
    )
    sh.set_defaults(func=cmd_show)

    from .vault.cli import add_vault_parser

    add_vault_parser(sub, common, debugp)

    argv = _glue_b64url(sys.argv[1:])
    if not argv:
        # argparse answers a bare invocation with a usage line and "the following
        # arguments are required: COMMAND", which tells a first-time caller - or an
        # agent probing what this thing does - nothing at all. The full help is the
        # honest answer to "what are you?". On stderr and still exit 2, because it is
        # still a usage error and stdout carries results, not prose.
        _say(p.format_help().rstrip("\n"))
        return 2

    a = p.parse_args(argv)
    if getattr(a, "debug", False):
        # Before the command runs, so the backend is on the record even if what follows
        # times out. _say, not print: a closed stderr must not fail the command.
        _say(relay.debug_report())
    return a.func(a)


if __name__ == "__main__":
    # The package module's main, not this copy's: `vault exec` imports that module, and
    # it must read STARTED_HANGUP before main() ignores SIGHUP.
    from jupyterlab_passkey_extension.cli import main as _main

    raise SystemExit(_main())
