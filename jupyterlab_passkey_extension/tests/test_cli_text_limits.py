"""Visible CLI texts stay within the 60-character bound, or a reason here says why.

The lines are read from the source as the product prints them: the argument of an
output call, a raised error, or a module-level constant a command prints later. The
source's `--help` texts are excluded by construction, since no output call carries
them. A new long line fails until it is shortened or given a reason here.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

FILES = [
    "jupyterlab_passkey_extension/cli.py",
    "jupyterlab_passkey_extension/vault/cli.py",
    "jupyterlab_passkey_extension/vault/client.py",
    "jupyterlab_passkey_extension/vault/gitcred.py",
]

# Calls whose argument is a line the user reads.
OUTPUT_CALLS = {
    "SystemExit",
    "Fail",
    "VaultError",
    "VaultClientError",
    "Conflict",
    "NoAnswer",
    "_say",
    "print",
}

# Module-level names that hold a line a command prints later.
LINED_NAMES = {"WAITING_UNLOCK", "WAITING_SETUP", "NAMED_NO_MORE", "hint", "message"}

# A fixed text longer than the bound, with the fact that keeps it long.
LONGER = {
    "cannot tell which server is the lab - run in a JupyterLab terminal or set JUPYTER_PORT. Running: ":
        "names the two settings that identify the lab and shows the running servers",
    "no server found - start JupyterLab, or set JUPYTER_PORT or JUPYTERHUB_SERVICE_PREFIX":
        "names both environment variables a caller can set",
    "trigger rejected (404) - the notifications extension is not installed in that lab":
        "names the missing extension and its status code",
    "ceremony failed: rp-id-mismatch - --rp-id must be the tab's hostname or a parent domain, "
    "with no scheme, port or path. An IP address is no RP ID: open JupyterLab by name, over "
    "HTTPS or at localhost.":
        "states every accepted RP ID form and why an IP address cannot be one",
    " from a terminal - pipe it in, pass a FILE, or use `passphrase`":
        "names the three ways to supply the value without a terminal",
    " - store the recovery passphrase offline; it opens the vault when no other method can":
        "names where to keep it and that it is the last way in",
    "the vault has no passkey - run `jupyterlab-passkey vault passkey add`, or add a method with the cog":
        "names the exact command and the cog",
    "--password needs the unlock password and an app code - run at a terminal or with --in-browser":
        "names both inputs and both ways to run it",
    "refusing to read secrets from a terminal - pipe or pass a FILE":
        "names both routes that are not a terminal",
    "vault recovery needs two passphrases - run at a terminal or with --in-browser":
        "names both passphrases and both ways to run it",
    "`jupyterlab-passkey vault git migrate --remove-source` (a plain path, `~` or a set variable only)":
        "names the exact command and the path forms it accepts",
    "the vault is locked - waiting for the notification in your JupyterLab tab":
        "names the tab and what it waits for",
    "no vault yet - waiting for the set-up notification in your JupyterLab tab":
        "names the tab and what it waits for; it says JupyterLab, not the caller's tab",
}


def _fragments(node: ast.AST) -> list[str]:
    """The fixed text of a line: each string part of a joined or concatenated value."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return [
            value.value
            for value in node.values
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        ]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _fragments(node.left) + _fragments(node.right)
    return []


def _texts(name: str, tree: ast.Module):
    """Each visible line's site and fixed fragments in one parsed file."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = node.func
            call = (
                called.id
                if isinstance(called, ast.Name)
                else getattr(called, "attr", "")
            )
            if call not in OUTPUT_CALLS:
                continue
            if call in ("_say", "print", "SystemExit", "Fail"):
                argument = node.args[0] if node.args else None
            else:
                argument = (
                    node.args[1]
                    if len(node.args) > 1
                    else (node.args[0] if node.args else None)
                )
            if argument is not None:
                for text in _fragments(argument):
                    yield f"{name}:{node.lineno}", text
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in LINED_NAMES:
                for text in _fragments(node.value):
                    yield f"{name}:{node.lineno}", text


def _lines():
    """Each visible line's site and fixed fragments."""
    for name in FILES:
        tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
        yield from _texts(name, tree)


def test_visible_cli_texts_fit_sixty_characters_or_say_why():
    too_long = [
        f"{site}: {len(text)} characters: {text!r}"
        for site, text in _lines()
        if len(text) > 60 and text not in LONGER
    ]
    assert too_long == []


def test_every_recorded_reason_belongs_to_a_line_still_in_the_source():
    texts = {text for _, text in _lines()}
    assert [text for text in LONGER if text not in texts] == []


def test_a_long_fail_message_is_reported():
    # Fail(message, code) puts the line in the first argument; reading the second
    # would scan the code and let every Fail message escape the bound.
    message = "x" * 61
    tree = ast.parse(f'raise Fail("{message}", "usage")')
    reported = [text for _, text in _texts("sample.py", tree)]
    assert [text for text in reported if len(text) > 60 and text not in LONGER] == [message]
