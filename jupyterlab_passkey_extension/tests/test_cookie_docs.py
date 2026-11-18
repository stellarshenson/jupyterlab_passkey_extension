"""The cookie and rename examples of docs/cli-reference.md parse (ACC-COOKIE-356, ACC-VDOCS-374),
and each document states the headers read (ACC-COOKIE-395).

Every `jupyterlab-passkey` command line in a bash block of the Cookie entries section,
and every `vault rename` example, goes through the CLI's own parser, so an example that
names an option or an argument the parser does not have fails here.
"""
import pathlib
import re
import shlex

import pytest

from jupyterlab_passkey_extension import cli

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "cli-reference.md"
# The shell words that end a command inside a line.
_ENDS = {"|", "||", "&&", ";", ")"}


def _blocks(text, language):
    """The lines of each fenced block in `language`, a backslash line end joined."""
    return [line for body in re.findall(rf"^```{language}\n(.*?)^```", text, re.M | re.S)
            for line in body.replace("\\\n", " ").splitlines()]


def _commands(lines):
    """The words after `jupyterlab-passkey`, up to the shell operator that ends the command."""
    found = []
    for line in lines:
        # A process substitution, `<(...)`, holds a command of its own.
        words = shlex.split(line.replace("<(", "<( ").replace(")", " )"), comments=True)
        if "jupyterlab-passkey" in words:
            rest = words[words.index("jupyterlab-passkey") + 1:]
            found.append(rest[:next((i for i, w in enumerate(rest) if w in _ENDS), len(rest))])
    return found


def test_every_cookie_and_rename_example_parses_with_the_cli_parser():
    text = DOC.read_text()
    start = text.index("\n### Cookie entries\n")
    section = text[start:re.compile(r"^##+ ", re.M).search(text, start + 2).start()]
    commands = (_commands(_blocks(section, "bash"))
                + _commands(line for line in _blocks(text, "bash") if "vault rename" in line))
    parsed = []
    for words in commands:
        try:
            parsed.append(cli._parser().parse_args(words))
        except SystemExit:
            pytest.fail(f"the documented example `jupyterlab-passkey {shlex.join(words)}` does not parse")

    # The examples ACC-COOKIE-356 and ACC-VDOCS-374 name.
    assert any(a.command == "vault add" and a.cookies and a.in_browser for a in parsed)
    recipe = 'printf "Cookie: %s\\n" "$C" | curl -H @- https://app.example.com/api'
    assert any(a.command == "vault exec" and a.env == ["C=site/app"] and recipe in a.argv for a in parsed)
    # No example gives a tool the cookie variable as an argument: the process list shows it.
    examples = "\n".join(_blocks(section, "bash"))
    assert '-b "$C"' not in examples and '--header "Cookie: $C"' not in examples
    # The cookies.txt a process substitution gives to wget.
    assert any(a.command == "vault get" and a.name == "site/app" and not a.format for a in parsed)
    assert any(a.command == "vault get" and a.format == "header" for a in parsed)
    # ACC-COOKIE-395: the cookies and the kept headers on curl's standard input.
    assert any(a.command == "vault get" and a.name == "site/app" and a.format == "headers" for a in parsed)
    assert ("jupyterlab-passkey vault get site/app --format headers | curl -H @- https://app.example.com/api"
            in examples)
    assert any(a.command == "vault rename" for a in parsed)
    assert "cookies=Vault().cookies(" in "\n".join(_blocks(section, "python"))


@pytest.mark.parametrize("path", ["docs/cli-reference.md", "docs/design-vault.md", "docs/usage.md", "README.md",
                                  ".agents/skills/jupyterlab-passkey-extension/SKILL.md"])
def test_each_document_states_the_headers_read(path):
    # ACC-COOKIE-395: what a cookie entry holds, the recipe, and the limit of a header.
    text = (ROOT / path).read_text()
    assert "--format headers" in text
    assert "request headers" in text
    assert re.search(r"vault get \S+ --format headers \| curl -H @- \S+", text)
    assert "header has no expiry" in text


def test_the_reference_states_what_a_refused_read_does_beside_the_pipe_and_the_wget_recipe():
    # ACC-COOKIE-398: curl and wget still send the request; under exec the command does not run.
    line = next((line for line in DOC.read_text().splitlines()
                 if "curl still sends the request, without the headers" in line), "")
    for said in ("`get` prints its reason on stderr", "`get NAME --format headers | curl -H @- URL`",
                 "`<(jupyterlab-passkey vault get NAME)` loads a cookies.txt with no cookie",
                 "under `exec --env VAR=NAME:headers` the command does not run"):
        assert said in line, said
