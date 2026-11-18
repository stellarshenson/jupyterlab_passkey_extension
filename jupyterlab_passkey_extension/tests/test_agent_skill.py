"""The agent skill installed by the wheel is the one in the repository (ACC-VDOCS-187).

The skill ships twice: the repository copy an agent reads from a clone, and the copy
the wheel's shared-data mapping puts under `sys.prefix`. Two copies drift, so they are
compared byte for byte. This fails when the mapping is absent from `pyproject.toml`,
when the installed copy is older than the repository copy, and when the skill is
renamed on one side only.
"""
import pathlib
import re
import sys

import pytest

SKILL_NAME = "jupyterlab-passkey-extension"

_REPOSITORY_COPY = (
    pathlib.Path(__file__).resolve().parents[2] / ".agents" / "skills" / SKILL_NAME / "SKILL.md"
)
_INSTALLED_COPY = (
    pathlib.Path(sys.prefix) / "share" / "jupyter" / "agents" / "skills" / SKILL_NAME / "SKILL.md"
)


needs_checkout = pytest.mark.skipif(
    not _REPOSITORY_COPY.is_file(),
    reason="no repository copy to compare against outside a source checkout",
)


@needs_checkout
def test_installed_agent_skill_matches_repository():
    assert _INSTALLED_COPY.is_file(), (
        f"{_INSTALLED_COPY} is missing: the installed wheel carries no agent skill, so "
        "either the shared-data mapping is absent from pyproject.toml or this environment "
        "predates it - run make install"
    )
    assert _INSTALLED_COPY.read_bytes() == _REPOSITORY_COPY.read_bytes(), (
        "the installed agent skill differs from the repository copy; the wheel in this "
        "environment was built from an older SKILL.md - run make install"
    )


@needs_checkout
def test_agent_skill_is_short_and_points_at_help():
    # The command reference lives in --help, which changes with the code; the skill
    # carries only the rules --help cannot state.
    text = _REPOSITORY_COPY.read_text()
    assert len(text.splitlines()) < 30
    assert f"name: {SKILL_NAME}\n" in text
    assert "jupyterlab-passkey --help" in text


@needs_checkout
def test_agent_skill_description_names_cookies_and_keeps_its_triggers():
    # ACC-WEBAUT-360: the cookie triggers join the ones the description had.
    description = next(line for line in _REPOSITORY_COPY.read_text().splitlines()
                       if line.startswith("description: "))
    for trigger in ("cookies", "cookies.txt", "logged-in session", "curl", "wget", "yt-dlp",
                    "requests", "credential or token", "passphrase typed in the browser",
                    "git credential helper", "AWS credentials", "credential_process",
                    # ACC-WEBAUT-395: the words a request for a logged-in API call uses.
                    "request headers", "Authorization header", "bearer token"):
        assert trigger in description, trigger


@needs_checkout
def test_agent_skill_states_the_three_cookie_rules():
    # The user pastes the cookies, a tool reads them through exec, and `expired` asks the
    # user for a fresh copy.
    text = _REPOSITORY_COPY.read_text()
    assert "`vault add NAME --cookies --in-browser`" in text
    assert "`vault exec --env C=NAME " in text
    assert re.search(r"`expired`: [^\n]*ask user for a fresh copy", text)


@needs_checkout
def test_agent_skill_states_the_headers_read():
    # ACC-WEBAUT-395: cookies and request headers reach curl on standard input, and
    # `requests` as a dict; a header has no expiry.
    text = _REPOSITORY_COPY.read_text()
    assert "`vault get NAME --format headers | curl -H @- URL`" in text
    assert "`Vault().headers(NAME)`" in text
    assert "header has no expiry" in text


@needs_checkout
def test_agent_skill_states_what_a_refused_read_does_in_the_pipe():
    # ACC-WEBAUT-398: curl still sends the request; under exec the command does not run.
    line = next(line for line in _REPOSITORY_COPY.read_text().splitlines()
                if "`vault get NAME --format headers | curl -H @- URL`" in line)
    assert "refused read: reason on stderr, curl still sends the request, without the headers" in line
    assert "under `vault exec --env H=NAME:headers` command does not run" in line


@needs_checkout
def test_agent_skill_names_the_vault_entry_methods():
    # ACC-VDOCS-375: add, edit, rename and delete beside get, on the Python line.
    line = next(line for line in _REPOSITORY_COPY.read_text().splitlines() if "import Vault" in line)
    for method in ("get", "add", "edit", "rename", "delete"):
        assert f"`{method}`" in line, method
