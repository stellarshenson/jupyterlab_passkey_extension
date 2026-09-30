"""The agent skill installed by the wheel is the one in the repository (ACC-VDOCS-187).

The skill ships twice: the repository copy an agent reads from a clone, and the copy
the wheel's shared-data mapping puts under `sys.prefix`. Two copies drift, so they are
compared byte for byte. This fails when the mapping is absent from `pyproject.toml`,
when the installed copy is older than the repository copy, and when the skill is
renamed on one side only.
"""
import pathlib
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
