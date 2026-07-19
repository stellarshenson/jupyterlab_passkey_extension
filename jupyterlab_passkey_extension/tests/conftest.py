"""Shared fixtures for the server + CLI unit tests.

The relay now has two backends (keyctl and shm) chosen once per process and cached
in a module global. A test process would otherwise inherit whichever backend the
first test resolved, so every test resets that cache here and pins a backend: shm by
default - the existing suite asserts file behaviour - and keyctl only for the tests
marked `@pytest.mark.keyctl`, which exercise the kernel-keyring path directly.
"""

import pytest

from jupyterlab_passkey_extension import relay


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "keyctl: run this test against the keyctl backend, not shm"
    )


@pytest.fixture(autouse=True)
def _relay_backend(request, monkeypatch):
    # Reset the per-process cache so each test's backend choice is honoured rather
    # than the first test's, and so the fallback warning fires afresh where tested.
    monkeypatch.setattr(relay, "_backend_cache", None)
    monkeypatch.setattr(relay, "_warned", False)
    if request.node.get_closest_marker("keyctl"):
        monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "keyctl")
    else:
        monkeypatch.setenv("JLAB_PASSKEY_RELAY_BACKEND", "shm")
    yield
