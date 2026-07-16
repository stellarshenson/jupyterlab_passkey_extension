"""Server configuration for integration tests.

!! Never use this configuration in production because it
opens the server to the world and provide access to JupyterLab
JavaScript objects through the global window variable.
"""
import os

from jupyterlab.galata import configure_jupyter_server

configure_jupyter_server(c)

# configure_jupyter_server pins port 8888 with port_retries=0, so the server dies
# rather than move when that port is taken - which is what stopped this suite running
# beside a developer's own lab. Kept in lockstep with playwright.config.js, which reads
# the same variable to build the base URL it waits on.
#
# `or`, not a get() default: an exported-but-empty JUPYTER_TEST_PORT must mean the same
# thing on both ends. JavaScript's `||` reads "" as absent and falls back to 8888, so a
# get("...", "8888") here would raise ValueError on the empty string and kill the server
# while Playwright happily waited on 8888 - the two halves of one knob disagreeing.
c.ServerApp.port = int(os.environ.get("JUPYTER_TEST_PORT") or "8888")

# Point the passkey relay dir at a path the Playwright test process can read back, so
# the tests can assert on the file the server writes (the full command -> WebAuthn
# ceremony -> POST -> server-write chain).
#
# Assigned unconditionally rather than setdefault: cli.spec.ts forces this same literal
# into the CLI's environment, so honouring an external override here would move the
# server's writes while the CLI kept polling the old path - every test then failing at
# its timeout with a message blaming the click. One end of a relay cannot be
# overridable while the other is pinned; the override it used to advertise never worked.
os.environ["JLAB_PASSKEY_RELAY_DIR"] = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".tmp-passkey-relay"
)

# Uncomment to set server log level to debug level
# c.ServerApp.log_level = "DEBUG"
