"""Server configuration for integration tests.

!! Never use this configuration in production because it
opens the server to the world and provide access to JupyterLab
JavaScript objects through the global window variable.
"""
import os

from jupyterlab.galata import configure_jupyter_server

configure_jupyter_server(c)

# Point the passkey relay dir at a path the Playwright test process can read back,
# so the integration test can assert on the one-shot file the server writes (the
# full command -> WebAuthn ceremony -> POST -> server-write chain). setdefault so
# an external override still wins.
os.environ.setdefault(
    "JLAB_PASSKEY_RELAY_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".tmp-passkey-relay"),
)

# Uncomment to set server log level to debug level
# c.ServerApp.log_level = "DEBUG"
