"""A password vault kept by the passkey bridge.

The Jupyter server is the only process that opens the vault: it unwraps the data key
at unlock, keeps it in a key holder (see `holders`) for the unlock duration, and
serves the CLI, the Python API and the panel over its authenticated REST API.

    from jupyterlab_passkey_extension.vault import Vault
    token = Vault().get("github/api")          # unlocks with the passkey if locked
"""


from .client import Vault

__all__ = ["Vault"]
