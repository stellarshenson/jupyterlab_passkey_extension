"""The extension's environment variables under the JUPYTERLAB_PASSKEY_ prefix.

A variable is read under its new name first and its old JLAB_PASSKEY_ name second,
so a setting made before the rename still takes effect. The old name is never
written; everything this package sets uses the new name.
"""

import os


def get(suffix):
    """`JUPYTERLAB_PASSKEY_<suffix>`, else `JLAB_PASSKEY_<suffix>`, else None."""
    return os.environ.get(
        "JUPYTERLAB_PASSKEY_" + suffix, os.environ.get("JLAB_PASSKEY_" + suffix)
    )
