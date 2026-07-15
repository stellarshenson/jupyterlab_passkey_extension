# jupyterlab_passkey_extension

[![GitHub Actions](https://github.com/stellarshenson/jupyterlab_passkey_extension/actions/workflows/build.yml/badge.svg)](https://github.com/stellarshenson/jupyterlab_passkey_extension/actions/workflows/build.yml)
[![npm version](https://img.shields.io/npm/v/jupyterlab_passkey_extension.svg)](https://www.npmjs.com/package/jupyterlab_passkey_extension)
[![PyPI version](https://img.shields.io/pypi/v/jupyterlab-passkey-extension.svg)](https://pypi.org/project/jupyterlab-passkey-extension/)
[![Total PyPI downloads](https://static.pepy.tech/badge/jupyterlab-passkey-extension)](https://pepy.tech/project/jupyterlab-passkey-extension)
[![JupyterLab 4](https://img.shields.io/badge/JupyterLab-4-orange.svg)](https://jupyterlab.readthedocs.io/en/stable/)
[![Brought To You By KOLOMOLO](https://img.shields.io/badge/Brought%20To%20You%20By-KOLOMOLO-00ffff?style=flat)](https://kolomolo.com)
[![Donate PayPal](https://img.shields.io/badge/Donate-PayPal-blue?style=flat)](https://www.paypal.com/donate/?hosted_button_id=B4KPBJDLLXTSA)

Capture passkeys in JupyterLab and expose them through a supporting server API, so internal functionality such as vaults or secrets can authenticate with the passkey (WebAuthn) capability of the user's browser or operating system instead of a stored password.

This extension is composed of a Python package named `jupyterlab_passkey_extension`
for the server extension and a NPM package named `jupyterlab_passkey_extension`
for the frontend extension.

## Features

- **Passkey capture in JupyterLab** - brings the passkey (WebAuthn) capability of the browser or operating system into the JupyterLab frontend
- **Supporting server API** - `jupyter_server` Tornado handlers expose passkey operations to the rest of JupyterLab
- **Secrets and vault foundation** - lets internal features such as vaults or secrets authenticate with a user's passkey rather than a stored credential

## Requirements

- JupyterLab >= 4.0.0

## Install

To install the extension, execute:

```bash
pip install jupyterlab_passkey_extension
```

## Uninstall

To remove the extension, execute:

```bash
pip uninstall jupyterlab_passkey_extension
```
