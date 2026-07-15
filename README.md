# jupyterlab_passkey_extension

[![GitHub Actions](https://github.com/stellarshenson/jupyterlab_passkey_extension/actions/workflows/build.yml/badge.svg)](https://github.com/stellarshenson/jupyterlab_passkey_extension/actions/workflows/build.yml)
[![npm version](https://img.shields.io/npm/v/jupyterlab_passkey_extension.svg)](https://www.npmjs.com/package/jupyterlab_passkey_extension)
[![PyPI version](https://img.shields.io/pypi/v/jupyterlab-passkey-extension.svg)](https://pypi.org/project/jupyterlab-passkey-extension/)
[![Total PyPI downloads](https://static.pepy.tech/badge/jupyterlab-passkey-extension)](https://pepy.tech/project/jupyterlab-passkey-extension)
[![JupyterLab 4](https://img.shields.io/badge/JupyterLab-4-orange.svg)](https://jupyterlab.readthedocs.io/en/stable/)
[![Brought To You By KOLOMOLO](https://img.shields.io/badge/Brought%20To%20You%20By-KOLOMOLO-00ffff?style=flat)](https://kolomolo.com)
[![Donate PayPal](https://img.shields.io/badge/Donate-PayPal-blue?style=flat)](https://www.paypal.com/donate/?hosted_button_id=B4KPBJDLLXTSA)

Bridge the passkey (WebAuthn) capability of the user's browser or operating system to local clients that have no browser of their own - the JupyterLab terminal and the CLI or API clients running on the Jupyter server. The extension runs the browser-side passkey ceremony and hands the result back to the requesting local process. It is purpose-agnostic and performs no cryptography of its own - every caller supplies its own parameters.

This extension is composed of a Python package named `jupyterlab_passkey_extension`
for the server extension and a NPM package named `jupyterlab_passkey_extension`
for the frontend extension.

## Features

- **Browser passkey ceremonies** - runs `navigator.credentials.get` (assert) and `create` (register), with optional WebAuthn PRF evaluation, inside the top-level JupyterLab page
- **Bridge to local clients** - returns the ceremony result to a terminal, CLI, or API client on the Jupyter server that cannot reach the browser directly
- **Purpose-agnostic** - the caller supplies the operation and all parameters; the extension performs no cryptography and holds no secret of its own

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
