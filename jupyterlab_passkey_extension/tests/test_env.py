"""The environment prefix: the new name first, the old JLAB_PASSKEY_ name second."""

from jupyterlab_passkey_extension import env
from jupyterlab_passkey_extension.vault import service, store

PASS = "correct horse battery staple"


def test_the_new_name_alone_is_read(monkeypatch):
    monkeypatch.delenv("JLAB_PASSKEY_CALLER", raising=False)
    monkeypatch.setenv("JUPYTERLAB_PASSKEY_CALLER", "the new name")
    assert env.get("CALLER") == "the new name"


def test_the_old_name_alone_is_read(monkeypatch):
    monkeypatch.delenv("JUPYTERLAB_PASSKEY_CALLER", raising=False)
    monkeypatch.setenv("JLAB_PASSKEY_CALLER", "the old name")
    assert env.get("CALLER") == "the old name"


def test_the_new_name_wins_when_both_are_set(monkeypatch):
    monkeypatch.setenv("JLAB_PASSKEY_CALLER", "the old name")
    monkeypatch.setenv("JUPYTERLAB_PASSKEY_CALLER", "the new name")
    assert env.get("CALLER") == "the new name"


def test_a_vault_at_the_old_name_path_is_still_found(vault_env, monkeypatch):
    """The setting decides where the vault lives, so the old name must still find it."""
    monkeypatch.delenv("JUPYTERLAB_PASSKEY_VAULT", raising=False)
    path = vault_env / "old-name" / "vault.json"
    monkeypatch.setenv("JLAB_PASSKEY_VAULT", str(path))
    vault = service.VaultService()
    vault.init(PASS)
    assert path.exists()
    assert store.vault_path() == str(path)
    assert vault.status()["initialized"] is True
