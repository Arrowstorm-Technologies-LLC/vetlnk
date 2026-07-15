import stat

import keyring.backends.fail

from vetlnk import config


def _force_no_keyring(monkeypatch):
    monkeypatch.setattr(keyring, "get_keyring", lambda: keyring.backends.fail.Keyring())


def test_file_fallback_used_when_no_keyring(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)

    backend = config.store_key("virustotal", "dummy-key")
    assert backend == "file"
    assert config.get_key("virustotal") == "dummy-key"


def test_file_fallback_has_0600_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)

    config.store_key("virustotal", "dummy-key")
    mode = stat.S_IMODE((tmp_path / "config.toml").stat().st_mode)
    assert mode == 0o600


def test_unlink_removes_key(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)

    config.store_key("virustotal", "dummy-key")
    assert config.get_key("virustotal") is not None
    config.unlink_key("virustotal")
    assert config.get_key("virustotal") is None


def test_status_reflects_linked_state(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)

    assert config.get_status("virustotal").linked is False
    config.store_key("virustotal", "dummy-key")
    status = config.get_status("virustotal")
    assert status.linked is True
    assert status.backend == "file"
