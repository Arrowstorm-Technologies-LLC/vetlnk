import dataclasses
import stat

import keyring.backends.fail
from typer.testing import CliRunner

from vetlnk import config, keyfile
from vetlnk.cli import app
from vetlnk.providers.base import REGISTRY

runner = CliRunner()


def _force_no_keyring(monkeypatch):
    monkeypatch.setattr(keyring, "get_keyring", lambda: keyring.backends.fail.Keyring())


def _stub_provider(monkeypatch, provider_id, ok=True, message="Valid key."):
    """Swap a provider's `validate` for a stub, so tests don't hit the network."""
    fake = dataclasses.replace(
        REGISTRY[provider_id], validate=lambda key, ok=ok, message=message: (ok, message)
    )
    monkeypatch.setitem(REGISTRY, provider_id, fake)
    return fake


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


def test_export_keys_empty_when_none_linked(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)

    assert config.export_keys() == {}


def test_export_keys_returns_linked(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)

    config.store_key("virustotal", "vt-secret")
    assert config.export_keys() == {"virustotal": "vt-secret"}


def test_apply_imported_key_unknown_provider():
    ok, message = config.apply_imported_key("not-a-real-provider", "whatever")
    assert ok is False
    assert "unknown" in message.lower()


def test_apply_imported_key_valid(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)
    _stub_provider(monkeypatch, "virustotal")

    ok, backend = config.apply_imported_key("virustotal", "vt-secret")
    assert ok is True
    assert backend == "file"
    assert config.get_key("virustotal") == "vt-secret"


def test_apply_imported_key_invalid_not_stored(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)
    _stub_provider(monkeypatch, "virustotal", ok=False, message="Invalid key.")

    ok, message = config.apply_imported_key("virustotal", "bad-key")
    assert ok is False
    assert message == "Invalid key."
    assert config.get_key("virustotal") is None


def test_export_no_keys_linked(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)

    result = runner.invoke(app, ["config", "export", str(tmp_path / "out.vlnk")])
    assert result.exit_code == 1
    assert "nothing to export" in result.output.lower()


def test_export_rejects_short_passphrase(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)
    _stub_provider(monkeypatch, "virustotal")
    config.store_key("virustotal", "vt-secret")

    result = runner.invoke(
        app, ["config", "export", str(tmp_path / "out.vlnk")], input="short\nshort\n"
    )
    assert result.exit_code == 1
    assert "at least" in result.output.lower()
    assert not (tmp_path / "out.vlnk").exists()


def test_export_import_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)
    _stub_provider(monkeypatch, "virustotal")

    config.store_key("virustotal", "vt-secret-123")

    export_path = tmp_path / "keys.vlnk"
    result = runner.invoke(
        app, ["config", "export", str(export_path)], input="passphrase123\npassphrase123\n"
    )
    assert result.exit_code == 0, result.output
    assert export_path.exists()
    mode = stat.S_IMODE(export_path.stat().st_mode)
    assert mode == 0o600

    # Simulate a fresh device: a different config dir with nothing linked yet.
    device2_dir = tmp_path / "device2"
    monkeypatch.setattr(config, "_CONFIG_DIR", device2_dir)
    monkeypatch.setattr(config, "_CONFIG_FILE", device2_dir / "config.toml")

    result = runner.invoke(app, ["config", "import", str(export_path)], input="passphrase123\n")
    assert result.exit_code == 0, result.output
    assert config.get_key("virustotal") == "vt-secret-123"


def test_import_wrong_passphrase(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)

    path = tmp_path / "keys.vlnk"
    path.write_bytes(keyfile.encrypt_export({"virustotal": "vt-secret"}, "passphrase123"))

    result = runner.invoke(app, ["config", "import", str(path)], input="wrong-passphrase\n")
    assert result.exit_code == 1
    assert "incorrect passphrase" in result.output.lower()
    assert config.get_key("virustotal") is None


def test_import_unknown_provider_skipped_others_imported(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)
    _stub_provider(monkeypatch, "virustotal")

    path = tmp_path / "keys.vlnk"
    path.write_bytes(
        keyfile.encrypt_export(
            {"virustotal": "vt-secret", "made-up-provider": "x"}, "passphrase123"
        )
    )

    result = runner.invoke(app, ["config", "import", str(path)], input="passphrase123\n")
    assert result.exit_code == 0, result.output
    assert "unknown provider" in result.output.lower()
    assert config.get_key("virustotal") == "vt-secret"


def test_import_overwrite_declined_keeps_existing(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)
    _stub_provider(monkeypatch, "virustotal")

    config.store_key("virustotal", "original-key")
    path = tmp_path / "keys.vlnk"
    path.write_bytes(keyfile.encrypt_export({"virustotal": "new-key"}, "passphrase123"))

    result = runner.invoke(app, ["config", "import", str(path)], input="passphrase123\nn\n")
    assert result.exit_code == 0, result.output
    assert config.get_key("virustotal") == "original-key"


def test_import_force_skips_overwrite_prompt(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.toml")
    _force_no_keyring(monkeypatch)
    _stub_provider(monkeypatch, "virustotal")

    config.store_key("virustotal", "original-key")
    path = tmp_path / "keys.vlnk"
    path.write_bytes(keyfile.encrypt_export({"virustotal": "new-key"}, "passphrase123"))

    result = runner.invoke(
        app, ["config", "import", str(path), "--force"], input="passphrase123\n"
    )
    assert result.exit_code == 0, result.output
    assert config.get_key("virustotal") == "new-key"


def test_config_help_commands_render():
    for args in (
        ["config", "--help"],
        ["config", "export", "--help"],
        ["config", "import", "--help"],
    ):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.output
