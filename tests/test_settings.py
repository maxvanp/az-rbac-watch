"""Tests for the settings configuration module."""

from __future__ import annotations

from pathlib import Path

from az_rbac_watch.config.settings import Settings, load_settings


class TestDefaults:
    """Verify default values."""

    def test_defaults(self) -> None:
        settings = load_settings()
        assert settings.policy is None
        assert settings.format == "console"
        assert settings.quiet is False
        assert settings.no_color is False


class TestLoadFromYaml:
    """Verify loading from a YAML file."""

    def test_load_from_yaml(self, tmp_path: Path) -> None:
        config = tmp_path / "config.yaml"
        config.write_text("policy: /path/to/policy.yaml\nformat: json\n")
        settings = load_settings(config_path=config)
        assert settings.policy == "/path/to/policy.yaml"
        assert settings.format == "json"

    def test_load_quiet_and_no_color(self, tmp_path: Path) -> None:
        config = tmp_path / "config.yaml"
        config.write_text("quiet: true\nno_color: true\n")
        settings = load_settings(config_path=config)
        assert settings.quiet is True
        assert settings.no_color is True

    def test_missing_config_file(self) -> None:
        """Missing file → default values only."""
        settings = load_settings(config_path=Path("/nonexistent/config.yaml"))
        assert settings.format == "console"
        assert settings.policy is None

    def test_empty_yaml_file(self, tmp_path: Path) -> None:
        """Empty YAML file → default values."""
        config = tmp_path / "config.yaml"
        config.write_text("")
        settings = load_settings(config_path=config)
        assert settings.format == "console"


class TestEnvVarOverride:
    """Verify that environment variables override values."""

    def test_env_var_override(self, monkeypatch: object) -> None:
        from pytest import MonkeyPatch

        assert isinstance(monkeypatch, MonkeyPatch)
        monkeypatch.setenv("AZ_RBAC_WATCH_FORMAT", "json")
        settings = load_settings()
        assert settings.format == "json"

    def test_env_var_policy(self, monkeypatch: object) -> None:
        from pytest import MonkeyPatch

        assert isinstance(monkeypatch, MonkeyPatch)
        monkeypatch.setenv("AZ_RBAC_WATCH_POLICY", "/env/policy.yaml")
        settings = load_settings()
        assert settings.policy == "/env/policy.yaml"

    def test_env_var_quiet_true(self, monkeypatch: object) -> None:
        from pytest import MonkeyPatch

        assert isinstance(monkeypatch, MonkeyPatch)
        monkeypatch.setenv("AZ_RBAC_WATCH_QUIET", "1")
        settings = load_settings()
        assert settings.quiet is True

    def test_env_var_no_color_true(self, monkeypatch: object) -> None:
        from pytest import MonkeyPatch

        assert isinstance(monkeypatch, MonkeyPatch)
        monkeypatch.setenv("AZ_RBAC_WATCH_NO_COLOR", "true")
        settings = load_settings()
        assert settings.no_color is True

    def test_env_var_quiet_false(self, monkeypatch: object) -> None:
        from pytest import MonkeyPatch

        assert isinstance(monkeypatch, MonkeyPatch)
        monkeypatch.setenv("AZ_RBAC_WATCH_QUIET", "0")
        settings = load_settings()
        assert settings.quiet is False

    def test_env_var_overrides_file(self, tmp_path: Path, monkeypatch: object) -> None:
        """Environment variable has priority over YAML file."""
        from pytest import MonkeyPatch

        assert isinstance(monkeypatch, MonkeyPatch)
        config = tmp_path / "config.yaml"
        config.write_text("format: json\n")
        monkeypatch.setenv("AZ_RBAC_WATCH_FORMAT", "console")
        settings = load_settings(config_path=config)
        assert settings.format == "console"  # env var wins


class TestConfigEnvVar:
    """Verify loading via $AZ_RBAC_WATCH_CONFIG."""

    def test_config_env_var(self, tmp_path: Path, monkeypatch: object) -> None:
        from pytest import MonkeyPatch

        assert isinstance(monkeypatch, MonkeyPatch)
        config = tmp_path / "custom.yaml"
        config.write_text("format: json\n")
        monkeypatch.setenv("AZ_RBAC_WATCH_CONFIG", str(config))
        settings = load_settings()
        assert settings.format == "json"


class TestSettingsModel:
    """Verify the Pydantic Settings model."""

    def test_settings_model_creation(self) -> None:
        s = Settings(policy="/test.yaml", format="json", quiet=True, no_color=True)
        assert s.policy == "/test.yaml"
        assert s.format == "json"
        assert s.quiet is True
        assert s.no_color is True
