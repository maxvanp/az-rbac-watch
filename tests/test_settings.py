"""Tests pour le module de configuration settings."""

from __future__ import annotations

from pathlib import Path

from az_rbac_watch.config.settings import Settings, load_settings


class TestDefaults:
    """Vérifie les valeurs par défaut."""

    def test_defaults(self) -> None:
        settings = load_settings()
        assert settings.policy is None
        assert settings.format == "console"
        assert settings.quiet is False
        assert settings.no_color is False


class TestLoadFromYaml:
    """Vérifie le chargement depuis un fichier YAML."""

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
        """Fichier inexistant → valeurs par défaut uniquement."""
        settings = load_settings(config_path=Path("/nonexistent/config.yaml"))
        assert settings.format == "console"
        assert settings.policy is None

    def test_empty_yaml_file(self, tmp_path: Path) -> None:
        """Fichier YAML vide → valeurs par défaut."""
        config = tmp_path / "config.yaml"
        config.write_text("")
        settings = load_settings(config_path=config)
        assert settings.format == "console"


class TestEnvVarOverride:
    """Vérifie que les variables d'environnement surchargent les valeurs."""

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
        """La variable d'environnement a priorité sur le fichier YAML."""
        from pytest import MonkeyPatch

        assert isinstance(monkeypatch, MonkeyPatch)
        config = tmp_path / "config.yaml"
        config.write_text("format: json\n")
        monkeypatch.setenv("AZ_RBAC_WATCH_FORMAT", "console")
        settings = load_settings(config_path=config)
        assert settings.format == "console"  # env var wins


class TestConfigEnvVar:
    """Vérifie le chargement via $AZ_RBAC_WATCH_CONFIG."""

    def test_config_env_var(self, tmp_path: Path, monkeypatch: object) -> None:
        from pytest import MonkeyPatch

        assert isinstance(monkeypatch, MonkeyPatch)
        config = tmp_path / "custom.yaml"
        config.write_text("format: json\n")
        monkeypatch.setenv("AZ_RBAC_WATCH_CONFIG", str(config))
        settings = load_settings()
        assert settings.format == "json"


class TestSettingsModel:
    """Vérifie le modèle Pydantic Settings."""

    def test_settings_model_creation(self) -> None:
        s = Settings(policy="/test.yaml", format="json", quiet=True, no_color=True)
        assert s.policy == "/test.yaml"
        assert s.format == "json"
        assert s.quiet is True
        assert s.no_color is True
