"""Load user settings from YAML file and environment variables.

Priority order (lowest to highest):
1. Default values
2. YAML configuration file
3. Environment variables AZ_RBAC_WATCH_*
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

__all__ = ["Settings", "load_settings"]


class Settings(BaseModel):
    """User settings for az-rbac-watch."""

    policy: str | None = None
    format: str = "console"
    quiet: bool = False
    no_color: bool = False


def _default_config_path() -> Path:
    """Default path to the configuration file."""
    return Path.home() / ".config" / "az-rbac-watch" / "config.yaml"


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file and return a dictionary (empty if file does not exist)."""
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        return {}
    return dict(data)


def _apply_env_overrides(values: dict[str, Any]) -> dict[str, Any]:
    """Apply environment variables as overrides."""
    env_mapping: dict[str, str] = {
        "AZ_RBAC_WATCH_POLICY": "policy",
        "AZ_RBAC_WATCH_FORMAT": "format",
        "AZ_RBAC_WATCH_QUIET": "quiet",
        "AZ_RBAC_WATCH_NO_COLOR": "no_color",
    }
    for env_var, field_name in env_mapping.items():
        env_value = os.environ.get(env_var)
        if env_value is not None:
            if field_name in ("quiet", "no_color"):
                values[field_name] = env_value.lower() in ("1", "true", "yes")
            else:
                values[field_name] = env_value
    return values


def load_settings(config_path: Path | None = None) -> Settings:
    """Load settings from configuration file and environment variables.

    Priority order:
    1. Default values from Settings model
    2. YAML file (explicit config_path, or $AZ_RBAC_WATCH_CONFIG, or ~/.config/az-rbac-watch/config.yaml)
    3. Environment variables AZ_RBAC_WATCH_*
    """
    # Determine the configuration file path
    if config_path is None:
        env_config = os.environ.get("AZ_RBAC_WATCH_CONFIG")
        config_path = Path(env_config) if env_config else _default_config_path()

    # Load values from YAML file
    values = _load_yaml(config_path)

    # Apply environment variable overrides
    values = _apply_env_overrides(values)

    return Settings(**values)
