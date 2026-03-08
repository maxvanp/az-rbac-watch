"""Chargement des paramètres utilisateur depuis fichier YAML et variables d'environnement.

Ordre de priorité (du plus faible au plus fort) :
1. Valeurs par défaut
2. Fichier de configuration YAML
3. Variables d'environnement AZ_RBAC_WATCH_*
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

__all__ = ["Settings", "load_settings"]


class Settings(BaseModel):
    """Paramètres utilisateur pour az-rbac-watch."""

    policy: str | None = None
    format: str = "console"
    quiet: bool = False
    no_color: bool = False


def _default_config_path() -> Path:
    """Chemin par défaut du fichier de configuration."""
    return Path.home() / ".config" / "az-rbac-watch" / "config.yaml"


def _load_yaml(path: Path) -> dict[str, Any]:
    """Charge un fichier YAML et retourne un dictionnaire (vide si le fichier n'existe pas)."""
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        return {}
    return dict(data)


def _apply_env_overrides(values: dict[str, Any]) -> dict[str, Any]:
    """Applique les variables d'environnement comme surcharges."""
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
    """Charge les paramètres depuis le fichier de configuration et les variables d'environnement.

    Ordre de priorité :
    1. Valeurs par défaut du modèle Settings
    2. Fichier YAML (config_path explicite, ou $AZ_RBAC_WATCH_CONFIG, ou ~/.config/az-rbac-watch/config.yaml)
    3. Variables d'environnement AZ_RBAC_WATCH_*
    """
    # Déterminer le chemin du fichier de configuration
    if config_path is None:
        env_config = os.environ.get("AZ_RBAC_WATCH_CONFIG")
        config_path = Path(env_config) if env_config else _default_config_path()

    # Charger les valeurs depuis le fichier YAML
    values = _load_yaml(config_path)

    # Appliquer les surcharges des variables d'environnement
    values = _apply_env_overrides(values)

    return Settings(**values)
