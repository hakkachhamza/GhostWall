"""JSON configuration and policy loader."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from ghostwall.constants import CONFIG_DIR
from ghostwall.exceptions import ConfigurationError

logger = logging.getLogger("ghostwall")


class ConfigLoader:
    """Load and validate GhostWall JSON configuration files.

    Supported files:
      * ``config/config.json`` — general runtime configuration
      * ``config/policy.json`` — policy / module enablement overrides
    """

    DEFAULT_CONFIG_PATH: Path = CONFIG_DIR / "config.json"
    DEFAULT_POLICY_PATH: Path = CONFIG_DIR / "policy.json"

    def __init__(
        self,
        config_path: Optional[Path] = None,
        policy_path: Optional[Path] = None,
    ) -> None:
        self.config_path = Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
        self.policy_path = Path(policy_path) if policy_path else self.DEFAULT_POLICY_PATH

    def load(self, path: Optional[Path] = None) -> Dict[str, Any]:
        """Load a JSON configuration file."""
        target = Path(path) if path else self.config_path
        if not target.exists():
            raise ConfigurationError(f"Configuration file not found: {target}")
        try:
            with target.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"Invalid JSON in {target}: {exc}") from exc
        except Exception as exc:  # noqa: BLE001
            raise ConfigurationError(f"Failed to read {target}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigurationError(f"Configuration file {target} must contain a JSON object.")
        return data

    def load_policy(self) -> Dict[str, Any]:
        """Load the default policy file if it exists, otherwise an empty dict."""
        if not self.policy_path.exists():
            return {}
        return self.load(self.policy_path)

    def merge(self) -> Dict[str, Any]:
        """Merge ``config.json`` and ``policy.json`` into a single mapping."""
        merged: Dict[str, Any] = {}
        if self.config_path.exists():
            merged.update(self.load(self.config_path))
        if self.policy_path.exists():
            merged.update(self.load(self.policy_path))
        return merged

    def save(self, data: Dict[str, Any], path: Optional[Path] = None) -> Path:
        """Persist a configuration mapping as formatted JSON."""
        target = Path(path) if path else self.config_path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        logger.info("Configuration saved to %s", target)
        return target
