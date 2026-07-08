"""GhostWall plugin loader.

Discovers user-supplied hardening modules placed in the ``plugins/`` directory.
A plugin is a Python file whose module-level ``register()`` function returns a
class (or list of classes) inheriting from :class:`ghostwall.core.SecurityModule`.
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
from pathlib import Path
from typing import List, Type

from ghostwall.constants import PLUGINS_DIR
from ghostwall.core import SecurityModule
from ghostwall.exceptions import PluginLoadError

logger = logging.getLogger("ghostwall")


class PluginLoader:
    """Discover and import plugin modules."""

    def __init__(self, plugins_dir: Path = PLUGINS_DIR) -> None:
        self.plugins_dir = Path(plugins_dir)
        self.plugins_dir.mkdir(parents=True, exist_ok=True)

    def discover(self) -> List[Type[SecurityModule]]:
        """Return all plugin module classes found in the plugins directory."""
        classes: List[Type[SecurityModule]] = []
        for file_path in sorted(self.plugins_dir.glob("*.py")):
            if file_path.name.startswith("_"):
                continue
            try:
                classes.extend(self._load_plugin(file_path))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to load plugin '%s': %s", file_path, exc)
        return classes

    def _load_plugin(self, file_path: Path) -> List[Type[SecurityModule]]:
        spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
        if spec is None or spec.loader is None:
            raise PluginLoadError(f"Could not create module spec for {file_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        register_fn = getattr(module, "register", None)
        if register_fn is None:
            raise PluginLoadError(f"Plugin {file_path} has no register() function")
        if not callable(register_fn):
            raise PluginLoadError(f"Plugin {file_path} register attribute is not callable")

        result = register_fn()
        if not isinstance(result, list):
            result = [result]

        valid_classes: List[Type[SecurityModule]] = []
        for item in result:
            if inspect.isclass(item) and issubclass(item, SecurityModule):
                valid_classes.append(item)
            else:
                logger.warning("Plugin %s returned non-SecurityModule item: %s", file_path, item)
        return valid_classes
