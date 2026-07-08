"""Startup persistence manager for GhostWall.

Registers a per-user autostart entry under ``HKCU\\...\\Run`` so the monitor
starts at every login. Using HKCU (rather than HKLM) keeps the entry visible
and removable from Task Manager / msconfig and does not require admin rights.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

from ghostwall.constants import APP_NAME, REG_PATH_STARTUP_RUN
from ghostwall.utils import reg_delete, reg_set

logger = logging.getLogger("ghostwall")


class StartupManager:
    """Install or remove the GhostWall monitor startup entry."""

    VALUE_NAME: str = APP_NAME

    def __init__(self, script_path: Optional[Path] = None) -> None:
        self.script_path = (script_path or self._default_script_path()).resolve()

    @staticmethod
    def _default_script_path() -> Path:
        return Path(sys.argv[0])

    def _command(self) -> str:
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        interpreter = str(pythonw) if pythonw.exists() else sys.executable
        return f'"{interpreter}" "{self.script_path}" --monitor'

    def install(self) -> bool:
        """Create the HKCU Run entry."""
        try:
            import winreg

            success = reg_set(
                winreg.HKEY_CURRENT_USER,
                REG_PATH_STARTUP_RUN,
                self.VALUE_NAME,
                self._command(),
                vtype=winreg.REG_SZ,
            )
            if success:
                logger.info("Startup entry installed: HKCU\\%s\\%s", REG_PATH_STARTUP_RUN, self.VALUE_NAME)
            return success
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to install startup entry: %s", exc)
            return False

    def uninstall(self) -> bool:
        """Remove the HKCU Run entry."""
        try:
            import winreg

            return reg_delete(
                winreg.HKEY_CURRENT_USER,
                REG_PATH_STARTUP_RUN,
                self.VALUE_NAME,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to remove startup entry: %s", exc)
            return False

    def is_installed(self) -> bool:
        """Return True if the startup entry exists."""
        try:
            import winreg

            from ghostwall.utils import reg_get

            return reg_get(winreg.HKEY_CURRENT_USER, REG_PATH_STARTUP_RUN, self.VALUE_NAME) is not None
        except Exception:  # noqa: BLE001
            return False
