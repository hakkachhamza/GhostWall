"""Autorun / Autoplay disable module."""

from __future__ import annotations

from typing import Any, Dict

from ghostwall.constants import REG_PATH_AUTORUN_POLICIES
from ghostwall.modules.base import SecurityModuleBase
from ghostwall.utils import reg_delete, reg_get, reg_set


class AutorunModule(SecurityModuleBase):
    """Disable Autorun and Autoplay for all drives."""

    AUTO_RUN_DISABLE_ALL: int = 0xFF

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__("Autorun/Autoplay Disable", dry_run=dry_run)

    def _apply(self) -> bool:
        return reg_set(
            self._hive(),
            REG_PATH_AUTORUN_POLICIES,
            "NoDriveTypeAutoRun",
            self.AUTO_RUN_DISABLE_ALL,
            dry_run=self.dry_run,
        )

    def _check(self) -> bool:
        return reg_get(self._hive(), REG_PATH_AUTORUN_POLICIES, "NoDriveTypeAutoRun") == self.AUTO_RUN_DISABLE_ALL

    def _backup(self) -> Dict[str, Any]:
        return {
            "NoDriveTypeAutoRun": reg_get(self._hive(), REG_PATH_AUTORUN_POLICIES, "NoDriveTypeAutoRun"),
        }

    def _restore(self, state: Dict[str, Any]) -> bool:
        val = state.get("NoDriveTypeAutoRun")
        if val is None:
            return reg_delete(
                self._hive(),
                REG_PATH_AUTORUN_POLICIES,
                "NoDriveTypeAutoRun",
                dry_run=self.dry_run,
            )
        return reg_set(
            self._hive(),
            REG_PATH_AUTORUN_POLICIES,
            "NoDriveTypeAutoRun",
            val,
            dry_run=self.dry_run,
        )

    @staticmethod
    def _hive() -> int:
        import winreg

        return winreg.HKEY_LOCAL_MACHINE
