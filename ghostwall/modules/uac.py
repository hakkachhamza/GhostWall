"""User Account Control (UAC) maximization module."""

from __future__ import annotations

from typing import Any, Dict

from ghostwall.constants import REG_PATH_UAC_POLICIES
from ghostwall.modules.base import SecurityModuleBase
from ghostwall.utils import reg_get, reg_set


class UacModule(SecurityModuleBase):
    """Set UAC to Always Notify and ensure LUA is enabled."""

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__("UAC Maximization", dry_run=dry_run)

    def _apply(self) -> bool:
        s1 = reg_set(
            self._hive(),
            REG_PATH_UAC_POLICIES,
            "ConsentPromptBehaviorAdmin",
            4,
            dry_run=self.dry_run,
        )
        s2 = reg_set(
            self._hive(),
            REG_PATH_UAC_POLICIES,
            "EnableLUA",
            1,
            dry_run=self.dry_run,
        )
        return s1 and s2

    def _check(self) -> bool:
        return reg_get(self._hive(), REG_PATH_UAC_POLICIES, "ConsentPromptBehaviorAdmin") == 4

    def _backup(self) -> Dict[str, Any]:
        return {
            "ConsentPromptBehaviorAdmin": reg_get(self._hive(), REG_PATH_UAC_POLICIES, "ConsentPromptBehaviorAdmin"),
            "EnableLUA": reg_get(self._hive(), REG_PATH_UAC_POLICIES, "EnableLUA"),
        }

    def _restore(self, state: Dict[str, Any]) -> bool:
        ok = True
        if state.get("ConsentPromptBehaviorAdmin") is not None:
            ok = (
                reg_set(
                    self._hive(),
                    REG_PATH_UAC_POLICIES,
                    "ConsentPromptBehaviorAdmin",
                    state["ConsentPromptBehaviorAdmin"],
                    dry_run=self.dry_run,
                )
                and ok
            )
        if state.get("EnableLUA") is not None:
            ok = (
                reg_set(
                    self._hive(),
                    REG_PATH_UAC_POLICIES,
                    "EnableLUA",
                    state["EnableLUA"],
                    dry_run=self.dry_run,
                )
                and ok
            )
        return ok

    @staticmethod
    def _hive() -> int:
        import winreg

        return winreg.HKEY_LOCAL_MACHINE
