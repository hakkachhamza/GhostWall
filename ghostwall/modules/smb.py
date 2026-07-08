"""Legacy protocol removal module (SMBv1 + LLMNR)."""

from __future__ import annotations

from typing import Any, Dict

from ghostwall.constants import REG_PATH_LLMNR
from ghostwall.modules.base import SecurityModuleBase
from ghostwall.utils import reg_delete, reg_get, reg_set, run_ps_action, run_ps_json


class LegacyProtocolModule(SecurityModuleBase):
    """Disable SMBv1 and LLMNR broadcast name resolution."""

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__("Legacy Protocol Removal", dry_run=dry_run, destructive=True)

    def _apply(self) -> bool:
        s1 = run_ps_action(
            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
            dry_run=self.dry_run,
        )
        s2 = reg_set(
            self._hive(),
            REG_PATH_LLMNR,
            "EnableMulticast",
            0,
            dry_run=self.dry_run,
        )
        return s1 and s2

    def _check(self) -> bool:
        ok, data = run_ps_json(
            "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object State",
            dry_run=self.dry_run,
        )
        smb_disabled = ok and data is not None and data.get("State") in ("Disabled", 2)
        llmnr = reg_get(self._hive(), REG_PATH_LLMNR, "EnableMulticast")
        return bool(smb_disabled) and llmnr == 0

    def _backup(self) -> Dict[str, Any]:
        ok, data = run_ps_json(
            "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object State",
            dry_run=self.dry_run,
        )
        llmnr = reg_get(self._hive(), REG_PATH_LLMNR, "EnableMulticast")
        return {
            "smb1_state": (data or {}).get("State") if ok else None,
            "llmnr_enable_multicast": llmnr,
        }

    def _restore(self, state: Dict[str, Any]) -> bool:
        ok = True
        if state.get("smb1_state") in ("Enabled", 1):
            ok = (
                run_ps_action(
                    "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
                    dry_run=self.dry_run,
                )
                and ok
            )
        if state.get("llmnr_enable_multicast") is not None:
            ok = (
                reg_set(
                    self._hive(),
                    REG_PATH_LLMNR,
                    "EnableMulticast",
                    state["llmnr_enable_multicast"],
                    dry_run=self.dry_run,
                )
                and ok
            )
        else:
            reg_delete(
                self._hive(),
                REG_PATH_LLMNR,
                "EnableMulticast",
                dry_run=self.dry_run,
            )
        return ok

    @staticmethod
    def _hive() -> int:
        import winreg

        return winreg.HKEY_LOCAL_MACHINE
