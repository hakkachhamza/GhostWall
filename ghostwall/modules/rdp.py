"""Remote Desktop Protocol (RDP) lockdown module."""

from __future__ import annotations

from typing import Any, Dict

from ghostwall.constants import REG_PATH_TERMINAL_SERVER
from ghostwall.modules.base import SecurityModuleBase
from ghostwall.utils import reg_get, reg_set, run_ps_action, run_ps_json


class RdpModule(SecurityModuleBase):
    """Disable RDP connections and the TermService."""

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__("Remote Desktop Lockdown", dry_run=dry_run, destructive=True)

    def _apply(self) -> bool:
        s1 = run_ps_action(
            "(Get-WmiObject -Namespace root/CIMV2/TerminalServices "
            "-Class Win32_TerminalServiceSetting).SetAllowTSConnections(0,1)",
            dry_run=self.dry_run,
        )
        s2 = reg_set(
            self._hive(),
            REG_PATH_TERMINAL_SERVER,
            "fDenyTSConnections",
            1,
            dry_run=self.dry_run,
        )
        s3 = run_ps_action(
            "Set-Service -Name TermService -StartupType Disabled",
            dry_run=self.dry_run,
        )
        return s1 and s2 and s3

    def _check(self) -> bool:
        return reg_get(self._hive(), REG_PATH_TERMINAL_SERVER, "fDenyTSConnections") == 1

    def _backup(self) -> Dict[str, Any]:
        deny = reg_get(self._hive(), REG_PATH_TERMINAL_SERVER, "fDenyTSConnections")
        ok, svc = run_ps_json(
            "Get-Service TermService | Select-Object StartType",
            dry_run=self.dry_run,
        )
        return {
            "fDenyTSConnections": deny,
            "service_start_type": (svc or {}).get("StartType") if ok else None,
        }

    def _restore(self, state: Dict[str, Any]) -> bool:
        ok1 = True
        val = state.get("fDenyTSConnections")
        if val is not None:
            ok1 = reg_set(
                self._hive(),
                REG_PATH_TERMINAL_SERVER,
                "fDenyTSConnections",
                val,
                dry_run=self.dry_run,
            )
        start_type = state.get("service_start_type") or "Manual"
        ok2 = run_ps_action(
            f"Set-Service -Name TermService -StartupType {start_type}",
            dry_run=self.dry_run,
        )
        return ok1 and ok2

    @staticmethod
    def _hive() -> int:
        import winreg

        return winreg.HKEY_LOCAL_MACHINE
