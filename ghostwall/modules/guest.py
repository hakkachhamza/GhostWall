"""Built-in Guest account lockdown module."""

from __future__ import annotations

from typing import Any, Dict

from ghostwall.modules.base import SecurityModuleBase
from ghostwall.utils import run_ps_action, run_ps_json


class GuestAccountModule(SecurityModuleBase):
    """Disable the built-in local Guest account."""

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__("Guest Account Lockdown", dry_run=dry_run, destructive=True)

    def _apply(self) -> bool:
        return run_ps_action("Disable-LocalUser -Name 'Guest'", dry_run=self.dry_run)

    def _check(self) -> bool:
        ok, data = run_ps_json(
            "Get-LocalUser -Name 'Guest' | Select-Object Enabled",
            dry_run=self.dry_run,
        )
        return ok and data is not None and data.get("Enabled") is False

    def _backup(self) -> Dict[str, Any]:
        ok, data = run_ps_json(
            "Get-LocalUser -Name 'Guest' | Select-Object Enabled",
            dry_run=self.dry_run,
        )
        return {"enabled": (data or {}).get("Enabled") if ok else None}

    def _restore(self, state: Dict[str, Any]) -> bool:
        if state.get("enabled"):
            return run_ps_action("Enable-LocalUser -Name 'Guest'", dry_run=self.dry_run)
        return run_ps_action("Disable-LocalUser -Name 'Guest'", dry_run=self.dry_run)
