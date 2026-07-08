"""Windows Firewall hardening module."""

from __future__ import annotations

from typing import Any, Dict

from ghostwall.modules.base import SecurityModuleBase
from ghostwall.utils import run_ps_action, run_ps_json


class FirewallModule(SecurityModuleBase):
    """Enforce Windows Firewall on all profiles with safe defaults."""

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__("Firewall Enforcement", dry_run=dry_run)

    def _apply(self) -> bool:
        return run_ps_action(
            "Set-NetFirewallProfile -All -Enabled True " "-DefaultInboundAction Block -DefaultOutboundAction Allow",
            dry_run=self.dry_run,
        )

    def _check(self) -> bool:
        ok, data = run_ps_json(
            "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction",
            dry_run=self.dry_run,
        )
        if not ok or data is None:
            return False
        rows = data if isinstance(data, list) else [data]
        return all(row.get("Enabled") in (1, True) and row.get("DefaultInboundAction") in (4, "Block") for row in rows)

    def _backup(self) -> Dict[str, Any]:
        ok, data = run_ps_json(
            "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction",
            dry_run=self.dry_run,
        )
        return {"profiles": data if ok else None}

    def _restore(self, state: Dict[str, Any]) -> bool:
        profiles = state.get("profiles") or []
        profiles = profiles if isinstance(profiles, list) else [profiles]
        ok = True
        for profile in profiles:
            name = profile.get("Name")
            enabled = "True" if profile.get("Enabled") in (1, True) else "False"
            in_action = "Block" if profile.get("DefaultInboundAction") in (4, "Block") else "Allow"
            out_action = "Block" if profile.get("DefaultOutboundAction") in (4, "Block") else "Allow"
            ok = (
                run_ps_action(
                    f"Set-NetFirewallProfile -Name '{name}' -Enabled {enabled} "
                    f"-DefaultInboundAction {in_action} -DefaultOutboundAction {out_action}",
                    dry_run=self.dry_run,
                )
                and ok
            )
        return ok
