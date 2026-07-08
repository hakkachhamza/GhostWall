"""PowerShell execution policy hardening module."""

from __future__ import annotations

from typing import Any, Dict

from ghostwall.modules.base import SecurityModuleBase
from ghostwall.utils import run_cmd, run_ps_action


class PowerShellPolicyModule(SecurityModuleBase):
    """Set the machine-wide PowerShell execution policy to RemoteSigned."""

    DEFAULT_POLICY: str = "Undefined"
    TARGET_POLICY: str = "RemoteSigned"

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__("PowerShell Script Policy", dry_run=dry_run)

    def _apply(self) -> bool:
        return run_ps_action(
            f"Set-ExecutionPolicy {self.TARGET_POLICY} -Scope LocalMachine -Force",
            dry_run=self.dry_run,
        )

    def _check(self) -> bool:
        ok, out = run_cmd(
            'powershell -NoProfile -Command "Get-ExecutionPolicy -Scope LocalMachine"',
            dry_run=self.dry_run,
        )
        return ok and self.TARGET_POLICY in (out or "")

    def _backup(self) -> Dict[str, Any]:
        ok, out = run_cmd(
            'powershell -NoProfile -Command "Get-ExecutionPolicy -Scope LocalMachine"',
            dry_run=self.dry_run,
        )
        return {"policy": out.strip() if ok else self.DEFAULT_POLICY}

    def _restore(self, state: Dict[str, Any]) -> bool:
        policy = state.get("policy", self.DEFAULT_POLICY) or self.DEFAULT_POLICY
        return run_ps_action(
            f"Set-ExecutionPolicy {policy} -Scope LocalMachine -Force",
            dry_run=self.dry_run,
        )
