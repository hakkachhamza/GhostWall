"""Microsoft Defender hardening modules."""

from __future__ import annotations

from typing import Any, Dict, Optional

from ghostwall.modules.base import SecurityModuleBase
from ghostwall.utils import run_ps_action, run_ps_json


# ---------------------------------------------------------------------------
# Tamper protection helper
# ---------------------------------------------------------------------------
def check_tamper_protection(dry_run: bool = False) -> Optional[bool]:
    """Return True if Defender Tamper Protection is on, False if off, None if unknown."""
    ok, data = run_ps_json(
        "Get-MpComputerStatus | Select-Object IsTamperProtected",
        dry_run=dry_run,
    )
    if not ok or data is None:
        return None
    return bool(data.get("IsTamperProtected"))


# ---------------------------------------------------------------------------
# Controlled Folder Access
# ---------------------------------------------------------------------------
class ControlledFolderAccessModule(SecurityModuleBase):
    """Enable Microsoft Defender Controlled Folder Access (ransomware protection)."""

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__("Ransomware Protection", dry_run=dry_run)

    def _apply(self) -> bool:
        return run_ps_action(
            "Set-MpPreference -EnableControlledFolderAccess Enabled",
            dry_run=self.dry_run,
        )

    def _check(self) -> bool:
        ok, data = run_ps_json(
            "Get-MpPreference | Select-Object EnableControlledFolderAccess",
            dry_run=self.dry_run,
        )
        return ok and data is not None and data.get("EnableControlledFolderAccess") == 1

    def _backup(self) -> Dict[str, Any]:
        ok, data = run_ps_json(
            "Get-MpPreference | Select-Object EnableControlledFolderAccess",
            dry_run=self.dry_run,
        )
        return {"value": (data or {}).get("EnableControlledFolderAccess") if ok else None}

    def _restore(self, state: Dict[str, Any]) -> bool:
        val = state.get("value")
        mapping = {0: "Disabled", 1: "Enabled", 2: "AuditMode"}
        action = mapping.get(val, "Disabled") if isinstance(val, int) else "Disabled"
        return run_ps_action(
            f"Set-MpPreference -EnableControlledFolderAccess {action}",
            dry_run=self.dry_run,
        )


# ---------------------------------------------------------------------------
# Real-time protection
# ---------------------------------------------------------------------------
class DefenderRealtimeModule(SecurityModuleBase):
    """Ensure Microsoft Defender real-time monitoring is enabled."""

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__("Defender Real-Time Protection", dry_run=dry_run)

    def _apply(self) -> bool:
        return run_ps_action(
            "Set-MpPreference -DisableRealtimeMonitoring $false",
            dry_run=self.dry_run,
        )

    def _check(self) -> bool:
        ok, data = run_ps_json(
            "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled",
            dry_run=self.dry_run,
        )
        return ok and data is not None and data.get("RealTimeProtectionEnabled") is True

    def _backup(self) -> Dict[str, Any]:
        ok, data = run_ps_json(
            "Get-MpPreference | Select-Object DisableRealtimeMonitoring",
            dry_run=self.dry_run,
        )
        return {"disabled": (data or {}).get("DisableRealtimeMonitoring") if ok else None}

    def _restore(self, state: Dict[str, Any]) -> bool:
        val = "$true" if state.get("disabled") else "$false"
        return run_ps_action(
            f"Set-MpPreference -DisableRealtimeMonitoring {val}",
            dry_run=self.dry_run,
        )

    def is_tamper_protected(self) -> Optional[bool]:
        """Convenience wrapper for tamper-protection detection."""
        return check_tamper_protection(dry_run=self.dry_run)
