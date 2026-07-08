"""Privacy / telemetry hardening module."""

from __future__ import annotations

from typing import Any, Dict

from ghostwall.constants import REG_PATH_PRIVACY_ADVERTISING, REG_PATH_PRIVACY_TELEMETRY
from ghostwall.modules.base import SecurityModuleBase
from ghostwall.utils import reg_get, reg_set


class PrivacyModule(SecurityModuleBase):
    """Reduce telemetry collection and disable the advertising ID."""

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__("Privacy Hardening", dry_run=dry_run)

    def _apply(self) -> bool:
        s1 = reg_set(
            self._hive(),
            REG_PATH_PRIVACY_TELEMETRY,
            "AllowTelemetry",
            0,
            dry_run=self.dry_run,
        )
        s2 = reg_set(
            self._hive(),
            REG_PATH_PRIVACY_ADVERTISING,
            "Enabled",
            0,
            dry_run=self.dry_run,
        )
        return s1 and s2

    def _check(self) -> bool:
        return reg_get(self._hive(), REG_PATH_PRIVACY_TELEMETRY, "AllowTelemetry") == 0

    def _backup(self) -> Dict[str, Any]:
        return {
            "AllowTelemetry": reg_get(self._hive(), REG_PATH_PRIVACY_TELEMETRY, "AllowTelemetry"),
            "AdvertisingId": reg_get(self._hive(), REG_PATH_PRIVACY_ADVERTISING, "Enabled"),
        }

    def _restore(self, state: Dict[str, Any]) -> bool:
        ok = True
        if state.get("AllowTelemetry") is not None:
            ok = (
                reg_set(
                    self._hive(),
                    REG_PATH_PRIVACY_TELEMETRY,
                    "AllowTelemetry",
                    state["AllowTelemetry"],
                    dry_run=self.dry_run,
                )
                and ok
            )
        if state.get("AdvertisingId") is not None:
            ok = (
                reg_set(
                    self._hive(),
                    REG_PATH_PRIVACY_ADVERTISING,
                    "Enabled",
                    state["AdvertisingId"],
                    dry_run=self.dry_run,
                )
                and ok
            )
        return ok

    @staticmethod
    def _hive() -> int:
        import winreg

        return winreg.HKEY_LOCAL_MACHINE
