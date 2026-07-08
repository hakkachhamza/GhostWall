"""Local account password policy hardening module."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from ghostwall.constants import (
    DEFAULT_LOCKOUT_THRESHOLD,
    DEFAULT_PASSWORD_MAX_AGE,
    DEFAULT_PASSWORD_MIN_LENGTH,
)
from ghostwall.modules.base import SecurityModuleBase
from ghostwall.utils import run_cmd


class PasswordPolicyModule(SecurityModuleBase):
    """Enforce minimum length, maximum age, and lockout threshold."""

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__("Password Policy", dry_run=dry_run, destructive=True)
        self._min_length = DEFAULT_PASSWORD_MIN_LENGTH
        self._max_age = DEFAULT_PASSWORD_MAX_AGE
        self._lockout = DEFAULT_LOCKOUT_THRESHOLD
        self._secedit_tmp: Optional[Path] = None

    def _apply(self) -> bool:
        ok = True
        for cmd in (
            f"net accounts /minpwlen:{self._min_length}",
            f"net accounts /maxpwage:{self._max_age}",
            f"net accounts /lockoutthreshold:{self._lockout}",
        ):
            success, _ = run_cmd(cmd, dry_run=self.dry_run)
            ok = ok and success
        return ok

    def _check(self) -> bool:
        vals = self._secedit_export()
        if not vals:
            return False
        try:
            return int(vals.get("MinimumPasswordLength", 0)) >= self._min_length
        except ValueError:
            return False

    def _backup(self) -> Dict[str, Any]:
        vals = self._secedit_export() or {}
        return {
            "MinimumPasswordLength": vals.get("MinimumPasswordLength"),
            "MaximumPasswordAge": vals.get("MaximumPasswordAge"),
            "LockoutBadCount": vals.get("LockoutBadCount"),
        }

    def _restore(self, state: Dict[str, Any]) -> bool:
        ok = True
        if state.get("MinimumPasswordLength"):
            success, _ = run_cmd(
                f"net accounts /minpwlen:{state['MinimumPasswordLength']}",
                dry_run=self.dry_run,
            )
            ok = ok and success
        if state.get("MaximumPasswordAge"):
            success, _ = run_cmd(
                f"net accounts /maxpwage:{state['MaximumPasswordAge']}",
                dry_run=self.dry_run,
            )
            ok = ok and success
        if state.get("LockoutBadCount"):
            success, _ = run_cmd(
                f"net accounts /lockoutthreshold:{state['LockoutBadCount']}",
                dry_run=self.dry_run,
            )
            ok = ok and success
        return ok

    def _secedit_export(self) -> Optional[Dict[str, str]]:
        """Export local security policy to a temporary INF and parse key values."""
        from datetime import datetime

        tmp = Path(f"_secedit_tmp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.inf")
        self._secedit_tmp = tmp
        ok, _ = run_cmd(f'secedit /export /cfg "{tmp}" /quiet', dry_run=self.dry_run)
        if self.dry_run:
            # In dry-run mode we did not create the file; return empty mapping.
            return {}
        if not ok or not tmp.exists():
            return None
        values: Dict[str, str] = {}
        try:
            for line in tmp.read_text(encoding="utf-16", errors="ignore").splitlines():
                if "=" in line:
                    key, _, value = line.partition("=")
                    values[key.strip()] = value.strip()
        finally:
            tmp.unlink(missing_ok=True)
            self._secedit_tmp = None
        return values
