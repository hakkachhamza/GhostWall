"""Data Execution Prevention (DEP) hardening module."""

from __future__ import annotations

from typing import Any, Dict

from ghostwall.modules.base import SecurityModuleBase
from ghostwall.utils import run_cmd


class DepModule(SecurityModuleBase):
    """Enable DEP for all processes via BCD (nx AlwaysOn).

    Note:
        ``bcdedit`` does not expose a locale-independent object API, but its
        keyword tokens (e.g. "AlwaysOn") are documented fixed identifiers and
        are not translated display text.
    """

    DEFAULT_NX_VALUE: str = "OptIn"

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__("DEP Enforcement", dry_run=dry_run)

    def _apply(self) -> bool:
        ok, _ = run_cmd("bcdedit /set {current} nx AlwaysOn", dry_run=self.dry_run)
        return ok

    def _check(self) -> bool:
        ok, out = run_cmd("bcdedit /enum {current}", dry_run=self.dry_run)
        return ok and "AlwaysOn" in (out or "")

    def _backup(self) -> Dict[str, Any]:
        ok, out = run_cmd("bcdedit /enum {current}", dry_run=self.dry_run)
        current = "Unknown"
        if ok and out:
            for line in out.splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("nx"):
                    parts = line.split()
                    if parts:
                        current = parts[-1]
        return {"nx_value": current}

    def _restore(self, state: Dict[str, Any]) -> bool:
        val = state.get("nx_value", self.DEFAULT_NX_VALUE)
        ok, _ = run_cmd(f"bcdedit /set {{current}} nx {val}", dry_run=self.dry_run)
        return ok
