"""Base class for GhostWall hardening modules."""

from __future__ import annotations

import logging
from abc import abstractmethod
from typing import Any, Dict, List, Optional

from ghostwall.constants import MODULE_DESCRIPTIONS, MODULE_FRAMEWORKS
from ghostwall.core import SecurityModule

logger = logging.getLogger("ghostwall")


class SecurityModuleBase(SecurityModule):
    """Convenience base class implementing common module bookkeeping.

    Subclasses only need to implement :meth:`_apply`, :meth:`_check`,
    :meth:`_backup`, and :meth:`_restore`. The base class handles result
    tracking, dry-run propagation, and framework description lookups.

    Args:
        name: Human-readable control name.
        dry_run: If True, no system changes are made.
        description: Optional override for the module description.
        destructive: Whether the control is higher-impact.
        framework_mapping: Optional override for compliance mappings.
    """

    def __init__(
        self,
        name: str,
        dry_run: bool = False,
        description: Optional[str] = None,
        destructive: bool = False,
        framework_mapping: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        super().__init__(
            name=name,
            description=description or MODULE_DESCRIPTIONS.get(name, ""),
            destructive=destructive,
            framework_mapping=framework_mapping or MODULE_FRAMEWORKS.get(name, {}),
        )
        self.dry_run = dry_run

    # ------------------------------------------------------------------
    # Public interface (wraps subclass implementations)
    # ------------------------------------------------------------------
    def apply(self) -> bool:
        """Apply the control and record the result."""
        self.reset_result()
        try:
            success = self._apply()
            self.result.success = success
            return success
        except Exception as exc:  # noqa: BLE001
            self.result.success = False
            self.result.error = str(exc)
            logger.error("Module '%s' apply failed: %s", self.name, exc)
            return False

    def check(self) -> bool:
        """Check the control state and record the result."""
        try:
            verified = self._check()
            self.result.verified = verified
            return verified
        except Exception as exc:  # noqa: BLE001
            self.result.verified = False
            self.result.error = str(exc)
            logger.error("Module '%s' check failed: %s", self.name, exc)
            return False

    def backup(self) -> Dict[str, Any]:
        """Capture current state."""
        try:
            return self._backup()
        except Exception as exc:  # noqa: BLE001
            logger.error("Module '%s' backup failed: %s", self.name, exc)
            return {}

    def restore(self, state: Dict[str, Any]) -> bool:
        """Restore from a previously captured state."""
        try:
            return self._restore(state)
        except Exception as exc:  # noqa: BLE001
            logger.error("Module '%s' restore failed: %s", self.name, exc)
            return False

    # ------------------------------------------------------------------
    # Subclass contract
    # ------------------------------------------------------------------
    @abstractmethod  # noqa: F821
    def _apply(self) -> bool:
        """Concrete apply logic."""

    @abstractmethod  # noqa: F821
    def _check(self) -> bool:
        """Concrete check logic."""

    @abstractmethod  # noqa: F821
    def _backup(self) -> Dict[str, Any]:
        """Concrete backup logic."""

    @abstractmethod  # noqa: F821
    def _restore(self, state: Dict[str, Any]) -> bool:
        """Concrete restore logic."""
