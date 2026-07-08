"""Core domain models and base classes for GhostWall.

This module contains the abstract contract every hardening module must
implement, plus shared data structures used across the engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ghostwall.constants import FRAMEWORK_LABELS, MODULE_DESCRIPTIONS, MODULE_FRAMEWORKS


# ---------------------------------------------------------------------------
# Module result
# ---------------------------------------------------------------------------
@dataclass
class ModuleResult:
    """Outcome of applying or checking a hardening module."""

    success: bool = False
    verified: bool = False
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Security module base class
# ---------------------------------------------------------------------------
class SecurityModule(ABC):
    """Abstract base class for a single hardening control.

    Concrete subclasses implement :meth:`apply`, :meth:`check`, :meth:`backup`,
    and :meth:`restore`. They also declare whether applying the control is
    destructive (higher impact) and map it to compliance frameworks.

    Args:
        name: Human-readable control name.
        description: One-line description of what the control does.
        destructive: Whether applying the control may disrupt normal usage.
        framework_mapping: Mapping of framework names to lists of references.
    """

    def __init__(
        self,
        name: str,
        description: Optional[str] = None,
        destructive: bool = False,
        framework_mapping: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        self.name = name
        self.description = description or MODULE_DESCRIPTIONS.get(name, "")
        self.destructive = destructive
        self.framework_mapping = framework_mapping or MODULE_FRAMEWORKS.get(name, {})
        self.result: ModuleResult = ModuleResult()

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------
    @abstractmethod
    def apply(self) -> bool:
        """Apply the hardening control. Return True on success."""

    @abstractmethod
    def check(self) -> bool:
        """Return True if the control is currently enforced."""

    @abstractmethod
    def backup(self) -> Dict[str, Any]:
        """Capture the current state so it can be restored later."""

    @abstractmethod
    def restore(self, state: Dict[str, Any]) -> bool:
        """Restore the control to the state captured by :meth:`backup`."""

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def framework_str(self) -> str:
        """Return a formatted framework-mapping string for display."""
        parts = []
        for framework in FRAMEWORK_LABELS:
            refs = ", ".join(self.framework_mapping.get(framework, []))
            if refs:
                parts.append(f"{framework.upper()} {refs}")
        return " | ".join(parts) if parts else "—"

    def reset_result(self) -> None:
        """Clear the transient result/error state."""
        self.result = ModuleResult()


# ---------------------------------------------------------------------------
# Legacy dataclass adapter
# ---------------------------------------------------------------------------
@dataclass
class SecurityModuleDescriptor:
    """Old-style dataclass used internally for some CLI serialization paths.

    Prefer :class:`SecurityModule` for new code. This descriptor exists to
    maintain compatibility with callers that expected the previous dataclass.
    """

    name: str
    description: str
    apply_fn: Callable[[], bool]
    check_fn: Callable[[], bool]
    backup_fn: Callable[[], Dict[str, Any]]
    restore_fn: Callable[[Dict[str, Any]], bool]
    framework_mapping: Dict[str, List[str]] = field(default_factory=dict)
    destructive: bool = False
    result: Optional[bool] = None
    error: Optional[str] = None

    def framework_str(self) -> str:
        cis = ", ".join(self.framework_mapping.get("cis", []))
        mitre = ", ".join(self.framework_mapping.get("mitre", []))
        nist = ", ".join(self.framework_mapping.get("nist", []))
        return f"CIS {cis} | MITRE {mitre} | NIST {nist}"
