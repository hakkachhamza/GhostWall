"""Custom exceptions for the GhostWall security framework."""

from __future__ import annotations


class GhostWallError(Exception):
    """Base exception for all GhostWall errors."""


class ConfigurationError(GhostWallError):
    """Raised when configuration loading or validation fails."""


class BackupError(GhostWallError):
    """Raised when backup creation, loading, or decryption fails."""


class RestoreError(GhostWallError):
    """Raised when rollback restoration fails."""


class PlatformNotSupportedError(GhostWallError):
    """Raised when a Windows-specific operation is invoked on a non-Windows host."""


class PrivilegeError(GhostWallError):
    """Raised when administrator privileges are required but not present."""


class RemoteOrchestrationError(GhostWallError):
    """Raised when remote WinRM orchestration fails at the transport level."""


class PluginLoadError(GhostWallError):
    """Raised when a plugin cannot be loaded or validated."""


class ModuleExecutionError(GhostWallError):
    """Raised when a hardening module fails unexpectedly."""
