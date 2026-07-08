"""Backup / rollback engine for GhostWall.

Captures the pre-change state of every hardening module into a single JSON
file (optionally Fernet-encrypted) and restores from it later.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, cast

from ghostwall.constants import BACKUPS_DIR, ENV_BACKUP_KEY
from ghostwall.exceptions import BackupError

try:
    from cryptography.fernet import Fernet  # type: ignore
except ImportError:  # pragma: no cover
    Fernet = None  # type: ignore

logger = logging.getLogger("ghostwall")


# ---------------------------------------------------------------------------
# Backup metadata
# ---------------------------------------------------------------------------
@dataclass
class BackupMetadata:
    """Lightweight container for backup provenance information."""

    host: str
    timestamp: str
    app_version: str
    encrypted: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "timestamp": self.timestamp,
            "app_version": self.app_version,
            "encrypted": self.encrypted,
            **self.extra,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BackupMetadata":
        extra = {k: v for k, v in data.items() if k not in ("host", "timestamp", "app_version", "encrypted")}
        return cls(
            host=data.get("host", "unknown"),
            timestamp=data.get("timestamp", "unknown"),
            app_version=data.get("app_version", "unknown"),
            encrypted=data.get("encrypted", False),
            extra=extra,
        )


# ---------------------------------------------------------------------------
# Backup manager
# ---------------------------------------------------------------------------
class BackupManager:
    """Serialize / deserialize hardening state with optional encryption."""

    def __init__(
        self,
        backup_path: Optional[Path] = None,
        encrypt: bool = False,
    ) -> None:
        self.backup_path = Path(backup_path) if backup_path else self._default_path()
        self.encrypt = encrypt and Fernet is not None
        self._warned_fallback = False

    @staticmethod
    def _default_path() -> Path:
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return BACKUPS_DIR / f"ghostwall_backup_{timestamp}.json"

    # ------------------------------------------------------------------
    # Key handling
    # ------------------------------------------------------------------
    def _get_or_create_key(self) -> bytes:
        env_key = os.environ.get(ENV_BACKUP_KEY)
        if env_key:
            return env_key.encode()
        if Fernet is None:
            raise BackupError("Encryption requested but 'cryptography' is not installed.")
        new_key = Fernet.generate_key()
        # The caller is responsible for surfacing this to the user.
        os.environ[ENV_BACKUP_KEY] = new_key.decode()
        return new_key

    def _load_key(self) -> bytes:
        env_key = os.environ.get(ENV_BACKUP_KEY)
        if not env_key:
            raise BackupError(
                f"Backup appears encrypted. Set the {ENV_BACKUP_KEY} environment "
                "variable to the key shown when the backup was created."
            )
        return env_key.encode()

    # ------------------------------------------------------------------
    # Save / load
    # ------------------------------------------------------------------
    def save(self, data: Dict[str, Any]) -> Path:
        """Persist ``data`` to :attr:`backup_path`, encrypting if configured."""
        raw = json.dumps(data, indent=2).encode("utf-8")
        if self.encrypt:
            if Fernet is None:
                raise BackupError("Encryption requested but 'cryptography' is not installed.")
            key = self._get_or_create_key()
            raw = Fernet(key).encrypt(raw)
        self.backup_path.write_bytes(raw)
        return self.backup_path

    def load(self, path: Optional[Path] = None) -> Dict[str, Any]:
        """Load backup data from *path* (or :attr:`backup_path`)."""
        target = Path(path) if path else self.backup_path
        if not target.exists():
            raise BackupError(f"Backup file not found: {target}")
        raw = target.read_bytes()
        try:
            return cast(Dict[str, Any], json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            if Fernet is None:
                raise BackupError("Backup appears encrypted but 'cryptography' is not installed.")
            try:
                decrypted = Fernet(self._load_key()).decrypt(raw)
            except Exception as exc:
                raise BackupError(f"Failed to decrypt backup: {exc}") from exc
            return cast(Dict[str, Any], json.loads(decrypted.decode("utf-8")))

    # ------------------------------------------------------------------
    # High-level build / restore helpers used by the engine
    # ------------------------------------------------------------------
    def build_backup(
        self,
        modules: list,
        host: str,
        timestamp: str,
        app_version: str,
    ) -> Dict[str, Any]:
        """Capture the current state of every module."""
        backup_data: Dict[str, Any] = {}
        for module in modules:
            try:
                backup_data[module.name] = module.backup()
            except Exception as exc:  # noqa: BLE001
                backup_data[module.name] = {}
                logger.error("Backup capture failed for '%s': %s", module.name, exc)
        backup_data["_meta"] = BackupMetadata(
            host=host,
            timestamp=timestamp,
            app_version=app_version,
            encrypted=self.encrypt,
        ).to_dict()
        return backup_data

    def restore_backup(
        self,
        modules: list,
        data: Dict[str, Any],
    ) -> Dict[str, bool]:
        """Restore every module from the supplied backup data."""
        results: Dict[str, bool] = {}
        for module in modules:
            state = data.get(module.name)
            if state is None:
                results[module.name] = False
                continue
            try:
                results[module.name] = module.restore(state)
            except Exception as exc:  # noqa: BLE001
                logger.error("Restore failed for '%s': %s", module.name, exc)
                results[module.name] = False
        return results

    # ------------------------------------------------------------------
    # Encryption fallback warning
    # ------------------------------------------------------------------
    def warn_if_encryption_unavailable(self) -> None:
        """Log a one-time warning if encryption was requested but unavailable."""
        if self._warned_fallback:
            return
        if self.encrypt is False and Fernet is None:
            logger.warning(
                "cryptography package not installed — falling back to plaintext JSON backup. "
                "Install with `pip install cryptography` for encrypted backups."
            )
            self._warned_fallback = True
