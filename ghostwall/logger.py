"""Logging subsystem for GhostWall.

Supports:
  * Plain-text audit log
  * Plain-text error log
  * ECS-compatible NDJSON log for SIEM ingestion
  * Monitor log for the background watcher
  * Rotating file handlers to keep disk usage bounded
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ghostwall.constants import APP_NAME, APP_VERSION, LOGS_DIR
from ghostwall.utils import get_hostname


# ---------------------------------------------------------------------------
# ECS formatter
# ---------------------------------------------------------------------------
class ECSJsonFormatter(logging.Formatter):
    """Emit one JSON object per line, aligned with Elastic Common Schema.

    Fields emitted:
      * ``@timestamp``
      * ``log.level``
      * ``message``
      * ``host.hostname``
      * ``user.name``
      * ``event.module`` / ``event.dataset``
      * ``event.action`` / ``event.outcome``
      * ``labels.app_version``
    """

    def __init__(self, host_name: str) -> None:
        super().__init__()
        self.host_name = host_name

    def format(self, record: logging.LogRecord) -> str:
        import os

        payload = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "log.level": record.levelname.lower(),
            "message": record.getMessage(),
            "host.hostname": self.host_name,
            "user.name": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
            "event.module": "ghostwall",
            "event.dataset": "ghostwall.audit",
            "event.action": getattr(record, "event_action", "log"),
            "event.outcome": getattr(record, "event_outcome", "unknown"),
            "labels.app_version": APP_VERSION,
        }
        return json.dumps(payload)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------
def ecs_log(
    logger: logging.Logger,
    level: int,
    message: str,
    action: str,
    outcome: str,
) -> None:
    """Attach ECS event.action / event.outcome fields to a log record."""
    logger.log(level, message, extra={"event_action": action, "event_outcome": outcome})


# ---------------------------------------------------------------------------
# Logger factory
# ---------------------------------------------------------------------------
class GhostWallLogger:
    """Configures and owns the application loggers and their file handlers."""

    DEFAULT_MAX_BYTES: int = 5 * 1024 * 1024  # 5 MiB
    DEFAULT_BACKUP_COUNT: int = 5

    def __init__(
        self,
        log_dir: Path = LOGS_DIR,
        timestamp: Optional[str] = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
    ) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.max_bytes = max_bytes
        self.backup_count = backup_count

        self.audit_log_path = self.log_dir / f"audit_{self.timestamp}.log"
        self.error_log_path = self.log_dir / "errors.log"
        self.ecs_log_path = self.log_dir / "ecs.json"
        self.monitor_log_path = self.log_dir / "monitor.log"

        self._logger: Optional[logging.Logger] = None
        self._monitor_logger: Optional[logging.Logger] = None

    # ------------------------------------------------------------------
    # Main application logger
    # ------------------------------------------------------------------
    def get_logger(self) -> logging.Logger:
        """Return the configured main application logger."""
        if self._logger is None:
            self._logger = logging.getLogger("ghostwall")
            self._logger.setLevel(logging.INFO)
            self._logger.handlers.clear()
            self._logger.propagate = False

            self._logger.addHandler(self._rotating_handler(self.audit_log_path))
            self._logger.addHandler(self._rotating_handler(self.error_log_path, level=logging.ERROR))
            self._logger.addHandler(self._ecs_handler(self.ecs_log_path))

            ecs_log(
                self._logger,
                logging.INFO,
                f"{APP_NAME} v{APP_VERSION} logger initialized",
                action="startup",
                outcome="success",
            )
        return self._logger

    # ------------------------------------------------------------------
    # Dedicated monitor logger
    # ------------------------------------------------------------------
    def get_monitor_logger(self) -> logging.Logger:
        """Return a logger tuned for the background monitor process."""
        if self._monitor_logger is None:
            self._monitor_logger = logging.getLogger("ghostwall.monitor")
            self._monitor_logger.setLevel(logging.INFO)
            self._monitor_logger.handlers.clear()
            self._monitor_logger.propagate = False
            self._monitor_logger.addHandler(self._rotating_handler(self.monitor_log_path))
        return self._monitor_logger

    # ------------------------------------------------------------------
    # Handler builders
    # ------------------------------------------------------------------
    def _rotating_handler(
        self,
        path: Path,
        level: int = logging.INFO,
    ) -> logging.handlers.RotatingFileHandler:
        handler = logging.handlers.RotatingFileHandler(
            path,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8",
        )
        handler.setLevel(level)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        return handler

    def _ecs_handler(self, path: Path) -> logging.handlers.RotatingFileHandler:
        handler = logging.handlers.RotatingFileHandler(
            path,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8",
        )
        handler.setFormatter(ECSJsonFormatter(get_hostname()))
        return handler

    # ------------------------------------------------------------------
    # Legacy path accessors for callers expecting old filenames
    # ------------------------------------------------------------------
    @property
    def log_file(self) -> Path:
        """Alias for the main audit log path."""
        return self.audit_log_path

    @property
    def ecs_log_file(self) -> Path:
        """Alias for the ECS JSON log path."""
        return self.ecs_log_path

    def close(self) -> None:
        """Close all handlers owned by GhostWall loggers."""
        for log in (self._logger, self._monitor_logger):
            if log is not None:
                for handler in log.handlers[:]:
                    handler.close()
                    log.removeHandler(handler)
