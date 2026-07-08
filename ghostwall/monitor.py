"""Background security monitor for GhostWall.

The monitor runs as a long-lived foreground process (typically launched by the
startup entry at login). It polls for:

  * Local password changes (via ``net user`` output)
  * New Windows Defender malware detections
  * Configuration drift (previously secure controls becoming vulnerable)

Each finding triggers exactly one toast notification. State is persisted to
disk so restarts do not re-fire stale alerts.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, cast

from rich.console import Console
from rich.panel import Panel

from ghostwall.constants import APP_NAME, MONITOR_POLL_SECONDS
from ghostwall.logger import GhostWallLogger
from ghostwall.notifications import ToastNotifier
from ghostwall.utils import run_cmd, run_ps_json

logger = logging.getLogger("ghostwall.monitor")


class SecurityMonitor:
    """Long-running background watcher.

    Args:
        engine: The local :class:`SecurityEngine` whose modules will be checked
            for drift.
        poll_seconds: Interval between poll cycles.
        state_dir: Directory where monitor state is persisted.
    """

    STATE_FILE_NAME: str = "monitor_state.json"

    def __init__(
        self,
        engine: Any,
        poll_seconds: int = MONITOR_POLL_SECONDS,
        state_dir: Optional[Path] = None,
        console: Optional[Console] = None,
    ) -> None:
        self.engine = engine
        self.poll_seconds = poll_seconds
        self.state_dir = Path(state_dir or self._default_state_dir())
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / self.STATE_FILE_NAME
        self.state = self._load_state()
        self.toaster = ToastNotifier(console=console)
        self.logger = GhostWallLogger().get_monitor_logger()
        self.console = console or Console()

    @staticmethod
    def _default_state_dir() -> Path:
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / APP_NAME
        return Path.home() / ".ghostwall"

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------
    def _load_state(self) -> Dict[str, Any]:
        try:
            return cast(Dict[str, Any], json.loads(self.state_file.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            return {
                "password_last_set": None,
                "last_threat_time": None,
                "secure_state": {},
            }

    def _save_state(self) -> None:
        try:
            self.state_file.write_text(json.dumps(self.state), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            self.logger.error("Monitor: failed to save state: %s", exc)

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------
    def _check_password_change(self) -> None:
        username = os.environ.get("USERNAME") or os.environ.get("USER")
        if not username:
            return
        ok, out = run_cmd(f"net user {username}")
        if not ok or not out:
            return
        last_set: Optional[str] = None
        for line in out.splitlines():
            if line.strip().lower().startswith("password last set"):
                last_set = line.split(None, 3)[-1].strip()
                break
        if last_set is None:
            return
        previous = self.state.get("password_last_set")
        if previous is not None and previous != last_set:
            self.toaster.notify(
                "Password changed",
                f"The Windows password for '{username}' was changed on {last_set}. "
                "If this wasn't you, secure the account now.",
            )
            self.logger.info("Password change detected for '%s'", username)
        self.state["password_last_set"] = last_set

    def _check_new_threats(self) -> None:
        ok, data = run_ps_json("Get-MpThreatDetection | Select-Object ThreatID,InitialDetectionTime")
        if not ok or not data:
            return
        rows = data if isinstance(data, list) else [data]
        last_seen = self.state.get("last_threat_time")
        newest = last_seen
        for row in rows:
            detected = row.get("InitialDetectionTime")
            if not detected:
                continue
            if last_seen is None or detected > last_seen:
                self.toaster.notify(
                    "Threat detected",
                    "Windows Defender detected a new threat on this PC. "
                    "Open Windows Security > Protection history for details.",
                )
                self.logger.info("New Defender threat detected at %s", detected)
            if newest is None or detected > newest:
                newest = detected
        if newest is not None:
            self.state["last_threat_time"] = newest

    def _check_drift(self) -> None:
        previous = self.state.get("secure_state", {})
        current: Dict[str, bool] = {}
        for module in self.engine.modules:
            try:
                verified = module.check()
            except Exception:  # noqa: BLE001
                verified = False
            current[module.name] = verified
            if previous.get(module.name) is True and verified is False:
                self.toaster.notify(
                    "Security setting reverted",
                    f"'{module.name}' was previously secure and is now VULNERABLE again.",
                )
                self.logger.warning("Configuration drift detected: %s", module.name)
        self.state["secure_state"] = current

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    def run_forever(self) -> None:
        """Start the polling loop. This method does not return."""
        self.console.print(
            Panel(
                f"[title]{APP_NAME} MONITOR[/] running — polling every {self.poll_seconds}s.\n"
                "Watching: password changes, new Defender detections, config drift.",
                border_style="cyan",
            )
        )
        while True:
            try:
                self._check_password_change()
                self._check_new_threats()
                self._check_drift()
                self._save_state()
            except Exception as exc:  # noqa: BLE001
                self.logger.error("Monitor loop error: %s", exc)
            time.sleep(self.poll_seconds)
