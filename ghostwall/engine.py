"""Core security orchestration engine for GhostWall.

The :class:`SecurityEngine` coordinates hardening modules, backup/rollback,
reporting, and logging. It is intentionally decoupled from the CLI and UI so
it can be driven programmatically, tested, or embedded in other tools.
"""

from __future__ import annotations

import importlib
import logging
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from ghostwall.backup import BackupManager
from ghostwall.config.loader import ConfigLoader
from ghostwall.constants import (
    APP_NAME,
    APP_VERSION,
    BACKUPS_DIR,
    REPORTS_DIR,
)
from ghostwall.core import SecurityModule
from ghostwall.exceptions import PrivilegeError
from ghostwall.logger import GhostWallLogger, ecs_log
from ghostwall.modules import (
    AutorunModule,
    ControlledFolderAccessModule,
    DefenderRealtimeModule,
    DepModule,
    FirewallModule,
    GuestAccountModule,
    LegacyProtocolModule,
    PasswordPolicyModule,
    PowerShellPolicyModule,
    PrivacyModule,
    RdpModule,
    UacModule,
)
from ghostwall.notifications import ToastNotifier
from ghostwall.plugins.loader import PluginLoader
from ghostwall.reports import ReportGenerator
from ghostwall.ui.progress import ProgressManager
from ghostwall.utils import get_hostname, is_admin, log_to_windows_eventlog

logger = logging.getLogger("ghostwall")


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class SecurityEngine:
    """Orchestrates local hardening, reporting, backup, and rollback.

    Args:
        dry_run: Simulate actions without changing the system.
        auto_yes: Skip interactive confirmation for destructive modules.
        encrypt_backup: Encrypt rollback backups with Fernet.
        use_eventlog: Write completion events to the Windows Event Log.
        log_dir: Directory for log files.
        backup_dir: Directory for backup files.
        report_dir: Directory for generated reports.
        console: Optional Rich console for UI output.
    """

    VERIFY_ATTEMPTS: int = 3
    VERIFY_DELAY: float = 1.0

    def __init__(
        self,
        dry_run: bool = False,
        auto_yes: bool = False,
        encrypt_backup: bool = False,
        use_eventlog: bool = False,
        log_dir: Optional[Path] = None,
        backup_dir: Optional[Path] = None,
        report_dir: Optional[Path] = None,
        console: Optional[Console] = None,
        config_loader: Optional[ConfigLoader] = None,
    ) -> None:
        self.hostname = get_hostname()
        self.is_admin = is_admin()
        self.dry_run = dry_run
        self.auto_yes = auto_yes
        self.use_eventlog = use_eventlog
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.log_dir = Path(log_dir) if log_dir else Path(BACKUPS_DIR).parent / "logs"
        self.backup_dir = Path(backup_dir) if backup_dir else BACKUPS_DIR
        self.report_dir = Path(report_dir) if report_dir else REPORTS_DIR

        for directory in (self.log_dir, self.backup_dir, self.report_dir):
            directory.mkdir(parents=True, exist_ok=True)

        self._log_manager = GhostWallLogger(
            log_dir=self.log_dir,
            timestamp=self.timestamp,
        )
        self.logger = self._log_manager.get_logger()

        backup_path = self.backup_dir / f"ghostwall_backup_{self.timestamp}.json"
        self.backup_manager = BackupManager(
            backup_path=backup_path,
            encrypt=encrypt_backup,
        )
        self.backup_manager.warn_if_encryption_unavailable()

        self.console = console or Console()
        self.progress = ProgressManager(self.console)
        self.report_generator = ReportGenerator(
            app_name=APP_NAME,
            app_version=APP_VERSION,
            hostname=self.hostname,
            report_dir=self.report_dir,
            log_path=self._log_manager.ecs_log_file,
            backup_path=self.backup_manager.backup_path,
        )
        self.toaster = ToastNotifier()

        self.config_loader = config_loader or ConfigLoader()
        self.modules: List[SecurityModule] = []
        self._wmi_declined = False
        self._build_modules()
        self._load_plugins()

    # ------------------------------------------------------------------
    # Module factory
    # ------------------------------------------------------------------
    def _build_modules(self) -> None:
        """Instantiate the built-in hardening modules."""
        self.modules = [
            FirewallModule(dry_run=self.dry_run),
            RdpModule(dry_run=self.dry_run),
            ControlledFolderAccessModule(dry_run=self.dry_run),
            DefenderRealtimeModule(dry_run=self.dry_run),
            UacModule(dry_run=self.dry_run),
            DepModule(dry_run=self.dry_run),
            LegacyProtocolModule(dry_run=self.dry_run),
            PrivacyModule(dry_run=self.dry_run),
            GuestAccountModule(dry_run=self.dry_run),
            AutorunModule(dry_run=self.dry_run),
            PowerShellPolicyModule(dry_run=self.dry_run),
            PasswordPolicyModule(dry_run=self.dry_run),
        ]

    def _load_plugins(self) -> None:
        """Discover and register user-supplied plugins."""
        plugin_loader = PluginLoader()
        try:
            for plugin in plugin_loader.discover():
                instance = plugin(self.dry_run)  # type: ignore[arg-type]
                if isinstance(instance, SecurityModule):
                    self.modules.append(instance)
                    self.logger.info("Loaded plugin module: %s", instance.name)
        except Exception as exc:  # noqa: BLE001
            self.logger.warning("Plugin loading failed: %s", exc)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    def load_configuration(self, path: Path) -> None:
        """Load a custom configuration/policy file and apply overrides."""
        try:
            config = self.config_loader.load(path)
        except Exception as exc:  # noqa: BLE001
            self.logger.error("Failed to load configuration from %s: %s", path, exc)
            return

        # Optional: reorder / filter modules by config
        enabled = config.get("enabled_modules")
        if enabled is not None:
            enabled_set = set(enabled)
            self.modules = [m for m in self.modules if m.name in enabled_set]

        # Apply module-specific parameter overrides
        params = config.get("module_params", {})
        for module in self.modules:
            overrides = params.get(module.name, {})
            for key, value in overrides.items():
                if hasattr(module, key):
                    setattr(module, key, value)

        self.logger.info("Loaded configuration from %s", path)

    # ------------------------------------------------------------------
    # Prerequisites
    # ------------------------------------------------------------------
    def check_prerequisites(self) -> None:
        """Validate platform and privileges; raise on fatal problems."""
        if not self._is_windows():
            self.console.print(
                Panel(
                    "[danger]Local hardening requires Windows[/] (winreg/WMI/PowerShell are Windows-only).\n"
                    "Remote orchestration via --targets can still be run from any OS with pywinrm installed, "
                    "since it drives *remote* Windows hosts over WinRM.",
                    title="Platform Notice",
                    border_style="yellow",
                )
            )
            return
        if not self.is_admin:
            self.console.print(
                Panel(
                    "[danger]ADMINISTRATOR PRIVILEGES REQUIRED![/]\n"
                    "This tool modifies firewall, registry, services, and account policy.",
                    title="Access Denied",
                    border_style="red",
                )
            )
            raise PrivilegeError("Administrator privileges are required for local hardening.")

        self.console.print("[success]✔ Administrator privileges confirmed.[/]\n")

    @staticmethod
    def _is_windows() -> bool:
        import os as _os

        return _os.name == "nt"

    # ------------------------------------------------------------------
    # Audit flow
    # ------------------------------------------------------------------
    def run_audit(self) -> None:
        """Run the full hardening audit: backup, apply, verify."""
        self.console.print(Panel("[title]INITIATING FULL SYSTEM HARDENING AUDIT[/]", border_style="cyan"))

        destructive = [m for m in self.modules if m.destructive]
        if destructive and not self.auto_yes and not self.dry_run:
            self.console.print(
                Panel(
                    "\n".join(f"[warning]•[/] [bold]{m.name}[/] — {m.description}" for m in destructive),
                    title="[danger]The following changes are higher-impact[/]",
                    border_style="yellow",
                )
            )
            if not Confirm.ask("Proceed with ALL modules, including the ones above?", default=False):
                self.console.print("[warning]Aborted by user. No changes were made.[/]")
                return

        # Backup pass
        self.console.print("[info]Capturing pre-change state for rollback...[/]")
        backup_data = self.backup_manager.build_backup(
            self.modules,
            self.hostname,
            self.timestamp,
            APP_VERSION,
        )
        if not self.dry_run:
            self.backup_manager.save(backup_data)
            self.console.print(f"[success]✔ Backup saved to {self.backup_manager.backup_path}[/]\n")
            ecs_log(self.logger, logging.INFO, "Pre-change backup captured", "backup", "success")

        # Apply pass
        with self.progress.create(len(self.modules), "Processing security modules...") as advance:
            for module in self.modules:
                self._apply_and_verify(module)
                advance()

        self.console.print("\n[success]✔ HARDENING PASS COMPLETE[/]\n")
        if self.use_eventlog:
            log_to_windows_eventlog(
                f"GhostWall audit completed on {self.hostname}",
                event_id_offset=1,
            )
        self.show_status(post_audit=True)

    def _apply_and_verify(self, module: SecurityModule) -> None:
        """Apply a single module and re-check it after a short propagation delay."""
        try:
            success = module.apply()
            ecs_log(
                self.logger,
                logging.INFO,
                f"Applied module: {module.name}",
                "hardening-apply",
                "success" if success else "failure",
            )

            if success and not self.dry_run:
                verified = self._verify_with_retry(module)
                if not verified:
                    error = (
                        "Apply reported success but re-checking after 3 retries "
                        "still shows VULNERABLE. This usually means the change was "
                        "blocked (e.g. Defender Tamper Protection, Group Policy "
                        "overriding the value) or needs a reboot to take effect."
                    )
                    if module.name in ("Ransomware Protection", "Defender Real-Time Protection"):
                        from ghostwall.modules.defender import check_tamper_protection

                        if check_tamper_protection(dry_run=self.dry_run):
                            error = (
                                "Blocked by Windows Defender Tamper Protection. "
                                "Turn it off in Windows Security > Virus & threat "
                                "protection > Manage settings, or manage this control "
                                "via Intune/MDM, then re-run the audit."
                            )
                    module.result.error = error
                    self.logger.warning("Module '%s': applied but re-check failed after retries.", module.name)
        except Exception as exc:  # noqa: BLE001
            module.result.success = False
            module.result.error = str(exc)
            self.logger.error("Module '%s' raised: %s", module.name, exc)
            ecs_log(
                self.logger,
                logging.ERROR,
                f"Module '{module.name}' raised: {exc}",
                "hardening-apply",
                "failure",
            )

    def _verify_with_retry(self, module: SecurityModule) -> bool:
        """Re-check a module, retrying briefly to allow propagation."""
        for attempt in range(self.VERIFY_ATTEMPTS):
            time.sleep(self.VERIFY_DELAY)
            try:
                if module.check():
                    return True
            except Exception:  # noqa: BLE001
                pass
        return False

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------
    def rollback(self, backup_file: Path) -> None:
        """Restore system state from a GhostWall backup file."""
        self.console.print(Panel(f"[title]ROLLBACK FROM {backup_file}[/]", border_style="yellow"))
        self.backup_manager.backup_path = backup_file
        try:
            data = self.backup_manager.load()
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[danger]Failed to load backup: {exc}[/]")
            return

        meta = data.get("_meta", {})
        self.console.print(f"[muted]Backup created {meta.get('timestamp', '?')} on host {meta.get('host', '?')}[/]\n")

        if not self.auto_yes and not Confirm.ask(
            "This will overwrite CURRENT settings with the values captured in this backup. Continue?",
            default=False,
        ):
            self.console.print("[warning]Rollback aborted by user.[/]")
            return

        results = self.backup_manager.restore_backup(self.modules, data)
        for name, ok in results.items():
            ecs_log(
                self.logger,
                logging.INFO,
                f"Rollback module: {name}",
                "rollback",
                "success" if ok else "failure",
            )

        self.console.print("\n[success]✔ Rollback complete. Recommend a restart to fully re-apply prior state.[/]\n")

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def show_status(self, post_audit: bool = False) -> Tuple[int, int]:
        """Render the current security posture table."""
        from ghostwall.ui.dashboard import StatusDashboard

        dashboard = StatusDashboard(self.console)
        secure_count, total = dashboard.render(self.modules, post_audit=post_audit)

        self.console.print(
            f"\n[dim]Log: {self._log_manager.log_file}   |   SIEM (ECS JSON): {self._log_manager.ecs_log_file}[/]\n"
        )
        return secure_count, total

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    def generate_html_report(self) -> Path:
        """Generate an HTML security report."""
        return self.report_generator.generate_html(self.modules)

    def generate_json_report(self) -> Path:
        """Generate a JSON security report."""
        return self.report_generator.generate_json(self.modules)

    def generate_csv_report(self) -> Path:
        """Generate a CSV security report."""
        return self.report_generator.generate_csv(self.modules)

    def generate_pdf_report(self) -> Path:
        """Generate a PDF security report."""
        return self.report_generator.generate_pdf(self.modules)

    # ------------------------------------------------------------------
    # Optional dependency management
    # ------------------------------------------------------------------
    def ensure_wmi_available(self) -> bool:
        """Optionally install the 'wmi' package if it is missing."""
        from ghostwall.utils import wmi_module

        if wmi_module is not None:
            return True
        if self._wmi_declined:
            return False

        from rich.box import box

        self.console.print(
            Panel(
                "[warning]Optional dependency 'wmi' is not installed.[/]\n"
                f"{APP_NAME} uses it for a few native WMI lookups (services, terminal-server "
                "settings). Everything still works without it — PowerShell/registry fallbacks "
                "cover the same ground.",
                title="[title]Optional Dependency: wmi[/]",
                border_style="yellow",
                box=box.ROUNDED,
                expand=False,
            )
        )

        if not Confirm.ask("Install the 'wmi' package now via pip?", default=True):
            self._wmi_declined = True
            self.console.print(
                "[muted]Continuing without WMI — PowerShell fallback will be used for this session.[/]\n"
            )
            self.logger.info("User declined automatic 'wmi' package install.")
            return False

        result = None
        with self.console.status("[cyan]Installing 'wmi' package via pip...[/]", spinner="dots"):
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "wmi", "--quiet", "--disable-pip-version-check"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except Exception as exc:  # noqa: BLE001
                self.console.print(f"[danger]✘ Install failed to launch: {exc}[/]\n")
                self.logger.error("wmi auto-install failed to launch: %s", exc)
                self._wmi_declined = True
                return False

        if result.returncode != 0:
            self.console.print(
                Panel(
                    f"[danger]Installation failed (exit code {result.returncode}).[/]\n"
                    f"{result.stderr.strip()[:400]}",
                    title="[danger]wmi install failed[/]",
                    border_style="red",
                    expand=False,
                )
            )
            self.logger.error("wmi auto-install failed: %s", result.stderr.strip())
            self._wmi_declined = True
            return False

        try:
            imported = importlib.import_module("wmi")
            import ghostwall.utils

            ghostwall.utils.wmi_module = imported
            self.console.print("[success]✔ 'wmi' installed and loaded successfully.[/]\n")
            self.logger.info("wmi package auto-installed and loaded successfully.")
            return True
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[danger]✘ Installed but failed to import 'wmi': {exc}[/]\n")
            self.logger.error("wmi import failed after successful pip install: %s", exc)
            self._wmi_declined = True
            return False
