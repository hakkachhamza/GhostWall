"""Command-line interface for GhostWall."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

# Ensure stdout can emit UTF-8 characters on legacy Windows terminals.
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass


from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.theme import Theme

from ghostwall.constants import APP_NAME, APP_VERSION
from ghostwall.engine import SecurityEngine
from ghostwall.exceptions import PrivilegeError
from ghostwall.monitor import SecurityMonitor
from ghostwall.remote.orchestrator import RemoteOrchestrator
from ghostwall.startup import StartupManager
from ghostwall.ui.banner import BannerRenderer
from ghostwall.utils import load_text_lines


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} v{APP_VERSION} — Enterprise Windows Security Orchestration",
    )

    local = parser.add_argument_group("Local actions")
    local.add_argument("--audit", action="store_true", help="Run the full hardening audit locally")
    local.add_argument("--status", action="store_true", help="Show current status only, no changes")
    local.add_argument("--report", action="store_true", help="Generate the HTML report and exit")
    local.add_argument(
        "--report-format",
        default="html",
        choices=["html", "json", "csv", "pdf", "all"],
        help="Report output format (default: html)",
    )
    local.add_argument("--dry-run", action="store_true", help="Simulate every action without changing the system")
    local.add_argument("-y", "--yes", action="store_true", help="Auto-confirm destructive modules")

    rollback = parser.add_argument_group("Rollback")
    rollback.add_argument(
        "--rollback",
        metavar="BACKUP_FILE",
        help="Restore state from a ghostwall_backup_*.json file",
    )
    rollback.add_argument(
        "--encrypt-backup",
        action="store_true",
        help="Encrypt the backup file with Fernet (needs 'cryptography')",
    )

    remote = parser.add_argument_group("Multi-host remote orchestration (WinRM)")
    remote.add_argument("--targets", metavar="FILE", help="Text file with one hostname/IP per line")
    remote.add_argument(
        "--max-workers",
        type=int,
        default=10,
        help="Concurrent remote sessions (default: 10)",
    )
    remote.add_argument(
        "--transport",
        default="ntlm",
        choices=["ntlm", "kerberos", "basic", "credssp"],
        help="WinRM auth transport (default: ntlm)",
    )
    remote.add_argument(
        "--http",
        action="store_true",
        help="Use plain HTTP (5985) instead of HTTPS (5986) — not recommended",
    )

    logging_grp = parser.add_argument_group("Logging")
    logging_grp.add_argument(
        "--eventlog",
        action="store_true",
        help="Also write completion events to the Windows Event Log",
    )

    config_grp = parser.add_argument_group("Configuration")
    config_grp.add_argument(
        "--config",
        metavar="FILE",
        help="Path to a custom config.json file",
    )

    monitor_grp = parser.add_argument_group("Startup & background monitoring")
    monitor_grp.add_argument(
        "--install-startup",
        action="store_true",
        help="Register this script to launch --monitor at every login",
    )
    monitor_grp.add_argument(
        "--uninstall-startup",
        action="store_true",
        help="Remove the startup entry",
    )
    monitor_grp.add_argument(
        "--monitor",
        action="store_true",
        help="Run the background watcher (password changes, malware detections, config drift)",
    )

    return parser.parse_args(argv)


def _main_menu(engine: SecurityEngine) -> None:
    """Run the interactive main menu loop."""
    console = engine.console
    while True:
        console.print(
            Panel(
                "[bold white]1.[/] Run Complete Security Hardening Audit [cyan](Recommended)[/]\n"
                "[bold white]2.[/] View Current Security Status\n"
                "[bold white]3.[/] Generate HTML Security Report\n"
                "[bold white]4.[/] Rollback from a Backup File\n"
                "[bold white]5.[/] Enable background monitoring at every login\n"
                "[bold white]6.[/] Disable background monitoring\n"
                "[bold white]7.[/] Exit",
                title="[title]MAIN MENU[/]",
                border_style="magenta",
            )
        )
        choice = Prompt.ask(
            "[bold]Select an option[/]",
            choices=["1", "2", "3", "4", "5", "6", "7"],
            default="1",
        )

        if choice != "7":
            engine.ensure_wmi_available()

        if choice == "1":
            engine.run_audit()
        elif choice == "2":
            engine.show_status()
        elif choice == "3":
            engine.generate_html_report()
        elif choice == "4":
            path = Prompt.ask("Path to backup JSON file")
            engine.rollback(Path(path))
        elif choice == "5":
            StartupManager().install()
        elif choice == "6":
            StartupManager().uninstall()
        elif choice == "7":
            console.print("[success]Stay secure! Goodbye.[/]")
            break


def _generate_report(engine: SecurityEngine, fmt: str) -> None:
    """Generate one or more report formats."""
    formats = ["html", "json", "csv", "pdf"] if fmt == "all" else [fmt]
    for report_format in formats:
        try:
            if report_format == "html":
                path = engine.generate_html_report()
            elif report_format == "json":
                path = engine.generate_json_report()
            elif report_format == "csv":
                path = engine.generate_csv_report()
            elif report_format == "pdf":
                path = engine.generate_pdf_report()
            else:
                continue
            engine.console.print(f"[success]✔ {report_format.upper()} report saved to {path}[/]")
        except Exception as exc:  # noqa: BLE001
            engine.console.print(f"[danger]Failed to generate {report_format.upper()} report: {exc}[/]")


def _run_remote(args: argparse.Namespace, console: Console) -> int:
    """Execute the remote orchestration path."""
    try:
        hosts = load_text_lines(Path(args.targets))
        if not hosts:
            console.print("[danger]Target file is empty.[/]")
            return 1
        orchestrator = RemoteOrchestrator(
            max_workers=args.max_workers,
            transport=args.transport,
            use_ssl=not args.http,
            console=console,
        )
        orchestrator.run(hosts)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[danger]Remote orchestration failed: {exc}[/]")
        return 1
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """GhostWall CLI entry point."""
    args = parse_args(argv)
    custom_theme = Theme(
        {
            "info": "cyan",
            "success": "bold green",
            "warning": "bold yellow",
            "danger": "bold red",
            "title": "bold magenta",
            "muted": "dim white",
            "accent": "bold cyan",
        }
    )
    console = Console(theme=custom_theme)

    # Startup registration / unregistration is independent of the engine.
    if args.install_startup:
        StartupManager().install()
        return 0
    if args.uninstall_startup:
        StartupManager().uninstall()
        return 0

    # Monitor mode runs in the foreground (launched hidden at login).
    if args.monitor:
        engine = SecurityEngine(dry_run=False, auto_yes=True, console=console)
        try:
            engine.check_prerequisites()
        except PrivilegeError:
            return 1
        SecurityMonitor(engine, console=console).run_forever()
        return 0

    # Remote orchestration path is independent of the local engine.
    if args.targets:
        return _run_remote(args, console)

    engine = SecurityEngine(
        dry_run=args.dry_run,
        auto_yes=args.yes,
        encrypt_backup=args.encrypt_backup,
        use_eventlog=args.eventlog,
        console=console,
    )

    if args.config:
        engine.load_configuration(Path(args.config))

    # Display banner before any local action.
    BannerRenderer(console=console, dry_run=args.dry_run, is_admin=engine.is_admin).render()

    if args.rollback:
        try:
            engine.check_prerequisites()
        except PrivilegeError:
            return 1
        engine.rollback(Path(args.rollback))
        return 0

    try:
        engine.check_prerequisites()
    except PrivilegeError:
        return 1

    if args.audit:
        engine.run_audit()
    elif args.status:
        engine.show_status()
    elif args.report:
        _generate_report(engine, args.report_format)
    else:
        _main_menu(engine)

    return 0


if __name__ == "__main__":
    sys.exit(main())
