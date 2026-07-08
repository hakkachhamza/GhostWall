"""Multi-host remote hardening orchestration via WinRM."""

from __future__ import annotations

import getpass
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from ghostwall.constants import ENV_REMOTE_PASS, ENV_REMOTE_USER
from ghostwall.remote.winrm import WinRMSession
from ghostwall.ui.progress import ProgressManager

logger = logging.getLogger("ghostwall")

# ---------------------------------------------------------------------------
# Consolidated remote hardening script
# ---------------------------------------------------------------------------
REMOTE_HARDENING_SCRIPT = "\n".join(
    [
        r"$results = @{",
        r"function Try-Step($name, $script) {",
        r"    try { & $script | Out-Null; $results[$name] = \"OK\" }",
        r"    catch { $results[$name] = \"FAILED: $($_.Exception.Message)\" }",
        r"}",
        r"",
        (
            r'Try-Step "Firewall" { Set-NetFirewallProfile -All -Enabled True '
            r"-DefaultInboundAction Block -DefaultOutboundAction Allow }"
        ),
        r'Try-Step "RDP" {',
        (
            r"    (Get-WmiObject -Namespace root/CIMV2/TerminalServices "
            r"-Class Win32_TerminalServiceSetting).SetAllowTSConnections(0,1)"
        ),
        r"    Set-Service -Name TermService -StartupType Disabled -ErrorAction SilentlyContinue",
        r"}",
        r'Try-Step "ControlledFolderAccess" { Set-MpPreference -EnableControlledFolderAccess Enabled }',
        r'Try-Step "DefenderRealtime" { Set-MpPreference -DisableRealtimeMonitoring $false }',
        r'Try-Step "UAC" {',
        (
            r"    Set-ItemProperty -Path "
            r'"HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" '
            r"-Name ConsentPromptBehaviorAdmin -Value 4"
        ),
        (
            r"    Set-ItemProperty -Path "
            r'"HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" '
            r"-Name EnableLUA -Value 1"
        ),
        r"}",
        r'Try-Step "SMB1_LLMNR" {',
        (
            r"    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
            r"-NoRestart -ErrorAction SilentlyContinue"
        ),
        (r'    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" ' r"-Force | Out-Null"),
        (
            r'    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" '
            r"-Name EnableMulticast -Value 0"
        ),
        r"}",
        r'Try-Step "Privacy" {',
        (r'    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" ' r"-Force | Out-Null"),
        (
            r'    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" '
            r"-Name AllowTelemetry -Value 0"
        ),
        r"}",
        r'Try-Step "GuestAccount" { Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue }',
        r'Try-Step "Autorun" {',
        (
            r'    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" '
            r"-Name NoDriveTypeAutoRun -Value 255"
        ),
        r"}",
        r'Try-Step "PSExecutionPolicy" { Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force }',
        r'Try-Step "PasswordPolicy" {',
        r"    net accounts /minpwlen:14 | Out-Null",
        r"    net accounts /maxpwage:30 | Out-Null",
        r"    net accounts /lockoutthreshold:3 | Out-Null",
        r"}",
        r"",
        r"$results | ConvertTo-Json -Compress",
    ]
)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
class RemoteOrchestrator:
    """Push the consolidated hardening script to many hosts in parallel.

    Credentials are never hardcoded. They are read from the environment
    variables ``GHOSTWALL_REMOTE_USER`` and ``GHOSTWALL_REMOTE_PASS`` or
    prompted interactively.

    Args:
        max_workers: Maximum concurrent WinRM sessions.
        transport: WinRM authentication transport.
        use_ssl: Whether to use HTTPS WinRM.
        console: Optional Rich console for output.
    """

    def __init__(
        self,
        max_workers: int = 10,
        transport: str = "ntlm",
        use_ssl: bool = True,
        console: Optional[Console] = None,
    ) -> None:
        self.max_workers = max_workers
        self.transport = transport
        self.use_ssl = use_ssl
        self.username, self.password = self._resolve_credentials()
        self.console = console or Console()
        self.progress = ProgressManager(self.console)

    @staticmethod
    def _resolve_credentials() -> tuple[str, str]:
        user = os.environ.get(ENV_REMOTE_USER)
        pw = os.environ.get(ENV_REMOTE_PASS)
        if user and pw:
            logger.debug("Using remote credentials from environment variables.")
            return user, pw
        console = Console()
        console.print(
            Panel(
                f"[warning]No {ENV_REMOTE_USER} / {ENV_REMOTE_PASS} "
                "environment variables found.[/]\n"
                "Enter credentials for the remote hosts now (not stored, not logged).",
                title="Remote Credentials",
                border_style="yellow",
            )
        )
        prompt = "Remote admin username (DOMAIN\\user or host\\user)"
        user = Prompt.ask(prompt)
        pw = getpass.getpass("Remote admin password: ")
        return user, pw

    def _run_on_host(self, host: str) -> Dict[str, Any]:
        try:
            session = WinRMSession(
                host,
                self.username,
                self.password,
                transport=self.transport,
                use_ssl=self.use_ssl,
            )
            result = session.run_ps(REMOTE_HARDENING_SCRIPT)
            success = result["status_code"] == 0
            output = result["stdout"]
            parsed = None
            if output:
                try:
                    parsed = json.loads(output)
                except json.JSONDecodeError:
                    parsed = {"raw_output": output}
            return {
                "host": host,
                "success": success,
                "status_code": result["status_code"],
                "stderr": result["stderr"],
                "results": parsed,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "host": host,
                "success": False,
                "status_code": -1,
                "stderr": str(exc),
                "results": None,
            }

    def run(self, hosts: List[str]) -> List[Dict[str, Any]]:
        """Run the hardening script against all hosts and render results."""
        scheme = "HTTPS" if self.use_ssl else "HTTP - not recommended"
        self.console.print(
            Panel(
                f"[title]REMOTE ORCHESTRATION[/]\n"
                f"Targets: {len(hosts)}   |   "
                f"Max concurrency: {self.max_workers}   |   "
                f"Transport: WinRM/{self.transport.upper()} ({scheme})",
                border_style="cyan",
            )
        )
        results: List[Dict[str, Any]] = []
        with self.progress.create(len(hosts), "Hardening remote hosts...") as advance:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(self._run_on_host, h): h for h in hosts}
                for future in as_completed(futures):
                    results.append(future.result())
                    advance()

        self._render_results(results)
        return results

    def _render_results(self, results: List[Dict[str, Any]]) -> None:
        table = Table(
            title="Remote Orchestration Results",
            box=ROUNDED,
            border_style="cyan",
        )
        table.add_column("Host")
        table.add_column("Status", justify="center")
        table.add_column("Modules OK", justify="center")
        table.add_column("Notes")
        for result in sorted(results, key=lambda x: x["host"]):
            if result["success"] and result["results"]:
                ok_count = sum(1 for v in result["results"].values() if v == "OK")
                total = len(result["results"])
                table.add_row(
                    result["host"],
                    "[success]✔ REACHED[/]",
                    f"{ok_count}/{total}",
                    "",
                )
            else:
                table.add_row(
                    result["host"],
                    "[danger]✘ FAILED[/]",
                    "—",
                    result["stderr"][:80],
                )
        self.console.print(table)
