"""Dashboard / status rendering for GhostWall."""

from __future__ import annotations

from typing import List, Optional, Tuple

from rich.align import Align
from rich.box import ROUNDED
from rich.console import Console
from rich.rule import Rule
from rich.table import Table

from ghostwall.constants import SCORE_GOOD_THRESHOLD, SCORE_WARNING_THRESHOLD
from ghostwall.core import SecurityModule


class StatusDashboard:
    """Render the current security posture as a Rich table."""

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()

    def render(self, modules: List[SecurityModule], post_audit: bool = False) -> Tuple[int, int]:
        """Render the posture table and score. Return (secure_count, total)."""
        table = Table(title="Current Security Posture", box=ROUNDED, border_style="cyan")
        table.add_column("Security Control", style="bold", ratio=2)
        table.add_column("Framework Mapping", style="muted", ratio=3)
        table.add_column("Applied", justify="center", ratio=1)
        table.add_column("Verified", justify="center", ratio=1)
        if post_audit:
            table.add_column("Notes", style="muted", ratio=3)

        secure_count = 0
        for module in modules:
            try:
                verified = module.check()
            except Exception:  # noqa: BLE001
                # Caller logger is responsible for full trace; we degrade gracefully.
                verified = False
            secure_count += int(verified)

            applied_str = "[muted]—[/]"
            if post_audit:
                applied_str = "[success]✔[/]" if module.result.success else "[danger]✘[/]"
            status_str = "[success]✔ SECURE[/]" if verified else "[danger]✘ VULNERABLE[/]"
            row = [module.name, module.framework_str(), applied_str, status_str]
            if post_audit:
                row.append(module.result.error or "")
            table.add_row(*row)

        self.console.print(table)
        total = len(modules)
        score_pct = round(100 * secure_count / total) if total else 0
        score_color = (
            "success"
            if score_pct >= SCORE_GOOD_THRESHOLD
            else ("warning" if score_pct >= SCORE_WARNING_THRESHOLD else "danger")
        )
        self.console.print(Rule(style="cyan"))
        self.console.print(
            Align.center(
                f"[{score_color}]SECURITY SCORE: {secure_count}/{total} controls verified secure ({score_pct}%)[/]"
            )
        )
        return secure_count, total
