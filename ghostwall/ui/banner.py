"""Animated banner rendering for GhostWall."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from rich.align import Align
from rich.box import ASCII, DOUBLE
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from ghostwall.constants import (
    APP_NAME,
    ASSETS_DIR,
    BANNER_FRAME_COUNT,
    BANNER_FRAME_DURATION,
    BANNER_WAVE_COLORS,
)
from ghostwall.utils import get_hostname


class BannerRenderer:
    """Render the GhostWall animated banner."""

    def __init__(
        self,
        console: Optional[Console] = None,
        dry_run: bool = False,
        is_admin: bool = False,
    ) -> None:
        self.console = console or Console()
        self.dry_run = dry_run
        self.is_admin = is_admin

    def _subtitle(self) -> str:
        mode = "[warning]DRY-RUN[/]" if self.dry_run else "[danger]LIVE MODE[/]"
        admin = "[success]ADMIN[/]" if self.is_admin else "[warning]NON-ADMIN[/]"
        return f"[dim]Host:[/] [bold]{get_hostname()}[/]  [dim]|[/]  {admin}  [dim]|[/]  {mode}"

    def _read_banner_lines(self) -> list[str]:
        candidates = [
            Path("banner.txt"),
            ASSETS_DIR / "banner.txt",
        ]
        for candidate in candidates:
            if candidate.exists():
                try:
                    return candidate.read_text(encoding="utf-8").splitlines()
                except Exception:  # noqa: BLE001
                    pass
        return []

    def render(self) -> None:
        """Render the animated banner (or a fallback title)."""
        self.console.clear()
        lines = self._read_banner_lines()
        title = f"[bold white]{APP_NAME}[/]"
        subtitle = self._subtitle()
        fallback = f"[bold cyan]*  {APP_NAME}  -  SECURITY ORCHESTRATION ENGINE  *[/]"

        def _render_panel(box_style) -> Panel:
            return Panel(
                Align.center(fallback),
                title=title,
                subtitle=subtitle,
                border_style="cyan",
                box=box_style,
                expand=False,
            )

        if not lines:
            self.console.print(_render_panel(DOUBLE))
            return

        colors = BANNER_WAVE_COLORS
        try:
            with Live(console=self.console, refresh_per_second=10, transient=False) as live:
                for frame in range(BANNER_FRAME_COUNT):
                    body = Text()
                    for idx, line in enumerate(lines):
                        line_color = colors[(frame + (idx // 4)) % len(colors)]
                        body.append(line, style=line_color)
                        body.append("\n")
                    panel = Panel(
                        body,
                        title=title,
                        subtitle=subtitle,
                        border_style="cyan",
                        box=DOUBLE,
                        expand=False,
                    )
                    live.update(Align.center(panel))
                    time.sleep(BANNER_FRAME_DURATION)
        except UnicodeEncodeError:
            # Some legacy Windows terminals cannot render the box-drawing
            # characters in banner.txt. Fall back to an ASCII-only panel.
            self.console.print(_render_panel(ASCII))
