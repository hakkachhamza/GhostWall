"""Progress-bar helpers for GhostWall."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Generator, Optional

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)


class ProgressManager:
    """Wrap Rich progress bars with a simple callback API."""

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()

    @contextmanager
    def create(
        self,
        total: int,
        description: str,
    ) -> Generator[Callable[[], None], None, None]:
        """Yield an ``advance`` callable that increments the progress bar."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:
            task_id = progress.add_task(f"[cyan]{description}", total=total)

            def advance() -> None:
                progress.advance(task_id)

            yield advance
