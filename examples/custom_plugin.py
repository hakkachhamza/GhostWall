"""Example GhostWall plugin.

Place this file in ghostwall/plugins/ or the configured plugins directory.
It will be discovered automatically at engine startup.
"""

from __future__ import annotations

from typing import Any, Dict

from ghostwall.core import SecurityModule


class ExamplePluginModule(SecurityModule):
    """An example hardening module implemented as a plugin."""

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__(
            "Example Plugin Control",
            description="Demonstrates the GhostWall plugin system.",
            destructive=False,
            framework_mapping={
                "cis": ["v8-99.9"],
                "mitre": ["M9999"],
                "nist": ["XX-0"],
            },
        )
        self.dry_run = dry_run

    def apply(self) -> bool:
        print(f"[DRY-RUN={self.dry_run}] Applying example control")
        return True

    def check(self) -> bool:
        return True

    def backup(self) -> Dict[str, Any]:
        return {"applied": True}

    def restore(self, state: Dict[str, Any]) -> bool:
        return True


def register():
    """Return the plugin class (or a list of classes)."""
    return ExamplePluginModule
