"""Tests for the GhostWall rollback flow through the engine."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from ghostwall.engine import SecurityEngine


class DummyModule:
    name = "Dummy"
    description = "Dummy module"
    destructive = False
    framework_mapping = {}
    result = type("obj", (object,), {"success": False, "error": None, "verified": False})()

    def __init__(self, dry_run):
        pass

    def apply(self):
        return True

    def check(self):
        return True

    def backup(self):
        return {"value": 1}

    def restore(self, state):
        return state.get("value") == 1


def test_engine_rollback_from_backup(temp_dir: Path, monkeypatch):
    engine = SecurityEngine(
        dry_run=True,
        auto_yes=True,
        backup_dir=temp_dir / "backups",
        log_dir=temp_dir / "logs",
        report_dir=temp_dir / "reports",
        console=Console(force_terminal=False),
    )
    try:
        engine.modules = [DummyModule(dry_run=True)]
        backup = engine.backup_manager.build_backup(engine.modules, "host", "ts", "2.0.0")
        engine.backup_manager.save(backup)

        # Reset result and ensure restore works
        engine.rollback(engine.backup_manager.backup_path)
        assert engine.modules[0].restore({"value": 1}) is True
    finally:
        engine._log_manager.close()
