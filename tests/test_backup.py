"""Tests for the GhostWall backup / rollback engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from ghostwall.backup import BackupManager, BackupMetadata
from ghostwall.exceptions import BackupError


def test_backup_metadata_roundtrip():
    meta = BackupMetadata(
        host="testhost",
        timestamp="20250101_120000",
        app_version="2.0.0",
        encrypted=False,
    )
    data = meta.to_dict()
    restored = BackupMetadata.from_dict(data)
    assert restored.host == meta.host
    assert restored.timestamp == meta.timestamp
    assert restored.app_version == meta.app_version
    assert restored.encrypted == meta.encrypted


def test_plaintext_save_and_load(temp_dir: Path):
    manager = BackupManager(backup_path=temp_dir / "backup.json", encrypt=False)
    payload = {"Firewall Enforcement": {"profiles": []}, "_meta": {"host": "test"}}
    path = manager.save(payload)
    assert path.exists()
    loaded = manager.load()
    assert loaded["Firewall Enforcement"]["profiles"] == []
    assert loaded["_meta"]["host"] == "test"


def test_load_missing_file_raises(temp_dir: Path):
    manager = BackupManager(backup_path=temp_dir / "missing.json")
    with pytest.raises(BackupError, match="not found"):
        manager.load()


def test_build_backup_collects_module_state(temp_dir: Path):
    class FakeModule:
        name = "TestModule"

        def backup(self):
            return {"enabled": True}

        def restore(self, state):
            return True

    manager = BackupManager(backup_path=temp_dir / "b.json")
    data = manager.build_backup([FakeModule()], "host", "ts", "2.0.0")
    assert data["TestModule"] == {"enabled": True}
    assert data["_meta"]["host"] == "host"


def test_restore_backup_invokes_module_restore(temp_dir: Path):
    calls = []

    class FakeModule:
        name = "TestModule"

        def backup(self):
            return {}

        def restore(self, state):
            calls.append(state)
            return True

    manager = BackupManager(backup_path=temp_dir / "b.json")
    results = manager.restore_backup([FakeModule()], {"TestModule": {"enabled": False}})
    assert results["TestModule"] is True
    assert calls == [{"enabled": False}]
