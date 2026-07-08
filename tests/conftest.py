"""Shared pytest fixtures for GhostWall tests."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Yield a temporary directory for isolated tests."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def mock_registry(monkeypatch):
    """Fixture to monkeypatch registry helpers for non-Windows hosts."""
    store = {}

    def fake_reg_get(hive, path, name):
        return store.get((hive, path, name))

    def fake_reg_set(hive, path, name, value, vtype=None, dry_run=False):
        if dry_run:
            return True
        store[(hive, path, name)] = value
        return True

    def fake_reg_delete(hive, path, name, dry_run=False):
        if dry_run:
            return True
        store.pop((hive, path, name), None)
        return True

    monkeypatch.setattr("ghostwall.utils.reg_get", fake_reg_get)
    monkeypatch.setattr("ghostwall.utils.reg_set", fake_reg_set)
    monkeypatch.setattr("ghostwall.utils.reg_delete", fake_reg_delete)
    return store
