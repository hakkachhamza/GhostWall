"""Tests for the GhostWall report generator."""

from __future__ import annotations
from pathlib import Path

from ghostwall.core import SecurityModule
from ghostwall.reports import ReportGenerator


class FakeModule(SecurityModule):
    def __init__(self, name, verified):
        super().__init__(name)
        self._verified = verified

    def apply(self):
        return True

    def check(self):
        return self._verified

    def backup(self):
        return {}

    def restore(self, state):
        return True


def test_generate_html_report(temp_dir: Path):
    gen = ReportGenerator(
        app_name="GhostWall",
        app_version="2.0.0",
        hostname="testhost",
        report_dir=temp_dir,
        log_path=temp_dir / "ecs.json",
        backup_path=temp_dir / "backup.json",
    )
    modules = [FakeModule("M1", True), FakeModule("M2", False)]
    path = gen.generate_html(modules)
    assert path.exists()
    assert path.suffix == ".html"
    content = path.read_text(encoding="utf-8")
    assert "GhostWall" in content
    assert "M1" in content
    assert "M2" in content


def test_generate_json_report(temp_dir: Path):
    gen = ReportGenerator(
        app_name="GhostWall",
        app_version="2.0.0",
        hostname="testhost",
        report_dir=temp_dir,
        log_path=temp_dir / "ecs.json",
        backup_path=temp_dir / "backup.json",
    )
    modules = [FakeModule("M1", True)]
    path = gen.generate_json(modules)
    assert path.exists()
    assert path.suffix == ".json"


def test_generate_csv_report(temp_dir: Path):
    gen = ReportGenerator(
        app_name="GhostWall",
        app_version="2.0.0",
        hostname="testhost",
        report_dir=temp_dir,
        log_path=temp_dir / "ecs.json",
        backup_path=temp_dir / "backup.json",
    )
    modules = [FakeModule("M1", True)]
    path = gen.generate_csv(modules)
    assert path.exists()
    assert path.suffix == ".csv"
    assert "M1" in path.read_text(encoding="utf-8")
