"""Tests for the GhostWall logging subsystem."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ghostwall.logger import ECSJsonFormatter, GhostWallLogger, ecs_log


def test_ecs_formatter_outputs_valid_json():
    formatter = ECSJsonFormatter("testhost")
    record = logging.LogRecord(
        name="ghostwall",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="test message",
        args=(),
        exc_info=None,
    )
    record.event_action = "test"
    record.event_outcome = "success"
    output = formatter.format(record)
    parsed = json.loads(output)
    assert parsed["message"] == "test message"
    assert parsed["host.hostname"] == "testhost"
    assert parsed["event.action"] == "test"
    assert parsed["event.outcome"] == "success"
    assert "@timestamp" in parsed


def test_ecs_log_helper_attaches_extra(temp_dir: Path):
    manager = GhostWallLogger(log_dir=temp_dir, timestamp="test")
    logger = manager.get_logger()
    ecs_log(logger, logging.INFO, "hello", "test-action", "failure")
    lines = (temp_dir / "ecs.json").read_text().strip().splitlines()
    parsed = json.loads(lines[-1])
    assert parsed["event.action"] == "test-action"
    assert parsed["event.outcome"] == "failure"
    manager.close()


def test_log_files_created(temp_dir: Path):
    manager = GhostWallLogger(log_dir=temp_dir, timestamp="test")
    logger = manager.get_logger()
    logger.info("audit entry")
    assert (temp_dir / "audit_test.log").exists()
    assert (temp_dir / "errors.log").exists()
    assert (temp_dir / "ecs.json").exists()
    manager.close()
