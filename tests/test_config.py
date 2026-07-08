"""Tests for the GhostWall configuration loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostwall.config.loader import ConfigLoader
from ghostwall.exceptions import ConfigurationError


def test_load_valid_config(temp_dir: Path):
    config_path = temp_dir / "config.json"
    config_path.write_text(json.dumps({"enabled_modules": ["Firewall"]}), encoding="utf-8")
    loader = ConfigLoader(config_path=config_path)
    data = loader.load()
    assert data["enabled_modules"] == ["Firewall"]


def test_load_missing_config_raises(temp_dir: Path):
    loader = ConfigLoader(config_path=temp_dir / "missing.json")
    with pytest.raises(ConfigurationError, match="not found"):
        loader.load()


def test_load_invalid_json_raises(temp_dir: Path):
    config_path = temp_dir / "bad.json"
    config_path.write_text("{not json", encoding="utf-8")
    loader = ConfigLoader(config_path=config_path)
    with pytest.raises(ConfigurationError):
        loader.load()


def test_merge_config_and_policy(temp_dir: Path):
    config_path = temp_dir / "config.json"
    policy_path = temp_dir / "policy.json"
    config_path.write_text(json.dumps({"logging": {"level": "info"}}), encoding="utf-8")
    policy_path.write_text(json.dumps({"enabled_modules": ["UAC"]}), encoding="utf-8")
    loader = ConfigLoader(config_path=config_path, policy_path=policy_path)
    merged = loader.merge()
    assert merged["logging"]["level"] == "info"
    assert merged["enabled_modules"] == ["UAC"]


def test_save_config(temp_dir: Path):
    loader = ConfigLoader(config_path=temp_dir / "out.json")
    path = loader.save({"key": "value"})
    assert path.exists()
    assert json.loads(path.read_text(encoding="utf-8")) == {"key": "value"}
