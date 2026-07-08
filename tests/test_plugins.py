"""Tests for the GhostWall plugin loader."""

from __future__ import annotations

from pathlib import Path

from ghostwall.plugins.loader import PluginLoader


def test_plugin_loader_discovers_valid_plugin(temp_dir: Path):
    plugin_file = temp_dir / "custom_plugin.py"
    plugin_file.write_text(
        "from ghostwall.core import SecurityModule\n"
        "class CustomModule(SecurityModule):\n"
        "    def apply(self): return True\n"
        "    def check(self): return True\n"
        "    def backup(self): return {}\n"
        "    def restore(self, state): return True\n"
        "def register(): return CustomModule\n",
        encoding="utf-8",
    )
    loader = PluginLoader(plugins_dir=temp_dir)
    classes = loader.discover()
    assert len(classes) == 1
    assert classes[0].__name__ == "CustomModule"


def test_plugin_loader_ignores_underscore_files(temp_dir: Path):
    hidden = temp_dir / "_private.py"
    hidden.write_text("def register(): pass\n", encoding="utf-8")
    loader = PluginLoader(plugins_dir=temp_dir)
    assert loader.discover() == []


def test_plugin_loader_skips_invalid_register(temp_dir: Path):
    bad = temp_dir / "bad.py"
    bad.write_text("def register(): return 42\n", encoding="utf-8")
    loader = PluginLoader(plugins_dir=temp_dir)
    assert loader.discover() == []
