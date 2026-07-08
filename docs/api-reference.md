# API Reference

This page documents the primary public classes and functions in GhostWall.

## `ghostwall.engine.SecurityEngine`

Main orchestration class.

```python
from ghostwall.engine import SecurityEngine

engine = SecurityEngine(dry_run=True)
engine.run_audit()
engine.show_status()
engine.generate_html_report()
```

### Constructor arguments

* `dry_run: bool` — simulate without changing the system.
* `auto_yes: bool` — skip destructive-module confirmation.
* `encrypt_backup: bool` — encrypt rollback backups.
* `use_eventlog: bool` — write completion events to Windows Event Log.
* `log_dir`, `backup_dir`, `report_dir: Path` — output directories.
* `console: Console` — Rich console for UI output.

### Key methods

* `run_audit()` — backup, apply, verify all modules.
* `show_status(post_audit=False)` — render posture table.
* `rollback(backup_file: Path)` — restore from backup.
* `generate_html_report()` / `generate_json_report()` / `generate_csv_report()` / `generate_pdf_report()`.
* `load_configuration(path: Path)` — load JSON config/policy overrides.

## `ghostwall.core.SecurityModule`

Abstract base class for hardening modules.

Required methods:

* `apply() -> bool`
* `check() -> bool`
* `backup() -> dict`
* `restore(state: dict) -> bool`

## `ghostwall.backup.BackupManager`

* `save(data: dict) -> Path`
* `load(path=None) -> dict`
* `build_backup(modules, host, timestamp, app_version) -> dict`
* `restore_backup(modules, data) -> dict[str, bool]`

## `ghostwall.remote.orchestrator.RemoteOrchestrator`

* `run(hosts: list[str]) -> list[dict]`

## `ghostwall.monitor.SecurityMonitor`

* `run_forever()` — start the polling loop.

## `ghostwall.notifications.ToastNotifier`

* `notify(title: str, message: str, duration: int = 10)`

## `ghostwall.config.loader.ConfigLoader`

* `load(path=None) -> dict`
* `merge() -> dict`
