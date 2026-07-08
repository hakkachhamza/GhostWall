# Architecture

GhostWall is organized as a layered, modular security framework.

```text
┌─────────────────────────────────────────────────────────────┐
│                         CLI / UI                            │
│  ghostwall/cli.py  |  ghostwall/ui/                         │
├─────────────────────────────────────────────────────────────┤
│                      Security Engine                         │
│  ghostwall/engine.py — orchestration, audit, rollback        │
├─────────────────────────────────────────────────────────────┤
│                    Hardening Modules                         │
│  ghostwall/modules/ — firewall, defender, rdp, uac, ...      │
├─────────────────────────────────────────────────────────────┤
│         Backup / Logging / Reports / Notifications           │
│  ghostwall/backup.py, logger.py, reports.py, notifications   │
├─────────────────────────────────────────────────────────────┤
│              Remote Orchestration (WinRM)                    │
│  ghostwall/remote/orchestrator.py, winrm.py                  │
├─────────────────────────────────────────────────────────────┤
│              Plugins / Configuration                         │
│  ghostwall/plugins/, ghostwall/config/                       │
├─────────────────────────────────────────────────────────────┤
│           Windows-specific execution helpers                 │
│  ghostwall/utils.py — PowerShell, registry, WMI              │
└─────────────────────────────────────────────────────────────┘
```

## Design principles

* **Separation of concerns**: CLI, engine, modules, and reports are independent.
* **Guarded imports**: All Windows-only imports are optional so the package
  imports cleanly on any OS.
* **Dry-run first**: Every module supports `--dry-run` simulation.
* **Rollback capable**: Every module captures and restores its pre-change state.
* **Compliance mapped**: Each control is tagged with CIS, MITRE, and NIST references.
* **Extensible**: Custom modules are loaded automatically from `plugins/`.

## Data flow

1. CLI parses arguments and constructs a `SecurityEngine`.
2. The engine builds built-in modules and discovers plugins.
3. For `--audit`, the engine backs up state, applies each module, then verifies.
4. Results are logged to rotating text and ECS-JSON logs.
5. Reports can be generated in HTML, JSON, CSV, or PDF.
6. Rollback uses `BackupManager` to restore captured state.
