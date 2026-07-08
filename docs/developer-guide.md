# Developer Guide

## Getting started

```bash
git clone https://github.com/hakkachhamza/GhostWall.git
cd ghostwall
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Project layout

```text
ghostwall/
  __init__.py          Package metadata
  cli.py               Entry point and argument parsing
  engine.py            Main orchestration engine
  core.py              Domain models (SecurityModule, ModuleResult)
  backup.py            Backup / rollback engine
  logger.py            ECS-ready logging
  monitor.py           Background watcher
  notifications.py     Toast notifications
  reports.py           HTML/JSON/CSV/PDF reports
  startup.py           Autostart registration
  utils.py             PowerShell / registry / WMI helpers
  constants.py         Shared constants and mappings
  exceptions.py        Custom exceptions
  modules/             Built-in hardening modules
  remote/              WinRM orchestration
  ui/                  Rich console UI
  config/              Configuration loader
  plugins/             Plugin directory
```

## Running tests

```bash
make test
# or
python -m pytest -v
```

## Linting and formatting

```bash
make lint
make format
make format-fix
```

## Security scanning

```bash
make security
# or
python -m bandit -r ghostwall
python -m safety check
```

## Adding a new module

1. Create `ghostwall/modules/your_module.py`.
2. Inherit from `SecurityModuleBase`.
3. Implement `_apply`, `_check`, `_backup`, `_restore`.
4. Add descriptions and framework mappings to `ghostwall/constants.py`.
5. Register the module in `SecurityEngine._build_modules`.
6. Add unit tests under `tests/`.

## Adding a plugin

Plugins live in `plugins/` and expose a `register()` function returning a
`SecurityModule` subclass. See `examples/custom_plugin.py`.
