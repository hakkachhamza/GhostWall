# Installation Guide

GhostWall is a Python package that runs on the host performing the
orchestration. Local hardening requires Windows with administrator privileges;
remote WinRM orchestration can be driven from Windows, Linux, or macOS.

## Requirements

### Host running GhostWall

* Python 3.9 or newer
* pip

### Target Windows hosts (for local hardening)

* Windows 10, Windows 11, or Windows Server 2016+
* PowerShell 5.1 or PowerShell 7+
* Administrator privileges
* WinRM listener enabled (for remote orchestration)

## Install from PyPI

```bash
pip install ghostwall
```

## Install from source

```bash
git clone https://github.com/hakkachhamza/GhostWall.git
cd ghostwall
pip install -e .
```

## Optional extras

```bash
# Windows-only integrations (pywin32, wmi)
pip install -e ".[windows]"

# Encrypted backups
pip install -e ".[encrypt]"

# PDF reports
pip install -e ".[pdf]"

# Everything
pip install -e ".[all]"

# Development tools
pip install -e ".[dev]"
```

## Verify installation

```bash
ghostwall --help
python -m ghostwall.cli --status
```
