# Changelog

All notable changes to GhostWall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-07-07

### Added

- Modular package structure with clean separation of concerns.
- 12 built-in hardening modules with compliance mappings.
- Plugin loader for custom modules.
- ECS-ready JSON logging with rotating file handlers.
- Multi-format reports: HTML, JSON, CSV, PDF.
- Remote WinRM orchestration with threaded execution.
- Background monitor for password changes, malware detections, and config drift.
- Toast notifications with plyer and win32 balloon fallbacks.
- Configuration loader supporting `config.json` and `policy.json`.
- Comprehensive pytest suite.
- GitHub Actions CI/CD pipeline with lint, security, test, and build jobs.
- Documentation suite (README, CHANGELOG, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, docs/).

### Changed

- Migrated from a single-file script to a professional enterprise package.
- Improved registry helpers with explicit WOW64 64-bit view.
- Reorganized CLI to support `--report-format` and `--config`.

### Fixed

- Locale-independent PowerShell object parsing.
- Dry-run propagation through all modules.
- Tamper-protection detection for Defender controls.
