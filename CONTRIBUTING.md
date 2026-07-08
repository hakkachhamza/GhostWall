# Contributing to GhostWall

Thank you for your interest in contributing! This document outlines the process
for reporting issues, proposing features, and submitting code.

## How to contribute

1. **Fork** the repository.
2. **Create a branch** for your change (`git checkout -b feature/my-feature`).
3. **Make your changes** following the coding standards below.
4. **Run tests** (`make test`).
5. **Run linting** (`make lint`).
6. **Commit** with a clear message.
7. **Open a pull request** against `main`.

## Coding standards

- Follow PEP 8.
- Use type hints where practical.
- Write docstrings for public modules, classes, and functions.
- Keep functions focused and small.
- Guard Windows-only imports so the package remains importable on Linux/macOS.
- Add or update tests for any changed behavior.

## Development setup

```bash
git clone https://github.com/hakkachhamza/GhostWall.git
cd ghostwall
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Reporting bugs

Use the issue tracker at https://github.com/hakkachhamza/GhostWall/issues or email
**hakkachhamza0@gmail.com** and include:

- GhostWall version
- Python version and OS
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or screenshots

## Proposing features

Open a discussion first for large features. For small enhancements, an issue is
sufficient.

## Code of conduct

All contributors are expected to adhere to the [Code of Conduct](CODE_OF_CONDUCT.md).
