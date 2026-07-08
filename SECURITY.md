# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | ✅ Yes    |
| 1.0.x   | ❌ No     |

## Reporting a vulnerability

If you discover a security vulnerability in GhostWall, please report it
responsibly:

1. **Do not open a public issue.**
2. Open a [GitHub Security Advisory](https://github.com/hakkachhamza/GhostWall/security/advisories/new)
   or email **hakkachhamza0@gmail.com** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Any suggested remediation

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Security practices

- GhostWall **never** stores remote credentials. They are accepted via
  environment variables or interactive prompts only.
- Backup encryption keys are generated per-run and must be stored securely by
  the operator.
- The tool requires administrator privileges because it intentionally modifies
  system security settings.
- All subprocess invocations use bounded timeouts and avoid shell injection by
  passing structured PowerShell commands.

## Running security scans

```bash
python -m bandit -r ghostwall
python -m safety check
```
