# Plugin Development

GhostWall loads custom hardening modules from the `plugins/` directory
automatically at startup.

## Plugin contract

A plugin file must:

* Be a `.py` file in `plugins/` (underscore-prefixed files are ignored).
* Define a top-level `register()` callable.
* Return a `SecurityModule` subclass, or a list of subclasses.

## Minimal example

```python
from ghostwall.core import SecurityModule


class MyPlugin(SecurityModule):
    def __init__(self, dry_run: bool = False):
        super().__init__("My Plugin", destructive=False)
        self.dry_run = dry_run

    def apply(self) -> bool:
        return True

    def check(self) -> bool:
        return True

    def backup(self) -> dict:
        return {}

    def restore(self, state: dict) -> bool:
        return True


def register():
    return MyPlugin
```

## Access to engine context

The engine constructs plugin instances with a single positional argument:
`dry_run: bool`. Plugins should respect this flag and avoid making changes when
`dry_run=True`.

## Best practices

* Use `ghostwall.utils.run_ps_action`, `run_ps_json`, `reg_get`, `reg_set`, and
  `run_cmd` for system interaction.
* Capture enough state in `backup()` to restore the original configuration.
* Tag controls with CIS, MITRE, and NIST references for compliance reporting.
* Raise clear exceptions; the engine catches them and marks the module failed.
