"""Shared utility helpers for GhostWall.

All Windows-specific imports are guarded so the package remains importable
(and unit-testable) on non-Windows platforms. Operations that require a
Windows API degrade gracefully with clear error messages when invoked on an
incompatible host.
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ghostwall.constants import APP_NAME
from ghostwall.exceptions import PlatformNotSupportedError, PrivilegeError

logger = logging.getLogger("ghostwall")

# ---------------------------------------------------------------------------
# Guarded platform-specific imports
# ---------------------------------------------------------------------------
try:
    import winreg  # type: ignore
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore

try:
    import wmi as wmi_module  # type: ignore
except ImportError:  # pragma: no cover
    wmi_module = None  # type: ignore

try:
    import win32evtlog  # type: ignore
    import win32evtlogutil  # type: ignore

    HAS_WIN32_EVENTLOG = True
except ImportError:  # pragma: no cover
    win32evtlog = None  # type: ignore
    win32evtlogutil = None  # type: ignore
    HAS_WIN32_EVENTLOG = False

try:
    import win32gui  # type: ignore
    import win32con  # type: ignore
    import win32api  # type: ignore

    HAS_WIN32_GUI = True
except ImportError:  # pragma: no cover
    win32gui = None  # type: ignore
    win32con = None  # type: ignore
    win32api = None  # type: ignore
    HAS_WIN32_GUI = False

try:
    from plyer import notification as plyer_notification  # type: ignore

    HAS_PLYER = True
except ImportError:  # pragma: no cover
    plyer_notification = None  # type: ignore
    HAS_PLYER = False

# ---------------------------------------------------------------------------
# Runtime capability flags
# ---------------------------------------------------------------------------
IS_WINDOWS: bool = os.name == "nt"


# ---------------------------------------------------------------------------
# Privilege / platform helpers
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    """Return True if the current process has administrator privileges."""
    if not IS_WINDOWS or ctypes is None:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_windows(operation: str) -> None:
    """Raise PlatformNotSupportedError if the current OS is not Windows."""
    if not IS_WINDOWS:
        raise PlatformNotSupportedError(f"{operation} requires Windows. Current platform: {os.name}")


def require_admin(operation: str) -> None:
    """Raise PrivilegeError if the current process is not elevated."""
    if not is_admin():
        raise PrivilegeError(f"{operation} requires administrator privileges.")


def get_hostname() -> str:
    """Return the local host name."""
    return socket.gethostname()


# ---------------------------------------------------------------------------
# Lazy WMI connection
# ---------------------------------------------------------------------------
class WmiConnection:
    """Thread-safe-ish lazy wrapper around the local WMI connection."""

    def __init__(self) -> None:
        self._conn: Optional[Any] = None

    def get(self) -> Any:
        """Return the local WMI CIMV2 connection, initializing it if needed."""
        if self._conn is None:
            if wmi_module is None:
                raise RuntimeError("The 'wmi' package is required for this action (pip install wmi).")
            self._conn = wmi_module.WMI()
        return self._conn

    def reset(self) -> None:
        """Drop the cached connection so the next call creates a fresh one."""
        self._conn = None


wmi_connection = WmiConnection()


# ---------------------------------------------------------------------------
# Command execution helpers
# ---------------------------------------------------------------------------
def run_ps_json(
    ps_body: str,
    dry_run: bool = False,
    timeout: int = 30,
) -> Tuple[bool, Optional[Any]]:
    """Run a PowerShell command and parse its JSON output.

    The command body is piped through ConvertTo-Json so we consume structured
    data instead of scraping localized display text.
    """
    full_cmd = f"{ps_body} | ConvertTo-Json -Depth 5 -Compress"
    if dry_run:
        logger.info("[DRY-RUN] Would run PS: %s", ps_body)
        return True, None
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                full_cmd,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        logger.info("PS OK: %s", ps_body)
        out = result.stdout.strip()
        if not out:
            return True, None
        return True, json.loads(out)
    except subprocess.CalledProcessError as exc:
        logger.warning("PS FAILED: %s -- %s", ps_body, exc.stderr.strip())
        return False, None
    except json.JSONDecodeError as exc:
        logger.error("PS output not valid JSON for '%s': %s", ps_body, exc)
        return False, None
    except Exception as exc:  # noqa: BLE001
        logger.error("PS EXCEPTION for '%s': %s", ps_body, exc)
        return False, None


def run_ps_action(
    ps_body: str,
    dry_run: bool = False,
    timeout: int = 30,
) -> bool:
    """Run a PowerShell command purely for its side effect."""
    if dry_run:
        logger.info("[DRY-RUN] Would run PS action: %s", ps_body)
        return True
    try:
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps_body,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        logger.info("PS ACTION OK: %s", ps_body)
        return True
    except subprocess.CalledProcessError as exc:
        logger.warning("PS ACTION FAILED: %s -- %s", ps_body, exc.stderr.strip())
        return False
    except Exception as exc:  # noqa: BLE001
        logger.error("PS ACTION EXCEPTION for '%s': %s", ps_body, exc)
        return False


def run_cmd(
    cmd: str,
    dry_run: bool = False,
    timeout: int = 30,
    shell: bool = True,
) -> Tuple[bool, str]:
    """Run an arbitrary command, returning (ok, stdout/stderr text).

    This is the escape hatch for tools without a clean object API (e.g.
    ``bcdedit``). It should be used sparingly; prefer PowerShell JSON-based
    helpers when possible.
    """
    if dry_run:
        logger.info("[DRY-RUN] Would run: %s", cmd)
        return True, "(dry-run, not executed)"
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        logger.info("RUN OK: %s", cmd)
        return True, result.stdout
    except subprocess.CalledProcessError as exc:
        logger.warning("RUN FAILED: %s -- %s", cmd, exc.stderr.strip())
        return False, exc.stderr
    except Exception as exc:  # noqa: BLE001
        logger.error("RUN EXCEPTION: %s: %s", cmd, exc)
        return False, str(exc)


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
def _ensure_winreg() -> Any:
    """Return the winreg module or raise PlatformNotSupportedError."""
    if winreg is None:
        raise PlatformNotSupportedError("Windows registry access requires Windows.")
    return winreg


def reg_get(hive: int, path: str, name: str) -> Optional[Any]:
    """Read a registry value using the 64-bit view of the registry.

    Without ``KEY_WOW64_64KEY``, a 32-bit Python interpreter on 64-bit Windows
    is redirected to ``Wow6432Node``, causing check/apply mismatches with
    64-bit readers.
    """
    _ensure_winreg()
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)  # type: ignore
        val, _ = winreg.QueryValueEx(key, name)  # type: ignore
        winreg.CloseKey(key)  # type: ignore
        return val
    except Exception:
        return None


def reg_set(
    hive: int,
    path: str,
    name: str,
    value: Any,
    vtype: Optional[int] = None,
    dry_run: bool = False,
) -> bool:
    """Create or update a registry value using the 64-bit view."""
    _ensure_winreg()
    if vtype is None:
        vtype = winreg.REG_DWORD  # type: ignore
    if dry_run:
        logger.info("[DRY-RUN] Would set %s\\%s = %s", path, name, value)
        return True
    try:
        key = winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)  # type: ignore
        winreg.SetValueEx(key, name, 0, vtype, value)  # type: ignore
        winreg.CloseKey(key)  # type: ignore
        logger.info("REG SET: %s\\%s = %s", path, name, value)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("REG SET FAILED %s\\%s: %s", path, name, exc)
        return False


def reg_delete(
    hive: int,
    path: str,
    name: str,
    dry_run: bool = False,
) -> bool:
    """Delete a registry value; returns True if already absent."""
    _ensure_winreg()
    if dry_run:
        logger.info("[DRY-RUN] Would delete %s\\%s", path, name)
        return True
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)  # type: ignore
        winreg.DeleteValue(key, name)  # type: ignore
        winreg.CloseKey(key)  # type: ignore
        return True
    except FileNotFoundError:
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("REG DELETE FAILED %s\\%s: %s", path, name, exc)
        return False


# ---------------------------------------------------------------------------
# Windows Event Log sink
# ---------------------------------------------------------------------------
def log_to_windows_eventlog(
    message: str,
    event_id_offset: int = 0,
    is_error: bool = False,
) -> None:
    """Write a custom event to the Windows Application event log.

    Silently no-ops if pywin32 is unavailable or the source is not registered.
    """
    if not HAS_WIN32_EVENTLOG:
        logger.debug("pywin32 not installed — skipping Windows Event Log write.")
        return
    try:
        event_type = (
            win32evtlog.EVENTLOG_ERROR_TYPE  # type: ignore
            if is_error
            else win32evtlog.EVENTLOG_INFORMATION_TYPE  # type: ignore
        )
        win32evtlogutil.ReportEvent(  # type: ignore
            APP_NAME,
            9000 + event_id_offset,
            eventCategory=1,
            eventType=event_type,
            strings=[message],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not write to Windows Event Log: %s", exc)


# ---------------------------------------------------------------------------
# File / path helpers
# ---------------------------------------------------------------------------
def load_text_lines(path: Path) -> List[str]:
    """Load non-empty, non-comment lines from a text file."""
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def ensure_dir(path: Path) -> Path:
    """Create a directory (and parents) if it does not exist."""
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Generic retry helper
# ---------------------------------------------------------------------------
def retry(
    fn: Callable[[], bool],
    attempts: int = 3,
    delay: float = 1.0,
) -> bool:
    """Retry a predicate until it returns True or attempts are exhausted."""
    for attempt in range(attempts):
        try:
            if fn():
                return True
        except Exception:  # noqa: BLE001
            pass
        if attempt < attempts - 1:
            time.sleep(delay)
    return False


# ---------------------------------------------------------------------------
# Public capability introspection
# ---------------------------------------------------------------------------
def platform_capabilities() -> Dict[str, bool]:
    """Return a dictionary describing available platform integrations."""
    return {
        "windows": IS_WINDOWS,
        "admin": is_admin(),
        "winreg": winreg is not None,
        "wmi": wmi_module is not None,
        "win32eventlog": HAS_WIN32_EVENTLOG,
        "win32gui": HAS_WIN32_GUI,
        "plyer": HAS_PLYER,
    }
