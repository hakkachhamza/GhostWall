"""Cross-platform notification subsystem for GhostWall.

On Windows, the notifier prefers ``plyer`` (modern toast UI) and falls back to
a classic ``Shell_NotifyIcon`` balloon via pywin32. If neither is available,
it prints a panel to the configured console so no notification is silently
lost.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from rich.panel import Panel

from ghostwall.constants import APP_NAME
from ghostwall.utils import HAS_PLYER, HAS_WIN32_GUI, plyer_notification, win32api, win32con, win32gui

logger = logging.getLogger("ghostwall")


class ToastNotifier:
    """Deliver notification-area / Action Center toasts.

    Args:
        app_name: Name displayed as the toast source.
        console: Optional Rich console for fallback rendering.
    """

    def __init__(
        self,
        app_name: str = APP_NAME,
        console: Optional[Any] = None,
    ) -> None:
        self.app_name = app_name
        self.console = console
        self._hwnd: Optional[int] = None
        if not HAS_PLYER and HAS_WIN32_GUI:
            self._init_balloon_window()

    def _init_balloon_window(self) -> None:
        try:
            wc = win32gui.WNDCLASS()  # type: ignore
            wc.hInstance = win32api.GetModuleHandle(None)  # type: ignore
            wc.lpszClassName = f"{self.app_name}ToastWndCls"
            wc.lpfnWndProc = {}
            class_atom = win32gui.RegisterClass(wc)  # type: ignore
            self._hwnd = win32gui.CreateWindow(  # type: ignore
                class_atom,
                self.app_name,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                wc.hInstance,
                None,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to initialize balloon fallback window: %s", exc)
            self._hwnd = None

    def notify(self, title: str, message: str, duration: int = 10) -> None:
        """Show a toast notification with the supplied title and message."""
        if HAS_PLYER:
            try:
                plyer_notification.notify(  # type: ignore
                    title=title,
                    message=message,
                    app_name=self.app_name,
                    timeout=duration,
                )
                return
            except Exception as exc:  # noqa: BLE001
                logger.debug("Toast (plyer) failed: %s", exc)

        if HAS_WIN32_GUI and self._hwnd is not None:
            try:
                flags = (
                    win32gui.NIF_ICON  # type: ignore
                    | win32gui.NIF_MESSAGE  # type: ignore
                    | win32gui.NIF_TIP  # type: ignore
                    | win32gui.NIF_INFO  # type: ignore
                )
                hicon = win32gui.LoadIcon(0, win32con.IDI_APPLICATION)  # type: ignore
                nid = (
                    self._hwnd,
                    0,
                    flags,
                    win32con.WM_USER + 20,  # type: ignore
                    hicon,
                    self.app_name,
                    message,
                    duration * 1000,
                    title,
                )
                win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, nid)  # type: ignore
                win32gui.Shell_NotifyIcon(win32gui.NIM_MODIFY, nid)  # type: ignore
                return
            except Exception as exc:  # noqa: BLE001
                logger.debug("Toast (win32 balloon) failed: %s", exc)

        # Last-resort fallback
        if self.console is not None:
            self.console.print(Panel(message, title=f"[warning]{title}[/]", border_style="yellow"))
        else:
            logger.info("[%s] %s", title, message)
