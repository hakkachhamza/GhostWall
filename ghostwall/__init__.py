"""GhostWall — Enterprise Windows Security Hardening & Orchestration Framework."""

from __future__ import annotations

from ghostwall.constants import (
    APP_NAME,
    APP_VERSION,
    APP_DESCRIPTION,
    APP_AUTHOR,
    APP_LICENSE,
)
from ghostwall.engine import SecurityEngine

__version__ = APP_VERSION
__all__ = [
    "APP_NAME",
    "APP_VERSION",
    "APP_DESCRIPTION",
    "APP_AUTHOR",
    "APP_LICENSE",
    "SecurityEngine",
]
