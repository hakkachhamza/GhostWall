"""Security hardening modules for GhostWall."""

from __future__ import annotations

from ghostwall.modules.base import SecurityModuleBase
from ghostwall.modules.firewall import FirewallModule
from ghostwall.modules.defender import (
    ControlledFolderAccessModule,
    DefenderRealtimeModule,
)
from ghostwall.modules.rdp import RdpModule
from ghostwall.modules.dep import DepModule
from ghostwall.modules.privacy import PrivacyModule
from ghostwall.modules.smb import LegacyProtocolModule
from ghostwall.modules.guest import GuestAccountModule
from ghostwall.modules.autorun import AutorunModule
from ghostwall.modules.powershell import PowerShellPolicyModule
from ghostwall.modules.password import PasswordPolicyModule
from ghostwall.modules.uac import UacModule

__all__ = [
    "SecurityModuleBase",
    "FirewallModule",
    "ControlledFolderAccessModule",
    "DefenderRealtimeModule",
    "RdpModule",
    "DepModule",
    "PrivacyModule",
    "LegacyProtocolModule",
    "GuestAccountModule",
    "AutorunModule",
    "PowerShellPolicyModule",
    "PasswordPolicyModule",
    "UacModule",
]
