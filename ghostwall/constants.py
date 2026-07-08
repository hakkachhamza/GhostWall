"""Global constants for the GhostWall security framework."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

# ---------------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------------
APP_NAME: str = "GhostWall"
APP_DISPLAY_NAME: str = "GhostWall — Enterprise Windows Security Hardening"
APP_VERSION: str = "2.0.0"
APP_DESCRIPTION: str = (
    "A compliance-mapped, rollback-capable, multi-host security hardening " "orchestrator for Windows fleets."
)
APP_AUTHOR: str = "GhostWall Contributors"
APP_LICENSE: str = "MIT"

# ---------------------------------------------------------------------------
# Platform / environment
# ---------------------------------------------------------------------------
WINDOWS_EVENTLOG_SOURCE: str = APP_NAME
WINDOWS_EVENTLOG_BASE_ID: int = 9_000

ENV_BACKUP_KEY: str = "GHOSTWALL_BACKUP_KEY"
ENV_REMOTE_USER: str = "GHOSTWALL_REMOTE_USER"
ENV_REMOTE_PASS: str = "GHOSTWALL_REMOTE_PASS"

# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
ASSETS_DIR: Path = PROJECT_ROOT / "assets"
BACKUPS_DIR: Path = PROJECT_ROOT / "backups"
LOGS_DIR: Path = PROJECT_ROOT / "logs"
REPORTS_DIR: Path = PROJECT_ROOT / "reports"
CONFIG_DIR: Path = PROJECT_ROOT / "config"
PLUGINS_DIR: Path = PROJECT_ROOT / "plugins"

for _dir in (BACKUPS_DIR, LOGS_DIR, REPORTS_DIR, CONFIG_DIR, PLUGINS_DIR):
    _dir.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Registry key constants
# ---------------------------------------------------------------------------
REG_PATH_TERMINAL_SERVER: str = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
REG_PATH_UAC_POLICIES: str = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
REG_PATH_LLMNR: str = r"Software\Policies\Microsoft\Windows NT\DNSClient"
REG_PATH_PRIVACY_TELEMETRY: str = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
REG_PATH_PRIVACY_ADVERTISING: str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
REG_PATH_AUTORUN_POLICIES: str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
REG_PATH_STARTUP_RUN: str = r"Software\Microsoft\Windows\CurrentVersion\Run"

# ---------------------------------------------------------------------------
# Default security policies
# ---------------------------------------------------------------------------
DEFAULT_PASSWORD_MIN_LENGTH: int = 14
DEFAULT_PASSWORD_MAX_AGE: int = 30
DEFAULT_LOCKOUT_THRESHOLD: int = 3

# ---------------------------------------------------------------------------
# Framework mappings
# ---------------------------------------------------------------------------
FRAMEWORK_CIS: str = "cis"
FRAMEWORK_MITRE: str = "mitre"
FRAMEWORK_NIST: str = "nist"

FRAMEWORK_LABELS: List[str] = [FRAMEWORK_CIS, FRAMEWORK_MITRE, FRAMEWORK_NIST]

# ---------------------------------------------------------------------------
# Compliance mapping helpers
# ---------------------------------------------------------------------------
CIS_V8: str = "v8"
MITRE_ATTACK: str = "attack"
NIST_SP800_53: str = "800-53"


def cis(ref: str) -> str:
    """Return a formatted CIS v8 reference."""
    return f"{CIS_V8}-{ref}"


def mitre(ref: str) -> str:
    """Return a formatted MITRE ATT&CK mitigation reference."""
    return f"{MITRE_ATTACK}-{ref}"


def nist(ref: str) -> str:
    """Return a formatted NIST SP 800-53 control reference."""
    return f"{NIST_SP800_53}-{ref}"


# ---------------------------------------------------------------------------
# Module metadata (human-readable descriptions + framework tags)
# ---------------------------------------------------------------------------
MODULE_DESCRIPTIONS: Dict[str, str] = {
    "Firewall Enforcement": "Enables Windows Firewall on all profiles; default inbound=block, outbound=allow.",
    "Remote Desktop Lockdown": "Disables the Remote Desktop (TermService) and blocks new RDP connections.",
    "Ransomware Protection": "Enables Microsoft Defender Controlled Folder Access.",
    "Defender Real-Time Protection": "Ensures Microsoft Defender real-time monitoring is enabled.",
    "UAC Maximization": "Sets User Account Control to 'Always Notify' (ConsentPromptBehaviorAdmin=4).",
    "DEP Enforcement": "Enables Data Execution Prevention for all processes via BCD (nx AlwaysOn).",
    "Legacy Protocol Removal": "Disables SMBv1 and LLMNR broadcast name resolution.",
    "Privacy Hardening": "Reduces telemetry collection level and disables the advertising ID.",
    "Guest Account Lockdown": "Disables the built-in Guest local account.",
    "Autorun/Autoplay Disable": "Disables Autorun and Autoplay for all drives.",
    "PowerShell Script Policy": "Sets the machine-wide PowerShell execution policy to RemoteSigned.",
    "Password Policy": "Enforces min length 14, max age 30 days, lockout after 3 failed attempts.",
}

MODULE_FRAMEWORKS: Dict[str, Dict[str, List[str]]] = {
    "Firewall Enforcement": {
        FRAMEWORK_CIS: [cis("4.5"), cis("13.1")],
        FRAMEWORK_MITRE: ["M1030", "M1037"],
        FRAMEWORK_NIST: ["SC-7", "CM-7"],
    },
    "Remote Desktop Lockdown": {
        FRAMEWORK_CIS: [cis("4.8")],
        FRAMEWORK_MITRE: ["M1042", "M1035"],
        FRAMEWORK_NIST: ["AC-17", "CM-7"],
    },
    "Ransomware Protection": {
        FRAMEWORK_CIS: [cis("10.1")],
        FRAMEWORK_MITRE: ["M1040"],
        FRAMEWORK_NIST: ["SI-3", "SI-7"],
    },
    "Defender Real-Time Protection": {
        FRAMEWORK_CIS: [cis("10.1")],
        FRAMEWORK_MITRE: ["M1049"],
        FRAMEWORK_NIST: ["SI-3"],
    },
    "UAC Maximization": {
        FRAMEWORK_CIS: [cis("4.1"), cis("5.4")],
        FRAMEWORK_MITRE: ["M1052"],
        FRAMEWORK_NIST: ["AC-6", "CM-6"],
    },
    "DEP Enforcement": {
        FRAMEWORK_CIS: [cis("10.5")],
        FRAMEWORK_MITRE: ["M1050"],
        FRAMEWORK_NIST: ["SI-16"],
    },
    "Legacy Protocol Removal": {
        FRAMEWORK_CIS: [cis("4.8"), cis("12.1")],
        FRAMEWORK_MITRE: ["M1042"],
        FRAMEWORK_NIST: ["CM-7", "SC-7"],
    },
    "Privacy Hardening": {
        FRAMEWORK_CIS: [cis("3.3")],
        FRAMEWORK_MITRE: ["M1057"],
        FRAMEWORK_NIST: ["SC-28"],
    },
    "Guest Account Lockdown": {
        FRAMEWORK_CIS: [cis("5.1"), cis("5.2")],
        FRAMEWORK_MITRE: ["M1027", "M1036"],
        FRAMEWORK_NIST: ["AC-2", "IA-4"],
    },
    "Autorun/Autoplay Disable": {
        FRAMEWORK_CIS: [cis("10.3")],
        FRAMEWORK_MITRE: ["M1042", "M1034"],
        FRAMEWORK_NIST: ["MP-7"],
    },
    "PowerShell Script Policy": {
        FRAMEWORK_CIS: [cis("2.6"), cis("8.5")],
        FRAMEWORK_MITRE: ["M1038", "M1045"],
        FRAMEWORK_NIST: ["CM-7", "SI-3"],
    },
    "Password Policy": {
        FRAMEWORK_CIS: [cis("5.2"), cis("6.1")],
        FRAMEWORK_MITRE: ["M1027"],
        FRAMEWORK_NIST: ["IA-5", "AC-7"],
    },
}

# ---------------------------------------------------------------------------
# Scoring thresholds
# ---------------------------------------------------------------------------
SCORE_GOOD_THRESHOLD: int = 85
SCORE_WARNING_THRESHOLD: int = 60

# ---------------------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------------------
MONITOR_POLL_SECONDS: int = 60

# ---------------------------------------------------------------------------
# Banner animation
# ---------------------------------------------------------------------------
BANNER_WAVE_COLORS: List[str] = [
    "green4",
    "green3",
    "spring_green3",
    "bright_green",
    "cyan",
    "bright_cyan",
    "spring_green3",
    "green3",
]
BANNER_FRAME_COUNT: int = 15
BANNER_FRAME_DURATION: float = 1.5 / BANNER_FRAME_COUNT
