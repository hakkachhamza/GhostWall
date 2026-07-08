# Security Modules

GhostWall ships with the following built-in hardening modules. Each module can
be applied, checked, backed up, and rolled back independently.

| Module | Description | Destructive | CIS | MITRE | NIST |
|--------|-------------|-------------|-----|-------|------|
| Firewall Enforcement | Enable Windows Firewall on all profiles; block inbound, allow outbound | No | v8-4.5, v8-13.1 | M1030, M1037 | SC-7, CM-7 |
| Remote Desktop Lockdown | Disable RDP and TermService | Yes | v8-4.8 | M1042, M1035 | AC-17, CM-7 |
| Ransomware Protection | Enable Controlled Folder Access | No | v8-10.1 | M1040 | SI-3, SI-7 |
| Defender Real-Time Protection | Ensure real-time monitoring is enabled | No | v8-10.1 | M1049 | SI-3 |
| UAC Maximization | Set UAC to Always Notify | No | v8-4.1, v8-5.4 | M1052 | AC-6, CM-6 |
| DEP Enforcement | Enable nx AlwaysOn via BCD | No | v8-10.5 | M1050 | SI-16 |
| Legacy Protocol Removal | Disable SMBv1 and LLMNR | Yes | v8-4.8, v8-12.1 | M1042 | CM-7, SC-7 |
| Privacy Hardening | Reduce telemetry and disable advertising ID | No | v8-3.3 | M1057 | SC-28 |
| Guest Account Lockdown | Disable the built-in Guest account | Yes | v8-5.1, v8-5.2 | M1027, M1036 | AC-2, IA-4 |
| Autorun/Autoplay Disable | Disable Autorun for all drives | No | v8-10.3 | M1042, M1034 | MP-7 |
| PowerShell Script Policy | Set execution policy to RemoteSigned | No | v8-2.6, v8-8.5 | M1038, M1045 | CM-7, SI-3 |
| Password Policy | Enforce length, age, and lockout | Yes | v8-5.2, v8-6.1 | M1027 | IA-5, AC-7 |

## Implementation notes

* **Locale independence**: Wherever possible, modules use PowerShell objects
  (`ConvertTo-Json`) and registry values instead of scraping localized text.
* **WOW64 safety**: Registry helpers use `KEY_WOW64_64KEY` so 32-bit and 64-bit
  readers agree on the key being modified.
* **Tamper protection**: The Defender modules detect when Tamper Protection
  blocks a requested change and surface a clear explanation.
* **Reboot requirements**: Some controls (e.g., SMB1, DEP) may require a reboot
  before the check reflects the applied state.
