"""Tests for the GhostWall firewall module."""

from __future__ import annotations

from ghostwall.modules.firewall import FirewallModule


def test_firewall_module_dry_run_apply(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "ghostwall.modules.firewall.run_ps_action",
        lambda ps_body, dry_run: calls.append((ps_body, dry_run)) or True,
    )

    module = FirewallModule(dry_run=True)
    result = module.apply()
    assert result is True
    assert any("Set-NetFirewallProfile" in cmd for cmd, _ in calls)


def test_firewall_check_secure(monkeypatch):
    monkeypatch.setattr(
        "ghostwall.modules.firewall.run_ps_json",
        lambda ps_body, dry_run: (
            True,
            [
                {"Name": "Domain", "Enabled": True, "DefaultInboundAction": "Block"},
                {"Name": "Private", "Enabled": 1, "DefaultInboundAction": 4},
            ],
        ),
    )
    module = FirewallModule(dry_run=False)
    assert module.check() is True


def test_firewall_check_vulnerable(monkeypatch):
    monkeypatch.setattr(
        "ghostwall.modules.firewall.run_ps_json",
        lambda ps_body, dry_run: (True, {"Name": "Domain", "Enabled": False, "DefaultInboundAction": "Block"}),
    )
    module = FirewallModule(dry_run=False)
    assert module.check() is False


def test_firewall_backup_and_restore(monkeypatch):
    state = {
        "profiles": [
            {"Name": "Domain", "Enabled": True, "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"}
        ]
    }
    monkeypatch.setattr(
        "ghostwall.modules.firewall.run_ps_json",
        lambda ps_body, dry_run: (True, state["profiles"]),
    )
    action_calls = []
    monkeypatch.setattr(
        "ghostwall.modules.firewall.run_ps_action",
        lambda ps_body, dry_run: action_calls.append(ps_body) or True,
    )

    module = FirewallModule(dry_run=False)
    backup = module.backup()
    assert backup["profiles"] == state["profiles"]
    assert module.restore(backup) is True
    assert any("Domain" in cmd for cmd in action_calls)
