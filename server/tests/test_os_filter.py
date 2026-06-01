"""Filtrare pe OS in motorul de reguli: @rule(os=) + _scan_os + evaluate."""
import pytest
from server.app import rules
from server.app.rules import evaluate, _scan_os


def _linux_scan(scan_type="standard"):
    return {"scan_type": scan_type,
            "os": {"system": "Linux", "release": "6.5", "is_admin": False},
            "network": {"open_ports": []}, "processes": [], "software": []}


def test_scan_os_detects_linux_windows_other():
    assert _scan_os({"os": {"system": "Linux"}}) == "linux"
    assert _scan_os({"os": {"system": "Windows"}}) == "windows"
    assert _scan_os({"os": {"system": "Darwin"}}) == "other"
    assert _scan_os({}) == "other"


def test_rule_os_invalid_raises():
    with pytest.raises(ValueError):
        @rules.rule("X-BAD-OS-1", os="bsd")
        def _bad(scan):
            return None


def test_windows_only_rule_skipped_on_linux():
    scan = _linux_scan("deep")
    scan["persistence"] = {"registry_run": [{"name": "x", "command": "c:\\evil.exe"}]}
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "REG-HIJACK-1" for f in findings)
