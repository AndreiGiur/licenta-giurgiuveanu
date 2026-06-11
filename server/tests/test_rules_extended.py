"""Teste pozitiv/negativ pentru cele 15 reguli noi (rules_extended.py)."""
from server.app.rules import evaluate


def _scan(scan_type="standard", **sections):
    base = {"scan_type": scan_type, "os": {"system": "Windows", "release": "11"}}
    base.update(sections)
    return base


def _rule_ids(scan):
    _, _, findings = evaluate(scan)
    return {f["rule_id"] for f in findings}


# -- OS-UPTIME-1 --------------------------------------------------------------

def test_uptime_fires_over_30_days():
    scan = _scan(os={"system": "Windows", "release": "11", "uptime_seconds": 31 * 86400})
    assert "OS-UPTIME-1" in _rule_ids(scan)


def test_uptime_quiet_under_threshold():
    scan = _scan(os={"system": "Windows", "release": "11", "uptime_seconds": 5 * 86400})
    assert "OS-UPTIME-1" not in _rule_ids(scan)


def test_uptime_cross_platform_fires_on_linux():
    scan = _scan(os={"system": "Linux", "release": "6.8", "uptime_seconds": 90 * 86400})
    assert "OS-UPTIME-1" in _rule_ids(scan)


# -- UAC-DISABLED-1 -----------------------------------------------------------

def test_uac_fires_when_enable_lua_off():
    scan = _scan(system_info={"uac": {"enable_lua": False}})
    assert "UAC-DISABLED-1" in _rule_ids(scan)


def test_uac_fires_on_silent_elevation():
    scan = _scan(system_info={"uac": {"enable_lua": True, "consent_prompt_admin": 0}})
    assert "UAC-DISABLED-1" in _rule_ids(scan)


def test_uac_quiet_when_enabled():
    scan = _scan(system_info={"uac": {"enable_lua": True, "consent_prompt_admin": 5}})
    assert "UAC-DISABLED-1" not in _rule_ids(scan)


# -- AUTOLOGON-PASSWORD-1 -----------------------------------------------------

def test_autologon_fires_on_password_present():
    scan = _scan(system_info={"autologon": {
        "enabled": True, "default_username": "andrei", "password_present": True}})
    ids = _rule_ids(scan)
    assert "AUTOLOGON-PASSWORD-1" in ids


def test_autologon_quiet_without_password():
    scan = _scan(system_info={"autologon": {
        "enabled": False, "default_username": "", "password_present": False}})
    assert "AUTOLOGON-PASSWORD-1" not in _rule_ids(scan)


def test_autologon_finding_is_critical():
    scan = _scan(system_info={"autologon": {
        "enabled": True, "default_username": "andrei", "password_present": True}})
    _, _, findings = evaluate(scan)
    f = next(x for x in findings if x["rule_id"] == "AUTOLOGON-PASSWORD-1")
    assert f["severity"] == "critical"
    # privacy: parola nu apare nicaieri in finding
    assert "password_value" not in str(f.get("evidence", {}))


# -- SMB-LEGACY-1 -----------------------------------------------------------

def test_smb1_fires_only_on_explicit_true():
    assert "SMB-LEGACY-1" in _rule_ids(_scan(system_info={"smb1_enabled": True}))


def test_smb1_quiet_on_false_or_missing():
    assert "SMB-LEGACY-1" not in _rule_ids(_scan(system_info={"smb1_enabled": False}))
    assert "SMB-LEGACY-1" not in _rule_ids(_scan(system_info={}))


# -- USER-GUEST-ENABLED-1 -----------------------------------------------------

def test_guest_enabled_fires():
    scan = _scan(system_info={"local_users": [
        {"name": "Guest", "enabled": True, "password_required": True, "is_admin": False},
    ]})
    assert "USER-GUEST-ENABLED-1" in _rule_ids(scan)


def test_passwordless_account_fires():
    scan = _scan(system_info={"local_users": [
        {"name": "kiosk", "enabled": True, "password_required": False, "is_admin": False},
    ]})
    assert "USER-GUEST-ENABLED-1" in _rule_ids(scan)


def test_guest_disabled_quiet():
    scan = _scan(system_info={"local_users": [
        {"name": "Guest", "enabled": False, "password_required": False, "is_admin": False},
        {"name": "andrei", "enabled": True, "password_required": True, "is_admin": True},
    ]})
    assert "USER-GUEST-ENABLED-1" not in _rule_ids(scan)
