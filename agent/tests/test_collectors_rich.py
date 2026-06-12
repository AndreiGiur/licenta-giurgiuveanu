"""Teste pentru colectorii noi (UAC/autologon/SMB1, secedit, defender exclusions).

Functiile impure sunt testate prin monkeypatch pe helperii _reg_value /
_reg_value_exists / _ps -- fara dependenta de starea masinii de dev."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent.collectors import system_info as si  # noqa: E402
from agent.collectors import network as net  # noqa: E402


def test_uac_status_reads_registry_values(monkeypatch):
    values = {"EnableLUA": 0, "ConsentPromptBehaviorAdmin": 0}
    monkeypatch.setattr(si, "_reg_value", lambda path, name: values.get(name))
    uac = si._uac_status()
    assert uac == {"enable_lua": False, "consent_prompt_admin": 0}


def test_uac_status_missing_keys_returns_empty(monkeypatch):
    monkeypatch.setattr(si, "_reg_value", lambda path, name: None)
    assert si._uac_status() == {}


def test_autologon_password_present_without_reading_value(monkeypatch):
    reg = {"AutoAdminLogon": "1", "DefaultUserName": "andrei"}
    monkeypatch.setattr(si, "_reg_value", lambda path, name: reg.get(name))
    monkeypatch.setattr(si, "_reg_value_exists", lambda path, name: name == "DefaultPassword")
    auto = si._autologon_status()
    assert auto == {"enabled": True, "default_username": "andrei", "password_present": True}
    # invariantul de privacy: dict-ul NU contine vreo cheie cu parola
    assert all("password" not in k.lower() for k in auto if k != "password_present")


def test_autologon_absent(monkeypatch):
    monkeypatch.setattr(si, "_reg_value", lambda path, name: None)
    monkeypatch.setattr(si, "_reg_value_exists", lambda path, name: False)
    auto = si._autologon_status()
    assert auto == {"enabled": False, "default_username": "", "password_present": False}


def test_smb1_explicit_enabled(monkeypatch):
    monkeypatch.setattr(si, "_reg_value", lambda path, name: 1)
    assert si._smb1_status() is True


def test_smb1_missing_key_returns_none(monkeypatch):
    monkeypatch.setattr(si, "_reg_value", lambda path, name: None)
    assert si._smb1_status() is None


def test_local_users_includes_password_required(monkeypatch):
    canned = {
        # primul apel _ps: Get-LocalUser; al doilea: Get-LocalGroupMember
        "Get-LocalUser": '[{"Name":"Guest","Enabled":true,"PasswordRequired":false},'
                         '{"Name":"andrei","Enabled":true,"PasswordRequired":true}]',
        "Get-LocalGroupMember": '["DESKTOP\\\\andrei"]',
    }

    def fake_ps(script, timeout=30):
        if "Get-LocalUser" in script:
            # pin pe contractul de query: fara PasswordRequired in Select-Object,
            # campul ar disparea silentios din output-ul real
            assert "PasswordRequired" in script
        for key, value in canned.items():
            if key in script:
                return value
        return None

    monkeypatch.setattr(si, "_ps", fake_ps)
    users = si._local_users()
    by_name = {u["name"]: u for u in users}
    assert by_name["Guest"]["password_required"] is False
    assert by_name["Guest"]["enabled"] is True
    assert by_name["andrei"]["password_required"] is True
    assert by_name["andrei"]["is_admin"] is True


def test_new_profile_flags_per_level():
    from agent.core import SCAN_PROFILES
    std, adv, deep = SCAN_PROFILES["standard"], SCAN_PROFILES["advanced"], SCAN_PROFILES["deep"]
    # standard: nimic din colectarea scumpa
    assert std.include_wifi_profiles is False
    assert std.include_password_policy is False
    assert std.include_audit_policy is False
    # advanced: wifi + password policy, fara audit
    assert adv.include_wifi_profiles is True
    assert adv.include_password_policy is True
    assert adv.include_audit_policy is False
    # deep: toate
    assert deep.include_wifi_profiles is True
    assert deep.include_password_policy is True
    assert deep.include_audit_policy is True


SECEDIT_INF_FIXTURE = """[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 0
MaximumPasswordAge = 42
MinimumPasswordLength = 0
PasswordComplexity = 1
LockoutBadCount = 0
[Event Audit]
AuditSystemEvents = 0
AuditLogonEvents = 0
AuditAccountManage = 3
[Version]
signature="$CHICAGO$"
"""


def test_parse_secedit_inf_extracts_numeric_keys():
    parsed = si._parse_secedit_inf(SECEDIT_INF_FIXTURE)
    assert parsed["min_password_length"] == 0
    assert parsed["max_password_age_days"] == 42
    assert parsed["lockout_threshold"] == 0
    assert parsed["audit_logon"] == 0
    assert parsed["audit_account_manage"] == 3


def test_parse_secedit_inf_garbage_returns_empty():
    assert si._parse_secedit_inf("nu e un INF valid") == {}


def test_parse_secedit_inf_strips_leading_bom():
    # utf-16-le NU consuma BOM-ul la citire — parserul nu trebuie sa piarda
    # prima sectiune din cauza lui
    parsed = si._parse_secedit_inf("﻿" + SECEDIT_INF_FIXTURE)
    assert parsed["min_password_length"] == 0
    assert parsed["audit_account_manage"] == 3


def test_parse_secedit_inf_negative_max_age_passes_through():
    # MaximumPasswordAge = -1 inseamna "parola nu expira" — valoarea ajunge
    # ca atare la server, unde regula decide semnificatia
    inf = "[System Access]\nMaximumPasswordAge = -1\n"
    assert si._parse_secedit_inf(inf) == {"max_password_age_days": -1}


def test_collect_system_splits_password_and_audit_policy(monkeypatch):
    import platform as plat
    if plat.system() != "Windows":
        return  # colectarea e Windows-only (pattern existent in test_collectors.py)
    from agent.core import ScanProfile
    monkeypatch.setattr(si, "_secedit_export", lambda: SECEDIT_INF_FIXTURE)
    # dezactiveaza colectarile lente irelevante pentru acest test
    cfg = ScanProfile(include_firewall=False, include_users=False,
                      include_password_policy=True, include_audit_policy=True)
    data = si.collect_system(cfg)
    assert data["password_policy"] == {
        "min_password_length": 0, "max_password_age_days": 42, "lockout_threshold": 0,
    }
    assert data["audit_policy"] == {"audit_logon": 0, "audit_account_manage": 3}


def test_defender_status_includes_exclusions(monkeypatch):
    def fake_ps(script, timeout=30):
        if "Get-MpPreference" in script:
            return ('{"ExclusionPath":["C:\\\\Users","C:\\\\dev\\\\tools"],'
                    '"ExclusionProcess":"powershell.exe","ExclusionExtension":null}')
        if "Get-MpComputerStatus" in script:
            return '{"AMRunningMode":"Normal","RealTimeProtectionEnabled":true,"AntivirusSignatureLastUpdated":""}'
        return None

    monkeypatch.setattr(si, "_ps", fake_ps)
    result = si._defender_status()
    assert result["exclusions"]["paths"] == ["C:\\Users", "C:\\dev\\tools"]
    assert result["exclusions"]["processes"] == ["powershell.exe"]  # scalar -> lista
    assert result["exclusions"]["extensions"] == []                  # null -> lista goala


WIFI_XML_FIXTURE = """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>CasaMea</name>
    <SSIDConfig><SSID><name>CasaMea</name></SSID></SSIDConfig>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
"""


def test_parse_wifi_profile_xml_extracts_ssid_and_auth():
    p = net._parse_wifi_profile_xml(WIFI_XML_FIXTURE)
    assert p == {"ssid": "CasaMea", "authentication": "WPA2PSK"}


def test_parse_wifi_profile_xml_never_contains_key_material():
    # exportul fara key=clear nu are keyMaterial; parserul oricum nu citeste decat name+authentication
    p = net._parse_wifi_profile_xml(WIFI_XML_FIXTURE)
    assert set(p.keys()) == {"ssid", "authentication"}


def test_parse_wifi_profile_xml_invalid_returns_none():
    assert net._parse_wifi_profile_xml("<broken") is None
    assert net._parse_wifi_profile_xml("<a><b/></a>") is None


def test_port_processes_include_exe(monkeypatch):
    import types as _t
    import psutil

    fake_conn = _t.SimpleNamespace(
        status=psutil.CONN_LISTEN, pid=4242,
        laddr=_t.SimpleNamespace(ip="0.0.0.0", port=8888), raddr=None,
    )

    class FakeProc:
        def __init__(self, pid):
            self.pid = pid
        def name(self):
            return "evil.exe"
        def exe(self):
            return r"C:\Users\x\AppData\Local\Temp\evil.exe"

    monkeypatch.setattr(net.psutil, "net_connections", lambda kind="tcp": [fake_conn])
    monkeypatch.setattr(net.psutil, "Process", FakeProc)
    listeners = net._port_processes()
    assert listeners == [{
        "port": 8888, "pid": 4242, "process": "evil.exe",
        "exe": r"C:\Users\x\AppData\Local\Temp\evil.exe",
    }]
