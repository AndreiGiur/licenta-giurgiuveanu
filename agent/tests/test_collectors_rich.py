"""Teste pentru colectorii noi (UAC/autologon/SMB1, secedit, defender exclusions).

Functiile impure sunt testate prin monkeypatch pe helperii _reg_value /
_reg_value_exists / _ps -- fara dependenta de starea masinii de dev."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent.collectors import system_info as si  # noqa: E402


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
