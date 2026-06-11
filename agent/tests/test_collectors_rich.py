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
    assert "password" not in {k.lower() for k in auto} - {"password_present"}


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
