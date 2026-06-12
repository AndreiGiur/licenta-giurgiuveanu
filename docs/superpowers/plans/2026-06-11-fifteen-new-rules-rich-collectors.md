# 15 Reguli Noi + Colectori Bogati — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 15 reguli noi de detectie (5 per nivel standard/advanced/deep, Windows + cross) cu subsisteme noi de colectare in agent (UAC/autologon/SMBv1 din registry, politica de parole + audit policy din secedit, exclusions Defender, profile WiFi, exe path pe listeners).

**Architecture:** Agentul primeste campuri noi in colectorii existenti (`system_info.py`, `network.py`) + 3 flag-uri noi in `ScanProfile`; parserele sunt functii pure testabile pe fixture-uri text. Serverul primeste modulul nou `rules_extended.py` cu cele 15 reguli `@rule`, importat la finalul `rules.py` (pattern identic cu `rules_linux.py`).

**Tech Stack:** Python (winreg, psutil, secedit, netsh, Get-MpPreference), FastAPI rules engine, pytest.

**Spec:** `docs/superpowers/specs/2026-06-11-fifteen-new-rules-rich-collectors-design.md`

**Reguli de proiect:** fara diacritice in cod; fara mentiuni de Claude in commits; dupa fiecare task care modifica fisiere dintr-un folder, actualizeaza `memory.md` din folderul respectiv (Task 11 le acopera centralizat — daca executi task-uri izolat, fa update-ul la fiecare).

**Comenzi de test:**
- Agent: `python -m pytest agent -q` (din radacina repo)
- Server: `cd server` apoi `.\.venv\Scripts\python.exe -m pytest -q` (venv-ul serverului, NU python-ul global)

**Formele de date existente relevante (verificate in cod):**
- `scan["os"]` = `{system, release, version, machine, hostname, uptime_seconds, is_admin, username}`
- `scan["system_info"]` = chei din `si_keys` in `core.py:701` — actualmente `("local_users", "firewall", "bitlocker", "defender")`
- `scan["processes"][i]["cmdline"]` este **string** (join cu spatiu, max 512 chars), doar la advanced+
- `scan["network"]["port_processes"]` = `[{port, pid, process}]` (advanced+)
- `scan["forensics"]["arp_table"]` = `[{ip, mac}]`; `dns_cache` = `[{name, ip}]`; `recent_files` = `[{path, modified}]` (deep)
- `scan["persistence"]["services"]` = `[{name, status, binary_path, ...}]` (advanced+)
- `local_users` are deja `{name, enabled, is_admin}` — adaugam `password_required`

---

### Task 1: Agent — colectori registry (UAC, autologon, SMBv1)

**Files:**
- Modify: `agent/collectors/system_info.py`
- Modify: `agent/core.py:701` (si_keys)
- Test: `agent/tests/test_collectors_rich.py` (NOU)

- [ ] **Step 1.1: Scrie testele failing**

Creeaza `agent/tests/test_collectors_rich.py`:

```python
"""Teste pentru colectorii noi (UAC/autologon/SMB1, secedit, defender exclusions).

Functiile impure sunt testate prin monkeypatch pe helperii _reg_value /
_reg_value_exists / _ps — fara dependenta de starea masinii de dev."""
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
```

- [ ] **Step 1.2: Ruleaza testele — trebuie sa pice**

Run: `python -m pytest agent/tests/test_collectors_rich.py -q`
Expected: FAIL / ERROR cu `AttributeError: ... has no attribute '_reg_value'`

- [ ] **Step 1.3: Implementeaza in `agent/collectors/system_info.py`**

Adauga dupa `_is_admin()` (linia ~50):

```python
_POLICIES_SYSTEM = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
_WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
_LANMAN_PARAMS = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"


def _reg_value(path: str, name: str):
    """Citeste o valoare din HKLM. None daca lipseste / non-Windows."""
    try:
        import winreg  # type: ignore[import-not-found]
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        try:
            val, _ = winreg.QueryValueEx(k, name)
            return val
        finally:
            winreg.CloseKey(k)
    except (ImportError, FileNotFoundError, OSError):
        return None


def _reg_value_exists(path: str, name: str) -> bool:
    """True daca valoarea exista in HKLM — enumerare nume, datele NU se citesc.
    Folosit pentru DefaultPassword (privacy: nu aducem parola in memorie)."""
    try:
        import winreg  # type: ignore[import-not-found]
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        try:
            i = 0
            while True:
                vname, _, _ = winreg.EnumValue(k, i)
                if vname.lower() == name.lower():
                    return True
                i += 1
        except OSError:
            return False
        finally:
            winreg.CloseKey(k)
    except (ImportError, FileNotFoundError, OSError):
        return False


def _uac_status() -> dict:
    """EnableLUA + ConsentPromptBehaviorAdmin din Policies\\System."""
    out: dict = {}
    enable_lua = _reg_value(_POLICIES_SYSTEM, "EnableLUA")
    if enable_lua is not None:
        out["enable_lua"] = bool(enable_lua)
    consent = _reg_value(_POLICIES_SYSTEM, "ConsentPromptBehaviorAdmin")
    if consent is not None:
        out["consent_prompt_admin"] = int(consent)
    return out


def _autologon_status() -> dict:
    """AutoAdminLogon + DefaultUserName + PREZENTA DefaultPassword (bool).
    Valoarea parolei nu se citeste niciodata (vezi _reg_value_exists)."""
    auto = str(_reg_value(_WINLOGON_KEY, "AutoAdminLogon") or "0").strip()
    return {
        "enabled": auto == "1",
        "default_username": str(_reg_value(_WINLOGON_KEY, "DefaultUserName") or ""),
        "password_present": _reg_value_exists(_WINLOGON_KEY, "DefaultPassword"),
    }


def _smb1_status() -> bool | None:
    """SMB1 din LanmanServer Parameters. None = cheia lipseste (default OS —
    pe Win10+ inseamna dezactivat; regula NU se declanseaza pe None)."""
    val = _reg_value(_LANMAN_PARAMS, "SMB1")
    if val is None:
        return None
    return bool(val)
```

In `collect_system()` adauga inainte de `return out`:

```python
    if platform.system() == "Windows":
        out["uac"] = _uac_status()
        out["autologon"] = _autologon_status()
        smb1 = _smb1_status()
        if smb1 is not None:
            out["smb1_enabled"] = smb1
```

In `agent/core.py` linia ~701, schimba:

```python
    si_keys = ("local_users", "firewall", "bitlocker", "defender")
```

in:

```python
    si_keys = ("local_users", "firewall", "bitlocker", "defender",
               "uac", "autologon", "smb1_enabled", "password_policy", "audit_policy")
```

(`password_policy`/`audit_policy` apar in Task 4 — includerea de pe acum e inofensiva: cheile lipsesc din `sys_data` pana atunci.)

- [ ] **Step 1.4: Ruleaza testele — trebuie sa treaca**

Run: `python -m pytest agent/tests/test_collectors_rich.py -q`
Expected: 6 passed

- [ ] **Step 1.5: Ruleaza toata suita agent (regresie)**

Run: `python -m pytest agent -q`
Expected: 123 passed (117 vechi + 6 noi)

- [ ] **Step 1.6: Commit**

```bash
git add agent/collectors/system_info.py agent/core.py agent/tests/test_collectors_rich.py
git commit -m "feat(agent): colectare UAC, autologon (doar flag prezenta parola) si SMBv1 din registry"
```

---

### Task 2: Agent — `password_required` pe local_users

**Files:**
- Modify: `agent/collectors/system_info.py:85-120` (`_local_users`)
- Test: `agent/tests/test_collectors_rich.py`

- [ ] **Step 2.1: Scrie testul failing** (adauga in `test_collectors_rich.py`)

```python
def test_local_users_includes_password_required(monkeypatch):
    canned = {
        # primul apel _ps: Get-LocalUser; al doilea: Get-LocalGroupMember
        "Get-LocalUser": '[{"Name":"Guest","Enabled":true,"PasswordRequired":false},'
                         '{"Name":"andrei","Enabled":true,"PasswordRequired":true}]',
        "Get-LocalGroupMember": '["DESKTOP\\\\andrei"]',
    }

    def fake_ps(script, timeout=30):
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
```

- [ ] **Step 2.2: Ruleaza — trebuie sa pice**

Run: `python -m pytest agent/tests/test_collectors_rich.py::test_local_users_includes_password_required -q`
Expected: FAIL cu `KeyError: 'password_required'`

- [ ] **Step 2.3: Implementeaza** — in `_local_users()` schimba query-ul si dict-ul:

```python
    out = _ps(
        "Get-LocalUser | Select-Object Name, Enabled, PasswordRequired | ConvertTo-Json -Compress"
    )
```

si in bucla de constructie:

```python
            for u in data:
                users.append({
                    "name": u.get("Name", ""),
                    "enabled": bool(u.get("Enabled", True)),
                    "password_required": bool(u.get("PasswordRequired", True)),
                    "is_admin": False,
                })
```

- [ ] **Step 2.4: Ruleaza testele agent**

Run: `python -m pytest agent -q`
Expected: 124 passed

- [ ] **Step 2.5: Commit**

```bash
git add agent/collectors/system_info.py agent/tests/test_collectors_rich.py
git commit -m "feat(agent): flag password_required pe conturile locale (Get-LocalUser)"
```

---

### Task 3: Agent — flag-uri noi ScanProfile + profiluri

**Files:**
- Modify: `agent/core.py:42-138` (ScanProfile + SCAN_PROFILES)
- Test: `agent/tests/test_collectors_rich.py`

- [ ] **Step 3.1: Scrie testul failing**

```python
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
```

- [ ] **Step 3.2: Ruleaza — trebuie sa pice**

Run: `python -m pytest agent/tests/test_collectors_rich.py::test_new_profile_flags_per_level -q`
Expected: FAIL cu `AttributeError: 'ScanProfile' object has no attribute 'include_wifi_profiles'`

- [ ] **Step 3.3: Implementeaza** — in `ScanProfile` (dupa `include_recent_files`, linia ~76):

```python
    # Colectare bogata (2026-06-11): WiFi, politici locale
    include_wifi_profiles: bool = False    # netsh wlan export (advanced+)
    include_password_policy: bool = False  # secedit [System Access] (advanced+)
    include_audit_policy: bool = False     # secedit [Event Audit] (deep)
```

In `SCAN_PROFILES["advanced"]` adauga:

```python
        include_wifi_profiles=True,
        include_password_policy=True,
```

In `SCAN_PROFILES["deep"]` adauga:

```python
        include_wifi_profiles=True,
        include_password_policy=True,
        include_audit_policy=True,
```

- [ ] **Step 3.4: Ruleaza testele agent**

Run: `python -m pytest agent -q`
Expected: 125 passed (testele existente `test_scan_profiles_have_three_levels` etc. raman verzi)

- [ ] **Step 3.5: Commit**

```bash
git add agent/core.py agent/tests/test_collectors_rich.py
git commit -m "feat(agent): flag-uri ScanProfile pentru wifi, password policy si audit policy"
```

---

### Task 4: Agent — export secedit (password policy + audit policy)

**Files:**
- Modify: `agent/collectors/system_info.py`
- Test: `agent/tests/test_collectors_rich.py`

- [ ] **Step 4.1: Scrie testele failing**

```python
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
```

- [ ] **Step 4.2: Ruleaza — trebuie sa pice**

Run: `python -m pytest agent/tests/test_collectors_rich.py -q -k "secedit or policy"`
Expected: FAIL cu `AttributeError: ... '_parse_secedit_inf'`

- [ ] **Step 4.3: Implementeaza** — adauga in `system_info.py`:

```python
def _to_int(val: str) -> int | None:
    try:
        return int(str(val).strip().strip('"'))
    except (ValueError, TypeError):
        return None


def _parse_secedit_inf(text: str) -> dict:
    """Parseaza INF-ul exportat de secedit. Cheile sunt fixe si numerice —
    imune la localizarea Windows (spre deosebire de `net accounts`/`auditpol`)."""
    out: dict = {}
    section = ""
    mapping = {
        ("system access", "minimumpasswordlength"): "min_password_length",
        ("system access", "maximumpasswordage"): "max_password_age_days",
        ("system access", "lockoutbadcount"): "lockout_threshold",
        ("event audit", "auditlogonevents"): "audit_logon",
        ("event audit", "auditaccountmanage"): "audit_account_manage",
    }
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        target = mapping.get((section, key.strip().lower()))
        if target is None:
            continue
        num = _to_int(val)
        if num is not None:
            out[target] = num
    return out


def _secedit_export() -> str | None:
    """Exporta politica locala de securitate (INF). None la esec/fara admin."""
    import tempfile
    try:
        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "sec.inf")
            r = subprocess.run(
                ["secedit", "/export", "/cfg", cfg_path, "/areas", "SECURITYPOLICY", "/quiet"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode != 0 or not os.path.exists(cfg_path):
                return None
            # secedit scrie UTF-16 LE cu BOM
            with open(cfg_path, encoding="utf-16") as f:
                return f.read()
    except (subprocess.SubprocessError, OSError, UnicodeError):
        return None
```

In `collect_system()`, inainte de `return out` (dupa blocul din Task 1):

```python
    if platform.system() == "Windows" and (cfg.include_password_policy or cfg.include_audit_policy):
        inf = _secedit_export()
        if inf:
            parsed = _parse_secedit_inf(inf)
            if cfg.include_password_policy:
                pw = {k: parsed[k] for k in
                      ("min_password_length", "max_password_age_days", "lockout_threshold")
                      if k in parsed}
                if pw:
                    out["password_policy"] = pw
            if cfg.include_audit_policy:
                ap = {k: parsed[k] for k in ("audit_logon", "audit_account_manage") if k in parsed}
                if ap:
                    out["audit_policy"] = ap
```

- [ ] **Step 4.4: Ruleaza testele agent**

Run: `python -m pytest agent -q`
Expected: 128 passed

- [ ] **Step 4.5: Commit**

```bash
git add agent/collectors/system_info.py agent/tests/test_collectors_rich.py
git commit -m "feat(agent): politica de parole si audit policy din export secedit (locale-independent)"
```

---

### Task 5: Agent — exclusions Windows Defender

**Files:**
- Modify: `agent/collectors/system_info.py:149-206` (`_defender_status`)
- Test: `agent/tests/test_collectors_rich.py`

- [ ] **Step 5.1: Scrie testul failing**

```python
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
```

- [ ] **Step 5.2: Ruleaza — trebuie sa pice**

Run: `python -m pytest agent/tests/test_collectors_rich.py::test_defender_status_includes_exclusions -q`
Expected: FAIL cu `KeyError: 'exclusions'`

- [ ] **Step 5.3: Implementeaza** — in `_defender_status()`, inainte de `result["third_party_av"] = third_party`:

```python
    # Exclusions Defender (tactica frecventa de malware: exclude C:\, Temp, powershell).
    excl_out = _ps(
        "Get-MpPreference -ErrorAction SilentlyContinue | "
        "Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension | "
        "ConvertTo-Json -Compress"
    )
    if excl_out:
        try:
            data = json.loads(excl_out)

            def _as_list(v) -> list[str]:
                if v is None:
                    return []
                if isinstance(v, str):
                    return [v]
                return [str(x) for x in v]

            result["exclusions"] = {
                "paths": _as_list(data.get("ExclusionPath")),
                "processes": _as_list(data.get("ExclusionProcess")),
                "extensions": _as_list(data.get("ExclusionExtension")),
            }
        except json.JSONDecodeError:
            pass
```

- [ ] **Step 5.4: Ruleaza testele agent**

Run: `python -m pytest agent -q`
Expected: 129 passed

- [ ] **Step 5.5: Commit**

```bash
git add agent/collectors/system_info.py agent/tests/test_collectors_rich.py
git commit -m "feat(agent): colectare exclusions Windows Defender (Get-MpPreference)"
```

---

### Task 6: Agent — profile WiFi + exe path pe listeners

**Files:**
- Modify: `agent/collectors/network.py`
- Test: `agent/tests/test_collectors_rich.py`

- [ ] **Step 6.1: Scrie testele failing**

```python
from agent.collectors import network as net  # adauga la importurile din test_collectors_rich.py

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
```

- [ ] **Step 6.2: Ruleaza — trebuie sa pice**

Run: `python -m pytest agent/tests/test_collectors_rich.py -q -k "wifi or port_processes"`
Expected: FAIL cu `AttributeError: ... '_parse_wifi_profile_xml'` si `KeyError/assert` pe exe

- [ ] **Step 6.3: Implementeaza in `agent/collectors/network.py`**

Verifica importurile din capul fisierului; adauga daca lipsesc: `import os`, `import subprocess`, `from pathlib import Path`.

```python
_WLAN_NS = "{http://www.microsoft.com/networking/WLAN/profile/v1}"


def _parse_wifi_profile_xml(xml_text: str) -> dict | None:
    """Extrage {ssid, authentication} din XML-ul netsh (schema fixa, imuna la
    localizare). NU citeste keyMaterial — exportul se face FARA key=clear."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    name_el = root.find(f"{_WLAN_NS}name")
    auth_el = root.find(
        f"{_WLAN_NS}MSM/{_WLAN_NS}security/{_WLAN_NS}authEncryption/{_WLAN_NS}authentication"
    )
    if name_el is None or auth_el is None:
        return None
    return {"ssid": (name_el.text or "").strip(),
            "authentication": (auth_el.text or "").strip()}


def _wifi_profiles() -> list[dict]:
    """Exporta profilele WiFi salvate (XML, fara chei) si le parseaza."""
    import tempfile
    profiles: list[dict] = []
    try:
        with tempfile.TemporaryDirectory() as td:
            r = subprocess.run(
                ["netsh", "wlan", "export", "profile", f"folder={td}"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode != 0:
                return []
            for fname in os.listdir(td):
                if not fname.lower().endswith(".xml"):
                    continue
                try:
                    text = (Path(td) / fname).read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    continue
                parsed = _parse_wifi_profile_xml(text)
                if parsed:
                    profiles.append(parsed)
    except (subprocess.SubprocessError, OSError):
        return []
    return profiles[:50]
```

In `collect_network()` dupa blocul `include_net_adapters`:

```python
    if cfg.include_wifi_profiles and platform.system() == "Windows":
        out["wifi_profiles"] = _wifi_profiles()
```

In `_port_processes()` schimba blocul try interior in:

```python
            try:
                p = psutil.Process(conn.pid)
                try:
                    exe = p.exe()
                except (psutil.AccessDenied, OSError):
                    exe = ""
                out.append({"port": conn.laddr.port, "pid": conn.pid,
                            "process": p.name(), "exe": exe})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                out.append({"port": conn.laddr.port, "pid": conn.pid,
                            "process": "", "exe": ""})
```

- [ ] **Step 6.4: Ruleaza testele agent**

Run: `python -m pytest agent -q`
Expected: 133 passed

- [ ] **Step 6.5: Commit**

```bash
git add agent/collectors/network.py agent/tests/test_collectors_rich.py
git commit -m "feat(agent): profile WiFi salvate (fara chei) si exe path pe procesele LISTEN"
```

---

### Task 7: Server — praguri config + 5 reguli standard

**Files:**
- Modify: `server/app/config.py`
- Create: `server/app/rules_extended.py`
- Modify: `server/app/rules.py:987` (import la final)
- Test: `server/tests/test_rules_extended.py` (NOU)

- [ ] **Step 7.1: Adauga pragurile in `server/app/config.py`** (dupa `MANY_PORTS_THRESHOLD`):

```python
# Zile de uptime peste care sistemul e considerat ne-restartat de prea mult timp
# (patch-uri in asteptare) — regula OS-UPTIME-1.
UPTIME_DAYS_THRESHOLD = int(os.environ.get("UPTIME_DAYS_THRESHOLD", "30"))

# Lungimea minima acceptata pentru parolele locale — regula PASS-POLICY-WEAK-1.
MIN_PASSWORD_LENGTH_THRESHOLD = int(os.environ.get("MIN_PASSWORD_LENGTH_THRESHOLD", "8"))
```

- [ ] **Step 7.2: Scrie testele failing** — creeaza `server/tests/test_rules_extended.py`:

```python
"""Teste pozitiv/negativ pentru cele 15 reguli noi (rules_extended.py)."""
from server.app.rules import evaluate


def _scan(scan_type="standard", **sections):
    base = {"scan_type": scan_type, "os": {"system": "Windows", "release": "11"}}
    base.update(sections)
    return base


def _rule_ids(scan):
    _, _, findings = evaluate(scan)
    return {f["rule_id"] for f in findings}


# ── OS-UPTIME-1 ──────────────────────────────────────────────────────────────

def test_uptime_fires_over_30_days():
    scan = _scan(os={"system": "Windows", "release": "11", "uptime_seconds": 31 * 86400})
    assert "OS-UPTIME-1" in _rule_ids(scan)


def test_uptime_quiet_under_threshold():
    scan = _scan(os={"system": "Windows", "release": "11", "uptime_seconds": 5 * 86400})
    assert "OS-UPTIME-1" not in _rule_ids(scan)


def test_uptime_cross_platform_fires_on_linux():
    scan = _scan(os={"system": "Linux", "release": "6.8", "uptime_seconds": 90 * 86400})
    assert "OS-UPTIME-1" in _rule_ids(scan)


# ── UAC-DISABLED-1 ───────────────────────────────────────────────────────────

def test_uac_fires_when_enable_lua_off():
    scan = _scan(system_info={"uac": {"enable_lua": False}})
    assert "UAC-DISABLED-1" in _rule_ids(scan)


def test_uac_fires_on_silent_elevation():
    scan = _scan(system_info={"uac": {"enable_lua": True, "consent_prompt_admin": 0}})
    assert "UAC-DISABLED-1" in _rule_ids(scan)


def test_uac_quiet_when_enabled():
    scan = _scan(system_info={"uac": {"enable_lua": True, "consent_prompt_admin": 5}})
    assert "UAC-DISABLED-1" not in _rule_ids(scan)


# ── AUTOLOGON-PASSWORD-1 ─────────────────────────────────────────────────────

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


# ── SMB1-ENABLED-1 ───────────────────────────────────────────────────────────

def test_smb1_fires_only_on_explicit_true():
    assert "SMB1-ENABLED-1" in _rule_ids(_scan(system_info={"smb1_enabled": True}))


def test_smb1_quiet_on_false_or_missing():
    assert "SMB1-ENABLED-1" not in _rule_ids(_scan(system_info={"smb1_enabled": False}))
    assert "SMB1-ENABLED-1" not in _rule_ids(_scan(system_info={}))


# ── USER-GUEST-ENABLED-1 ─────────────────────────────────────────────────────

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
```

- [ ] **Step 7.3: Ruleaza — trebuie sa pice**

Run (din `server/`): `.\.venv\Scripts\python.exe -m pytest tests/test_rules_extended.py -q`
Expected: FAIL — rule ID-urile lipsesc din findings

- [ ] **Step 7.4: Creeaza `server/app/rules_extended.py`** cu regulile standard:

```python
"""Reguli extinse (2026-06-11): 15 reguli noi, 5 per nivel, Windows + cross.

Modul separat (pattern identic cu rules_linux.py) ca rules.py sa ramana
focusat pe engine + setul initial. Importat la FINALUL rules.py, dupa
definirea decoratorului @rule.
"""
from __future__ import annotations

from .config import MIN_PASSWORD_LENGTH_THRESHOLD, UPTIME_DAYS_THRESHOLD
from .rules import SUSPICIOUS_STARTUP_PATHS, rule

# ── Constante ────────────────────────────────────────────────────────────────

# Pattern-uri ofensive in cmdline PowerShell (procese RULANTE — completeaza
# TASK-SUSPICIOUS-1 care se uita doar la task-uri planificate).
PS_OFFENSIVE_CMDLINE_PATTERNS: tuple[str, ...] = (
    "-enc ", "-encodedcommand", "downloadstring", "frombase64string",
    "invoke-expression", "iex(",
)

# Autentificari WiFi nesigure -> severitate. Valorile vin din XML-ul netsh
# (element <authentication>): open/shared = fara protectie / WEP; WPA/WPAPSK = WPA1.
WIFI_INSECURE_AUTH: dict[str, str] = {
    "open": "high", "shared": "high", "wep": "high",
    "wpa": "medium", "wpapsk": "medium",
}

# Radacini de exclusions Defender care anuleaza practic protectia.
SUSPICIOUS_EXCLUSION_ROOTS: frozenset[str] = frozenset({
    "c:", "c:\\users", "c:\\windows", "c:\\programdata", "c:\\temp",
})

# Procese a caror excludere din Defender e tactica clasica de malware.
SUSPICIOUS_EXCLUSION_PROCESSES: frozenset[str] = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
})

# MAC-uri broadcast/multicast — excluse din analiza ARP (nu sunt spoofing).
BROADCAST_MAC_PREFIXES: tuple[str, ...] = (
    "ff-ff-ff", "ff:ff:ff", "01-00-5e", "01:00:5e", "33-33", "33:33",
)

# TLD-uri cu abuz ridicat (frecvent folosite de phishing/malware C2).
ABUSED_TLDS: tuple[str, ...] = (".tk", ".ml", ".ga", ".cf", ".gq", ".top")

# Extensii de fisiere executabile pentru RECENT-SYSTEM-FILES-1.
SYSTEM_EXECUTABLE_EXTENSIONS: tuple[str, ...] = (".exe", ".dll", ".sys")


# ─────────────────────────────────────────────────────────────────────────────
# STANDARD (5)
# ─────────────────────────────────────────────────────────────────────────────


@rule("OS-UPTIME-1", min_level="standard", category="hygiene", weight=0.5,
      compliance=["CIS-7.3", "NIST-PR.PS-02"])
def check_uptime(scan: dict) -> dict | None:
    uptime = (scan.get("os", {}) or {}).get("uptime_seconds")
    if not isinstance(uptime, (int, float)):
        return None
    days = int(uptime // 86400)
    if days <= UPTIME_DAYS_THRESHOLD:
        return None
    return {
        "rule_id": "OS-UPTIME-1",
        "title": f"Sistem nerepornit de {days} zile",
        "severity": "low",
        "evidence": {"uptime_days": days, "threshold_days": UPTIME_DAYS_THRESHOLD},
        "recommendation": (
            "Repornirile aplica patch-urile de kernel/OS in asteptare. "
            "Reporneste sistemul si verifica Windows Update / managerul de pachete."
        ),
    }


@rule("UAC-DISABLED-1", min_level="standard", category="hygiene", weight=1.2,
      compliance=["CIS-4.1", "CIS-5.4", "NIST-PR.AA-05"], os="windows")
def check_uac_disabled(scan: dict) -> dict | None:
    uac = (scan.get("system_info", {}) or {}).get("uac", {}) or {}
    issues = []
    if uac.get("enable_lua") is False:
        issues.append("EnableLUA=0 (UAC complet dezactivat)")
    if uac.get("consent_prompt_admin") == 0:
        issues.append("ConsentPromptBehaviorAdmin=0 (elevare fara prompt)")
    if not issues:
        return None
    return {
        "rule_id": "UAC-DISABLED-1",
        "title": "User Account Control dezactivat sau configurat nesigur",
        "severity": "high",
        "evidence": {"issues": issues, "uac": uac},
        "recommendation": (
            "Reactiveaza UAC: seteaza EnableLUA=1 in "
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System "
            "si reporneste. Fara UAC orice proces ruleaza cu drepturi depline."
        ),
    }


@rule("AUTOLOGON-PASSWORD-1", min_level="standard", category="critical_risk", weight=1.5,
      compliance=["CIS-5.2", "CIS-4.1", "NIST-PR.AA-01"], os="windows")
def check_autologon_password(scan: dict) -> dict | None:
    auto = (scan.get("system_info", {}) or {}).get("autologon", {}) or {}
    if not auto.get("password_present"):
        return None
    return {
        "rule_id": "AUTOLOGON-PASSWORD-1",
        "title": "Parola stocata in clar in registry (AutoLogon)",
        "severity": "critical",
        "evidence": {
            "autologon_enabled": bool(auto.get("enabled")),
            "default_username": auto.get("default_username", ""),
        },
        "recommendation": (
            "Sterge valoarea DefaultPassword din "
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon. "
            "Pentru autologon sigur foloseste Sysinternals Autologon (stocheaza ca LSA secret)."
        ),
    }


@rule("SMB1-ENABLED-1", min_level="standard", category="network_exposure", weight=1.5,
      compliance=["CIS-4.2", "CIS-4.8", "NIST-PR.PS-01", "NIST-ID.RA-01"], os="windows")
def check_smb1_enabled(scan: dict) -> dict | None:
    if (scan.get("system_info", {}) or {}).get("smb1_enabled") is not True:
        return None
    return {
        "rule_id": "SMB1-ENABLED-1",
        "title": "Protocolul SMBv1 este activat",
        "severity": "high",
        "evidence": {"smb1_enabled": True},
        "recommendation": (
            "SMBv1 este vulnerabil la EternalBlue (WannaCry/NotPetya). Dezactiveaza: "
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false"
        ),
    }


@rule("USER-GUEST-ENABLED-1", min_level="standard", category="hygiene", weight=1.0,
      compliance=["CIS-5.2", "CIS-5.3", "NIST-PR.AA-01"], os="windows")
def check_guest_or_passwordless(scan: dict) -> dict | None:
    users = (scan.get("system_info", {}) or {}).get("local_users", []) or []
    flagged = []
    for u in users:
        if u.get("enabled") is not True:
            continue
        name = (u.get("name") or "")
        if name.lower() == "guest":
            flagged.append({"name": name, "reason": "cont Guest activ"})
        elif u.get("password_required") is False:
            flagged.append({"name": name, "reason": "parola neobligatorie"})
    if not flagged:
        return None
    return {
        "rule_id": "USER-GUEST-ENABLED-1",
        "title": "Conturi locale fara protectie adecvata",
        "severity": "medium",
        "evidence": {"accounts": flagged},
        "recommendation": (
            "Dezactiveaza contul Guest (net user Guest /active:no) si seteaza "
            "parole obligatorii pentru toate conturile active."
        ),
    }
```

- [ ] **Step 7.5: Inregistreaza modulul** — in `server/app/rules.py`, ultima linie devine:

```python
from . import rules_linux  # noqa: E402,F401  (trebuie dupa definirea @rule)
from . import rules_extended  # noqa: E402,F401  (idem — reguli 2026-06-11)
```

- [ ] **Step 7.6: Ruleaza — trebuie sa treaca**

Run (din `server/`): `.\.venv\Scripts\python.exe -m pytest tests/test_rules_extended.py -q`
Expected: 14 passed

- [ ] **Step 7.7: Ruleaza toata suita server (regresie + contract auto-cover)**

Run (din `server/`): `.\.venv\Scripts\python.exe -m pytest -q`
Expected: toate verzi (contract tests acopera automat noile reguli: unique id, compliance, category, semnatura, empty-scan; `test_rule_returns_valid_type_on_empty_scan` se parametrizeaza singur din `_RULES`)

- [ ] **Step 7.8: Commit**

```bash
git add server/app/config.py server/app/rules_extended.py server/app/rules.py server/tests/test_rules_extended.py
git commit -m "feat(rules): 5 reguli standard noi (uptime, UAC, autologon, SMBv1, Guest) in modul rules_extended"
```

---

### Task 8: Server — 5 reguli advanced

**Files:**
- Modify: `server/app/rules_extended.py`
- Test: `server/tests/test_rules_extended.py`

- [ ] **Step 8.1: Scrie testele failing** (adauga in `test_rules_extended.py`)

```python
# ── PROC-ENCODED-CMDLINE-1 (advanced) ────────────────────────────────────────

def test_encoded_cmdline_fires():
    scan = _scan("advanced", processes=[
        {"pid": 1, "name": "powershell.exe",
         "cmdline": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA..."},
    ])
    assert "PROC-ENCODED-CMDLINE-1" in _rule_ids(scan)


def test_encoded_cmdline_quiet_on_normal_powershell():
    scan = _scan("advanced", processes=[
        {"pid": 1, "name": "powershell.exe", "cmdline": "powershell.exe -File deploy.ps1"},
    ])
    assert "PROC-ENCODED-CMDLINE-1" not in _rule_ids(scan)


def test_encoded_cmdline_ignores_non_powershell():
    scan = _scan("advanced", processes=[
        {"pid": 1, "name": "python.exe", "cmdline": "python -c \"print('iex(')\""},
    ])
    assert "PROC-ENCODED-CMDLINE-1" not in _rule_ids(scan)


def test_encoded_cmdline_not_at_standard_level():
    scan = _scan("standard", processes=[
        {"pid": 1, "name": "powershell.exe", "cmdline": "powershell -enc AAA"},
    ])
    assert "PROC-ENCODED-CMDLINE-1" not in _rule_ids(scan)


# ── WIFI-INSECURE-1 (advanced) ───────────────────────────────────────────────

def test_wifi_open_fires_high():
    scan = _scan("advanced", network={"wifi_profiles": [
        {"ssid": "CafeFree", "authentication": "open"},
        {"ssid": "Acasa", "authentication": "WPA2PSK"},
    ]})
    _, _, findings = evaluate(scan)
    f = next(x for x in findings if x["rule_id"] == "WIFI-INSECURE-1")
    assert f["severity"] == "high"
    ssids = [p["ssid"] for p in f["evidence"]["profiles"]]
    assert ssids == ["CafeFree"]


def test_wifi_wpa1_fires_medium():
    scan = _scan("advanced", network={"wifi_profiles": [
        {"ssid": "VechiRouter", "authentication": "WPAPSK"},
    ]})
    _, _, findings = evaluate(scan)
    f = next(x for x in findings if x["rule_id"] == "WIFI-INSECURE-1")
    assert f["severity"] == "medium"


def test_wifi_all_secure_quiet():
    scan = _scan("advanced", network={"wifi_profiles": [
        {"ssid": "Acasa", "authentication": "WPA2PSK"},
        {"ssid": "Birou", "authentication": "WPA3SAE"},
    ]})
    assert "WIFI-INSECURE-1" not in _rule_ids(scan)


# ── PASS-POLICY-WEAK-1 (advanced) ────────────────────────────────────────────

def test_password_policy_weak_fires():
    scan = _scan("advanced", system_info={"password_policy": {
        "min_password_length": 0, "max_password_age_days": 42, "lockout_threshold": 0,
    }})
    assert "PASS-POLICY-WEAK-1" in _rule_ids(scan)


def test_password_policy_strong_quiet():
    scan = _scan("advanced", system_info={"password_policy": {
        "min_password_length": 12, "max_password_age_days": 90, "lockout_threshold": 5,
    }})
    assert "PASS-POLICY-WEAK-1" not in _rule_ids(scan)


def test_password_policy_absent_quiet():
    assert "PASS-POLICY-WEAK-1" not in _rule_ids(_scan("advanced", system_info={}))


# ── SVC-UNQUOTED-PATH-1 (advanced) ───────────────────────────────────────────

def test_unquoted_service_path_fires():
    scan = _scan("advanced", persistence={"services": [
        {"name": "EvilSvc", "status": "running",
         "binary_path": r"C:\Program Files\My App\service.exe -k netsvcs"},
    ]})
    assert "SVC-UNQUOTED-PATH-1" in _rule_ids(scan)


def test_quoted_service_path_quiet():
    scan = _scan("advanced", persistence={"services": [
        {"name": "GoodSvc", "status": "running",
         "binary_path": r'"C:\Program Files\My App\service.exe" -k netsvcs'},
    ]})
    assert "SVC-UNQUOTED-PATH-1" not in _rule_ids(scan)


def test_unquoted_path_without_spaces_quiet():
    scan = _scan("advanced", persistence={"services": [
        {"name": "Svc", "status": "running", "binary_path": r"C:\Windows\system32\svchost.exe -k x y"},
    ]})
    assert "SVC-UNQUOTED-PATH-1" not in _rule_ids(scan)


# ── PORT-PROCESS-SUSPECT-1 (advanced) ────────────────────────────────────────

def test_listener_from_temp_fires():
    scan = _scan("advanced", network={"port_processes": [
        {"port": 8888, "pid": 4242, "process": "evil.exe",
         "exe": r"C:\Users\x\AppData\Local\Temp\evil.exe"},
    ]})
    assert "PORT-PROCESS-SUSPECT-1" in _rule_ids(scan)


def test_listener_from_program_files_quiet():
    scan = _scan("advanced", network={"port_processes": [
        {"port": 5432, "pid": 100, "process": "postgres.exe",
         "exe": r"C:\Program Files\PostgreSQL\16\bin\postgres.exe"},
    ]})
    assert "PORT-PROCESS-SUSPECT-1" not in _rule_ids(scan)


def test_listener_without_exe_info_quiet():
    scan = _scan("advanced", network={"port_processes": [
        {"port": 8080, "pid": 1, "process": "x.exe", "exe": ""},
    ]})
    assert "PORT-PROCESS-SUSPECT-1" not in _rule_ids(scan)
```

- [ ] **Step 8.2: Ruleaza — trebuie sa pice**

Run (din `server/`): `.\.venv\Scripts\python.exe -m pytest tests/test_rules_extended.py -q`
Expected: FAIL pe noile teste (rule ID-uri absente)

- [ ] **Step 8.3: Implementeaza in `rules_extended.py`** (sectiune ADVANCED):

```python
# ─────────────────────────────────────────────────────────────────────────────
# ADVANCED (5)
# ─────────────────────────────────────────────────────────────────────────────


@rule("PROC-ENCODED-CMDLINE-1", min_level="advanced", category="activity",
      weight=1.2, confidence=0.8,
      compliance=["CIS-8.5", "CIS-10.7", "NIST-DE.AE-02"], os="windows")
def check_encoded_cmdline(scan: dict) -> dict | None:
    procs = scan.get("processes", []) or []
    suspicious = []
    for p in procs:
        name = (p.get("name") or "").lower()
        if "powershell" not in name and "pwsh" not in name:
            continue
        cmdline = (p.get("cmdline") or "").lower()
        if any(pat in cmdline for pat in PS_OFFENSIVE_CMDLINE_PATTERNS):
            suspicious.append({
                "pid": p.get("pid"), "name": p.get("name"),
                "cmdline": (p.get("cmdline") or "")[:200],
            })
    if not suspicious:
        return None
    return {
        "rule_id": "PROC-ENCODED-CMDLINE-1",
        "title": "Proces PowerShell rulant cu comanda encodata/ofensiva",
        "severity": "high",
        "evidence": {"processes": suspicious[:10]},
        "recommendation": (
            "Comenzile -EncodedCommand/IEX/DownloadString sunt tipice payload-urilor "
            "ofensive. Investigheaza procesul parinte si opreste procesul daca nu e legitim."
        ),
    }


@rule("WIFI-INSECURE-1", min_level="advanced", category="network_exposure", weight=1.0,
      compliance=["CIS-12.6", "NIST-PR.IR-01"], os="windows")
def check_wifi_insecure(scan: dict) -> dict | None:
    profiles = (scan.get("network", {}) or {}).get("wifi_profiles", []) or []
    flagged = []
    worst = "medium"
    for p in profiles:
        auth = (p.get("authentication") or "").lower()
        sev = WIFI_INSECURE_AUTH.get(auth)
        if sev is None:
            continue
        flagged.append({"ssid": p.get("ssid"), "authentication": p.get("authentication")})
        if sev == "high":
            worst = "high"
    if not flagged:
        return None
    return {
        "rule_id": "WIFI-INSECURE-1",
        "title": "Profile WiFi salvate cu autentificare nesigura",
        "severity": worst,
        "evidence": {"profiles": flagged},
        "recommendation": (
            "Sterge profilele nesigure (netsh wlan delete profile name=\"<SSID>\") "
            "sau reconfigureaza retelele pe WPA2/WPA3. Retelele Open/WEP permit "
            "interceptarea traficului."
        ),
    }


@rule("PASS-POLICY-WEAK-1", min_level="advanced", category="hygiene", weight=1.0,
      compliance=["CIS-5.2", "NIST-PR.AA-01"], os="windows")
def check_password_policy(scan: dict) -> dict | None:
    pol = (scan.get("system_info", {}) or {}).get("password_policy", {}) or {}
    if not pol:
        return None
    issues = []
    mpl = pol.get("min_password_length")
    if isinstance(mpl, int) and mpl < MIN_PASSWORD_LENGTH_THRESHOLD:
        issues.append(
            f"Lungime minima parola: {mpl} (recomandat >= {MIN_PASSWORD_LENGTH_THRESHOLD})")
    lockout = pol.get("lockout_threshold")
    if isinstance(lockout, int) and lockout == 0:
        issues.append("Account lockout dezactivat (LockoutBadCount=0)")
    if not issues:
        return None
    return {
        "rule_id": "PASS-POLICY-WEAK-1",
        "title": "Politica locala de parole este slaba",
        "severity": "medium",
        "evidence": {"issues": issues, "policy": pol},
        "recommendation": (
            "Configureaza in secpol.msc: lungime minima >= 8, "
            "account lockout threshold 5-10 incercari."
        ),
    }


def _is_unquoted_path_with_spaces(path: str) -> bool:
    """True pentru path de serviciu necitat cu spatii inainte de .exe —
    vectorul clasic 'unquoted service path' de escaladare de privilegii."""
    p = (path or "").strip()
    if not p or p.startswith('"'):
        return False
    low = p.lower()
    idx = low.find(".exe")
    exe_part = p[: idx + 4] if idx != -1 else p
    return " " in exe_part


@rule("SVC-UNQUOTED-PATH-1", min_level="advanced", category="hygiene",
      weight=0.8, confidence=0.9,
      compliance=["CIS-4.1", "NIST-PR.PS-01"], os="windows")
def check_unquoted_service_paths(scan: dict) -> dict | None:
    services = (scan.get("persistence", {}) or {}).get("services", []) or []
    flagged = [
        {"name": s.get("name"), "path": s.get("binary_path")}
        for s in services
        if _is_unquoted_path_with_spaces(s.get("binary_path", ""))
    ]
    if not flagged:
        return None
    return {
        "rule_id": "SVC-UNQUOTED-PATH-1",
        "title": "Servicii cu path necitat continand spatii (unquoted service path)",
        "severity": "medium",
        "evidence": {"services": flagged[:20]},
        "recommendation": (
            "Adauga ghilimele in jurul path-ului executabilului: "
            "sc config <name> binPath= '\"C:\\Program Files\\App\\svc.exe\"'. "
            "Un atacator poate planta C:\\Program.exe pentru escaladare."
        ),
    }


@rule("PORT-PROCESS-SUSPECT-1", min_level="advanced", category="network_exposure", weight=1.2,
      compliance=["CIS-4.5", "CIS-13.5", "NIST-DE.CM-01"], os="windows")
def check_listener_user_writable(scan: dict) -> dict | None:
    listeners = (scan.get("network", {}) or {}).get("port_processes", []) or []
    flagged = [
        {"port": l.get("port"), "process": l.get("process"), "exe": l.get("exe")}
        for l in listeners
        if any(pat in (l.get("exe") or "").lower() for pat in SUSPICIOUS_STARTUP_PATHS)
    ]
    if not flagged:
        return None
    return {
        "rule_id": "PORT-PROCESS-SUSPECT-1",
        "title": "Proces din director user-writable asculta pe retea",
        "severity": "high",
        "evidence": {"listeners": flagged[:20]},
        "recommendation": (
            "Un executabil din Temp/AppData care asculta pe un port este tipic "
            "pentru backdoor-uri. Verifica semnatura si provenienta; opreste "
            "procesul si scaneaza sistemul daca nu il recunosti."
        ),
    }
```

- [ ] **Step 8.4: Ruleaza testele**

Run (din `server/`): `.\.venv\Scripts\python.exe -m pytest tests/test_rules_extended.py -q`
Expected: 30 passed

- [ ] **Step 8.5: Commit**

```bash
git add server/app/rules_extended.py server/tests/test_rules_extended.py
git commit -m "feat(rules): 5 reguli advanced noi (cmdline encodat, wifi, parole, unquoted path, listener temp)"
```

---

### Task 9: Server — 5 reguli deep

**Files:**
- Modify: `server/app/rules_extended.py`
- Test: `server/tests/test_rules_extended.py`

- [ ] **Step 9.1: Scrie testele failing**

```python
# ── DEFENDER-EXCLUSIONS-1 (deep) ─────────────────────────────────────────────

def test_defender_exclusion_root_fires():
    scan = _scan("deep", system_info={"defender": {"enabled": True, "exclusions": {
        "paths": ["C:\\", "C:\\dev\\proiect"], "processes": [], "extensions": [],
    }}})
    assert "DEFENDER-EXCLUSIONS-1" in _rule_ids(scan)


def test_defender_exclusion_powershell_process_fires():
    scan = _scan("deep", system_info={"defender": {"enabled": True, "exclusions": {
        "paths": [], "processes": ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"],
        "extensions": [],
    }}})
    assert "DEFENDER-EXCLUSIONS-1" in _rule_ids(scan)


def test_defender_narrow_exclusion_quiet():
    scan = _scan("deep", system_info={"defender": {"enabled": True, "exclusions": {
        "paths": ["C:\\dev\\proiect\\node_modules"], "processes": ["msbuild.exe"],
        "extensions": [],
    }}})
    assert "DEFENDER-EXCLUSIONS-1" not in _rule_ids(scan)


# ── ARP-SPOOF-1 (deep) ───────────────────────────────────────────────────────

def test_arp_duplicate_mac_fires():
    scan = _scan("deep", forensics={"arp_table": [
        {"ip": "192.168.1.1", "mac": "aa-bb-cc-dd-ee-ff"},
        {"ip": "192.168.1.50", "mac": "aa-bb-cc-dd-ee-ff"},
        {"ip": "192.168.1.7", "mac": "11-22-33-44-55-66"},
    ]})
    assert "ARP-SPOOF-1" in _rule_ids(scan)


def test_arp_broadcast_and_multicast_ignored():
    scan = _scan("deep", forensics={"arp_table": [
        {"ip": "192.168.1.255", "mac": "ff-ff-ff-ff-ff-ff"},
        {"ip": "224.0.0.22", "mac": "01-00-5e-00-00-16"},
        {"ip": "224.0.0.251", "mac": "01-00-5e-00-00-fb"},
        {"ip": "192.168.1.1", "mac": "aa-bb-cc-dd-ee-ff"},
    ]})
    assert "ARP-SPOOF-1" not in _rule_ids(scan)


# ── DNS-SUSPICIOUS-1 (deep) ──────────────────────────────────────────────────

def test_dns_punycode_fires():
    scan = _scan("deep", forensics={"dns_cache": [
        {"name": "xn--pple-43d.com", "ip": "1.2.3.4"},
    ]})
    assert "DNS-SUSPICIOUS-1" in _rule_ids(scan)


def test_dns_abused_tld_fires():
    scan = _scan("deep", forensics={"dns_cache": [
        {"name": "login-update.tk", "ip": "5.6.7.8"},
    ]})
    assert "DNS-SUSPICIOUS-1" in _rule_ids(scan)


def test_dns_dga_label_fires():
    scan = _scan("deep", forensics={"dns_cache": [
        {"name": "xkcdqwrtzpsdfghjklbnmvcxzqwrt.com", "ip": "9.9.9.9"},
    ]})
    assert "DNS-SUSPICIOUS-1" in _rule_ids(scan)


def test_dns_normal_domains_quiet():
    scan = _scan("deep", forensics={"dns_cache": [
        {"name": "www.google.com", "ip": "142.250.1.1"},
        {"name": "github.com", "ip": "140.82.1.1"},
        {"name": "fastapi.tiangolo.com", "ip": "1.1.1.1"},
    ]})
    assert "DNS-SUSPICIOUS-1" not in _rule_ids(scan)


# ── RECENT-SYSTEM-FILES-1 (deep) ─────────────────────────────────────────────

def test_recent_executable_in_system32_fires():
    scan = _scan("deep", forensics={"recent_files": [
        {"path": "C:\\Windows\\System32\\evil.dll", "modified": "2026-06-10T12:00:00"},
    ]})
    assert "RECENT-SYSTEM-FILES-1" in _rule_ids(scan)


def test_recent_non_executable_quiet():
    scan = _scan("deep", forensics={"recent_files": [
        {"path": "C:\\Windows\\System32\\config.log", "modified": "2026-06-10T12:00:00"},
    ]})
    assert "RECENT-SYSTEM-FILES-1" not in _rule_ids(scan)


# ── AUDIT-POLICY-OFF-1 (deep) ────────────────────────────────────────────────

def test_audit_logon_off_fires():
    scan = _scan("deep", system_info={"audit_policy": {
        "audit_logon": 0, "audit_account_manage": 3,
    }})
    assert "AUDIT-POLICY-OFF-1" in _rule_ids(scan)


def test_audit_all_on_quiet():
    scan = _scan("deep", system_info={"audit_policy": {
        "audit_logon": 3, "audit_account_manage": 3,
    }})
    assert "AUDIT-POLICY-OFF-1" not in _rule_ids(scan)


def test_audit_absent_quiet():
    assert "AUDIT-POLICY-OFF-1" not in _rule_ids(_scan("deep", system_info={}))


# ── nivel: regulile deep nu ruleaza la advanced ──────────────────────────────

def test_deep_rules_skipped_at_advanced():
    scan = _scan("advanced",
                 system_info={"audit_policy": {"audit_logon": 0}},
                 forensics={"dns_cache": [{"name": "a.tk", "ip": "1.1.1.1"}]})
    ids = _rule_ids(scan)
    assert "AUDIT-POLICY-OFF-1" not in ids
    assert "DNS-SUSPICIOUS-1" not in ids
```

- [ ] **Step 9.2: Ruleaza — trebuie sa pice**

Run (din `server/`): `.\.venv\Scripts\python.exe -m pytest tests/test_rules_extended.py -q`
Expected: FAIL pe noile teste

- [ ] **Step 9.3: Implementeaza in `rules_extended.py`** (sectiune DEEP):

```python
# ─────────────────────────────────────────────────────────────────────────────
# DEEP (5)
# ─────────────────────────────────────────────────────────────────────────────


@rule("DEFENDER-EXCLUSIONS-1", min_level="deep", category="critical_risk", weight=1.5,
      compliance=["CIS-10.1", "CIS-10.6", "NIST-PR.PS-05"], os="windows")
def check_defender_exclusions(scan: dict) -> dict | None:
    defender = (scan.get("system_info", {}) or {}).get("defender", {}) or {}
    excl = defender.get("exclusions", {}) or {}
    flagged = []
    for path in excl.get("paths", []) or []:
        norm = (path or "").strip().lower().rstrip("\\")
        if norm in SUSPICIOUS_EXCLUSION_ROOTS or "\\temp" in norm or "\\appdata" in norm:
            flagged.append({"type": "path", "value": path})
    for proc in excl.get("processes", []) or []:
        base = (proc or "").strip().lower().split("\\")[-1]
        if base in SUSPICIOUS_EXCLUSION_PROCESSES:
            flagged.append({"type": "process", "value": proc})
    if not flagged:
        return None
    return {
        "rule_id": "DEFENDER-EXCLUSIONS-1",
        "title": "Exclusions Windows Defender care anuleaza protectia",
        "severity": "high",
        "evidence": {"exclusions": flagged[:20]},
        "recommendation": (
            "Malware-ul adauga frecvent exclusions largi pentru a evita detectia. "
            "Revizuieste: Get-MpPreference | Select Exclusion*; "
            "sterge: Remove-MpPreference -ExclusionPath '<path>'"
        ),
    }


@rule("ARP-SPOOF-1", min_level="deep", category="network_exposure",
      weight=1.2, confidence=0.7,
      compliance=["CIS-13.3", "NIST-DE.CM-01"], os="windows")
def check_arp_spoof(scan: dict) -> dict | None:
    table = (scan.get("forensics", {}) or {}).get("arp_table", []) or []
    by_mac: dict[str, set[str]] = {}
    for e in table:
        ip = (e.get("ip") or "").strip()
        mac = (e.get("mac") or "").strip().lower()
        if not ip or not mac:
            continue
        if any(mac.startswith(p) for p in BROADCAST_MAC_PREFIXES):
            continue
        try:
            first_octet = int(ip.split(".")[0])
        except ValueError:
            continue
        if first_octet >= 224 or ip.endswith(".255"):
            continue
        by_mac.setdefault(mac, set()).add(ip)
    duplicates = {m: sorted(ips) for m, ips in by_mac.items() if len(ips) >= 2}
    if not duplicates:
        return None
    return {
        "rule_id": "ARP-SPOOF-1",
        "title": "Acelasi MAC raspunde pentru mai multe IP-uri (posibil ARP spoofing)",
        "severity": "high",
        "evidence": {"duplicates": [
            {"mac": m, "ips": ips} for m, ips in sorted(duplicates.items())
        ][:10]},
        "recommendation": (
            "Poate indica un atac man-in-the-middle pe retea locala. Verifica "
            "echipamentele (un router legitim poate detine mai multe IP-uri); "
            "pe retele sensibile foloseste ARP inspection / intrari ARP statice."
        ),
    }


def _looks_dga(label: str) -> bool:
    """Heuristic simplu de Domain Generation Algorithm: label lung, alfanumeric,
    fara vocale (siruri pseudo-aleatoare tipice C2)."""
    return len(label) >= 25 and label.isalnum() and not any(v in label for v in "aeiou")


@rule("DNS-SUSPICIOUS-1", min_level="deep", category="activity",
      weight=0.8, confidence=0.6,
      compliance=["CIS-9.2", "NIST-DE.AE-02"], os="windows")
def check_dns_suspicious(scan: dict) -> dict | None:
    cache = (scan.get("forensics", {}) or {}).get("dns_cache", []) or []
    flagged = []
    for e in cache:
        name = (e.get("name") or "").strip().lower().rstrip(".")
        if not name:
            continue
        reasons = []
        if "xn--" in name:
            reasons.append("punycode (posibil homograph)")
        if any(name.endswith(t) for t in ABUSED_TLDS):
            reasons.append("TLD frecvent abuzat")
        if _looks_dga(name.split(".")[0]):
            reasons.append("label pseudo-aleator (posibil DGA)")
        if reasons:
            flagged.append({"name": e.get("name"), "ip": e.get("ip"), "reasons": reasons})
    if not flagged:
        return None
    return {
        "rule_id": "DNS-SUSPICIOUS-1",
        "title": "Intrari suspecte in cache-ul DNS",
        "severity": "medium",
        "evidence": {"entries": flagged[:20]},
        "recommendation": (
            "Verifica ce procese au rezolvat aceste domenii. Domeniile punycode "
            "imita branduri (homograph); TLD-urile gratuite si labelurile aleatoare "
            "sunt tipice pentru C2/phishing."
        ),
    }


@rule("RECENT-SYSTEM-FILES-1", min_level="deep", category="activity",
      weight=0.7, confidence=0.6,
      compliance=["CIS-10.7", "NIST-PR.DS-06"], os="windows")
def check_recent_system_files(scan: dict) -> dict | None:
    files = (scan.get("forensics", {}) or {}).get("recent_files", []) or []
    flagged = [
        {"path": f.get("path"), "modified": f.get("modified")}
        for f in files
        if (f.get("path") or "").lower().endswith(SYSTEM_EXECUTABLE_EXTENSIONS)
    ]
    if not flagged:
        return None
    return {
        "rule_id": "RECENT-SYSTEM-FILES-1",
        "title": "Executabile modificate recent in directoare de sistem",
        "severity": "medium",
        "evidence": {"files": flagged[:20], "total": len(flagged)},
        "recommendation": (
            "Windows Update modifica legitim fisiere de sistem — coreleaza datele "
            "cu istoricul de update-uri. Fisierele necorelate merita verificate "
            "(semnatura digitala, hash pe VirusTotal)."
        ),
    }


@rule("AUDIT-POLICY-OFF-1", min_level="deep", category="hygiene",
      weight=1.0, confidence=0.8,
      compliance=["CIS-8.2", "CIS-8.5", "NIST-DE.CM-09"], os="windows")
def check_audit_policy(scan: dict) -> dict | None:
    ap = (scan.get("system_info", {}) or {}).get("audit_policy", {}) or {}
    if not ap:
        return None
    issues = []
    if ap.get("audit_logon") == 0:
        issues.append("Auditarea evenimentelor de logon este dezactivata")
    if ap.get("audit_account_manage") == 0:
        issues.append("Auditarea administrarii conturilor este dezactivata")
    if not issues:
        return None
    return {
        "rule_id": "AUDIT-POLICY-OFF-1",
        "title": "Politica de audit dezactivata pe categorii critice",
        "severity": "medium",
        "evidence": {"issues": issues, "audit_policy": ap},
        "recommendation": (
            "Fara audit de logon, atacurile brute-force si accesele neautorizate "
            "nu lasa urme. Activeaza in secpol.msc -> Local Policies -> Audit Policy "
            "(sau auditpol /set)."
        ),
    }
```

- [ ] **Step 9.4: Ruleaza testele**

Run (din `server/`): `.\.venv\Scripts\python.exe -m pytest tests/test_rules_extended.py -q`
Expected: 45 passed

- [ ] **Step 9.5: Commit**

```bash
git add server/app/rules_extended.py server/tests/test_rules_extended.py
git commit -m "feat(rules): 5 reguli deep noi (exclusions Defender, ARP spoof, DNS, fisiere sistem, audit policy)"
```

---

### Task 10: Server — prag contract + regresie completa

**Files:**
- Modify: `server/tests/test_rule_contract.py:123-126`

- [ ] **Step 10.1: Ridica pragul minim de reguli**

In `test_rules_count_matches_expectation` schimba:

```python
def test_rules_count_matches_expectation():
    """Pragul de regularitate — daca cineva sterge accidental o regula, prinde aici.
    Actualmente: 61 reguli active (23 Windows/cross + NMAP-LUA-1 + 22 Linux + 15 extended).
    Cresterea e OK (adaugare). Scaderea trebuie verificata."""
    assert len(_RULES) >= 61, f"Numarul de reguli a scazut: {len(_RULES)} (minim asteptat 61)"
```

- [ ] **Step 10.2: Ruleaza TOATA suita server**

Run (din `server/`): `.\.venv\Scripts\python.exe -m pytest -q`
Expected: ~437+ passed, 0 failed (392 vechi + 45 noi; contract tests parametrizate cresc automat numarul)

- [ ] **Step 10.3: Ruleaza TOATA suita agent**

Run (din radacina): `python -m pytest agent -q`
Expected: 133 passed

- [ ] **Step 10.4: Commit**

```bash
git add server/tests/test_rule_contract.py
git commit -m "test(rules): prag contract ridicat la 61 de reguli"
```

---

### Task 11: Documentatie — memory.md + CLAUDE.md

**Files:**
- Modify: `agent/memory.md` (sectiunea core.py: flag-uri noi ScanProfile)
- Modify: `agent/collectors/memory.md` (system_info.py: uac/autologon/smb1/password_policy/audit_policy/exclusions; network.py: wifi_profiles + exe pe port_processes)
- Modify: `agent/tests/memory.md` (intrare noua: test_collectors_rich.py)
- Modify: `server/app/memory.md` (intrare noua: rules_extended.py; config.py: praguri noi)
- Modify: `server/tests/memory.md` (intrare noua: test_rules_extended.py; test_rule_contract.py: prag 61)
- Modify: `CLAUDE.md` (sectiunea rules engine: actualizeaza numarul de reguli si enumerarea — adauga cele 15 ID-uri noi pe nivelurile lor)

- [ ] **Step 11.1: Actualizeaza fiecare memory.md** — descrie pe scurt fisierele noi/modificate, in formatul existent al fiecarui fisier (tabel sau lista). Continutul concret: rezumatul functiilor adaugate in task-urile 1-10 (vezi titlurile commit-urilor).

- [ ] **Step 11.2: Actualizeaza CLAUDE.md** — in sectiunea "Rules engine": numarul total devine 61; adauga la enumerare: **Standard +5:** `OS-UPTIME-1` (cross), `UAC-DISABLED-1`, `AUTOLOGON-PASSWORD-1`, `SMB1-ENABLED-1`, `USER-GUEST-ENABLED-1`. **Advanced +5:** `PROC-ENCODED-CMDLINE-1`, `WIFI-INSECURE-1`, `PASS-POLICY-WEAK-1`, `SVC-UNQUOTED-PATH-1`, `PORT-PROCESS-SUSPECT-1`. **Deep +5:** `DEFENDER-EXCLUSIONS-1`, `ARP-SPOOF-1`, `DNS-SUSPICIOUS-1`, `RECENT-SYSTEM-FILES-1`, `AUDIT-POLICY-OFF-1`. Mentioneaza modulul `rules_extended.py` (importat la finalul rules.py, ca rules_linux.py).

- [ ] **Step 11.3: Verificare finala completa**

Run (din `server/`): `.\.venv\Scripts\python.exe -m pytest -q`
Run (din radacina): `python -m pytest agent -q`
Expected: totul verde

- [ ] **Step 11.4: Commit**

```bash
git add agent/memory.md agent/collectors/memory.md agent/tests/memory.md server/app/memory.md server/tests/memory.md CLAUDE.md
git commit -m "docs: memory.md + CLAUDE.md actualizate pentru cele 15 reguli noi si colectorii bogati"
```

---

## Note pentru executant

- **Ordinea task-urilor conteaza** doar partial: 1→6 (agent) si 7→10 (server) sunt lanturi independente intre ele; 11 e ultimul. In interiorul fiecarui lant, respecta ordinea.
- **Nu rula `python -m pytest` global pentru server** — pica cu `ModuleNotFoundError: slowapi`; foloseste venv-ul din `server/.venv`.
- Numerele "Expected: N passed" pentru agent presupun ca pornesti de la 117; daca suita a evoluat intre timp, valideaza delta (+6, +1, +1, +3, +1, +4), nu valoarea absoluta.
- Executabilul agentului trebuie reconstruit dupa task-urile de agent (`powershell -ExecutionPolicy Bypass -File agent\build.ps1`) doar daca vrei sa testezi end-to-end cu un device real — nu e necesar pentru suitele de teste.
