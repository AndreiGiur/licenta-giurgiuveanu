"""Colectare info sistem: OS, firewall, utilizatori, BitLocker, Defender."""
from __future__ import annotations

import ctypes
import json
import os
import platform
import socket
import subprocess
import time

import psutil

from ..core import ScanProfile


def collect_system(cfg: ScanProfile) -> dict:
    out: dict = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "hostname": socket.gethostname(),
        "username": _username(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "is_admin": _is_admin(),
    }
    if cfg.include_firewall and platform.system() == "Windows":
        out["firewall"] = _firewall_status()
    if cfg.include_users and platform.system() == "Windows":
        out["local_users"] = _local_users()
    if cfg.include_bitlocker and platform.system() == "Windows":
        out["bitlocker"] = _bitlocker_status()
    if cfg.include_defender and platform.system() == "Windows":
        out["defender"] = _defender_status()
    if platform.system() == "Windows":
        out["uac"] = _uac_status()
        out["autologon"] = _autologon_status()
        smb1 = _smb1_status()
        if smb1 is not None:
            out["smb1_enabled"] = smb1
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
    return out


def _username() -> str:
    return os.environ.get("USERNAME") or os.environ.get("USER") or ""


def _is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


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
    """True daca valoarea exista in HKLM -- enumerare nume, datele NU se citesc.
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
    """SMB1 din LanmanServer Parameters. None = cheia lipseste (default OS --
    pe Win10+ inseamna dezactivat; regula NU se declanseaza pe None)."""
    val = _reg_value(_LANMAN_PARAMS, "SMB1")
    if val is None:
        return None
    return bool(val)


def _to_int(val: str) -> int | None:
    try:
        return int(str(val).strip().strip('"'))
    except (ValueError, TypeError):
        return None


def _parse_secedit_inf(text: str) -> dict:
    """Parseaza INF-ul exportat de secedit. Cheile sunt fixe si numerice --
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


def _ps(script: str, timeout: int = 30) -> str | None:
    """Ruleaza PowerShell silent; returneaza stdout sau None la esec."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return None


def _firewall_status() -> dict:
    """Citeste profilurile firewall din registry."""
    profiles = {"domain": None, "private": None, "public": None}
    try:
        import winreg  # type: ignore[import-not-found]
        base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        for name, sub in [("domain", "DomainProfile"), ("private", "StandardProfile"), ("public", "PublicProfile")]:
            try:
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{base}\\{sub}")
                val, _ = winreg.QueryValueEx(k, "EnableFirewall")
                profiles[name] = bool(val)
                winreg.CloseKey(k)
            except (FileNotFoundError, OSError):
                pass
    except ImportError:
        pass
    return {"profiles": profiles}


def _local_users() -> list[dict]:
    """Conturi locale + flag is_admin (folosind PowerShell Get-LocalUser)."""
    out = _ps(
        "Get-LocalUser | Select-Object Name, Enabled, PasswordRequired | ConvertTo-Json -Compress"
    )
    users: list[dict] = []
    if out:
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for u in data:
                users.append({
                    "name": u.get("Name", ""),
                    "enabled": bool(u.get("Enabled", True)),
                    "password_required": bool(u.get("PasswordRequired", True)),
                    "is_admin": False,
                })
        except json.JSONDecodeError:
            pass

    admin_names = _ps(
        "Get-LocalGroupMember -Group Administrators | "
        "Select-Object -ExpandProperty Name | ConvertTo-Json -Compress"
    )
    if admin_names:
        try:
            members = json.loads(admin_names)
            if isinstance(members, str):
                members = [members]
            short = {str(m).split("\\")[-1].lower() for m in members}
            for u in users:
                if u["name"].lower() in short:
                    u["is_admin"] = True
        except json.JSONDecodeError:
            pass
    return users


def _bitlocker_status() -> list[dict]:
    out = _ps(
        "Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus, EncryptionPercentage | "
        "ConvertTo-Json -Compress"
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        result: list[dict] = []
        for v in data:
            ps_val = v.get("ProtectionStatus")
            # ProtectionStatus: 0=Off, 1=On, 2=Unknown
            status = "on" if ps_val == 1 else ("off" if ps_val == 0 else "unknown")
            result.append({
                "volume": v.get("MountPoint", ""),
                "protection_status": status,
                "encryption_percent": v.get("EncryptionPercentage", 0),
            })
        return result
    except json.JSONDecodeError:
        return []


def _defender_status() -> dict:
    """Status Defender + lista AV-uri terte din SecurityCenter2.

    Returneaza:
      - `enabled`/`signature_age_days`/`mode` pentru Defender
      - `third_party_av`: lista nume AV-uri terte cu real-time activ
        (bit 0x1000 in productState). Daca exista, Defender disabled e NORMAL.
    """
    result: dict = {}

    out = _ps(
        "Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled, "
        "AntivirusSignatureLastUpdated | ConvertTo-Json -Compress"
    )
    if out:
        try:
            data = json.loads(out)
            enabled = bool(data.get("RealTimeProtectionEnabled", False))
            sig_age = 0
            sig_raw = str(data.get("AntivirusSignatureLastUpdated", ""))
            if "Date(" in sig_raw:
                try:
                    ms = int(sig_raw.split("Date(")[1].split(")")[0])
                    sig_age = int((time.time() - ms / 1000) / 86400)
                except (ValueError, IndexError):
                    pass
            result["enabled"] = enabled
            result["signature_age_days"] = max(0, sig_age)
            result["mode"] = data.get("AMRunningMode", "")
        except json.JSONDecodeError:
            pass

    # SecurityCenter2: listare AV-uri inregistrate (Defender + terti).
    # productState bit 0x1000 (4096) = real-time activ.
    sc_out = _ps(
        "Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct "
        "-ErrorAction SilentlyContinue | Select-Object displayName, productState | "
        "ConvertTo-Json -Compress"
    )
    third_party = []
    if sc_out:
        try:
            data = json.loads(sc_out)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                name = (item.get("displayName") or "").strip()
                state = int(item.get("productState") or 0)
                # Skip Defender (raportat separat) + skip AV-uri inactive.
                if "windows defender" in name.lower() or "microsoft defender" in name.lower():
                    continue
                # Bit 0x1000 = real-time enabled. Folosim pentru a marca "activ".
                if state & 0x1000:
                    third_party.append({"name": name, "product_state": state})
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
    result["third_party_av"] = third_party
    return result
