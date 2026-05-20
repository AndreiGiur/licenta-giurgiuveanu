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
        "Get-LocalUser | Select-Object Name, Enabled | ConvertTo-Json -Compress"
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
