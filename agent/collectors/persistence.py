"""Colectare persistente: startup, tasks, services, PS policy, WMI subs, registry hijack."""
from __future__ import annotations

import json
import platform
import subprocess

from ..core import ScanProfile


def collect_persistence(cfg: ScanProfile) -> dict:
    if platform.system() != "Windows":
        return {}

    out: dict = {}
    if cfg.include_startup:
        out["startup"] = _startup()
    if cfg.include_tasks:
        out["tasks"] = _tasks()
    if cfg.include_services:
        out["services"] = _services()
    if cfg.include_ps_policy:
        out["ps_policy"] = _ps_policy()
    if cfg.include_reg_hijack:
        out["reg_persistence"] = _reg_hijack()
    if cfg.include_wmi:
        out["wmi_subscriptions"] = _wmi_subscriptions()
    return out


def _ps(script: str, timeout: int = 60) -> str | None:
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


def _startup() -> list[dict]:
    entries: list[dict] = []
    try:
        import winreg  # type: ignore[import-not-found]
        for hive, base in [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]:
            try:
                k = winreg.OpenKey(hive, base)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                        entries.append({"key": name, "path": str(value), "source": base})
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(k)
            except FileNotFoundError:
                pass
    except ImportError:
        pass
    return entries


def _tasks() -> list[dict]:
    out = _ps(
        "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
        "ForEach-Object { "
        "  $a = $_.Actions[0]; "
        "  [PSCustomObject]@{ "
        "    Name = $_.TaskName; "
        "    Action = if ($a.Execute) { \"$($a.Execute) $($a.Arguments)\" } else { '' } "
        "  } "
        "} | ConvertTo-Json -Compress"
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [{"name": t.get("Name", ""), "action": t.get("Action", "")} for t in data]
    except json.JSONDecodeError:
        return []


def _services() -> list[dict]:
    out = _ps(
        "Get-CimInstance Win32_Service | "
        "Select-Object Name, DisplayName, State, StartMode, PathName | "
        "ConvertTo-Json -Compress"
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [
            {
                "name": s.get("Name", ""),
                "display_name": s.get("DisplayName", ""),
                "status": str(s.get("State", "")).lower(),
                "start_type": str(s.get("StartMode", "")).lower(),
                "binary_path": s.get("PathName") or "",
            }
            for s in data
        ]
    except json.JSONDecodeError:
        return []


def _ps_policy() -> str:
    out = _ps("Get-ExecutionPolicy")
    return out or ""


def _reg_hijack() -> dict:
    """Citeste AppInit_DLLs, IFEO Debugger overrides, Winlogon shell/userinit."""
    result: dict = {"AppInit_DLLs": "", "IFEO": {}, "Winlogon": {}}
    try:
        import winreg  # type: ignore[import-not-found]

        try:
            k = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            )
            val, _ = winreg.QueryValueEx(k, "AppInit_DLLs")
            result["AppInit_DLLs"] = str(val).strip()
            winreg.CloseKey(k)
        except (FileNotFoundError, OSError):
            pass

        try:
            base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
            i = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(k, i)
                    i += 1
                    try:
                        sk = winreg.OpenKey(k, sub_name)
                        try:
                            dbg, _ = winreg.QueryValueEx(sk, "Debugger")
                            result["IFEO"][sub_name] = str(dbg)
                        except FileNotFoundError:
                            pass
                        winreg.CloseKey(sk)
                    except OSError:
                        pass
                except OSError:
                    break
            winreg.CloseKey(k)
        except FileNotFoundError:
            pass

        try:
            k = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            )
            DEFAULTS = {
                "Userinit": "C:\\Windows\\system32\\userinit.exe,",
                "Shell": "explorer.exe",
            }
            for valname in ("Userinit", "Shell", "Notify"):
                try:
                    v, _ = winreg.QueryValueEx(k, valname)
                    s = str(v).strip()
                    if s and s != DEFAULTS.get(valname, ""):
                        result["Winlogon"][valname] = s
                except FileNotFoundError:
                    pass
            winreg.CloseKey(k)
        except FileNotFoundError:
            pass
    except ImportError:
        pass
    return result


def _wmi_subscriptions() -> list[dict]:
    out = _ps(
        "Get-WmiObject -Namespace root\\subscription -Class __EventConsumer "
        "-ErrorAction SilentlyContinue | "
        "Select-Object Name, CommandLineTemplate, ExecutablePath | ConvertTo-Json -Compress"
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [
            {
                "name": s.get("Name", ""),
                "command": s.get("CommandLineTemplate") or s.get("ExecutablePath") or "",
            }
            for s in data
        ]
    except json.JSONDecodeError:
        return []
