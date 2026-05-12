"""Colectare software instalat: registry Windows (Uninstall keys)."""
from __future__ import annotations

import platform

from ..core import ScanProfile


def collect_software(cfg: ScanProfile) -> list[dict]:
    if not cfg.include_software or platform.system() != "Windows":
        return []
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return []

    software: list[dict] = []
    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, path in keys:
        try:
            key = winreg.OpenKey(hive, path)
        except FileNotFoundError:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(key, i)
                i += 1
                try:
                    subkey = winreg.OpenKey(key, sub)
                    name = ""
                    version = ""
                    try:
                        name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                    except FileNotFoundError:
                        pass
                    try:
                        version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                    except FileNotFoundError:
                        pass
                    if name:
                        software.append({"name": name, "version": version or ""})
                    winreg.CloseKey(subkey)
                except OSError:
                    pass
            except OSError:
                break
        winreg.CloseKey(key)

    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for s in software:
        key = (s["name"], s["version"])
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    return deduped
