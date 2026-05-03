"""
Autostart la logon — helper cross-platform.

Strategii (toate functioneaza fara admin):
- Windows : registry HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- Linux   : ~/.config/systemd/user/vulnwatch-agent.service + systemctl --user enable
- macOS   : ~/Library/LaunchAgents/com.vulnwatch.agent.plist + launchctl load

Folosim cheia HKCU pe Windows (nu HKLM) ca sa nu cerem elevation. Cheia
ruleaza scriptul/exe-ul la login pentru user-ul curent — acelasi user al
carui token e in `~/.vulnwatch/config.ini`.
"""

from __future__ import annotations

import os
import platform
import shlex
import sys
from pathlib import Path

from . import core


REGISTRY_VALUE_NAME = "VulnWatchAgent"
SYSTEMD_UNIT_NAME = "vulnwatch-agent.service"
LAUNCHD_LABEL = "com.vulnwatch.agent"


def _agent_command() -> list[str]:
    """Comanda care va fi pornita la logon. Forma argv (lista de stringuri)."""
    if core.is_frozen():
        # Bundled .exe — argumentul implicit e "daemon".
        # Cand este lansat din autostart vrem direct daemon mode (fara fereastra).
        return [str(core.executable_path()), "daemon"]
    # Rulam ca script Python — folosim pythonw.exe pe Windows pentru a evita
    # consola; scan.py detecteaza modul GUI ca alternativa cand nu sunt
    # argumente, dar la autostart preferam daemon explicit.
    py = sys.executable
    if platform.system() == "Windows":
        # pythonw.exe = Python fara consola
        pyw = py.replace("python.exe", "pythonw.exe")
        if Path(pyw).exists():
            py = pyw
    script = str(Path(__file__).parent / "scan.py")
    return [py, script, "daemon"]


def _quote_for_run_key(argv: list[str]) -> str:
    """Construieste un command-line valid pentru HKCU\\...\\Run.
    Pune ghilimele duble pe argumentele cu spatii."""
    out = []
    for a in argv:
        if " " in a or "\t" in a:
            out.append(f'"{a}"')
        else:
            out.append(a)
    return " ".join(out)


# ── Windows ───────────────────────────────────────────────────────────────────

def _win_enable() -> tuple[bool, str]:
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return False, "winreg indisponibil (Windows-only)."
    cmd = _quote_for_run_key(_agent_command())
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE,
        ) as k:
            winreg.SetValueEx(k, REGISTRY_VALUE_NAME, 0, winreg.REG_SZ, cmd)
    except OSError as e:
        return False, f"Eroare la scrierea cheii Run: {e}"
    return True, f"Pornire automata activata. Comanda: {cmd}"


def _win_disable() -> tuple[bool, str]:
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return False, "winreg indisponibil (Windows-only)."
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE,
        ) as k:
            try:
                winreg.DeleteValue(k, REGISTRY_VALUE_NAME)
            except FileNotFoundError:
                return True, "Pornirea automata era deja dezactivata."
    except OSError as e:
        return False, f"Eroare la stergerea cheii Run: {e}"
    return True, "Pornire automata dezactivata."


def _win_status() -> tuple[bool, str]:
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return False, "winreg indisponibil."
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_READ,
        ) as k:
            try:
                value, _ = winreg.QueryValueEx(k, REGISTRY_VALUE_NAME)
                return True, f"Activata: {value}"
            except FileNotFoundError:
                return False, "Dezactivata."
    except OSError as e:
        return False, f"Eroare: {e}"


# ── Linux (systemd user) ──────────────────────────────────────────────────────

def _linux_unit_path() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / SYSTEMD_UNIT_NAME


def _linux_unit_content() -> str:
    argv = _agent_command()
    exec_start = " ".join(shlex.quote(a) for a in argv)
    return (
        "[Unit]\n"
        "Description=VulnWatch Agent (daemon)\n"
        "After=network-online.target\n"
        "\n"
        "[Service]\n"
        f"ExecStart={exec_start}\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def _linux_enable() -> tuple[bool, str]:
    unit = _linux_unit_path()
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text(_linux_unit_content(), encoding="utf-8")
    rc1 = os.system("systemctl --user daemon-reload")
    rc2 = os.system(f"systemctl --user enable --now {SYSTEMD_UNIT_NAME}")
    if rc1 != 0 or rc2 != 0:
        return False, ("Unit creat dar systemctl a esuat. Activeaza manual:\n"
                       f"  systemctl --user enable --now {SYSTEMD_UNIT_NAME}")
    return True, f"Activata. Unit: {unit}"


def _linux_disable() -> tuple[bool, str]:
    rc = os.system(f"systemctl --user disable --now {SYSTEMD_UNIT_NAME} 2>/dev/null")
    unit = _linux_unit_path()
    if unit.exists():
        unit.unlink()
    return rc == 0, "Pornire automata dezactivata."


def _linux_status() -> tuple[bool, str]:
    unit = _linux_unit_path()
    if not unit.exists():
        return False, "Dezactivata (unit lipseste)."
    rc = os.system(f"systemctl --user is-enabled --quiet {SYSTEMD_UNIT_NAME}")
    return rc == 0, f"Activata: {unit}" if rc == 0 else "Unit prezent dar dezactivat."


# ── macOS (launchd) ───────────────────────────────────────────────────────────

def _mac_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"


def _mac_plist_content() -> str:
    argv = _agent_command()
    args_xml = "\n        ".join(f"<string>{a}</string>" for a in argv)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        f"  <key>Label</key><string>{LAUNCHD_LABEL}</string>\n"
        "  <key>ProgramArguments</key>\n"
        f"  <array>\n        {args_xml}\n  </array>\n"
        "  <key>RunAtLoad</key><true/>\n"
        "  <key>KeepAlive</key><true/>\n"
        "</dict></plist>\n"
    )


def _mac_enable() -> tuple[bool, str]:
    plist = _mac_plist_path()
    plist.parent.mkdir(parents=True, exist_ok=True)
    plist.write_text(_mac_plist_content(), encoding="utf-8")
    os.system(f"launchctl unload {shlex.quote(str(plist))} 2>/dev/null")
    rc = os.system(f"launchctl load {shlex.quote(str(plist))}")
    return rc == 0, f"Activata: {plist}"


def _mac_disable() -> tuple[bool, str]:
    plist = _mac_plist_path()
    os.system(f"launchctl unload {shlex.quote(str(plist))} 2>/dev/null")
    if plist.exists():
        plist.unlink()
    return True, "Pornire automata dezactivata."


def _mac_status() -> tuple[bool, str]:
    plist = _mac_plist_path()
    return plist.exists(), f"Activata: {plist}" if plist.exists() else "Dezactivata."


# ── Public API ────────────────────────────────────────────────────────────────

def enable() -> tuple[bool, str]:
    s = platform.system()
    if s == "Windows":
        return _win_enable()
    if s == "Linux":
        return _linux_enable()
    if s == "Darwin":
        return _mac_enable()
    return False, f"Platforma {s} nesuportata."


def disable() -> tuple[bool, str]:
    s = platform.system()
    if s == "Windows":
        return _win_disable()
    if s == "Linux":
        return _linux_disable()
    if s == "Darwin":
        return _mac_disable()
    return False, f"Platforma {s} nesuportata."


def status() -> tuple[bool, str]:
    s = platform.system()
    if s == "Windows":
        return _win_status()
    if s == "Linux":
        return _linux_status()
    if s == "Darwin":
        return _mac_status()
    return False, f"Platforma {s} nesuportata."


def is_enabled() -> bool:
    ok, _ = status()
    return ok
