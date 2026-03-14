#!/usr/bin/env python3
"""
Exposure Platform Agent
Colecteaza date reale despre sistem si le trimite la backend.
Configurare prin agent/config.ini
"""

import configparser
import ctypes
import os
import platform
import socket
import sys
from datetime import datetime
from pathlib import Path

import psutil
import requests

# ── Config ────────────────────────────────────────────────────────────────────

CONFIG_FILE = Path(__file__).parent / "config.ini"

def load_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    if not CONFIG_FILE.exists():
        print(f"ERROR: Fisierul de configurare lipseste: {CONFIG_FILE}")
        print("Creaza-l dupa modelul config.ini.example")
        sys.exit(1)
    config.read(CONFIG_FILE, encoding="utf-8")
    return config

# ── Colectare date ─────────────────────────────────────────────────────────────

def is_admin() -> bool:
    """Verifica daca procesul curent ruleaza cu privilegii de administrator."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_open_ports() -> list[int]:
    """Returneaza lista porturilor TCP care asculta pe toate interfetele (0.0.0.0 / ::)."""
    open_ports = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            # Doar conexiuni in stare LISTEN
            if conn.status != psutil.CONN_LISTEN:
                continue
            # Doar cele expuse public (0.0.0.0 sau ::) sau localhost
            laddr = conn.laddr
            if laddr and laddr.port not in open_ports:
                open_ports.append(laddr.port)
    except (psutil.AccessDenied, Exception) as e:
        print(f"  Avertisment: nu s-au putut citi conexiunile de retea: {e}")
    return sorted(open_ports)


def get_processes() -> list[dict]:
    """Returneaza lista proceselor active cu PID, nume si consum memorie."""
    processes = []
    for proc in psutil.process_iter(["pid", "name", "memory_info", "username"]):
        try:
            info = proc.info
            mem = info["memory_info"]
            processes.append({
                "pid": info["pid"],
                "name": info["name"] or "",
                "memory_mb": round(mem.rss / (1024 * 1024), 1) if mem else 0,
                "username": info["username"] or "",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    # Sortat dupa memorie descrescator
    processes.sort(key=lambda x: x["memory_mb"], reverse=True)
    return processes[:50]


def get_installed_software() -> list[dict]:
    """
    Windows: citeste din registru lista programelor instalate.
    Linux/macOS: returneaza lista goala (se poate extinde cu dpkg/brew).
    """
    software = []
    if platform.system() != "Windows":
        return software
    try:
        import winreg
        keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ]
        for key_path in keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            except FileNotFoundError:
                continue
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    try:
                        name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                        version = ""
                        try:
                            version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                        except FileNotFoundError:
                            pass
                        if name:
                            software.append({"name": name, "version": version})
                    except FileNotFoundError:
                        pass
                    winreg.CloseKey(subkey)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
    except Exception as e:
        print(f"  Avertisment: nu s-a putut citi registrul: {e}")
    return software


def collect_system_data(device_uid: str) -> dict:
    """Colecteaza toate datele despre sistem."""
    admin = is_admin()
    open_ports = get_open_ports()
    processes = get_processes()
    software = get_installed_software()

    return {
        "device_id": device_uid,
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "hostname": socket.gethostname(),
            "is_admin": admin,
        },
        "network": {
            "open_ports": open_ports,
        },
        "processes": processes,
        "software": software,
    }


# ── Trimitere la backend ───────────────────────────────────────────────────────

def send_scan(data: dict, api_base: str, device_token: str) -> dict:
    headers = {
        "X-Device-Token": device_token,
        "Content-Type": "application/json",
    }
    try:
        response = requests.post(
            f"{api_base}/scans",
            json=data,
            headers=headers,
            timeout=15,
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        print(f"ERROR: Nu ma pot conecta la {api_base}. Serverul ruleaza?")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"ERROR: Raspuns HTTP {e.response.status_code}: {e.response.text}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: {e}")
        sys.exit(1)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    config = load_config()

    api_base = config.get("agent", "api_base", fallback="http://127.0.0.1:8000/api/v1")
    device_uid = config.get("agent", "device_uid", fallback="").strip()
    device_token = config.get("agent", "device_token", fallback="").strip()

    if not device_uid:
        print("ERROR: 'device_uid' nu este configurat in config.ini")
        sys.exit(1)
    if not device_token:
        print("ERROR: 'device_token' nu este configurat in config.ini")
        print("Inregistreaza dispozitivul in platforma si copiaza token-ul.")
        sys.exit(1)

    print("Exposure Platform Agent")
    print("=" * 50)
    print(f"Device UID : {device_uid}")
    print(f"API        : {api_base}")
    print(f"Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Admin      : {is_admin()}")
    print()

    print("Colectez date sistem...")
    data = collect_system_data(device_uid)
    print(f"  OS       : {data['os']['system']} {data['os']['release']}")
    print(f"  Hostname : {data['os']['hostname']}")
    print(f"  Porturi  : {data['network']['open_ports'] or 'niciunul detectat'}")
    print(f"  Procese  : {len(data['processes'])}")
    print(f"  Software : {len(data['software'])} programe instalate")
    print()

    print("Trimit scanare la backend...")
    result = send_scan(data, api_base, device_token)

    print()
    print("Scanare trimisa cu succes!")
    print(f"  Scan ID       : {result['scan_id']}")
    print(f"  Exposure Score: {result['exposure_score']}/100")
    print(f"  Findings      : {len(result['findings'])}")
    print()

    if result["findings"]:
        print("Vulnerabilitati detectate:")
        for f in result["findings"]:
            icon = {"high": "[HIGH]  ", "medium": "[MEDIUM]", "low": "[LOW]   "}.get(f["severity"], "[INFO]  ")
            print(f"  {icon} {f['title']}")
            print(f"           {f['recommendation']}")
        print()

    frontend = api_base.replace("/api/v1", "").replace("8000", "5173")
    print(f"Vezi rezultatele la: {frontend}/dashboard?device={device_uid}")


if __name__ == "__main__":
    main()
