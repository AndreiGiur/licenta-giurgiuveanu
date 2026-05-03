#!/usr/bin/env python3
"""
VulnWatch Agent

Comenzi:
    python scan.py enroll [--api URL]   Inroleaza dispozitivul (interactiv).
    python scan.py                      Ruleaza o scanare folosind config-ul salvat.
    python scan.py scan                 Sinonim pentru implicit.
    python scan.py logout               Sterge configul local (token + URL).
    python scan.py status               Afiseaza configul curent (fara token).

Configul este salvat la:
    ~/.vulnwatch/config.ini

User-ul nu mai trebuie sa copieze tokenul manual: comanda `enroll` se autentifica
in backend, creeaza dispozitivul si salveaza tokenul local automat.
"""

from __future__ import annotations

import argparse
import configparser
import ctypes
import getpass
import os
import platform
import socket
import stat
import sys
from datetime import datetime
from pathlib import Path

import psutil
import requests


# ── Configuratie locala ────────────────────────────────────────────────────────

CONFIG_DIR = Path.home() / ".vulnwatch"
CONFIG_FILE = CONFIG_DIR / "config.ini"
DEFAULT_API_BASE = "http://127.0.0.1:8000/api/v1"


def _read_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        config.read(CONFIG_FILE, encoding="utf-8")
    return config


def _write_config(config: configparser.ConfigParser) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with CONFIG_FILE.open("w", encoding="utf-8") as f:
        config.write(f)
    # Permisiuni 0600 pe POSIX (token-ul este sensibil).
    if os.name == "posix":
        try:
            os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def _get_config_or_die() -> tuple[str, str, str]:
    """Returneaza (api_base, device_uid, device_token) sau iese cu mesaj."""
    config = _read_config()
    if not config.has_section("agent"):
        print("Agent neinrolat. Ruleaza: python scan.py enroll")
        sys.exit(1)
    api_base = config.get("agent", "api_base", fallback=DEFAULT_API_BASE)
    device_uid = config.get("agent", "device_uid", fallback="").strip()
    device_token = config.get("agent", "device_token", fallback="").strip()
    if not device_uid or not device_token:
        print("Configuratie incompleta. Ruleaza: python scan.py enroll")
        sys.exit(1)
    return api_base, device_uid, device_token


# ── Colectare date sistem ──────────────────────────────────────────────────────

def is_admin() -> bool:
    """Verifica daca procesul curent ruleaza cu privilegii de administrator."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def get_open_ports() -> list[int]:
    """Returneaza lista porturilor TCP in stare LISTEN.
    Pe Linux poate necesita root pentru a vedea procesele asociate."""
    open_ports: list[int] = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != psutil.CONN_LISTEN:
                continue
            laddr = conn.laddr
            if laddr and laddr.port not in open_ports:
                open_ports.append(laddr.port)
    except (psutil.AccessDenied, PermissionError) as e:
        print(f"  Avertisment: nu s-au putut citi conexiunile de retea ({e}).")
    except Exception as e:  # ultim resort
        print(f"  Avertisment: eroare la citirea porturilor: {e}")
    return sorted(open_ports)


def get_processes(limit: int = 50) -> list[dict]:
    processes: list[dict] = []
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
    processes.sort(key=lambda x: x["memory_mb"], reverse=True)
    return processes[:limit]


def get_installed_software() -> list[dict]:
    """Windows: citeste registry-ul. Pe alte SO returneaza lista goala."""
    software: list[dict] = []
    if platform.system() != "Windows":
        return software
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return software

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
    return software


def collect_system_data(device_uid: str) -> dict:
    return {
        "device_uid": device_uid,
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "hostname": socket.gethostname(),
            "is_admin": is_admin(),
        },
        "network": {
            "open_ports": get_open_ports(),
        },
        "processes": get_processes(),
        "software": get_installed_software(),
    }


# ── Apeluri HTTP catre backend ────────────────────────────────────────────────

class ApiError(Exception):
    pass


def _request(method: str, url: str, *, json=None, headers=None, timeout=15) -> dict:
    try:
        r = requests.request(method, url, json=json, headers=headers, timeout=timeout)
    except requests.exceptions.ConnectionError:
        raise ApiError(f"Nu ma pot conecta la {url}. Serverul ruleaza?")
    except requests.exceptions.Timeout:
        raise ApiError(f"Timeout la {url}")
    except requests.exceptions.RequestException as e:
        raise ApiError(str(e))

    if not r.ok:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        raise ApiError(f"HTTP {r.status_code}: {detail}")

    if not r.text:
        return {}
    try:
        return r.json()
    except ValueError:
        return {}


def api_login(api_base: str, email: str, password: str) -> str:
    data = _request("POST", f"{api_base}/auth/login",
                    json={"email": email, "password": password})
    token = data.get("session_token")
    if not token:
        raise ApiError("Raspuns login invalid: lipseste session_token")
    return token


def api_register(api_base: str, email: str, password: str) -> None:
    _request("POST", f"{api_base}/auth/register",
             json={"email": email, "password": password})


def api_create_device(api_base: str, session_token: str, device_uid: str, name: str) -> dict:
    return _request(
        "POST",
        f"{api_base}/devices",
        json={"device_uid": device_uid, "name": name},
        headers={"X-Session-Token": session_token},
    )


def api_logout(api_base: str, session_token: str) -> None:
    try:
        _request("DELETE", f"{api_base}/auth/logout",
                 headers={"X-Session-Token": session_token})
    except ApiError:
        pass  # logout idempotent


def api_send_scan(api_base: str, device_token: str, payload: dict) -> dict:
    return _request(
        "POST",
        f"{api_base}/scans",
        json=payload,
        headers={"X-Device-Token": device_token},
    )


# ── Subcomenzi ────────────────────────────────────────────────────────────────

def cmd_enroll(args: argparse.Namespace) -> int:
    api_base = (args.api or DEFAULT_API_BASE).rstrip("/")

    print("=" * 60)
    print(" VulnWatch — inrolare dispozitiv")
    print("=" * 60)
    print(f" API: {api_base}")
    print()

    # 1) Credentiale user
    email = (args.email or input("Email: ")).strip().lower()
    password = args.password or getpass.getpass("Parola: ")
    if not email or not password:
        print("Email si parola sunt obligatorii.")
        return 2

    # 2) Login (sau register + login daca contul nu exista)
    print("\nAutentificare...")
    session_token: str
    try:
        session_token = api_login(api_base, email, password)
        print("  → autentificat.")
    except ApiError as e:
        if "401" in str(e) or "invalid credentials" in str(e).lower():
            print("  → credentiale incorecte sau cont inexistent.")
            choice = input("Vrei sa creez cont nou cu acest email? [Y/n] ").strip().lower()
            if choice in ("", "y", "yes", "da", "d"):
                try:
                    api_register(api_base, email, password)
                    print("  → cont creat.")
                    session_token = api_login(api_base, email, password)
                    print("  → autentificat.")
                except ApiError as e2:
                    print(f"  EROARE: {e2}")
                    return 3
            else:
                return 3
        else:
            print(f"  EROARE: {e}")
            return 3

    # 3) Inrolare device
    default_uid = args.device_uid or socket.gethostname().lower()
    device_uid = input(f"Device UID [{default_uid}]: ").strip() or default_uid
    default_name = args.name or f"{platform.system()} {socket.gethostname()}"
    device_name = input(f"Nume afisat [{default_name}]: ").strip() or default_name

    print("\nInregistrez dispozitivul...")
    try:
        created = api_create_device(api_base, session_token, device_uid, device_name)
    except ApiError as e:
        if "already exists" in str(e):
            print(f"  Dispozitivul '{device_uid}' exista deja.")
            print("  Sterge-l din UI sau alege alt UID.")
            api_logout(api_base, session_token)
            return 4
        print(f"  EROARE: {e}")
        api_logout(api_base, session_token)
        return 4

    device_token = created.get("device_token")
    if not device_token:
        print("  EROARE: backend-ul nu a returnat device_token.")
        api_logout(api_base, session_token)
        return 4

    # 4) Salvare config
    config = configparser.ConfigParser()
    config["agent"] = {
        "api_base": api_base,
        "device_uid": device_uid,
        "device_token": device_token,
    }
    _write_config(config)

    # 5) Cleanup sesiune (nu mai avem nevoie de ea pe agent — folosim device_token)
    api_logout(api_base, session_token)

    print(f"  → dispozitiv inregistrat ({created.get('name')})")
    print(f"\nConfig salvat: {CONFIG_FILE}")
    print("\nPoti rula acum: python scan.py")
    return 0


def cmd_scan(_args: argparse.Namespace) -> int:
    api_base, device_uid, device_token = _get_config_or_die()

    print("=" * 60)
    print(" VulnWatch — scanare")
    print("=" * 60)
    print(f" API        : {api_base}")
    print(f" Device UID : {device_uid}")
    print(f" Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Admin      : {is_admin()}")
    print()

    print("Colectez date sistem...")
    data = collect_system_data(device_uid)
    print(f"  OS       : {data['os']['system']} {data['os']['release']}")
    print(f"  Hostname : {data['os']['hostname']}")
    print(f"  Porturi  : {data['network']['open_ports'] or 'niciunul detectat'}")
    print(f"  Procese  : {len(data['processes'])}")
    print(f"  Software : {len(data['software'])} programe")
    print()

    print("Trimit scanarea...")
    try:
        result = api_send_scan(api_base, device_token, data)
    except ApiError as e:
        print(f"  EROARE: {e}")
        if "invalid device token" in str(e).lower():
            print("  Tokenul nu mai e valid. Re-inroleaza dispozitivul:")
            print("    python scan.py enroll")
        return 5

    print()
    print("Scanare trimisa cu succes!")
    print(f"  Scan ID       : {result.get('scan_id')}")
    print(f"  Exposure Score: {result.get('exposure_score')}/100")
    findings = result.get("findings", [])
    print(f"  Findings      : {len(findings)}")
    print()

    if findings:
        print("Vulnerabilitati detectate:")
        sev_label = {"critical": "[CRIT] ", "high": "[HIGH] ", "medium": "[MED]  ", "low": "[LOW]  "}
        for f in findings:
            label = sev_label.get(f.get("severity", ""), "[INFO] ")
            print(f"  {label} {f.get('title', '')}")
            print(f"           {f.get('recommendation', '')}")
        print()

    frontend = api_base.replace("/api/v1", "").replace("8000", "5173")
    print(f"Vezi rezultatele: {frontend}/dashboard?device={device_uid}")
    return 0


def cmd_logout(_args: argparse.Namespace) -> int:
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
        print(f"Config sters: {CONFIG_FILE}")
    else:
        print("Niciun config gasit.")
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    config = _read_config()
    if not config.has_section("agent"):
        print("Agent neinrolat.")
        return 1
    api_base = config.get("agent", "api_base", fallback="?")
    device_uid = config.get("agent", "device_uid", fallback="?")
    has_token = bool(config.get("agent", "device_token", fallback="").strip())
    print(f"API        : {api_base}")
    print(f"Device UID : {device_uid}")
    print(f"Token      : {'configurat' if has_token else 'lipseste'}")
    print(f"Config file: {CONFIG_FILE}")
    return 0


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan.py",
        description="VulnWatch Agent — colectare locala si trimitere catre backend.",
    )
    sub = parser.add_subparsers(dest="cmd")

    p_enroll = sub.add_parser("enroll", help="Inrolare interactiva (login + creare device).")
    p_enroll.add_argument("--api", help=f"URL API (default: {DEFAULT_API_BASE})")
    p_enroll.add_argument("--email", help="Email (altfel se cere interactiv)")
    p_enroll.add_argument("--password", help="Parola (altfel se cere interactiv)")
    p_enroll.add_argument("--device-uid", dest="device_uid",
                          help="UID device (default: hostname)")
    p_enroll.add_argument("--name", help="Nume afisat (default: 'OS hostname')")
    p_enroll.set_defaults(func=cmd_enroll)

    p_scan = sub.add_parser("scan", help="Ruleaza o scanare (default).")
    p_scan.set_defaults(func=cmd_scan)

    sub.add_parser("logout", help="Sterge configul local.").set_defaults(func=cmd_logout)
    sub.add_parser("status", help="Afiseaza configul curent.").set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.cmd:
        # default: scan
        return cmd_scan(args)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
