"""
VulnWatch Agent — modulul de baza.

Contine logica refolosibila intre CLI (scan.py) si GUI (gui.py):
- citire/scriere config
- colectare date sistem (OS, porturi, procese, software)
- apeluri HTTP catre backend
- bucla daemon (polling job queue)

Toate functiile sunt independente de UI — nu fac print/input.
Comunicarea cu UI-ul se face prin callback-uri (parametrul `log` mai jos)
si prin exceptii bine definite (`ApiError`).
"""

from __future__ import annotations

import configparser
import ctypes
import os
import platform
import socket
import stat
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

import psutil
import requests


# ── Configuratie locala ────────────────────────────────────────────────────────

CONFIG_DIR = Path.home() / ".vulnwatch"
CONFIG_FILE = CONFIG_DIR / "config.ini"
DEFAULT_API_BASE = "http://127.0.0.1:8000/api/v1"

# Tip pentru un callback de log (folosit ca punte intre logica si UI).
# Severity: "info" | "warn" | "error" | "ok"
LogFn = Callable[[str, str], None]


def _noop_log(_msg: str, _severity: str = "info") -> None:
    pass


def read_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        cfg.read(CONFIG_FILE, encoding="utf-8")
    return cfg


def write_config(cfg: configparser.ConfigParser) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with CONFIG_FILE.open("w", encoding="utf-8") as f:
        cfg.write(f)
    # Permisiuni 0600 pe POSIX (token-ul este sensibil).
    if os.name == "posix":
        try:
            os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def clear_config() -> bool:
    """Returneaza True daca a fost sters ceva."""
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
        return True
    return False


def is_enrolled() -> bool:
    cfg = read_config()
    if not cfg.has_section("agent"):
        return False
    return bool(
        cfg.get("agent", "device_uid", fallback="").strip()
        and cfg.get("agent", "device_token", fallback="").strip()
    )


def get_enrollment() -> tuple[str, str, str]:
    """Returneaza (api_base, device_uid, device_token). Arunca daca lipseste."""
    cfg = read_config()
    if not cfg.has_section("agent"):
        raise RuntimeError("Agent neinrolat")
    api_base = cfg.get("agent", "api_base", fallback=DEFAULT_API_BASE).rstrip("/")
    device_uid = cfg.get("agent", "device_uid", fallback="").strip()
    device_token = cfg.get("agent", "device_token", fallback="").strip()
    if not device_uid or not device_token:
        raise RuntimeError("Configuratie incompleta")
    return api_base, device_uid, device_token


def save_enrollment(api_base: str, device_uid: str, device_token: str) -> None:
    cfg = configparser.ConfigParser()
    cfg["agent"] = {
        "api_base": api_base.rstrip("/"),
        "device_uid": device_uid,
        "device_token": device_token,
    }
    write_config(cfg)


# ── Colectare date sistem ─────────────────────────────────────────────────────

def is_admin() -> bool:
    """Verifica daca procesul ruleaza cu privilegii ridicate."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def get_open_ports() -> list[int]:
    """Lista porturilor TCP in stare LISTEN."""
    open_ports: list[int] = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != psutil.CONN_LISTEN:
                continue
            laddr = conn.laddr
            if laddr and laddr.port not in open_ports:
                open_ports.append(laddr.port)
    except (psutil.AccessDenied, PermissionError):
        # Pe Linux poate cere root. Nu blocam scanul.
        pass
    except Exception:
        pass
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
    """Windows: registry HKLM Uninstall. Alte SO: lista goala."""
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
        "network": {"open_ports": get_open_ports()},
        "processes": get_processes(),
        "software": get_installed_software(),
    }


# ── HTTP catre backend ────────────────────────────────────────────────────────

class ApiError(Exception):
    """Eroare la nivelul API (HTTP non-2xx, network down, timeout, etc.)."""


def _request(method: str, url: str, *, json=None, headers=None, timeout=15) -> dict:
    try:
        r = requests.request(method, url, json=json, headers=headers, timeout=timeout)
    except requests.exceptions.ConnectionError:
        raise ApiError(f"Nu ma pot conecta la {url}")
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
        "POST", f"{api_base}/devices",
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
        "POST", f"{api_base}/scans",
        json=payload,
        headers={"X-Device-Token": device_token},
    )


def api_get_next_job(api_base: str, device_token: str) -> dict | None:
    """Returneaza dict-ul jobului sau None daca nu sunt joburi pending."""
    try:
        r = requests.get(
            f"{api_base}/agent/jobs/next",
            headers={"X-Device-Token": device_token, "Content-Type": "application/json"},
            timeout=15,
        )
    except requests.exceptions.ConnectionError:
        raise ApiError(f"Nu ma pot conecta la {api_base}")
    except requests.exceptions.RequestException as e:
        raise ApiError(str(e))

    if r.status_code == 204:
        return None
    if not r.ok:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        raise ApiError(f"HTTP {r.status_code}: {detail}")
    return r.json()


def api_submit_job_result(api_base: str, device_token: str, job_id: int, payload: dict) -> dict:
    body = {
        "os": payload["os"],
        "network": payload.get("network", {}),
        "processes": payload.get("processes", []),
        "software": payload.get("software", []),
    }
    return _request(
        "POST", f"{api_base}/agent/jobs/{job_id}/result",
        json=body,
        headers={"X-Device-Token": device_token},
    )


def api_submit_job_failure(api_base: str, device_token: str, job_id: int, error_message: str) -> dict:
    return _request(
        "POST", f"{api_base}/agent/jobs/{job_id}/fail",
        json={"error_message": error_message[:512]},
        headers={"X-Device-Token": device_token},
    )


# ── Bucla daemon (refolosita de CLI si GUI) ───────────────────────────────────

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def run_one_job(api_base: str, device_uid: str, device_token: str,
                job: dict, log: LogFn = _noop_log) -> None:
    """Executa un job primit de la coada. Raporteaza rezultatul/esecul."""
    job_id = job["job_id"]
    log(f"[{_ts()}] Job #{job_id} primit. Colectez date...", "info")
    try:
        data = collect_system_data(device_uid)
        result = api_submit_job_result(api_base, device_token, job_id, data)
        score = result.get("exposure_score")
        scan_id = result.get("scan_id")
        log(f"[{_ts()}] Job #{job_id} done. Scan #{scan_id}, score {score}/100.", "ok")
    except ApiError as e:
        log(f"[{_ts()}] Job #{job_id} failed: {e}", "error")
        try:
            api_submit_job_failure(api_base, device_token, job_id, str(e))
        except ApiError:
            pass
    except Exception as e:  # ultim resort
        log(f"[{_ts()}] Job #{job_id} eroare interna: {e}", "error")
        try:
            api_submit_job_failure(api_base, device_token, job_id, f"agent error: {e}")
        except ApiError:
            pass


def daemon_loop(
    api_base: str, device_uid: str, device_token: str,
    *,
    poll_interval: int = 3,
    auto_interval: int = 0,
    log: LogFn = _noop_log,
    should_stop: Callable[[], bool] = lambda: False,
    should_pause: Callable[[], bool] = lambda: False,
) -> None:
    """
    Bucla principala a daemon-ului. Polleaza coada de joburi si executa.

    `should_stop`  → callback ce returneaza True cand bucla trebuie sa iasa
                     (folosit de GUI cand user-ul apasa Quit).
    `should_pause` → callback ce returneaza True cand bucla doar asteapta
                     (folosit de tray pentru optiunea "Pauza").
    """
    last_auto_scan = time.monotonic()

    while not should_stop():
        if should_pause():
            time.sleep(min(poll_interval, 1))
            continue

        # 1) Polleaza pentru un job
        try:
            job = api_get_next_job(api_base, device_token)
        except ApiError as e:
            log(f"[{_ts()}] Eroare polling: {e}", "warn")
            _interruptible_sleep(poll_interval, should_stop)
            continue

        if job is not None:
            run_one_job(api_base, device_uid, device_token, job, log=log)
            continue  # poate exista alt job pending

        # 2) Auto-scan periodic (optional)
        if auto_interval and (time.monotonic() - last_auto_scan) >= auto_interval:
            log(f"[{_ts()}] Auto-scan (interval {auto_interval}s)...", "info")
            try:
                data = collect_system_data(device_uid)
                result = api_send_scan(api_base, device_token, data)
                log(f"[{_ts()}] Auto-scan done. Scan #{result.get('scan_id')}, "
                    f"score {result.get('exposure_score')}/100.", "ok")
            except ApiError as e:
                log(f"[{_ts()}] Auto-scan failed: {e}", "warn")
            last_auto_scan = time.monotonic()

        _interruptible_sleep(poll_interval, should_stop)


def _interruptible_sleep(seconds: float, should_stop: Callable[[], bool]) -> None:
    """Sleep care raspunde rapid la cererea de stop."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if should_stop():
            return
        time.sleep(min(0.25, end - time.monotonic()))


# ── Helper pentru fluxul de enrollment (folosit si de CLI si de GUI) ─────────

def perform_enrollment(api_base: str, email: str, password: str,
                       device_uid: str, device_name: str,
                       allow_create_account: bool = True,
                       log: LogFn = _noop_log) -> None:
    """
    Login (sau register-then-login) + creare device + salvare config local.
    Arunca ApiError daca esueaza.
    """
    api_base = api_base.rstrip("/")
    log("Autentificare...", "info")
    try:
        session_token = api_login(api_base, email, password)
    except ApiError as e:
        if "401" in str(e) or "invalid credentials" in str(e).lower():
            if not allow_create_account:
                raise
            log("Credentiale invalide → incerc creare cont nou.", "info")
            api_register(api_base, email, password)
            session_token = api_login(api_base, email, password)
        else:
            raise

    log("Inregistrez dispozitivul...", "info")
    try:
        created = api_create_device(api_base, session_token, device_uid, device_name)
    except ApiError as e:
        api_logout(api_base, session_token)
        raise ApiError(f"Eroare la creare device: {e}")

    device_token = created.get("device_token")
    if not device_token:
        api_logout(api_base, session_token)
        raise ApiError("Backend-ul nu a returnat device_token")

    save_enrollment(api_base, device_uid, device_token)
    api_logout(api_base, session_token)
    log("Inrolare reusita. Configul e salvat.", "ok")


# ── PyInstaller / packaging helpers ──────────────────────────────────────────

def is_frozen() -> bool:
    """True daca rulam dintr-un PyInstaller bundle (.exe)."""
    return getattr(sys, "frozen", False)


def executable_path() -> Path:
    """Calea catre executabilul curent (exe sau script Python)."""
    if is_frozen():
        return Path(sys.executable)
    return Path(sys.argv[0]).resolve()
