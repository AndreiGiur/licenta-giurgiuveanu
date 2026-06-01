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
import json
import os
import platform
import shutil
import socket
import stat
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

import dataclasses

import psutil
import requests


# ── Strategy Pattern: profiluri de scanare ─────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class ScanProfile:
    """Strategie de colectare pentru un nivel de scanare. Flag-urile booleane
    activeaza/dezactiveaza sub-colectorii individual. Folosit de colectorii
    composabili din `agent/collectors/`."""
    # Procese
    process_limit: int | None = 30
    include_cmdline: bool = False

    # Standard
    include_software: bool = True
    include_users: bool = True
    include_firewall: bool = True

    # Advanced
    include_connections: bool = False
    include_port_process: bool = False
    include_net_adapters: bool = False
    include_persistence: bool = False  # umbrella pentru collect_persistence
    include_services: bool = False
    include_startup: bool = False
    include_tasks: bool = False
    include_shares: bool = False
    include_ps_policy: bool = False

    # Deep
    include_wmi: bool = False
    include_reg_hijack: bool = False
    include_forensics: bool = False  # umbrella pentru collect_forensics
    include_defender: bool = False
    include_bitlocker: bool = False
    include_eventlog: bool = False
    include_hosts: bool = False
    include_certs: bool = False
    include_arp_dns: bool = False
    include_recent_files: bool = False

    # Linux audit (ruleaza doar pe Linux — vezi collectors/linux_audit.py)
    include_linux_basic: bool = False   # ssh, firewall, useri, kernel, sysctl, pachete, login.defs, mounts
    include_linux_jobs: bool = False    # cron, servicii systemd (advanced+)
    include_linux_files: bool = False   # suid, sgid, world-writable (deep, lente)


SCAN_PROFILES: dict[str, ScanProfile] = {
    "standard": ScanProfile(
        process_limit=30,
        include_cmdline=False,
        include_software=True,
        include_users=True,
        include_firewall=True,
        include_linux_basic=True,
    ),
    "advanced": ScanProfile(
        process_limit=None,
        include_cmdline=True,
        include_software=True,
        include_users=True,
        include_firewall=True,
        include_connections=True,
        include_port_process=True,
        include_net_adapters=True,
        include_persistence=True,
        include_services=True,
        include_startup=True,
        include_tasks=True,
        include_shares=True,
        include_ps_policy=True,
        include_linux_basic=True,
        include_linux_jobs=True,
    ),
    "deep": ScanProfile(
        process_limit=None,
        include_cmdline=True,
        include_software=True,
        include_users=True,
        include_firewall=True,
        include_connections=True,
        include_port_process=True,
        include_net_adapters=True,
        include_persistence=True,
        include_services=True,
        include_startup=True,
        include_tasks=True,
        include_shares=True,
        include_ps_policy=True,
        include_wmi=True,
        include_reg_hijack=True,
        include_forensics=True,
        include_defender=True,
        include_bitlocker=True,
        include_eventlog=True,
        include_hosts=True,
        include_certs=True,
        include_arp_dns=True,
        include_recent_files=True,
        include_linux_basic=True,
        include_linux_jobs=True,
        include_linux_files=True,
    ),
}


AGENT_VERSION = "2.0.0"


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


def get_enrollment_meta() -> dict:
    """Returneaza metadate vizuale despre enrollment (pentru afisare in GUI):
    device_name, user_email. Cheile lipsa returneaza string gol."""
    cfg = read_config()
    if not cfg.has_section("agent"):
        return {"device_name": "", "user_email": ""}
    return {
        "device_name": cfg.get("agent", "device_name", fallback="").strip(),
        "user_email": cfg.get("agent", "user_email", fallback="").strip(),
    }


def save_enrollment(api_base: str, device_uid: str, device_token: str,
                    device_name: str = "", user_email: str = "") -> None:
    """Salveaza configul de enrollment. `device_name` si `user_email` sunt
    optionale dar recomandate — sunt afisate in GUI ca sa user-ul stie pe
    ce cont si ce device e logat."""
    cfg = configparser.ConfigParser()
    cfg["agent"] = {
        "api_base": api_base.rstrip("/"),
        "device_uid": device_uid,
        "device_token": device_token,
    }
    if device_name:
        cfg["agent"]["device_name"] = device_name
    if user_email:
        cfg["agent"]["user_email"] = user_email
    write_config(cfg)


# ── nmap detection + NSE deploy ──────────────────────────────────────────────

def _nmap_path() -> Path | None:
    """Returnează path către nmap.exe instalat de user, sau None dacă lipsește.

    Verifică în această ordine:
    1. nmap în PATH
    2. C:\\Program Files (x86)\\Nmap\\nmap.exe
    3. C:\\Program Files\\Nmap\\nmap.exe
    """
    found = shutil.which("nmap")
    if found:
        return Path(found)
    for candidate in [
        Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
        Path(r"C:\Program Files\Nmap\nmap.exe"),
    ]:
        if candidate.is_file():
            return candidate
    return None


def _bundled_nse_path() -> Path | None:
    """Returnează path către vulnwatch-audit.nse din bundle/dev tree."""
    if getattr(sys, "frozen", False):
        # PyInstaller bundle — script extras sub _MEIPASS/nse/
        return Path(sys._MEIPASS) / "nse" / "vulnwatch-audit.nse"  # type: ignore[attr-defined]
    # Dev mode — script trăiește în agent/nse/
    repo_root = Path(__file__).resolve().parent.parent
    candidate = repo_root / "agent" / "nse" / "vulnwatch-audit.nse"
    return candidate if candidate.is_file() else None


def _nse_scripts_dir(nmap: Path) -> Path | None:
    """Localizeaza NSE scripts dir per-OS. Windows: `{nmap_dir}\\scripts`.
    Linux/macOS: scripturile NU sunt langa binar, ci in share dir
    (`/usr/share/nmap/scripts`, `/usr/local/share/nmap/scripts`). Intoarce
    primul director existent, sau None."""
    candidates = [nmap.parent / "scripts"]
    if sys.platform != "win32":
        candidates += [
            Path("/usr/share/nmap/scripts"),
            Path("/usr/local/share/nmap/scripts"),
        ]
    for c in candidates:
        if c.is_dir():
            return c
    return None


def deploy_nse_script(log: LogFn = _noop_log) -> bool:
    """Copiaza vulnwatch-audit.nse in NSE scripts dir al instalarii de nmap.
    **Best-effort** — scanarea foloseste oricum calea absoluta a scriptului
    (vezi `_run_nmap_if_needed`), deci esecul aici NU blocheaza deep scan-ul
    (pe Linux scrierea in /usr/share/nmap/scripts cere root; e ok daca esueaza).
    Idempotent. Intoarce True doar daca a copiat efectiv."""
    nmap = _nmap_path()
    if not nmap:
        return False
    bundled = _bundled_nse_path()
    if not bundled:
        return False
    scripts_dir = _nse_scripts_dir(nmap)
    if not scripts_dir:
        log("NSE scripts dir negasit (folosesc calea absoluta la scanare)", "info")
        return False
    target = scripts_dir / "vulnwatch-audit.nse"
    try:
        shutil.copy2(bundled, target)
    except OSError as e:
        # Tipic pe Linux fara root — non-fatal, scanarea foloseste calea absoluta.
        log(f"Deploy NSE skip (folosesc calea absoluta): {e}", "info")
        return False
    log(f"Deploy NSE script OK: {target}", "ok")
    try:
        subprocess.run([str(nmap), "--script-updatedb"],
                       capture_output=True, timeout=30)
    except subprocess.SubprocessError:
        pass
    return True


def _run_nmap_if_needed(
    job: dict,
    log: LogFn = _noop_log,
    progress_cb: Callable[[int, str], None] | None = None,
) -> dict | None:
    """Ruleaza nmap pentru scan advanced (moderat) sau deep (agresiv).

    Profilul nmap (args, scripturi, top_ports, timeout) este preluat din
    `nmap_runner.NMAP_PROFILES[scan_type]`. Intoarce dict cu schema nmap pentru
    payload, sau None pentru scan_type='standard'. Daca nmap lipseste,
    intoarce {error: nmap_missing} (advanced il sare silentios cu warn,
    deep il marcheaza explicit ca eroare).
    """
    scan_type = job.get("scan_type")
    if scan_type not in ("advanced", "deep"):
        return None
    from . import nmap_runner, nmap_parser

    nmap = _nmap_path()
    if not nmap:
        log(f"nmap.exe nu e instalat — sarim faza nmap pentru {scan_type} scan", "warn")
        return {"error": "nmap_missing"}

    targets = ["127.0.0.1"]
    nmap_target = job.get("nmap_target")
    if nmap_target:
        try:
            nmap_runner.validate_lan_target(nmap_target)
            targets.append(nmap_target)
        except nmap_runner.NmapRunnerError as e:
            log(f"nmap_target invalid: {e}; continui cu localhost only", "warn")

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        xml_out = Path(tmp) / "nmap_result.xml"

        # nmap ocupa intervalul global 65..95% (colectarea s-a oprit la 65%).
        def _nmap_progress(pct: float, remaining: str) -> None:
            global_pct = 65 + round(pct / 100 * 30)
            eta = f" (ETC {remaining})" if remaining else ""
            if progress_cb:
                progress_cb(global_pct, f"Nmap: {pct:.0f}%{eta}")

        if progress_cb:
            label = "Nmap moderat pornit..." if scan_type == "advanced" else "Nmap agresiv pornit..."
            progress_cb(65, label)
        # Pasam calea absoluta a scriptului NSE — nmap il gaseste fara sa-l
        # copiem in scripts dir-ul de sistem (pe Linux ar cere root).
        bundled_nse = _bundled_nse_path()
        nse_path = str(bundled_nse) if bundled_nse else None
        t0 = time.time()
        try:
            exit_code, stderr = nmap_runner.run_nmap(
                targets=targets,
                xml_out=xml_out,
                profile=scan_type,
                progress_cb=_nmap_progress,
                nse_script_path=nse_path,
                log=log,
            )
        except nmap_runner.NmapRunnerError as e:
            log(f"nmap esuat: {e}", "error")
            return {"error": str(e)}
        elapsed = time.time() - t0
        if not xml_out.is_file():
            log("nmap: XML output lipseste", "error")
            return {"error": "no_output", "stderr": stderr[:500] if stderr else ""}
        try:
            parsed = nmap_parser.parse_nmap_xml(xml_out.read_text(encoding="utf-8"))
        except nmap_parser.NmapParseError as e:
            log(f"nmap parser esuat: {e}", "error")
            return {"error": str(e)}
        parsed["targets"] = targets
        parsed["scan_time_sec"] = round(elapsed, 1)
        parsed["lan_opt_in"] = bool(nmap_target)
        parsed["profile"] = scan_type
        parsed["lua_errors"] = []
        if stderr:
            for line in stderr.splitlines():
                if "vulnwatch-audit" in line.lower():
                    parsed["lua_errors"].append(line.strip())
        log(f"nmap [{scan_type}]: {len(parsed.get('hosts', []))} hosts in {elapsed:.0f}s", "ok")
        return parsed


# Alias backwards-compat pentru cod / teste vechi
_run_nmap_if_deep = _run_nmap_if_needed


def agent_capabilities() -> list[str]:
    """Returnează lista de scan_type-uri suportate pe acest device.

    `standard` și `advanced` sunt mereu suportate (psutil).
    `deep` se adaugă DOAR dacă nmap e instalat.
    """
    caps = ["standard", "advanced"]
    if _nmap_path() is not None:
        caps.append("deep")
    return caps


# ── Instalare nmap (OS-aware) ──────────────────────────────────────────────────

def detect_package_manager() -> str | None:
    """Intoarce primul package manager Linux gasit in PATH, sau None."""
    for pm in ("apt-get", "dnf", "pacman", "zypper"):
        if shutil.which(pm):
            return pm
    return None


_PM_INSTALL = {
    "apt-get": ["apt-get", "install", "-y", "nmap"],
    "dnf": ["dnf", "install", "-y", "nmap"],
    "pacman": ["pacman", "-S", "--noconfirm", "nmap"],
    "zypper": ["zypper", "install", "-y", "nmap"],
}


def build_nmap_install_command() -> list[str] | None:
    """Comanda de instalare nmap pentru OS-ul curent (fara escaladare de
    privilegii). None daca nu stim cum sa instalam."""
    if sys.platform == "win32":
        return ["winget", "install", "-e", "--id", "Insecure.Nmap", "--silent"]
    pm = detect_package_manager()
    if pm:
        return _PM_INSTALL[pm]
    return None


def install_nmap(log: LogFn = _noop_log) -> tuple[bool, str]:
    """Instaleaza nmap pe OS-ul curent. Intoarce (succes, mesaj).

    Windows: winget (gestioneaza UAC). Linux: prefixeaza cu pkexec (prompt grafic
    PolicyKit) sau sudo; daca niciunul nu exista, intoarce comanda manuala."""
    cmd = build_nmap_install_command()
    if cmd is None:
        return False, ("Nu pot detecta cum sa instalez nmap pe acest sistem. "
                       "Descarca-l manual de pe https://nmap.org/download.html")

    if sys.platform == "win32":
        full = cmd
    else:
        if shutil.which("pkexec"):
            full = ["pkexec"] + cmd
        elif shutil.which("sudo"):
            full = ["sudo"] + cmd
        else:
            manual = " ".join(["sudo"] + cmd)
            return False, f"Ruleaza manual (necesita root): {manual}"

    log(f"Instalez nmap: {' '.join(full)}", "info")
    try:
        result = subprocess.run(full, capture_output=True, text=True, timeout=300)
    except (subprocess.SubprocessError, OSError) as e:
        return False, f"Instalare esuata: {e}"
    if result.returncode != 0:
        return False, f"Instalare esuata (cod {result.returncode}): {(result.stderr or '')[:300]}"
    if _nmap_path():
        return True, "nmap a fost instalat cu succes."
    return True, "Comanda de instalare a rulat. Reporneste agentul daca nmap nu e detectat inca."


# ── Colectare date sistem ─────────────────────────────────────────────────────

def is_admin() -> bool:
    """Verifica daca procesul ruleaza cu privilegii ridicate."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


# ── Metrics cache local (persistent intre restart-uri) ────────────────────────

METRICS_FILE = CONFIG_DIR / "metrics.json"
_METRICS_VERSION = 1
_HISTORY_MAX = 20


class MetricsTracker:
    """Persista counters de scanari local pentru afisare rapida in GUI.

    Sursa de adevar ramane backend-ul; cache-ul e doar pentru UX (responsivitate
    GUI fara polling backend pentru fiecare deschidere). Scriere atomica prin
    write-to-temp-then-rename. Citire defensiva: JSON corupt → state gol."""

    def __init__(self, cache_path: Path):
        self.cache_path = cache_path
        self.state = self._load()

    def _load(self) -> dict:
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            # Validare basic: cheile esentiale exista
            if not isinstance(data, dict) or "scans_total" not in data:
                raise ValueError("schema invalida")
            # Backfill chei lipsa pentru forward-compat
            data.setdefault("version", _METRICS_VERSION)
            data.setdefault("last_exposure_score", None)
            data.setdefault("last_scan_at", None)
            data.setdefault("history", [])
            return data
        except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
            return self._empty_state()

    @staticmethod
    def _empty_state() -> dict:
        return {
            "version": _METRICS_VERSION,
            "scans_total": 0,
            "last_exposure_score": None,
            "last_scan_at": None,
            "history": [],
        }

    def record_scan(self, score: int, scan_type: str, job_id: int) -> None:
        """Apelat din daemon thread dupa submit_job_result OK."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.state["scans_total"] = self.state.get("scans_total", 0) + 1
        self.state["last_exposure_score"] = int(score)
        self.state["last_scan_at"] = now
        entry = {
            "timestamp": now,
            "score": int(score),
            "scan_type": scan_type,
            "job_id": int(job_id),
        }
        self.state["history"].insert(0, entry)
        self.state["history"] = self.state["history"][:_HISTORY_MAX]
        self._save_atomic()

    def reset(self) -> None:
        """Apelat la 'Deconecteaza acest PC' — sterge cache-ul."""
        self.state = self._empty_state()
        try:
            self.cache_path.unlink(missing_ok=True)
        except OSError:
            pass

    def _save_atomic(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
            os.replace(tmp, self.cache_path)
        except OSError:
            pass  # best-effort; nu blocam daemon-ul daca disk-ul e plin


def collect_system_data(device_uid: str, scan_type: str = "standard",
                        progress_cb: Callable[[int, str], None] | None = None,
                        max_progress: int = 100) -> dict:
    """Orchestrator: ruleaza colectorii activi pentru `scan_type` ales.
    `progress_cb(percent, phase)` este apelat intre colectori — util pentru
    UI in cazul scanarilor Advanced/Deep care dureaza minute. Default
    `scan_type="standard"` pentru backward compatibility cu apelantii vechi.

    `max_progress` scaleaza procentele: cand urmeaza o faza nmap (advanced/deep),
    colectarea ocupa 0..max_progress (ex: 65), lasand restul nmap-ului — asa
    progresul ramane monoton crescator (fix bug: nmap nu mai 'da inapoi')."""
    from . import collectors  # import tardiv: evita circular cu colectorii

    cfg = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["standard"])

    def step(pct: int, phase: str) -> None:
        if progress_cb is not None:
            try:
                scaled = round(pct / 100 * max_progress)
                progress_cb(scaled, phase)
            except Exception:
                pass

    step(5, "Sistem & OS")
    sys_data = collectors.collect_system(cfg)

    step(15, "Retea")
    net_data = collectors.collect_network(cfg)

    step(35, "Procese")
    procs = collectors.collect_processes(cfg)

    step(55, "Software")
    software = collectors.collect_software(cfg)

    persistence = None
    if cfg.include_persistence:
        step(70, "Persistente")
        persistence = collectors.collect_persistence(cfg)

    forensics = None
    if cfg.include_forensics:
        step(85, "Forensics")
        forensics = collectors.collect_forensics(cfg)

    step(95, "Finalizare")

    os_keys = ("system", "release", "version", "machine", "hostname",
               "uptime_seconds", "is_admin", "username")
    si_keys = ("local_users", "firewall", "bitlocker", "defender")

    return {
        "device_uid": device_uid,
        "scan_type": scan_type,
        "os": {k: sys_data.get(k) for k in os_keys if k in sys_data},
        "system_info": {k: sys_data[k] for k in si_keys if k in sys_data},
        "network": net_data,
        "processes": procs,
        "software": software,
        "persistence": persistence,
        "forensics": forensics,
    }


# ── Token generation ──────────────────────────────────────────────────────────


def generate_device_token() -> tuple[str, str]:
    """Genereaza un device_token random local + hash-ul SHA-256 hex.

    Returneaza (token_plain, token_hash_hex). Tokenul plain trebuie salvat
    in config-ul local IMEDIAT — nu va putea fi recuperat ulterior."""
    import hashlib
    import secrets
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, token_hash


# ── HTTP catre backend ────────────────────────────────────────────────────────

class ApiError(Exception):
    """Eroare la nivelul API (HTTP non-2xx, network down, timeout, etc.)."""


class DeviceTokenInvalidError(Exception):
    """Backend a respins device_token-ul cu HTTP 401.

    Daemon-ul trebuie sa se opreasca si UI-ul trebuie sa intoarca la Login.
    Aceasta exceptie e ridicata DOAR de apelurile care folosesc X-Device-Token."""


def _request_with_device_token(method: str, url: str, *, device_token: str,
                                json=None, timeout=15) -> dict:
    """Variant a `_request` care detecteaza 401 specific pentru X-Device-Token
    si arunca `DeviceTokenInvalidError`. Toate celelalte erori → `ApiError`."""
    headers = {"X-Device-Token": device_token, "Content-Type": "application/json"}
    try:
        r = requests.request(method, url, json=json, headers=headers, timeout=timeout)
    except requests.exceptions.ConnectionError:
        raise ApiError(f"Nu ma pot conecta la {url}")
    except requests.exceptions.Timeout:
        raise ApiError(f"Timeout la {url}")
    except requests.exceptions.RequestException as e:
        raise ApiError(str(e))

    if r.status_code == 401:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        raise DeviceTokenInvalidError(f"HTTP 401: {detail}")

    if r.status_code == 204:
        return {}

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


def api_create_device(api_base: str, session_token: str, device_uid: str, name: str,
                       *, token_hash: str) -> dict:
    """Inrolare device noua. Clientul trimite token_hash; tokenul plain ramane local."""
    return _request(
        "POST", f"{api_base}/devices",
        json={"device_uid": device_uid, "name": name, "token_hash": token_hash},
        headers={"X-Session-Token": session_token},
    )


def api_get_device_by_uid(api_base: str, session_token: str, device_uid: str) -> dict | None:
    """Returneaza device-ul daca exista pe contul user-ului, altfel None.
    Folosit pentru smart re-link (verificare daca user-ul are deja un device
    cu acest UID inainte de a-l recrea)."""
    try:
        return _request(
            "GET", f"{api_base}/devices/by-uid/{device_uid}",
            headers={"X-Session-Token": session_token},
        )
    except ApiError as e:
        if "404" in str(e):
            return None
        raise


def api_relink_device(api_base: str, session_token: str, device_uid: str,
                       *, token_hash: str) -> dict:
    """Re-emite tokenul pentru un device existent (smart re-link).
    Clientul trimite noul token_hash; backend doar inlocuieste."""
    return _request(
        "POST", f"{api_base}/devices/{device_uid}/relink",
        json={"token_hash": token_hash},
        headers={"X-Session-Token": session_token},
    )


def api_me(api_base: str, session_token: str) -> dict:
    """Verifica daca un session_token este valid si returneaza user-ul."""
    return _request(
        "GET", f"{api_base}/auth/me",
        headers={"X-Session-Token": session_token},
    )


def api_logout(api_base: str, session_token: str) -> None:
    try:
        _request("DELETE", f"{api_base}/auth/logout",
                 headers={"X-Session-Token": session_token})
    except ApiError:
        pass  # logout idempotent


def api_send_scan(api_base: str, device_token: str, payload: dict) -> dict:
    """Push direct la `POST /scans` — folosit doar de comanda CLI `scan.py scan`
    (one-shot manual). Daemon-ul UI-ului foloseste scan-on-demand prin /agent/jobs/*."""
    return _request_with_device_token(
        "POST", f"{api_base}/scans",
        device_token=device_token, json=payload,
    )


def api_get_next_job(api_base: str, device_token: str) -> dict | None:
    """Returneaza dict-ul jobului sau None daca nu sunt joburi pending."""
    result = _request_with_device_token(
        "GET", f"{api_base}/agent/jobs/next", device_token=device_token,
    )
    # 204 No Content → dict gol → tratam ca None
    return result if result else None


def api_submit_job_result(api_base: str, device_token: str, job_id: int, payload: dict) -> dict:
    """Trimite rezultatul scanarii. `system_info`, `persistence` si `forensics`
    sunt optionale (pentru Advanced/Deep)."""
    body = {
        "os": payload.get("os", {}),
        "system_info": payload.get("system_info", {}),
        "network": payload.get("network", {}),
        "processes": payload.get("processes", []),
        "software": payload.get("software", []),
        "persistence": payload.get("persistence"),
        "forensics": payload.get("forensics"),
        "nmap": payload.get("nmap"),
    }
    return _request_with_device_token(
        "POST", f"{api_base}/agent/jobs/{job_id}/result",
        device_token=device_token, json=body,
    )


def api_submit_job_failure(api_base: str, device_token: str, job_id: int, error_message: str) -> dict:
    return _request_with_device_token(
        "POST", f"{api_base}/agent/jobs/{job_id}/fail",
        device_token=device_token, json={"error_message": error_message[:512]},
    )


def api_google_enroll(api_base: str, id_token: str, device_uid: str,
                       device_name: str, *, token_hash: str) -> dict:
    """Trimite id_token Google + token_hash la backend pentru a crea/relink Device.
    Returneaza dict cu device_uid, device_name, user_email (FARA device_token —
    clientul are deja tokenul plain corespunzator hash-ului trimis)."""
    return _request(
        "POST", f"{api_base}/agent/google-enroll",
        json={
            "id_token": id_token,
            "device_uid": device_uid,
            "device_name": device_name,
            "token_hash": token_hash,
        },
        timeout=15,
    )


def build_heartbeat_payload(capabilities: list[str]) -> dict:
    """Construieste payload-ul de heartbeat, inclusiv contoarele de trafic de
    retea (psutil) — folosite de backend pentru graficul de trafic live."""
    try:
        io = psutil.net_io_counters()
        sent, recv = int(io.bytes_sent), int(io.bytes_recv)
    except Exception:
        sent, recv = 0, 0
    try:
        conn_count = len([c for c in psutil.net_connections(kind="inet")
                          if c.status == "ESTABLISHED"])
    except Exception:
        conn_count = 0
    return {
        "agent_version": AGENT_VERSION,
        "capabilities": capabilities,
        "os_version": f"{platform.system()} {platform.release()}",
        "net_bytes_sent": sent,
        "net_bytes_recv": recv,
        "net_conn_count": conn_count,
    }


def api_heartbeat(api_base: str, device_token: str, payload: dict) -> None:
    """Trimite heartbeat la backend (la fiecare ~10s). Best-effort: nu arunca
    daca esueaza — daemon-ul continua sa polleze pentru joburi."""
    # ApiError (network down, 5xx) → best-effort, inghite.
    # DeviceTokenInvalidError NU e prins aici — daemon_loop il prinde si reactioneaza.
    try:
        _request_with_device_token(
            "POST", f"{api_base}/agent/heartbeat",
            device_token=device_token,
            json=payload, timeout=10,
        )
    except ApiError:
        pass


def api_send_progress(api_base: str, device_token: str, job_id: int,
                       progress: int, phase: str) -> None:
    """Trimite progres pentru un job activ. Best-effort pentru ApiError;
    DeviceTokenInvalidError propaga."""
    try:
        _request_with_device_token(
            "POST", f"{api_base}/agent/jobs/{job_id}/progress",
            device_token=device_token,
            json={"progress": int(progress), "phase": phase[:128]},
            timeout=5,
        )
    except ApiError:
        pass


# ── Bucla daemon (refolosita de CLI si GUI) ───────────────────────────────────

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def run_one_job(api_base: str, device_uid: str, device_token: str,
                job: dict, log: LogFn = _noop_log,
                on_scan_done: Callable[[int, str, int], None] | None = None) -> None:
    """Executa un job primit de la coada. Foloseste `scan_type` din job
    pentru a alege profilul de colectare. Trimite progress updates intre
    colectori (util pentru Advanced/Deep care dureaza minute)."""
    job_id = job["job_id"]
    scan_type = job.get("scan_type", "standard")
    log(f"[{_ts()}] Job #{job_id} primit ({scan_type}). Colectez date...", "info")

    def progress_cb(pct: int, phase: str) -> None:
        log(f"[{_ts()}] Job #{job_id} {pct}% — {phase}", "info")
        api_send_progress(api_base, device_token, job_id, pct, phase)

    try:
        # Pentru advanced/deep urmeaza nmap → colectarea se opreste la 65% ca
        # progresul sa ramana monoton (nmap ocupa 65..95%, submit = 100%).
        nmap_will_run = scan_type in ("advanced", "deep")
        collect_max = 65 if nmap_will_run else 100
        data = collect_system_data(device_uid, scan_type=scan_type,
                                   progress_cb=progress_cb, max_progress=collect_max)
        nmap_result = _run_nmap_if_needed(job, log=log, progress_cb=progress_cb)
        if nmap_result is not None:
            data["nmap"] = nmap_result
        result = api_submit_job_result(api_base, device_token, job_id, data)
        score = result.get("exposure_score")
        scan_id = result.get("scan_id")
        log(f"[{_ts()}] Job #{job_id} done ({scan_type}). Scan #{scan_id}, score {score}/100.", "ok")
        if on_scan_done and score is not None:
            try:
                on_scan_done(int(score), scan_type, int(job_id))
            except Exception:
                pass
    except DeviceTokenInvalidError:
        raise  # propaga catre daemon_loop pentru recovery
    except ApiError as e:
        log(f"[{_ts()}] Job #{job_id} failed: {e}", "error")
        try:
            api_submit_job_failure(api_base, device_token, job_id, str(e))
        except (ApiError, DeviceTokenInvalidError):
            pass
    except Exception as e:  # ultim resort
        log(f"[{_ts()}] Job #{job_id} eroare interna: {e}", "error")
        try:
            api_submit_job_failure(api_base, device_token, job_id, f"agent error: {e}")
        except (ApiError, DeviceTokenInvalidError):
            pass


def daemon_loop(
    api_base: str, device_uid: str, device_token: str,
    *,
    poll_interval: int = 3,
    heartbeat_interval: int = 10,
    log: LogFn = _noop_log,
    should_stop: Callable[[], bool] = lambda: False,
    should_pause: Callable[[], bool] = lambda: False,
    on_token_invalid: Callable[[], None] | None = None,
    on_heartbeat_ok: Callable[[], None] | None = None,
    on_scan_done: Callable[[int, str, int], None] | None = None,
) -> None:
    """
    Bucla principala a daemon-ului. Trimite heartbeat la fiecare 10s,
    polleaza coada de joburi si executa scanarile.

    Iese imediat la primul HTTP 401 (token invalid) din orice apel device-token.
    Semnalizeaza `on_token_invalid` (daca e setat) inainte de a iesi. Erorile
    tranzitorii (network down, 5xx) → retry, nu trigger.

    `should_stop`  → callback ce returneaza True cand bucla trebuie sa iasa.
    `should_pause` → callback ce returneaza True cand bucla doar asteapta.
    `on_token_invalid` → callback apelat la HTTP 401, inainte de a iesi din loop.
    """
    last_heartbeat = 0.0  # forteaza heartbeat la primul tick

    capabilities = agent_capabilities()  # dinamic: include "deep" doar dacă nmap e instalat
    deploy_nse_script(log=log)  # idempotent — copiază scriptul în nmap scripts dir

    def _handle_token_invalid(e: DeviceTokenInvalidError) -> None:
        log(f"[{_ts()}] Device token respins de backend: {e}", "error")
        if on_token_invalid:
            try:
                on_token_invalid()
            except Exception as cb_err:
                log(f"[{_ts()}] on_token_invalid callback err: {cb_err}", "warn")

    while not should_stop():
        if should_pause():
            time.sleep(min(poll_interval, 1))
            continue

        # 0) Heartbeat (best-effort pentru ApiError, fatal pentru token invalid)
        now = time.monotonic()
        if now - last_heartbeat >= heartbeat_interval:
            try:
                api_heartbeat(api_base, device_token, build_heartbeat_payload(capabilities))
                if on_heartbeat_ok:
                    try:
                        on_heartbeat_ok()
                    except Exception:
                        pass
            except DeviceTokenInvalidError as e:
                _handle_token_invalid(e)
                return
            except ApiError as e:
                log(f"[{_ts()}] Heartbeat esuat (continui): {e}", "warn")
            last_heartbeat = now

        # 1) Polleaza pentru un job
        try:
            job = api_get_next_job(api_base, device_token)
        except DeviceTokenInvalidError as e:
            _handle_token_invalid(e)
            return
        except ApiError as e:
            log(f"[{_ts()}] Eroare polling: {e}", "warn")
            _interruptible_sleep(poll_interval, should_stop)
            continue

        if job is not None:
            try:
                run_one_job(api_base, device_uid, device_token, job, log=log,
                            on_scan_done=on_scan_done)
            except DeviceTokenInvalidError as e:
                _handle_token_invalid(e)
                return
            continue  # poate exista alt job pending

        _interruptible_sleep(poll_interval, should_stop)


def _interruptible_sleep(seconds: float, should_stop: Callable[[], bool]) -> None:
    """Sleep care raspunde rapid la cererea de stop."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if should_stop():
            return
        time.sleep(min(0.25, end - time.monotonic()))


# ── Helper pentru fluxul de enrollment (folosit si de CLI si de GUI) ─────────

def login_or_register(api_base: str, email: str, password: str,
                      allow_create_account: bool = True,
                      log: LogFn = _noop_log) -> str:
    """
    Login. Daca esueaza cu 401 si `allow_create_account=True`, incearca
    register-then-login. Returneaza session_token. Arunca ApiError la esec.
    """
    api_base = api_base.rstrip("/")
    log("Autentificare...", "info")
    try:
        return api_login(api_base, email, password)
    except ApiError as e:
        if "401" in str(e) or "invalid credentials" in str(e).lower():
            if not allow_create_account:
                raise
            log("Credentiale invalide → incerc creare cont nou.", "info")
            api_register(api_base, email, password)
            return api_login(api_base, email, password)
        raise


def enroll_device_with_session(api_base: str, session_token: str,
                                device_uid: str, device_name: str,
                                relink_if_exists: bool = False,
                                log: LogFn = _noop_log) -> dict:
    """
    Creeaza un device pe contul autentificat. Genereaza local (token_plain,
    token_hash) si trimite doar hash-ul la backend. Returneaza dict-ul cu
    `device_token` plain injectat local. NU salveaza configul local —
    apelantul decide cand.

    `relink_if_exists`: daca True si device-ul cu acest UID exista deja, face
    POST /devices/{uid}/relink (re-emitere token, fara duplicare).
    """
    api_base = api_base.rstrip("/")

    token_plain, token_hash = generate_device_token()

    if relink_if_exists:
        existing = api_get_device_by_uid(api_base, session_token, device_uid)
        if existing:
            log(f"Device existent ({existing.get('name', '?')}) — re-emit tokenul.", "info")
            result = api_relink_device(api_base, session_token, device_uid,
                                       token_hash=token_hash)
            result["device_token"] = token_plain
            return result

    log("Inregistrez dispozitivul...", "info")
    result = api_create_device(api_base, session_token, device_uid, device_name,
                               token_hash=token_hash)
    result["device_token"] = token_plain
    return result


def perform_enrollment(api_base: str, email: str, password: str,
                       device_uid: str, device_name: str,
                       allow_create_account: bool = True,
                       relink_if_exists: bool = False,
                       log: LogFn = _noop_log) -> None:
    """
    Compus: login (sau register-then-login) + creare/relink device + salvare
    config local. Apelantul nu trebuie sa stie despre session_token.

    Mentinut pentru CLI (`python scan.py enroll`) si pentru testare.
    GUI-ul separa pasii in mai multe ecrane si foloseste login_or_register +
    enroll_device_with_session direct.
    """
    api_base = api_base.rstrip("/")
    session_token = login_or_register(api_base, email, password,
                                      allow_create_account=allow_create_account,
                                      log=log)
    try:
        created = enroll_device_with_session(
            api_base, session_token, device_uid, device_name,
            relink_if_exists=relink_if_exists, log=log,
        )
    except ApiError as e:
        api_logout(api_base, session_token)
        raise ApiError(f"Eroare la creare device: {e}")

    device_token = created.get("device_token")
    if not device_token:
        api_logout(api_base, session_token)
        raise ApiError("Eroare interna: enroll_device_with_session nu a returnat device_token")

    save_enrollment(api_base, device_uid, device_token,
                    device_name=created.get("name", device_name),
                    user_email=email)
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
