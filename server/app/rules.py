"""
Rules engine cu auto-filtrare dupa scan_type.

Decorator @rule(id, min_level): inregistreaza o functie ca regula. La
evaluare, doar regulile cu min_level <= scan_type ruleaza.

Adaugare regula noua = decoreaza o functie. Zero modificari in alte parti.
"""
from __future__ import annotations

from typing import Any, Callable

from .config import (
    MANY_PORTS_THRESHOLD,
    SIGNATURE_AGE_DAYS_THRESHOLD,
    BRUTEFORCE_FAIL_COUNT_THRESHOLD,
)

SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 3,
    "info": 0,
}


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTE LA NIVEL MODUL (extrase din interiorul funcțiilor regulilor)
# ─────────────────────────────────────────────────────────────────────────────
# Beneficii: evita re-crearea structurilor la fiecare call; permite reutilizarea
# in teste/alte module; deduplica logica intre reguli (ex: VIRTUAL_PREFIXES).

# Prefixe IP private + adaptoare virtuale (Hyper-V vSwitch / WSL / Docker bridge).
# Folosit de NET-OPEN-PORTS-1 (downgrade severitate) si NET-ESTABLISHED-1 (skip).
VIRTUAL_PREFIXES: tuple[str, ...] = (
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.",  # link-local
    "fe80:",     # link-local IPv6
)

# Toate prefixele private (include LAN-uri tipice + virtual). Folosit pentru
# NET-ESTABLISHED-1: o conexiune catre IP cu astfel de prefix nu e expunere externa.
PRIVATE_IP_PREFIXES: tuple[str, ...] = (
    "10.", "127.", "192.168.", "::1",
) + VIRTUAL_PREFIXES

# Porturi cunoscute periculoase si descrierile lor.
RISKY_PORTS: dict[int, str] = {
    21:   "FTP – transfer fisiere necriptat",
    23:   "Telnet – acces remote necriptat",
    25:   "SMTP – server de mail expus",
    139:  "NetBIOS – partajare fisiere Windows",
    445:  "SMB – partajare fisiere Windows (risc EternalBlue)",
    3389: "RDP – Remote Desktop Protocol",
    5900: "VNC – acces remote grafic",
    5985: "WinRM HTTP – management remote Windows",
    5986: "WinRM HTTPS – management remote Windows",
}

# Procese cunoscute ca instrumente de atac (mimikatz, etc.) sau cu utilizare
# legitima dar frecvent abuzata (nmap, wireshark).
SUSPICIOUS_PROCESSES: dict[str, str] = {
    "nc.exe":           "Netcat – tool de retea, frecvent abuzat",
    "netcat":           "Netcat – tool de retea, frecvent abuzat",
    "ncat.exe":         "Ncat (Nmap) – tool de retea",
    "nmap.exe":         "Nmap – scanner de retea",
    "mimikatz.exe":     "Mimikatz – extragere credentiale (malware)",
    "psexec.exe":       "PsExec – executie remote",
    "meterpreter":      "Meterpreter – payload Metasploit",
    "cobaltstrike":     "Cobalt Strike – framework ofensiv",
    "wireshark.exe":    "Wireshark – sniffer de retea",
    "rawcap.exe":       "RawCap – captare pachete",
}

# ─────────────────────────────────────────────────────────────────────────────
# Semnaturi de software vulnerabil / OS EOL — incarcate dintr-un data file JSON
# ─────────────────────────────────────────────────────────────────────────────
# Sursa de adevar editabila fara modificari de cod: `app/data/vuln_signatures.json`.
# Daca fisierul lipseste sau e corupt, cadem pe un set minimal embedded (engine-ul
# nu crapa niciodata). Vezi `_refresh_from_feed()` pentru hook-ul de feed live.
import json
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent / "data"
_VULN_SIGNATURES_FILE = _DATA_DIR / "vuln_signatures.json"

# Fallback minimal embedded — folosit DOAR daca data file-ul lipseste/e corupt.
_FALLBACK_VULNERABLE_SOFTWARE: tuple[dict, ...] = (
    {"name_contains": "Adobe Flash",        "severity": "critical", "cve": "multiple",       "note": "EOL din 2020, nu mai primeste patch-uri"},
    {"name_contains": "Internet Explorer",  "severity": "high",     "cve": "multiple",       "note": "EOL din 2022, vulnerabilitati nepatched"},
    {"name_contains": "Java 6",             "severity": "high",     "cve": "multiple",       "note": "EOL, versiune nesupportata"},
    {"name_contains": "OpenSSL 1.0",        "severity": "high",     "cve": "CVE-2022-0778",  "note": "Versiune vulnerabila"},
    {"name_contains": "WinRAR 5",           "severity": "medium",   "cve": "CVE-2023-38831", "note": "Versiune vulnerabila la executie de cod"},
)
_FALLBACK_EOL_OS: tuple[dict, ...] = (
    {"system": "Windows", "rel": "XP",    "severity": "critical"},
    {"system": "Windows", "rel": "Vista", "severity": "critical"},
    {"system": "Windows", "rel": "7",     "severity": "high"},
    {"system": "Windows", "rel": "8.0",   "severity": "high"},
    {"system": "Linux",   "rel": "2.6",   "severity": "high"},
)


def _load_vuln_signatures() -> tuple[tuple[dict, ...], tuple[dict, ...]]:
    """Incarca semnaturile din JSON. Fallback la setul embedded la orice eroare."""
    try:
        data = json.loads(_VULN_SIGNATURES_FILE.read_text(encoding="utf-8"))
        sw = tuple(data.get("vulnerable_software", []))
        eol = tuple(data.get("eol_operating_systems", []))
        if sw and eol:
            return sw, eol
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return _FALLBACK_VULNERABLE_SOFTWARE, _FALLBACK_EOL_OS


# Software vulnerabil cunoscut + OS EOL. Match prin substring case-insensitive.
VULNERABLE_SOFTWARE, EOL_OPERATING_SYSTEMS = _load_vuln_signatures()


def _refresh_from_feed(signatures: dict) -> None:
    """Hook pentru un feed live de semnaturi (ex: NVD / OSV / vendor advisories).

    Productie: un job periodic ar descarca semnaturi proaspete, le-ar valida si
    le-ar scrie in `vuln_signatures.json`, apoi ar apela aceasta functie pentru
    hot-reload fara restart. Pentru lucrare ramane offline (data file curat),
    dar punctul de extindere e definit explicit.
    """
    global VULNERABLE_SOFTWARE, EOL_OPERATING_SYSTEMS
    VULNERABLE_SOFTWARE = tuple(signatures.get("vulnerable_software", VULNERABLE_SOFTWARE))
    EOL_OPERATING_SYSTEMS = tuple(signatures.get("eol_operating_systems", EOL_OPERATING_SYSTEMS))

# Path-uri suspecte pentru startup entries (executabile in directoare scrise de
# user, frecvent folosite de malware pentru persistenta).
SUSPICIOUS_STARTUP_PATHS: tuple[str, ...] = (
    "%temp%", "%appdata%", "\\temp\\", "\\appdata\\local\\temp",
    "\\users\\public\\", "\\programdata\\temp",
)

# Flag-uri PowerShell folosite frecvent in payload-uri ofensive (comenzi encoded).
POWERSHELL_OFFENSIVE_FLAGS: tuple[str, ...] = ("-enc ", "-encodedcommand", " -e ")

# Path-uri standard pentru servicii Windows legitime.
STANDARD_SERVICE_PATHS: tuple[str, ...] = (
    "c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\",
)

# Share-uri default Windows (nu trebuie alertate).
DEFAULT_WINDOWS_SHARES: frozenset[str] = frozenset({"admin$", "ipc$", "c$", "d$", "e$", "print$"})

# Porturi standard care nu sunt suspecte la conexiuni externe (HTTP, push, etc.).
STD_OUTBOUND_PORTS: frozenset[int] = frozenset({
    80, 443, 53, 22, 25, 587, 465, 993, 995, 8080, 8443,
    5228, 5229, 5230,  # Google FCM / push notifications
    5223, 5222,        # XMPP
    3478, 3479,        # STUN (WebRTC)
    5061, 5060,        # SIP
    1935,              # RTMP (streaming)
    8009, 8008,        # Chromecast
})

# Procese cunoscute care fac multe conexiuni externe legitime (browsere, comunicare).
KNOWN_NETWORK_PROCESSES: frozenset[str] = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe", "safari.exe",
    "anydesk.exe", "teamviewer.exe", "teamviewer_service.exe",
    "teams.exe", "ms-teams.exe", "slack.exe", "discord.exe", "skype.exe", "zoom.exe",
    "spotify.exe", "steam.exe", "epicgameslauncher.exe", "battle.net.exe",
    "code.exe", "code - insiders.exe",
    "outlook.exe", "thunderbird.exe",
    "onedrive.exe", "dropbox.exe", "googledrivefs.exe",
})

# Valori default Windows pentru Winlogon — NU sunt suspecte (toate sistemele le au).
WINLOGON_DEFAULTS: dict[str, tuple[str, ...]] = {
    "userinit": ("c:\\windows\\system32\\userinit.exe", "c:\\windows\\system32\\userinit.exe,"),
    "shell": ("explorer.exe",),
}

# Subscriptii WMI built-in Windows cu command vid — nu sunt malware.
WMI_BUILTIN_NAMES: frozenset[str] = frozenset({
    "scm event log consumer",
    "bvtconsumer",
    "bvtfilter",
    "ntevent_logbiosfilter",
})

# Issuer-i de certificate de root cunoscuti (CA-uri globale + self-signed app legit).
KNOWN_CERT_ISSUERS: tuple[str, ...] = (
    "microsoft", "digicert", "comodo", "sectigo", "verisign",
    "globalsign", "entrust", "thawte", "geotrust", "symantec",
    "let's encrypt", "lets encrypt", "amazon", "google trust services",
    "go daddy", "starfield", "identrust", "isrg",
    # Self-signed cert-uri legit instalate de app-uri populare:
    "blizzard", "battle.net",
    "valve", "steam",
    "epic games", "easyanticheat",
    "riot games",
    "dell", "hp inc", "lenovo",
    "intel", "amd", "nvidia",
    "qualcomm", "realtek",
)

# Conturi sistem care nu trebuie alertate la event 4672 (privilegii speciale).
SYSTEM_ACCOUNTS_PRIVESC: frozenset[str] = frozenset({
    "system", "local service", "network service", "administrator", "",
})

# Entry-uri default in hosts file (incluse de Docker Desktop si altele).
HOSTS_DEFAULTS: frozenset[tuple[str, str]] = frozenset({
    ("127.0.0.1", "localhost"), ("::1", "localhost"),
    ("127.0.0.1", "localhost.localdomain"),
    ("127.0.0.1", "kubernetes.docker.internal"),  # Docker Desktop
    ("127.0.0.1", "host.docker.internal"),
    ("127.0.0.1", "gateway.docker.internal"),
})


# Helper public — disponibil pentru teste si pentru reutilizare intre reguli.
def is_virtual_ip(ip: str) -> bool:
    """True daca IP-ul e pe adaptor virtual (Hyper-V/WSL/Docker bridge) sau link-local.
    NU acopera 10.x si 192.168.x (LAN-uri reale, accesibile in retea privata)."""
    if not ip or ip in ("0.0.0.0", "::"):
        return False
    return any(ip.startswith(p) for p in VIRTUAL_PREFIXES)


def is_private_or_virtual_ip(ip: str) -> bool:
    """True daca IP-ul e privat (LAN/loopback) sau virtual. Folosit pentru a
    decide daca o conexiune merita raportata ca expunere externa."""
    if not ip:
        return False
    return any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES)

LEVEL_ORDER: dict[str, int] = {"standard": 0, "advanced": 1, "deep": 2}

CATEGORIES: tuple[str, ...] = (
    "critical_risk",
    "network_exposure",
    "hygiene",
    "activity",
)

# Ponderi pentru agregarea finala (suma = 1.0).
CATEGORY_AGGREGATE_WEIGHT: dict[str, float] = {
    "critical_risk":    0.40,
    "network_exposure": 0.30,
    "hygiene":          0.20,
    "activity":         0.10,
}

# Tip pentru o functie-regula: primeste scan dict, returneaza None / dict / list[dict].
RuleFn = Callable[[dict[str, Any]], "dict | list[dict] | None"]

# Lista globala de reguli inregistrate prin decorator. Ordinea = ordinea de
# definitie. Nu este expusa public — accesul se face prin evaluate().
_RULES: list[RuleFn] = []


def rule(
    rule_id: str,
    min_level: str = "standard",
    category: str = "hygiene",
    weight: float = 1.0,
    confidence: float = 1.0,
    compliance: list[str] | None = None,
    os: str = "any",
) -> Callable[[RuleFn], RuleFn]:
    """Decorator: marcheaza o functie ca regula si o inregistreaza in _RULES.

    `category`: una din `CATEGORIES` — determina sub-scorul in care contribuie.
    `weight`: multiplicator per-regula peste severity (default 1.0).
    `confidence`: penalizare pentru reguli cu fals-pozitivi (0-1, default 1.0).
    `compliance`: lista de referinte la standarde de securitate (CIS Controls v8 +
        NIST CSF 2.0). Exemple: ["CIS-9.2", "NIST-PR.AC-4"]. Folosit pentru
        afisare in UI/PDF si calcul de coverage per framework.
    `os`: "any" (default), "windows" sau "linux" — regula ruleaza doar daca OS-ul
        scanului se potriveste (vezi `_scan_os` + filtrul din `evaluate`).
    """
    if min_level not in LEVEL_ORDER:
        raise ValueError(f"min_level invalid: {min_level!r}")
    if category not in CATEGORIES:
        raise ValueError(f"category invalid: {category!r}, asteptat unul din {CATEGORIES}")
    if not (0.0 <= confidence <= 1.0):
        raise ValueError(f"confidence trebuie in [0, 1], dat: {confidence}")
    if weight <= 0:
        raise ValueError(f"weight trebuie > 0, dat: {weight}")
    if os not in ("any", "windows", "linux"):
        raise ValueError(f"os invalid: {os!r}, asteptat any|windows|linux")
    compliance_list = list(compliance or [])
    for ref in compliance_list:
        if not isinstance(ref, str) or not ref.strip():
            raise ValueError(f"compliance ref invalid: {ref!r}")

    def decorator(fn: RuleFn) -> RuleFn:
        fn._rule_id = rule_id        # type: ignore[attr-defined]
        fn._min_level = min_level    # type: ignore[attr-defined]
        fn._category = category      # type: ignore[attr-defined]
        fn._weight = weight          # type: ignore[attr-defined]
        fn._confidence = confidence  # type: ignore[attr-defined]
        fn._compliance = compliance_list  # type: ignore[attr-defined]
        fn._os = os                  # type: ignore[attr-defined]
        _RULES.append(fn)
        return fn

    return decorator


def _scan_os(scan: dict[str, Any]) -> str:
    """Detecteaza OS-ul scanului din payload: 'linux' | 'windows' | 'other'."""
    system = str((scan.get("os") or {}).get("system", "")).lower()
    if system.startswith("linux"):
        return "linux"
    if system.startswith("windows"):
        return "windows"
    return "other"


def evaluate(scan: dict[str, Any]) -> tuple[int, dict[str, int], list[dict[str, Any]]]:
    """Ruleaza toate regulile aplicabile pentru `scan["scan_type"]`.

    Returneaza tuple:
      - exposure_score (0-100, agregat ponderat pe categorii)
      - breakdown dict {category: score 0-100}
      - lista de findings (fiecare cu `_category`, `_rule_weight`, `_rule_confidence`)
    """
    scan_type = scan.get("scan_type", "standard")
    level = LEVEL_ORDER.get(scan_type, 0)
    scan_os = _scan_os(scan)

    findings: list[dict[str, Any]] = []
    # Acumulator raw per categorie (inainte de cap).
    cat_raw: dict[str, float] = {c: 0.0 for c in CATEGORIES}

    for fn in _RULES:
        if LEVEL_ORDER.get(fn._min_level, 0) > level:
            continue
        rule_os = getattr(fn, "_os", "any")
        if rule_os != "any" and rule_os != scan_os:
            continue
        result = fn(scan)
        if result is None:
            continue
        items = result if isinstance(result, list) else [result]
        for f in items:
            # Anoteaza fiecare finding cu metadata regulii sursa (util pentru UI).
            f["category"] = fn._category
            f["rule_weight"] = fn._weight
            f["rule_confidence"] = fn._confidence
            f["compliance"] = list(getattr(fn, "_compliance", []))
            sev_w = SEVERITY_WEIGHT.get(f.get("severity", "info"), 0)
            cat_raw[fn._category] += sev_w * fn._weight * fn._confidence
            findings.append(f)

    # Cap per categorie la 100, apoi agregat ponderat.
    breakdown: dict[str, int] = {c: min(100, round(cat_raw[c])) for c in CATEGORIES}
    exposure_score = round(sum(
        CATEGORY_AGGREGATE_WEIGHT[c] * breakdown[c] for c in CATEGORIES
    ))
    exposure_score = max(0, min(100, exposure_score))
    return exposure_score, breakdown, findings


# ─────────────────────────────────────────────────────────────────────────────
# REGULI EXISTENTE (7) — migrate la decorator
# ─────────────────────────────────────────────────────────────────────────────


@rule("NET-OPEN-PORTS-1", min_level="standard", category="network_exposure", weight=1.5,
       compliance=["CIS-4.5", "CIS-12.4", "NIST-PR.PS-01", "NIST-PR.IR-01"])
def check_risky_ports(scan: dict) -> dict | None:
    net = scan.get("network", {}) or {}
    open_ports: list[int] = net.get("open_ports", []) or []
    bindings: list[dict] = net.get("port_bindings", []) or []

    def _is_public_only_virtual(port: int) -> bool:
        """True daca portul e bind-uit DOAR pe adaptoare virtuale (nu pe
        0.0.0.0, IP public, IP LAN tipic). Folosit pentru downgrade severitate."""
        if not bindings:
            return False  # fara info, fallback la high
        ips = [b.get("ip", "") for b in bindings if b.get("port") == port]
        if not ips:
            return False
        return all(is_virtual_ip(ip) for ip in ips)

    risky_real = {}
    risky_virtual = {}
    for p in open_ports:
        if p not in RISKY_PORTS:
            continue
        if _is_public_only_virtual(p):
            risky_virtual[p] = RISKY_PORTS[p]
        else:
            risky_real[p] = RISKY_PORTS[p]

    if not risky_real and not risky_virtual:
        return None

    # Prioritate pe finding-ul real (high). Daca exista doar pe virtual, scoatem
    # un finding info (severitate "low") cu mentiunea adaptorului.
    if risky_real:
        return {
            "rule_id": "NET-OPEN-PORTS-1",
            "title": "Porturi cu risc ridicat expuse",
            "severity": "high",
            "evidence": {"ports": [{"port": p, "service": d} for p, d in risky_real.items()]},
            "recommendation": (
                "Inchide porturile neutilizate din firewall. "
                "Daca sunt necesare, restrictioneaza accesul la IP-uri de incredere "
                "si utilizeaza VPN pentru acces remote."
            ),
        }
    # Doar pe virtual: low / informational.
    return {
        "rule_id": "NET-OPEN-PORTS-1",
        "title": "Porturi cu risc ridicat expuse doar pe adaptoare virtuale",
        "severity": "low",
        "evidence": {
            "ports": [{"port": p, "service": d} for p, d in risky_virtual.items()],
            "note": "Porturile sunt expuse doar pe adaptoare virtuale (WSL/Hyper-V/Docker). Nu sunt accesibile din internet.",
        },
        "recommendation": (
            "Acceptabil pentru dezvoltatori cu WSL/Docker. "
            "Pentru reducere supraf. atac: dezactiveaza NetBIOS pe adaptorul virtual."
        ),
    }


@rule("NET-MANY-PORTS-2", min_level="standard", category="network_exposure", weight=1.0,
       compliance=["CIS-4.5", "NIST-PR.PS-01"])
def check_many_ports(scan: dict) -> dict | None:
    open_ports = scan.get("network", {}).get("open_ports", []) or []
    if len(open_ports) <= MANY_PORTS_THRESHOLD:
        return None
    return {
        "rule_id": "NET-MANY-PORTS-2",
        "title": "Suprafata de atac mare – multe porturi deschise",
        "severity": "medium",
        "evidence": {"total_open_ports": len(open_ports)},
        "recommendation": (
            f"Sistemul are {len(open_ports)} porturi deschise. "
            "Aplica principiul least-privilege: deschide doar porturile strict necesare."
        ),
    }


@rule("OS-ADMIN-1", min_level="standard", category="hygiene", weight=0.8,
       compliance=["CIS-5.4", "CIS-6.8", "NIST-PR.AA-01", "NIST-PR.AA-05"])
def check_admin_session(scan: dict) -> dict | None:
    os_info = scan.get("os", {}) or {}
    if os_info.get("is_admin") is not True:
        return None
    return {
        "rule_id": "OS-ADMIN-1",
        "title": "Sesiune activa cu privilegii de administrator",
        "severity": "medium",
        "evidence": {"is_admin": True, "hostname": os_info.get("hostname", "")},
        "recommendation": (
            "Foloseste un cont standard pentru activitatile zilnice. "
            "Contul de administrator trebuie utilizat doar pentru operatii administrative punctuale."
        ),
    }


@rule("PROC-SUSPICIOUS-1", min_level="standard", category="critical_risk", weight=1.5,
       compliance=["CIS-10.1", "CIS-13.2", "NIST-DE.CM-01", "NIST-DE.AE-02"])
def check_suspicious_processes(scan: dict) -> dict | None:
    procs = scan.get("processes", []) or []
    proc_names = {p.get("name", "").lower() for p in procs}
    found = {n: SUSPICIOUS_PROCESSES[n] for n in proc_names if n in SUSPICIOUS_PROCESSES}
    if not found:
        return None
    return {
        "rule_id": "PROC-SUSPICIOUS-1",
        "title": "Procese suspecte detectate",
        "severity": "high",
        "evidence": {"processes": [{"name": n, "description": d} for n, d in found.items()]},
        "recommendation": (
            "Verifica daca aceste procese sunt legitime pe acest sistem. "
            "Daca nu le recunosti, opreste-le si investigheaza sursa."
        ),
    }


@rule("PROC-POWERSHELL-2", min_level="standard", category="activity", weight=0.3,
       compliance=["CIS-8.5", "CIS-8.11", "NIST-DE.CM-09"])
def check_powershell_running(scan: dict) -> dict | None:
    procs = scan.get("processes", []) or []
    proc_names = {p.get("name", "").lower() for p in procs}
    ps = [n for n in proc_names if "powershell" in n]
    if not ps:
        return None
    return {
        "rule_id": "PROC-POWERSHELL-2",
        "title": "PowerShell activ",
        "severity": "low",
        "evidence": {"processes": sorted(ps)},
        "recommendation": (
            "PowerShell este legitim dar frecvent abuzat. "
            "Verifica daca sesiunile active sunt asteptate si activeaza "
            "PowerShell Script Block Logging pentru audit."
        ),
    }


@rule("SW-VULNERABLE-1", min_level="standard", category="critical_risk", weight=1.5,
       compliance=["CIS-2.2", "CIS-7.4", "NIST-ID.RA-01", "NIST-PR.PS-02"])
def check_vulnerable_software(scan: dict) -> list[dict]:
    software = scan.get("software", []) or []
    sw_names = [s.get("name", "") for s in software]
    out: list[dict] = []
    for r in VULNERABLE_SOFTWARE:
        for sw_name in sw_names:
            if r["name_contains"].lower() in sw_name.lower():
                out.append({
                    "rule_id": "SW-VULNERABLE-1",
                    "title": f"Software vulnerabil detectat: {sw_name[:60]}",
                    "severity": r["severity"],
                    "evidence": {"software": sw_name, "cve": r["cve"], "note": r["note"]},
                    "recommendation": (
                        "Dezinstaleaza sau actualizeaza software-ul la cea mai recenta versiune. "
                        "Software-ul EOL (End of Life) nu mai primeste patch-uri de securitate."
                    ),
                })
                break
    return out


@rule("OS-EOL-1", min_level="standard", category="critical_risk", weight=1.5,
       compliance=["CIS-2.2", "CIS-7.3", "NIST-PR.PS-02", "NIST-ID.RA-01"])
def check_eol_os(scan: dict) -> dict | None:
    os_info = scan.get("os", {}) or {}
    system = os_info.get("system", "")
    release = os_info.get("release", "")
    for r in EOL_OPERATING_SYSTEMS:
        if r["system"] in system and r["rel"] in release:
            return {
                "rule_id": "OS-EOL-1",
                "title": f"Sistem de operare EOL: {system} {release}",
                "severity": r["severity"],
                "evidence": {
                    "system": system,
                    "release": release,
                    "version": os_info.get("version", ""),
                },
                "recommendation": (
                    "Acest sistem de operare nu mai primeste actualizari de securitate. "
                    "Upgradeaza la o versiune suportata cat mai curand posibil."
                ),
            }
    return None


# ─────────────────────────────────────────────────────────────────────────────
# REGULI NOI (16): 2 standard + 6 advanced + 8 deep
# ─────────────────────────────────────────────────────────────────────────────


@rule("FW-DISABLED-1", min_level="standard", category="hygiene", weight=1.2,
       compliance=["CIS-4.4", "CIS-4.5", "NIST-PR.IR-01", "NIST-PR.PS-01"], os="windows")
def check_firewall_disabled(scan: dict) -> dict | None:
    profiles = (scan.get("system_info", {}) or {}).get("firewall", {}).get("profiles", {})
    disabled = [p for p in ("domain", "public") if profiles.get(p) is False]
    if not disabled:
        return None
    return {
        "rule_id": "FW-DISABLED-1",
        "title": "Windows Firewall dezactivat pe profil critic",
        "severity": "high",
        "evidence": {"disabled_profiles": disabled},
        "recommendation": (
            "Activeaza firewall: netsh advfirewall set allprofiles state on"
        ),
    }


@rule("USER-ADMIN-1", min_level="standard", category="hygiene", weight=1.0,
       compliance=["CIS-5.4", "CIS-6.2", "NIST-PR.AA-05"], os="windows")
def check_extra_admins(scan: dict) -> dict | None:
    users = (scan.get("system_info", {}) or {}).get("local_users", []) or []
    current = (scan.get("os", {}) or {}).get("username", "").lower()
    extra = [
        u["name"] for u in users
        if u.get("is_admin")
        and u.get("name", "").lower() not in ("administrator",)
        and u.get("name", "").lower() != current
    ]
    if not extra:
        return None
    return {
        "rule_id": "USER-ADMIN-1",
        "title": "Conturi locale cu privilegii de administrator neasteptate",
        "severity": "medium",
        "evidence": {"extra_admin_accounts": extra},
        "recommendation": (
            "Revoca drepturile inutile: net localgroup administrators <user> /delete"
        ),
    }


@rule("STARTUP-SUSPICIOUS-1", min_level="advanced", category="activity", weight=0.7, confidence=0.7,
       compliance=["CIS-10.1", "CIS-2.3", "NIST-DE.AE-02", "NIST-PR.PS-04"], os="windows")
def check_suspicious_startup(scan: dict) -> dict | None:
    startup = (scan.get("persistence", {}) or {}).get("startup", []) or []
    suspicious = [
        s for s in startup
        if any(p in s.get("path", "").lower() for p in SUSPICIOUS_STARTUP_PATHS)
    ]
    if not suspicious:
        return None
    return {
        "rule_id": "STARTUP-SUSPICIOUS-1",
        "title": "Startup entry in director suspect",
        "severity": "high",
        "evidence": {"entries": [{"key": s.get("key"), "path": s.get("path")} for s in suspicious]},
        "recommendation": (
            "Sterge cheile suspecte din HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."
        ),
    }


@rule("TASK-SUSPICIOUS-1", min_level="advanced", category="activity", weight=1.0,
       compliance=["CIS-8.5", "CIS-10.7", "NIST-DE.AE-02"], os="windows")
def check_suspicious_tasks(scan: dict) -> dict | None:
    tasks = (scan.get("persistence", {}) or {}).get("tasks", []) or []
    suspicious = [
        t for t in tasks
        if "powershell" in t.get("action", "").lower()
        and any(f in t.get("action", "").lower() for f in POWERSHELL_OFFENSIVE_FLAGS)
    ]
    if not suspicious:
        return None
    return {
        "rule_id": "TASK-SUSPICIOUS-1",
        "title": "Task Scheduler cu comanda PowerShell encodata",
        "severity": "high",
        "evidence": {"tasks": [{"name": t.get("name"), "action": t.get("action", "")[:200]} for t in suspicious]},
        "recommendation": (
            "Sterge task-urile: schtasks /delete /tn \"<TaskName>\" /f"
        ),
    }


@rule("SVC-SUSPICIOUS-1", min_level="advanced", category="activity", weight=0.8,
       compliance=["CIS-2.3", "CIS-10.1", "NIST-DE.CM-09"], os="windows")
def check_suspicious_services(scan: dict) -> dict | None:
    services = (scan.get("persistence", {}) or {}).get("services", []) or []
    suspicious = [
        s for s in services
        if s.get("status", "").lower() == "running"
        and s.get("binary_path", "")
        and not any(s.get("binary_path", "").lstrip('"').lower().startswith(p) for p in STANDARD_SERVICE_PATHS)
    ]
    if not suspicious:
        return None
    return {
        "rule_id": "SVC-SUSPICIOUS-1",
        "title": "Servicii Windows cu executabil in path nestandard",
        "severity": "medium",
        "evidence": {"services": [{"name": s.get("name"), "path": s.get("binary_path")} for s in suspicious]},
        "recommendation": (
            "Verifica si opreste: sc stop <name> && sc delete <name>"
        ),
    }


@rule("NET-SHARE-1", min_level="advanced", category="network_exposure", weight=1.0,
       compliance=["CIS-3.3", "CIS-12.2", "NIST-PR.DS-01", "NIST-PR.AA-05"], os="windows")
def check_network_shares(scan: dict) -> dict | None:
    shares = (scan.get("network", {}) or {}).get("shares", []) or []
    non_default = [s for s in shares if s.get("name", "").lower() not in DEFAULT_WINDOWS_SHARES]
    if not non_default:
        return None
    return {
        "rule_id": "NET-SHARE-1",
        "title": "Foldere partajate in retea detectate",
        "severity": "medium",
        "evidence": {"shares": [{"name": s.get("name"), "path": s.get("path")} for s in non_default]},
        "recommendation": (
            "Sterge share-urile inutile: net share <Name> /delete"
        ),
    }


@rule("PS-POLICY-1", min_level="advanced", category="activity", weight=0.8,
       compliance=["CIS-2.7", "CIS-4.8", "NIST-PR.PS-01"], os="windows")
def check_ps_policy(scan: dict) -> dict | None:
    policy = (scan.get("persistence", {}) or {}).get("ps_policy", "")
    if not policy or policy.lower() not in ("bypass", "unrestricted"):
        return None
    return {
        "rule_id": "PS-POLICY-1",
        "title": f"PowerShell Execution Policy permisiva: {policy}",
        "severity": "medium",
        "evidence": {"policy": policy},
        "recommendation": (
            "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine"
        ),
    }


@rule("NET-ESTABLISHED-1", min_level="advanced", category="network_exposure", weight=0.7,
       compliance=["CIS-13.5", "CIS-13.1", "NIST-DE.CM-01", "NIST-DE.AE-07"])
def check_established_connections(scan: dict) -> dict | None:
    conns = (scan.get("network", {}) or {}).get("connections", []) or []
    suspicious = [
        c for c in conns
        if c.get("remote_ip")
        and not is_private_or_virtual_ip(c["remote_ip"])
        and c.get("remote_port", 0) not in STD_OUTBOUND_PORTS
        and (c.get("process") or "").lower() not in KNOWN_NETWORK_PROCESSES
    ]
    if not suspicious:
        return None
    return {
        "rule_id": "NET-ESTABLISHED-1",
        "title": "Conexiuni active pe porturi nestandard catre IP-uri externe",
        "severity": "low",
        "evidence": {"connections": [
            {"ip": c.get("remote_ip"), "port": c.get("remote_port"), "process": c.get("process")}
            for c in suspicious[:20]
        ]},
        "recommendation": (
            "Verifica conexiunile cu netstat -b sau Resource Monitor."
        ),
    }


def _is_winlogon_default(values: dict) -> bool:
    """True daca dict Winlogon contine doar valori default Windows."""
    if not isinstance(values, dict):
        return False
    for k, v in values.items():
        k_low = k.lower()
        v_low = (v or "").strip().lower()
        if k_low not in WINLOGON_DEFAULTS:
            return False  # cheie necunoscuta -> suspect
        if v_low not in WINLOGON_DEFAULTS[k_low]:
            return False
    return True


@rule("REG-HIJACK-1", min_level="deep", category="critical_risk", weight=2.0,
       compliance=["CIS-10.1", "CIS-10.7", "NIST-DE.AE-02", "NIST-DE.CM-09"], os="windows")
def check_registry_hijack(scan: dict) -> dict | None:
    reg = (scan.get("persistence", {}) or {}).get("reg_persistence", {}) or {}
    # Pastram doar entry-uri non-default + non-empty.
    suspicious: dict = {}
    for key, value in reg.items():
        if not value:
            continue
        if key == "Winlogon" and _is_winlogon_default(value):
            continue
        suspicious[key] = value

    if not suspicious:
        return None
    return {
        "rule_id": "REG-HIJACK-1",
        "title": "Persistenta prin registry (AppInit_DLLs / IFEO / Winlogon)",
        "severity": "critical",
        "evidence": {"registry_keys": suspicious},
        "recommendation": (
            "Investigheaza si sterge valorile suspecte din regedit.exe."
        ),
    }


@rule("WMI-PERSIST-1", min_level="deep", category="critical_risk", weight=2.0,
       compliance=["CIS-10.1", "CIS-10.7", "NIST-DE.AE-02", "NIST-DE.CM-09"], os="windows")
def check_wmi_persistence(scan: dict) -> dict | None:
    subs = (scan.get("persistence", {}) or {}).get("wmi_subscriptions", []) or []
    suspicious = []
    for s in subs:
        cmd = (s.get("command") or "").strip()
        name_low = (s.get("name") or "").strip().lower()
        # Skip subscriptii cu command vid (built-in) sau cu name in lista cunoscuta.
        if not cmd or name_low in WMI_BUILTIN_NAMES:
            continue
        suspicious.append(s)
    if not suspicious:
        return None
    return {
        "rule_id": "WMI-PERSIST-1",
        "title": "Subscriptii WMI active detectate",
        "severity": "critical",
        "evidence": {"subscriptions": [{"name": s.get("name"), "command": s.get("command")} for s in suspicious]},
        "recommendation": (
            "Sterge cu: Get-WMIObject -Namespace root\\subscription -Class __EventFilter | Remove-WMIObject"
        ),
    }


@rule("CERT-UNTRUSTED-1", min_level="deep", category="hygiene", weight=1.0,
       compliance=["CIS-3.10", "CIS-12.2", "NIST-PR.DS-02", "NIST-PR.IR-01"], os="windows")
def check_untrusted_certs(scan: dict) -> dict | None:
    certs = (scan.get("forensics", {}) or {}).get("certificates", []) or []
    suspicious = [
        c for c in certs
        if not any(k in c.get("issuer", "").lower() for k in KNOWN_CERT_ISSUERS)
        and not any(k in c.get("subject", "").lower() for k in ("microsoft", "windows"))
    ]
    if not suspicious:
        return None
    return {
        "rule_id": "CERT-UNTRUSTED-1",
        "title": "Certificate root necunoscute instalate",
        "severity": "high",
        "evidence": {"certificates": [
            {"subject": c.get("subject"), "issuer": c.get("issuer"), "thumbprint": (c.get("thumbprint") or "")[:40]}
            for c in suspicious[:20]
        ]},
        "recommendation": (
            "Certificatele root necunoscute permit interceptari HTTPS (MITM). "
            "Sterge din certmgr.msc → Trusted Root Certification Authorities."
        ),
    }


@rule("AV-DISABLED-1", min_level="deep", category="hygiene", weight=1.2,
       compliance=["CIS-10.1", "CIS-10.6", "NIST-PR.PS-05", "NIST-DE.CM-09"], os="windows")
def check_av_disabled(scan: dict) -> dict | None:
    defender = (scan.get("system_info", {}) or {}).get("defender", {})
    if not defender:
        return None

    # Daca exista un AV tert activ (Bitdefender/Kaspersky/etc.), Defender disabled
    # e comportamentul normal Windows — nu trigger FP.
    third_party = defender.get("third_party_av") or []
    if third_party:
        return None

    issues = []
    if defender.get("enabled") is False:
        issues.append("Windows Defender dezactivat")
    age = defender.get("signature_age_days", 0)
    if isinstance(age, (int, float)) and age > SIGNATURE_AGE_DAYS_THRESHOLD:
        issues.append(f"Semnaturi vechi ({age} zile)")
    if not issues:
        return None
    return {
        "rule_id": "AV-DISABLED-1",
        "title": "Windows Defender dezactivat sau semnaturi expirate",
        "severity": "high",
        "evidence": {"issues": issues, "defender": defender},
        "recommendation": (
            "Activeaza: Set-MpPreference -DisableRealtimeMonitoring $false. Update: Update-MpSignature."
        ),
    }


@rule("EVENTLOG-BRUTEFORCE-1", min_level="deep", category="activity", weight=1.2,
       compliance=["CIS-6.5", "CIS-8.5", "NIST-DE.AE-02", "NIST-PR.AA-03"], os="windows")
def check_brute_force(scan: dict) -> dict | None:
    events = (scan.get("forensics", {}) or {}).get("event_log", []) or []
    failures = [e for e in events if e.get("event_id") == 4625]
    if len(failures) < BRUTEFORCE_FAIL_COUNT_THRESHOLD:
        return None
    accounts = sorted({e.get("account", "") for e in failures})[:5]
    return {
        "rule_id": "EVENTLOG-BRUTEFORCE-1",
        "title": f"Posibil atac brute-force ({len(failures)} esecuri de autentificare)",
        "severity": "high",
        "evidence": {"failed_logon_count": len(failures), "sample_accounts": accounts},
        "recommendation": (
            "Restrictioneaza RDP/SMB la IP-uri de incredere. Configureaza Account Lockout Policy."
        ),
    }


@rule("EVENTLOG-PRIVESC-1", min_level="deep", category="activity", weight=1.0,
       compliance=["CIS-5.4", "CIS-8.5", "NIST-PR.AA-05", "NIST-DE.AE-02"], os="windows")
def check_privesc(scan: dict) -> dict | None:
    events = (scan.get("forensics", {}) or {}).get("event_log", []) or []
    suspicious = [
        e for e in events
        if e.get("event_id") == 4672
        and e.get("account", "").lower() not in SYSTEM_ACCOUNTS_PRIVESC
        and not e.get("account", "").endswith("$")
    ]
    if not suspicious:
        return None
    accounts = sorted({e.get("account", "") for e in suspicious})
    return {
        "rule_id": "EVENTLOG-PRIVESC-1",
        "title": "Privilegii speciale acordate conturilor non-sistem",
        "severity": "high",
        "evidence": {"accounts": accounts, "event_count": len(suspicious)},
        "recommendation": (
            "Verifica daca aceste conturi necesita privilegii speciale. Revizuieste User Rights Assignment."
        ),
    }


def _is_clean_hosts_entry(h: dict) -> bool:
    """Filtreaza entry-uri hosts care nu sunt valide (BOM, comentarii, etc.)."""
    ip = (h.get("ip") or "").strip()
    host = (h.get("hostname") or "").strip().lower()
    # Skip linii fara IP valid (gol, BOM, comentariu).
    if not ip or ip.startswith("#") or "﻿" in ip:
        return False
    # Skip linii fara hostname valid.
    if not host:
        return False
    return True


@rule("HOSTS-TAMPERED-1", min_level="deep", category="activity", weight=1.0,
       compliance=["CIS-10.1", "NIST-DE.AE-02", "NIST-PR.DS-06"], os="windows")
def check_hosts_tampered(scan: dict) -> dict | None:
    entries = (scan.get("forensics", {}) or {}).get("hosts", []) or []
    suspicious = [
        h for h in entries
        if _is_clean_hosts_entry(h)
        and (h.get("ip", "").strip(), h.get("hostname", "").strip().lower()) not in HOSTS_DEFAULTS
    ]
    if not suspicious:
        return None
    return {
        "rule_id": "HOSTS-TAMPERED-1",
        "title": "Fisierul hosts modificat cu intrari nestandard",
        "severity": "medium",
        "evidence": {"entries": [{"ip": h.get("ip"), "hostname": h.get("hostname")} for h in suspicious]},
        "recommendation": (
            "Hosts este modificat de malware pentru redirectionare trafic. "
            "Restaureaza: notepad C:\\Windows\\System32\\drivers\\etc\\hosts"
        ),
    }


@rule("BITLOCKER-OFF-1", min_level="deep", category="hygiene", weight=1.0,
       compliance=["CIS-3.6", "CIS-3.11", "NIST-PR.DS-01"], os="windows")
def check_bitlocker_off(scan: dict) -> dict | None:
    volumes = (scan.get("system_info", {}) or {}).get("bitlocker", []) or []
    sys_vols = [
        v for v in volumes
        if v.get("volume", "").upper().startswith("C")
        and v.get("protection_status", "").lower() in ("off", "disabled", "unknown")
    ]
    if not sys_vols:
        return None
    return {
        "rule_id": "BITLOCKER-OFF-1",
        "title": "Volumul de sistem nu este protejat cu BitLocker",
        "severity": "medium",
        "evidence": {"volumes": [{"volume": v.get("volume"), "status": v.get("protection_status")} for v in sys_vols]},
        "recommendation": (
            "Activeaza: Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector"
        ),
    }


@rule("NMAP-LUA-1", min_level="deep", category="critical_risk", weight=1.0,
       compliance=["CIS-7.5", "CIS-7.6", "NIST-ID.RA-01"])
def collect_nmap_lua_findings(scan: dict) -> list[dict] | None:
    """Wrapper pass-through pentru finding-urile emise de scriptul NSE custom
    `vulnwatch-audit.nse`. Lua a decis deja severitatea; Python doar le muta
    in lista finala cu prefix source='nmap-lua' + host_ip in evidence."""
    nmap = scan.get("nmap")
    if not nmap or not nmap.get("hosts"):
        return None
    findings: list[dict] = []
    for host in nmap["hosts"]:
        host_ip = host.get("ip", "")
        for f in host.get("vulnwatch_findings", []) or []:
            evidence = dict(f.get("evidence", {}) or {})
            evidence["host_ip"] = host_ip
            findings.append({
                "rule_id": f.get("rule_id", "NMAP-UNKNOWN"),
                "title": f.get("title", "Finding from nmap NSE"),
                "severity": f.get("severity", "info"),
                "evidence": evidence,
                "recommendation": f.get("recommendation",
                    "Vezi detaliile in sectiunea Network scan din raport."),
                "source": "nmap-lua",
            })
    return findings or None


# ─────────────────────────────────────────────────────────────────────────────
# Regulile Linux stau intr-un modul dedicat (rules_linux.py) ca sa nu amestece
# codul Windows cu cel Linux. Importul de mai jos le inregistreaza in _RULES
# (decoratorul @rule din acest modul le adauga la import).
# ─────────────────────────────────────────────────────────────────────────────
from . import rules_linux  # noqa: E402,F401  (trebuie dupa definirea @rule)
from . import rules_extended  # noqa: E402,F401  (idem -- reguli 2026-06-11)
