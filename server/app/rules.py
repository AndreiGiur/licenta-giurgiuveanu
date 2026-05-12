"""
Rules engine cu auto-filtrare dupa scan_type.

Decorator @rule(id, min_level): inregistreaza o functie ca regula. La
evaluare, doar regulile cu min_level <= scan_type ruleaza.

Adaugare regula noua = decoreaza o functie. Zero modificari in alte parti.
"""
from __future__ import annotations

import math
from typing import Any, Callable

SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
    "info": 0,
}

LEVEL_ORDER: dict[str, int] = {"standard": 0, "advanced": 1, "deep": 2}

# Tip pentru o functie-regula: primeste scan dict, returneaza None / dict / list[dict].
RuleFn = Callable[[dict[str, Any]], "dict | list[dict] | None"]

# Lista globala de reguli inregistrate prin decorator. Ordinea = ordinea de
# definitie. Nu este expusa public — accesul se face prin evaluate().
_RULES: list[RuleFn] = []


def rule(rule_id: str, min_level: str = "standard") -> Callable[[RuleFn], RuleFn]:
    """Decorator: marcheaza o functie ca regula si o inregistreaza in _RULES."""
    if min_level not in LEVEL_ORDER:
        raise ValueError(f"min_level invalid: {min_level!r}")

    def decorator(fn: RuleFn) -> RuleFn:
        fn._rule_id = rule_id        # type: ignore[attr-defined]
        fn._min_level = min_level    # type: ignore[attr-defined]
        _RULES.append(fn)
        return fn

    return decorator


def evaluate(scan: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    """Ruleaza toate regulile aplicabile pentru `scan["scan_type"]`.
    Returneaza (exposure_score 0-100, lista de findings)."""
    scan_type = scan.get("scan_type", "standard")
    level = LEVEL_ORDER.get(scan_type, 0)

    findings: list[dict[str, Any]] = []
    for fn in _RULES:
        if LEVEL_ORDER.get(fn._min_level, 0) > level:
            continue
        result = fn(scan)
        if result is None:
            continue
        if isinstance(result, list):
            findings.extend(result)
        else:
            findings.append(result)

    raw = sum(SEVERITY_WEIGHT.get(f.get("severity", "info"), 0) for f in findings)
    exposure_score = min(100, round(100 * (1 - math.exp(-raw / 60))))
    return exposure_score, findings


# ─────────────────────────────────────────────────────────────────────────────
# REGULI EXISTENTE (7) — migrate la decorator
# ─────────────────────────────────────────────────────────────────────────────


@rule("NET-OPEN-PORTS-1", min_level="standard")
def check_risky_ports(scan: dict) -> dict | None:
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
    open_ports: list[int] = scan.get("network", {}).get("open_ports", []) or []
    risky_found = {p: RISKY_PORTS[p] for p in open_ports if p in RISKY_PORTS}
    if not risky_found:
        return None
    return {
        "rule_id": "NET-OPEN-PORTS-1",
        "title": "Porturi cu risc ridicate expuse",
        "severity": "high",
        "evidence": {"ports": [{"port": p, "service": d} for p, d in risky_found.items()]},
        "recommendation": (
            "Inchide porturile neutilizate din firewall. "
            "Daca sunt necesare, restrictioneaza accesul la IP-uri de incredere "
            "si utilizeaza VPN pentru acces remote."
        ),
    }


@rule("NET-MANY-PORTS-2", min_level="standard")
def check_many_ports(scan: dict) -> dict | None:
    open_ports = scan.get("network", {}).get("open_ports", []) or []
    if len(open_ports) <= 20:
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


@rule("OS-ADMIN-1", min_level="standard")
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


@rule("PROC-SUSPICIOUS-1", min_level="standard")
def check_suspicious_processes(scan: dict) -> dict | None:
    SUSPICIOUS_PROCS: dict[str, str] = {
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
    procs = scan.get("processes", []) or []
    proc_names = {p.get("name", "").lower() for p in procs}
    found = {n: SUSPICIOUS_PROCS[n] for n in proc_names if n in SUSPICIOUS_PROCS}
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


@rule("PROC-POWERSHELL-2", min_level="standard")
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


@rule("SW-VULNERABLE-1", min_level="standard")
def check_vulnerable_software(scan: dict) -> list[dict]:
    VULNERABLE_SOFTWARE: list[dict] = [
        {"name_contains": "Adobe Flash",        "severity": "critical", "cve": "multiple",       "note": "EOL din 2020, nu mai primeste patch-uri"},
        {"name_contains": "Internet Explorer",  "severity": "high",     "cve": "multiple",       "note": "EOL din 2022, vulnerabilitati nepatched"},
        {"name_contains": "Java 6",             "severity": "high",     "cve": "multiple",       "note": "EOL, versiune nesupportata"},
        {"name_contains": "Java 7",             "severity": "high",     "cve": "multiple",       "note": "EOL, versiune nesupportata"},
        {"name_contains": "OpenSSL 1.0",        "severity": "high",     "cve": "CVE-2022-0778",  "note": "Versiune vulnerabila"},
        {"name_contains": "WinRAR 5",           "severity": "medium",   "cve": "CVE-2023-38831", "note": "Versiune vulnerabila la executie de cod"},
        {"name_contains": "7-Zip 2",            "severity": "low",      "cve": "CVE-2023-31102", "note": "Versiune mai veche"},
    ]
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


@rule("OS-EOL-1", min_level="standard")
def check_eol_os(scan: dict) -> dict | None:
    OS_EOL = [
        {"system": "Windows", "rel": "XP",    "severity": "critical"},
        {"system": "Windows", "rel": "Vista", "severity": "critical"},
        {"system": "Windows", "rel": "7",     "severity": "high"},
        {"system": "Windows", "rel": "8.0",   "severity": "high"},
        {"system": "Linux",   "rel": "2.6",   "severity": "high"},
    ]
    os_info = scan.get("os", {}) or {}
    system = os_info.get("system", "")
    release = os_info.get("release", "")
    for r in OS_EOL:
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
