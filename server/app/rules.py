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


# ─────────────────────────────────────────────────────────────────────────────
# REGULI NOI (16): 2 standard + 6 advanced + 8 deep
# ─────────────────────────────────────────────────────────────────────────────


@rule("FW-DISABLED-1", min_level="standard")
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


@rule("USER-ADMIN-1", min_level="standard")
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


@rule("STARTUP-SUSPICIOUS-1", min_level="advanced")
def check_suspicious_startup(scan: dict) -> dict | None:
    startup = (scan.get("persistence", {}) or {}).get("startup", []) or []
    SUSP = ("%temp%", "%appdata%", "\\temp\\", "\\appdata\\local\\temp",
            "\\users\\public\\", "\\programdata\\temp")
    suspicious = [
        s for s in startup
        if any(p in s.get("path", "").lower() for p in SUSP)
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


@rule("TASK-SUSPICIOUS-1", min_level="advanced")
def check_suspicious_tasks(scan: dict) -> dict | None:
    tasks = (scan.get("persistence", {}) or {}).get("tasks", []) or []
    FLAGS = ("-enc ", "-encodedcommand", " -e ")
    suspicious = [
        t for t in tasks
        if "powershell" in t.get("action", "").lower()
        and any(f in t.get("action", "").lower() for f in FLAGS)
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


@rule("SVC-SUSPICIOUS-1", min_level="advanced")
def check_suspicious_services(scan: dict) -> dict | None:
    services = (scan.get("persistence", {}) or {}).get("services", []) or []
    STD = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")
    suspicious = [
        s for s in services
        if s.get("status", "").lower() == "running"
        and s.get("binary_path", "")
        and not any(s.get("binary_path", "").lower().startswith(p) for p in STD)
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


@rule("NET-SHARE-1", min_level="advanced")
def check_network_shares(scan: dict) -> dict | None:
    shares = (scan.get("network", {}) or {}).get("shares", []) or []
    DEFAULT = {"admin$", "ipc$", "c$", "d$", "e$", "print$"}
    non_default = [s for s in shares if s.get("name", "").lower() not in DEFAULT]
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


@rule("PS-POLICY-1", min_level="advanced")
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


@rule("NET-ESTABLISHED-1", min_level="advanced")
def check_established_connections(scan: dict) -> dict | None:
    conns = (scan.get("network", {}) or {}).get("connections", []) or []
    PRIVATE = ("10.", "127.", "192.168.", "169.254.", "::1", "fe80:",
               "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
               "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
               "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")
    STD_PORTS = {80, 443, 53, 22, 25, 587, 465, 993, 995, 8080, 8443}
    suspicious = [
        c for c in conns
        if c.get("remote_ip")
        and not any(c["remote_ip"].startswith(p) for p in PRIVATE)
        and c.get("remote_port", 0) not in STD_PORTS
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


@rule("REG-HIJACK-1", min_level="deep")
def check_registry_hijack(scan: dict) -> dict | None:
    reg = (scan.get("persistence", {}) or {}).get("reg_persistence", {}) or {}
    suspicious = {k: v for k, v in reg.items() if v}
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


@rule("WMI-PERSIST-1", min_level="deep")
def check_wmi_persistence(scan: dict) -> dict | None:
    subs = (scan.get("persistence", {}) or {}).get("wmi_subscriptions", []) or []
    if not subs:
        return None
    return {
        "rule_id": "WMI-PERSIST-1",
        "title": "Subscriptii WMI active detectate",
        "severity": "critical",
        "evidence": {"subscriptions": [{"name": s.get("name"), "command": s.get("command")} for s in subs]},
        "recommendation": (
            "Sterge cu: Get-WMIObject -Namespace root\\subscription -Class __EventFilter | Remove-WMIObject"
        ),
    }


@rule("CERT-UNTRUSTED-1", min_level="deep")
def check_untrusted_certs(scan: dict) -> dict | None:
    certs = (scan.get("forensics", {}) or {}).get("certificates", []) or []
    KNOWN = ("microsoft", "digicert", "comodo", "sectigo", "verisign",
             "globalsign", "entrust", "thawte", "geotrust", "symantec",
             "let's encrypt", "lets encrypt", "amazon", "google trust services",
             "go daddy", "starfield", "identrust", "isrg")
    suspicious = [
        c for c in certs
        if not any(k in c.get("issuer", "").lower() for k in KNOWN)
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


@rule("AV-DISABLED-1", min_level="deep")
def check_av_disabled(scan: dict) -> dict | None:
    defender = (scan.get("system_info", {}) or {}).get("defender", {})
    if not defender:
        return None
    issues = []
    if defender.get("enabled") is False:
        issues.append("Windows Defender dezactivat")
    age = defender.get("signature_age_days", 0)
    if isinstance(age, (int, float)) and age > 7:
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


@rule("EVENTLOG-BRUTEFORCE-1", min_level="deep")
def check_brute_force(scan: dict) -> dict | None:
    events = (scan.get("forensics", {}) or {}).get("event_log", []) or []
    failures = [e for e in events if e.get("event_id") == 4625]
    if len(failures) < 10:
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


@rule("EVENTLOG-PRIVESC-1", min_level="deep")
def check_privesc(scan: dict) -> dict | None:
    events = (scan.get("forensics", {}) or {}).get("event_log", []) or []
    SYS = {"system", "local service", "network service", "administrator", ""}
    suspicious = [
        e for e in events
        if e.get("event_id") == 4672
        and e.get("account", "").lower() not in SYS
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


@rule("HOSTS-TAMPERED-1", min_level="deep")
def check_hosts_tampered(scan: dict) -> dict | None:
    entries = (scan.get("forensics", {}) or {}).get("hosts", []) or []
    OK = {("127.0.0.1", "localhost"), ("::1", "localhost"),
          ("127.0.0.1", "localhost.localdomain")}
    suspicious = [
        h for h in entries
        if (h.get("ip", ""), h.get("hostname", "").lower()) not in OK
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


@rule("BITLOCKER-OFF-1", min_level="deep")
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
