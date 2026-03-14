from typing import Dict, Any, List

# Severitate → punctaj de risc (folosit in calculul scorului)
SEVERITY_WEIGHT = {
    "critical": 40,
    "high":     25,
    "medium":   15,
    "low":       5,
    "info":      0,
}


def evaluate(scan: Dict[str, Any]) -> tuple[int, List[Dict[str, Any]]]:
    findings: List[Dict[str, Any]] = []

    open_ports: list[int] = scan.get("network", {}).get("open_ports", [])
    os_info: dict        = scan.get("os", {})
    processes: list      = scan.get("processes", [])
    software: list       = scan.get("software", [])
    proc_names           = {p.get("name", "").lower() for p in processes}

    # ── REGULA 1: Porturi cu risc ridicat expuse ──────────────────────────────
    # FTP (21), Telnet (23), SMTP (25), NetBIOS (139, 445),
    # RDP (3389), VNC (5900), WinRM (5985, 5986)
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
    risky_found = {p: RISKY_PORTS[p] for p in open_ports if p in RISKY_PORTS}
    if risky_found:
        findings.append({
            "rule_id": "NET-OPEN-PORTS-1",
            "title": "Porturi cu risc ridicate expuse",
            "severity": "high",
            "evidence": {
                "ports": [{"port": p, "service": desc} for p, desc in risky_found.items()]
            },
            "recommendation": (
                "Inchide porturile neutilizate din firewall. "
                "Daca sunt necesare, restrictioneaza accesul la IP-uri de incredere "
                "si utilizeaza VPN pentru acces remote."
            ),
        })

    # ── REGULA 2: Numar mare de porturi deschise ──────────────────────────────
    if len(open_ports) > 20:
        findings.append({
            "rule_id": "NET-MANY-PORTS-2",
            "title": "Suprafata de atac mare – multe porturi deschise",
            "severity": "medium",
            "evidence": {"total_open_ports": len(open_ports)},
            "recommendation": (
                f"Sistemul are {len(open_ports)} porturi deschise. "
                "Aplica principiul least-privilege: deschide doar porturile strict necesare."
            ),
        })

    # ── REGULA 3: Agent rulat cu privilegii de administrator ──────────────────
    if os_info.get("is_admin") is True:
        findings.append({
            "rule_id": "OS-ADMIN-1",
            "title": "Sesiune activa cu privilegii de administrator",
            "severity": "medium",
            "evidence": {"is_admin": True, "hostname": os_info.get("hostname", "")},
            "recommendation": (
                "Foloseste un cont standard pentru activitatile zilnice. "
                "Contul de administrator trebuie utilizat doar pentru operatii administrative punctuale."
            ),
        })

    # ── REGULA 4: Procese suspecte / instrumente de hacking ──────────────────
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
    found_suspicious = {name: SUSPICIOUS_PROCS[name] for name in proc_names if name in SUSPICIOUS_PROCS}
    if found_suspicious:
        findings.append({
            "rule_id": "PROC-SUSPICIOUS-1",
            "title": "Procese suspecte detectate",
            "severity": "high",
            "evidence": {
                "processes": [{"name": n, "description": d} for n, d in found_suspicious.items()]
            },
            "recommendation": (
                "Verifica daca aceste procese sunt legitime pe acest sistem. "
                "Daca nu le recunosti, opreste-le si investigheaza sursa."
            ),
        })

    # ── REGULA 5: PowerShell in executie (informativ) ─────────────────────────
    powershell_procs = [n for n in proc_names if "powershell" in n]
    if powershell_procs:
        findings.append({
            "rule_id": "PROC-POWERSHELL-2",
            "title": "PowerShell activ",
            "severity": "low",
            "evidence": {"processes": sorted(powershell_procs)},
            "recommendation": (
                "PowerShell este legitim dar frecvent abuzat. "
                "Verifica daca sesiunile active sunt asteptate si activeaza "
                "PowerShell Script Block Logging pentru audit."
            ),
        })

    # ── REGULA 6: Software cu vulnerabilitati cunoscute ───────────────────────
    # Lista simplificata de versiuni vulnerabile (proof-of-concept pentru licenta)
    VULNERABLE_SOFTWARE: list[dict] = [
        {"name_contains": "Adobe Flash",        "severity": "critical", "cve": "multiple", "note": "EOL din 2020, nu mai primeste patch-uri"},
        {"name_contains": "Internet Explorer",  "severity": "high",     "cve": "multiple", "note": "EOL din 2022, vulnerabilitati nepatched"},
        {"name_contains": "Java 6",             "severity": "high",     "cve": "multiple", "note": "EOL, versiune nesupportata"},
        {"name_contains": "Java 7",             "severity": "high",     "cve": "multiple", "note": "EOL, versiune nesupportata"},
        {"name_contains": "OpenSSL 1.0",        "severity": "high",     "cve": "CVE-2022-0778", "note": "Versiune vulnerabila"},
        {"name_contains": "WinRAR 5",           "severity": "medium",   "cve": "CVE-2023-38831", "note": "Versiune vulnerabila la executie de cod"},
        {"name_contains": "7-Zip 2",            "severity": "low",      "cve": "CVE-2023-31102", "note": "Versiune mai veche"},
    ]
    vuln_found = []
    sw_names = [s.get("name", "") for s in software]
    for rule in VULNERABLE_SOFTWARE:
        for sw_name in sw_names:
            if rule["name_contains"].lower() in sw_name.lower():
                vuln_found.append({
                    "software": sw_name,
                    "cve": rule["cve"],
                    "note": rule["note"],
                    "severity": rule["severity"],
                })
                break  # o singura intrare per regula

    for v in vuln_found:
        sev = v.pop("severity")
        findings.append({
            "rule_id": "SW-VULNERABLE-1",
            "title": f"Software vulnerabil detectat: {v['software'][:60]}",
            "severity": sev,
            "evidence": v,
            "recommendation": (
                "Dezinstaleaza sau actualizeaza software-ul la cea mai recenta versiune. "
                "Software-ul EOL (End of Life) nu mai primeste patch-uri de securitate."
            ),
        })

    # ── REGULA 7: Sistem de operare EOL ──────────────────────────────────────
    OS_EOL: list[dict] = [
        {"system": "Windows", "release_contains": "XP",    "severity": "critical"},
        {"system": "Windows", "release_contains": "Vista", "severity": "critical"},
        {"system": "Windows", "release_contains": "7",     "severity": "high"},
        {"system": "Windows", "release_contains": "8.0",   "severity": "high"},
        {"system": "Linux",   "release_contains": "2.6",   "severity": "high"},
    ]
    os_system  = os_info.get("system", "")
    os_release = os_info.get("release", "")
    for rule in OS_EOL:
        if rule["system"] in os_system and rule["release_contains"] in os_release:
            findings.append({
                "rule_id": "OS-EOL-1",
                "title": f"Sistem de operare EOL: {os_system} {os_release}",
                "severity": rule["severity"],
                "evidence": {
                    "system": os_system,
                    "release": os_release,
                    "version": os_info.get("version", ""),
                },
                "recommendation": (
                    "Acest sistem de operare nu mai primeste actualizari de securitate. "
                    "Upgradeaza la o versiune suportata cat mai curand posibil."
                ),
            })
            break

    # ── Calcul scor ───────────────────────────────────────────────────────────
    # Scorul reprezinta nivelul de expunere: 0 = sigur, 100 = critic
    # Fiecare finding adauga puncte in functie de severitate,
    # dar cu diminishing returns (nu se cumuleaza liniar).
    raw_score = 0
    for f in findings:
        raw_score += SEVERITY_WEIGHT.get(f["severity"], 0)

    # Aplicam o functie de saturare: scorul creste rapid la inceput,
    # dar nu depaseste 100 chiar daca exista multe vulnerabilitati.
    # Formula: score = 100 * (1 - e^(-raw/60))  → aproape liniar sub 40, satureaza la 100
    import math
    exposure_score = min(100, round(100 * (1 - math.exp(-raw_score / 60))))

    return exposure_score, findings
