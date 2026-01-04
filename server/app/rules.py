from typing import Dict, Any, List

def evaluate(scan: Dict[str, Any]) -> tuple[int, List[Dict[str, Any]]]:
    findings: List[Dict[str, Any]] = []
    score = 0

    # Regula 1: porturi expuse comune
    open_ports = scan.get("network", {}).get("open_ports", [])
    risky = {21, 23, 3389}
    hit = [p for p in open_ports if p in risky]
    if hit:
        findings.append({
            "rule_id": "NET-OPEN-PORTS-1",
            "title": "Porturi cu risc expuse",
            "severity": "high",
            "evidence": {"open_ports": hit},
            "recommendation": "Inchide porturile sau limiteaza accesul prin firewall."
        })
        score += 35

    # Regula 2: rulare ca admin/root (daca agentul furnizeaza)
    if scan.get("os", {}).get("is_admin") is True:
        findings.append({
            "rule_id": "OS-ADMIN-1",
            "title": "Colectare efectuata cu privilegii ridicate",
            "severity": "medium",
            "evidence": {"is_admin": True},
            "recommendation": "Foloseste cont standard pentru utilizare zilnica; admin doar la nevoie."
        })
        score += 10

    # Regula 3: procese suspecte by name (demo)
    proc_names = {p.get("name", "").lower() for p in scan.get("processes", [])}
    suspicious = {"nc.exe", "netcat", "powershell.exe"}
    if proc_names & suspicious:
        findings.append({
            "rule_id": "PROC-SUS-1",
            "title": "Procese care necesita verificare",
            "severity": "low",
            "evidence": {"names": sorted(list(proc_names & suspicious))},
            "recommendation": "Verifica daca procesele sunt legitime pentru acest sistem."
        })
        score += 5

    if score > 100:
        score = 100
    return score, findings
