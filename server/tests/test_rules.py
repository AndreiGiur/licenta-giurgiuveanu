"""Teste pentru motorul de reguli din server/app/rules.py.

Acoperim fiecare regula in parte si verificam ca:
- finding-urile corecte sunt produse
- severitatea e corecta
- exposure_score este in [0, 100] si non-zero cand exista findings
"""
from server.app import rules
from server.app.rules import evaluate


def _empty_scan() -> dict:
    return {
        "device_uid": "test",
        "os": {"system": "Windows", "release": "11", "version": "10.0", "machine": "AMD64",
               "hostname": "host", "is_admin": False},
        "network": {"open_ports": []},
        "processes": [],
        "software": [],
    }


def test_clean_system_has_no_findings():
    score, _, findings = evaluate(_empty_scan())
    assert findings == []
    assert score == 0


def test_risky_ports_detected():
    scan = _empty_scan()
    scan["network"]["open_ports"] = [22, 80, 445, 3389]  # 22/80 ok, 445/3389 risky
    score, _, findings = evaluate(scan)

    risky = [f for f in findings if f["rule_id"] == "NET-OPEN-PORTS-1"]
    assert len(risky) == 1
    assert risky[0]["severity"] == "high"
    ports_listed = [p["port"] for p in risky[0]["evidence"]["ports"]]
    assert 445 in ports_listed and 3389 in ports_listed
    assert 22 not in ports_listed and 80 not in ports_listed
    assert 0 < score <= 100


def test_many_open_ports_warning():
    scan = _empty_scan()
    scan["network"]["open_ports"] = list(range(1000, 1025))  # 25 porturi
    _, _, findings = evaluate(scan)
    assert any(f["rule_id"] == "NET-MANY-PORTS-2" for f in findings)


def test_admin_session_warning():
    scan = _empty_scan()
    scan["os"]["is_admin"] = True
    _, _, findings = evaluate(scan)
    assert any(f["rule_id"] == "OS-ADMIN-1" and f["severity"] == "medium" for f in findings)


def test_suspicious_processes_detected():
    scan = _empty_scan()
    scan["processes"] = [
        {"pid": 1, "name": "explorer.exe", "memory_mb": 100},
        {"pid": 2, "name": "mimikatz.exe", "memory_mb": 5},
    ]
    _, _, findings = evaluate(scan)
    sus = [f for f in findings if f["rule_id"] == "PROC-SUSPICIOUS-1"]
    assert len(sus) == 1
    assert sus[0]["severity"] == "high"


def test_powershell_informational():
    scan = _empty_scan()
    scan["processes"] = [{"pid": 10, "name": "powershell.exe", "memory_mb": 50}]
    _, _, findings = evaluate(scan)
    ps = [f for f in findings if f["rule_id"] == "PROC-POWERSHELL-2"]
    assert len(ps) == 1
    assert ps[0]["severity"] == "low"


def test_vulnerable_software_detected():
    scan = _empty_scan()
    scan["software"] = [
        {"name": "Mozilla Firefox 120", "version": "120.0"},
        {"name": "Adobe Flash Player", "version": "32.0.0.371"},
        {"name": "WinRAR 5.91", "version": "5.91"},
    ]
    _, _, findings = evaluate(scan)
    vuln = [f for f in findings if f["rule_id"] == "SW-VULNERABLE-1"]
    titles = " | ".join(f["title"] for f in vuln)
    assert "Adobe Flash" in titles
    assert "WinRAR 5" in titles
    # Critical (Flash) trebuie sa apara
    assert any(f["severity"] == "critical" for f in vuln)


def test_eol_os_detected():
    scan = _empty_scan()
    scan["os"]["release"] = "XP"
    _, _, findings = evaluate(scan)
    eol = [f for f in findings if f["rule_id"] == "OS-EOL-1"]
    assert len(eol) == 1
    assert eol[0]["severity"] == "critical"


def test_score_saturates_below_100():
    """Findings in toate cele 4 categorii → scorul ar trebui sa fie ridicat
    (dar nu poate depasi 100). In noul sistem, scorul agregat e ponderat:
    0.4 critical + 0.3 network + 0.2 hygiene + 0.1 activity. Findings critice
    intr-o singura categorie satureaza acea categorie la 100, dar agregatul
    necesita acoperire pe toate dimensiunile pentru a se apropia de 100."""
    scan = _empty_scan()
    scan["scan_type"] = "advanced"
    scan["os"]["release"] = "XP"      # critical_risk
    scan["os"]["is_admin"] = True     # hygiene
    # Network: porturi riscante + multe porturi (suprafata mare)
    scan["network"]["open_ports"] = [21, 23, 25, 139, 445, 3389, 5900, 5985, 5986] + list(range(8000, 8025))
    scan["network"]["shares"] = [{"name": "Public", "path": "C:\\Pub"}]  # network_exposure
    scan["software"] = [
        {"name": "Adobe Flash Player"},        # critical_risk
        {"name": "Internet Explorer 11"},      # critical_risk
        {"name": "Java 6 Update 45"},          # critical_risk
        {"name": "OpenSSL 1.0.2"},             # critical_risk
    ]
    scan["processes"] = [
        {"pid": 1, "name": "mimikatz.exe", "memory_mb": 1},   # critical_risk
        {"pid": 2, "name": "powershell.exe", "memory_mb": 1}, # activity
    ]
    scan["system_info"] = {
        "firewall": {"profiles": {"domain": False, "public": False}}  # hygiene
    }
    scan["persistence"] = {
        "tasks": [{"name": "Updater", "action": "powershell.exe -enc AAAA"}],  # activity
        "ps_policy": "Bypass",  # activity
    }
    score, breakdown, findings = evaluate(scan)
    assert len(findings) >= 7
    assert 0 <= score <= 100
    # Findings pe toate cele 4 dimensiuni → scorul agregat trebuie sa fie ridicat.
    assert all(breakdown[c] > 0 for c in breakdown), f"all cats > 0; got {breakdown}"
    assert score >= 60, f"expected >=60 with broad coverage; got {score} from {breakdown}"


# ─────────────────────────────────────────────────────────────────────────────
# Semnaturi externalizate (data file JSON) — incarcare + extindere + hot-reload
# ─────────────────────────────────────────────────────────────────────────────

def test_vuln_signatures_loaded_from_data_file():
    """Datele vin din JSON, nu din fallback: setul extins include intrari noi
    (log4j, Office) absente din fallback-ul minimal embedded."""
    names = {s["name_contains"] for s in rules.VULNERABLE_SOFTWARE}
    assert "log4j" in names
    assert "Microsoft Office 2010" in names
    # Fallback-ul embedded e mai mic decat setul din data file
    assert len(rules.VULNERABLE_SOFTWARE) > len(rules._FALLBACK_VULNERABLE_SOFTWARE)


def test_new_signature_log4j_detected_as_critical():
    """Log4Shell: un software care contine 'log4j' → finding critical."""
    scan = _empty_scan()
    scan["software"] = [{"name": "apache-log4j-core 2.14.1", "version": "2.14.1"}]
    _, _, findings = evaluate(scan)
    vuln = [f for f in findings if f["rule_id"] == "SW-VULNERABLE-1"]
    assert any(f["severity"] == "critical" for f in vuln)
    assert any("log4j" in f["evidence"]["software"].lower() for f in vuln)


def test_windows_81_detected_as_eol():
    """Windows 8.1 (EOL ianuarie 2023) → finding OS-EOL high."""
    scan = _empty_scan()
    scan["os"]["release"] = "8.1"
    _, _, findings = evaluate(scan)
    eol = [f for f in findings if f["rule_id"] == "OS-EOL-1"]
    assert len(eol) == 1
    assert eol[0]["severity"] == "high"


def test_fallback_signatures_used_when_data_file_missing(monkeypatch):
    """Daca data file-ul lipseste, _load_vuln_signatures cade pe fallback embedded."""
    from pathlib import Path
    monkeypatch.setattr(rules, "_VULN_SIGNATURES_FILE", Path("nonexistent-xyz.json"))
    sw, eol = rules._load_vuln_signatures()
    assert sw == rules._FALLBACK_VULNERABLE_SOFTWARE
    assert eol == rules._FALLBACK_EOL_OS


def test_refresh_from_feed_hot_reloads_signatures():
    """Hook-ul _refresh_from_feed inlocuieste semnaturile in memorie (hot-reload)."""
    original_sw = rules.VULNERABLE_SOFTWARE
    original_eol = rules.EOL_OPERATING_SYSTEMS
    try:
        rules._refresh_from_feed({
            "vulnerable_software": [
                {"name_contains": "FooBarVuln", "severity": "high", "cve": "CVE-9999-0001", "note": "test"}
            ],
            "eol_operating_systems": [
                {"system": "Windows", "rel": "95", "severity": "critical"}
            ],
        })
        scan = _empty_scan()
        scan["software"] = [{"name": "FooBarVuln 1.0"}]
        _, _, findings = evaluate(scan)
        assert any(f["rule_id"] == "SW-VULNERABLE-1" for f in findings)
    finally:
        # Restore globals ca sa nu contaminam alte teste
        rules.VULNERABLE_SOFTWARE = original_sw
        rules.EOL_OPERATING_SYSTEMS = original_eol
