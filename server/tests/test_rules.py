"""Teste pentru motorul de reguli din server/app/rules.py.

Acoperim fiecare regula in parte si verificam ca:
- finding-urile corecte sunt produse
- severitatea e corecta
- exposure_score este in [0, 100] si non-zero cand exista findings
"""
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
    score, findings = evaluate(_empty_scan())
    assert findings == []
    assert score == 0


def test_risky_ports_detected():
    scan = _empty_scan()
    scan["network"]["open_ports"] = [22, 80, 445, 3389]  # 22/80 ok, 445/3389 risky
    score, findings = evaluate(scan)

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
    _, findings = evaluate(scan)
    assert any(f["rule_id"] == "NET-MANY-PORTS-2" for f in findings)


def test_admin_session_warning():
    scan = _empty_scan()
    scan["os"]["is_admin"] = True
    _, findings = evaluate(scan)
    assert any(f["rule_id"] == "OS-ADMIN-1" and f["severity"] == "medium" for f in findings)


def test_suspicious_processes_detected():
    scan = _empty_scan()
    scan["processes"] = [
        {"pid": 1, "name": "explorer.exe", "memory_mb": 100},
        {"pid": 2, "name": "mimikatz.exe", "memory_mb": 5},
    ]
    _, findings = evaluate(scan)
    sus = [f for f in findings if f["rule_id"] == "PROC-SUSPICIOUS-1"]
    assert len(sus) == 1
    assert sus[0]["severity"] == "high"


def test_powershell_informational():
    scan = _empty_scan()
    scan["processes"] = [{"pid": 10, "name": "powershell.exe", "memory_mb": 50}]
    _, findings = evaluate(scan)
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
    _, findings = evaluate(scan)
    vuln = [f for f in findings if f["rule_id"] == "SW-VULNERABLE-1"]
    titles = " | ".join(f["title"] for f in vuln)
    assert "Adobe Flash" in titles
    assert "WinRAR 5" in titles
    # Critical (Flash) trebuie sa apara
    assert any(f["severity"] == "critical" for f in vuln)


def test_eol_os_detected():
    scan = _empty_scan()
    scan["os"]["release"] = "XP"
    _, findings = evaluate(scan)
    eol = [f for f in findings if f["rule_id"] == "OS-EOL-1"]
    assert len(eol) == 1
    assert eol[0]["severity"] == "critical"


def test_score_saturates_below_100():
    """Chiar si cu multe findings critice, scorul nu trebuie sa depaseasca 100."""
    scan = _empty_scan()
    scan["os"]["release"] = "XP"  # critical
    scan["os"]["is_admin"] = True  # medium
    scan["network"]["open_ports"] = [21, 23, 25, 139, 445, 3389, 5900, 5985, 5986]  # high
    scan["software"] = [
        {"name": "Adobe Flash Player"},        # critical
        {"name": "Internet Explorer 11"},      # high
        {"name": "Java 6 Update 45"},          # high
        {"name": "OpenSSL 1.0.2"},             # high
    ]
    scan["processes"] = [
        {"pid": 1, "name": "mimikatz.exe", "memory_mb": 1},
        {"pid": 2, "name": "powershell.exe", "memory_mb": 1},
    ]
    score, findings = evaluate(scan)
    assert len(findings) >= 5
    assert 0 <= score <= 100
    # Cu atatea critice scorul ar trebui sa fie aproape de 100
    assert score >= 90
