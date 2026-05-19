"""Tests pentru NMAP-LUA-1 rule — pass-through finding-uri din vulnwatch-audit.nse."""
from app.rules import evaluate


def test_nmap_lua_findings_passthrough():
    scan = {
        "scan_type": "deep",
        "nmap": {
            "hosts": [
                {
                    "ip": "127.0.0.1",
                    "vulnwatch_findings": [
                        {"rule_id": "NMAP-CVE-2017-0144", "severity": "critical",
                         "title": "EternalBlue", "evidence": {"port": 445}}
                    ]
                }
            ]
        },
        "network": {"open_ports": []},
        "system": {},
        "processes": [],
        "software": [],
    }
    score, _, findings = evaluate(scan)
    nmap_findings = [f for f in findings if f.get("source") == "nmap-lua"]
    assert len(nmap_findings) == 1
    assert nmap_findings[0]["rule_id"] == "NMAP-CVE-2017-0144"
    assert nmap_findings[0]["evidence"]["host_ip"] == "127.0.0.1"
    assert score > 0


def test_nmap_lua_no_findings_when_no_nmap_data():
    scan = {
        "scan_type": "deep",
        "network": {"open_ports": []},
        "system": {},
        "processes": [],
        "software": [],
    }
    score, _, findings = evaluate(scan)
    nmap_findings = [f for f in findings if f.get("source") == "nmap-lua"]
    assert len(nmap_findings) == 0


def test_nmap_lua_skipped_for_standard_scan():
    scan = {
        "scan_type": "standard",
        "nmap": {
            "hosts": [{"ip": "127.0.0.1",
                      "vulnwatch_findings": [
                          {"rule_id": "X", "severity": "high", "title": "Y",
                           "evidence": {}}
                      ]}]
        },
        "network": {"open_ports": []},
        "system": {},
        "processes": [],
        "software": [],
    }
    score, _, findings = evaluate(scan)
    nmap_findings = [f for f in findings if f.get("source") == "nmap-lua"]
    assert len(nmap_findings) == 0
