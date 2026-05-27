"""Teste parametrizate pentru toate cele 24 de reguli — varianta condensata.

Acest fisier complementeaza (NU inlocuieste) `test_rules.py`, `test_new_rules.py`
si `test_rule_fp_fixes.py`. Acolo se valideaza scenarii specifice cu evidence
detaliata. Aici verificam, in mod uniform si compact, ca fiecare regula:
  1. trigger pe input pozitiv (must-fire)
  2. NU trigger pe sistem curat (must-not-fire on empty)
  3. severity este in setul {critical, high, medium, low, info}

Pattern-ul cu @pytest.mark.parametrize face adaugarea unei reguli noi
mult mai usoara (1 entry in tabel vs 2-3 functii noi de test).
"""
import pytest

from server.app.rules import evaluate


# Pentru fiecare regula: (rule_id, scan_type necesar, mutator pe scan dict)
# Mutator-ul primeste un scan curat (din fixture-ul make_scan) si returneaza
# scan-ul modificat astfel incat regula respectiva SA TRIGGER.
RULE_TRIGGERS = [
    (
        "NET-OPEN-PORTS-1", "standard",
        lambda s: s | {"network": {**s["network"], "open_ports": [3389]}},
    ),
    (
        "NET-MANY-PORTS-2", "standard",
        lambda s: s | {"network": {**s["network"], "open_ports": list(range(1000, 1030))}},
    ),
    (
        "OS-ADMIN-1", "standard",
        lambda s: s | {"os": {**s["os"], "is_admin": True}},
    ),
    (
        "PROC-SUSPICIOUS-1", "standard",
        lambda s: s | {"processes": [{"pid": 1, "name": "mimikatz.exe"}]},
    ),
    (
        "PROC-POWERSHELL-2", "standard",
        lambda s: s | {"processes": [{"pid": 1, "name": "powershell.exe"}]},
    ),
    (
        "SW-VULNERABLE-1", "standard",
        lambda s: s | {"software": [{"name": "Adobe Flash Player"}]},
    ),
    (
        "OS-EOL-1", "standard",
        lambda s: s | {"os": {**s["os"], "release": "XP"}},
    ),
    (
        "FW-DISABLED-1", "standard",
        lambda s: s | {"system_info": {"firewall": {"profiles": {"domain": False, "public": False}}}},
    ),
    (
        "USER-ADMIN-1", "standard",
        lambda s: s | {"system_info": {"local_users": [{"name": "evil", "is_admin": True}]}},
    ),
    (
        "STARTUP-SUSPICIOUS-1", "advanced",
        lambda s: s | {"persistence": {"startup": [{"key": "X", "path": "C:\\Users\\u\\AppData\\Local\\Temp\\evil.exe"}]}},
    ),
    (
        "TASK-SUSPICIOUS-1", "advanced",
        lambda s: s | {"persistence": {"tasks": [{"name": "T", "action": "powershell.exe -enc AAA"}]}},
    ),
    (
        "SVC-SUSPICIOUS-1", "advanced",
        lambda s: s | {"persistence": {"services": [{"name": "S", "status": "running", "binary_path": "D:\\evil\\svc.exe"}]}},
    ),
    (
        "NET-SHARE-1", "advanced",
        lambda s: s | {"network": {**s["network"], "shares": [{"name": "Public", "path": "C:\\Pub"}]}},
    ),
    (
        "PS-POLICY-1", "advanced",
        lambda s: s | {"persistence": {"ps_policy": "Bypass"}},
    ),
    (
        "NET-ESTABLISHED-1", "advanced",
        lambda s: s | {"network": {**s["network"], "connections": [
            {"remote_ip": "203.0.113.42", "remote_port": 1337, "process": "unknown.exe"}
        ]}},
    ),
    (
        "REG-HIJACK-1", "deep",
        lambda s: s | {"persistence": {"reg_persistence": {"AppInit_DLLs": "C:\\evil.dll"}}},
    ),
    (
        "WMI-PERSIST-1", "deep",
        lambda s: s | {"persistence": {"wmi_subscriptions": [{"name": "EvilPersist", "command": "powershell.exe -enc XXXX"}]}},
    ),
    (
        "CERT-UNTRUSTED-1", "deep",
        lambda s: s | {"forensics": {"certificates": [{"subject": "CN=Shady", "issuer": "CN=Shady", "thumbprint": "X"}]}},
    ),
    (
        "AV-DISABLED-1", "deep",
        lambda s: s | {"system_info": {"defender": {"enabled": False, "third_party_av": []}}},
    ),
    (
        "EVENTLOG-BRUTEFORCE-1", "deep",
        lambda s: s | {"forensics": {"event_log": [{"event_id": 4625, "account": f"u{i}"} for i in range(15)]}},
    ),
    (
        "EVENTLOG-PRIVESC-1", "deep",
        lambda s: s | {"forensics": {"event_log": [{"event_id": 4672, "account": "rogue_user"}]}},
    ),
    (
        "HOSTS-TAMPERED-1", "deep",
        lambda s: s | {"forensics": {"hosts": [{"ip": "203.0.113.42", "hostname": "windowsupdate.microsoft.com"}]}},
    ),
    (
        "BITLOCKER-OFF-1", "deep",
        lambda s: s | {"system_info": {"bitlocker": [{"volume": "C:", "protection_status": "Off"}]}},
    ),
]


@pytest.mark.parametrize("rule_id,scan_type,mutator", RULE_TRIGGERS, ids=lambda v: v if isinstance(v, str) else "")
def test_rule_fires_on_positive_input(make_scan, rule_id, scan_type, mutator):
    """Fiecare regula trebuie sa produca cel putin un finding pentru input-ul
    construit specific sa o declanseze."""
    scan = mutator(make_scan(scan_type))
    scan["scan_type"] = scan_type
    _, _, findings = evaluate(scan)
    matching = [f for f in findings if f["rule_id"] == rule_id]
    assert matching, (
        f"Regula {rule_id} nu a declanșat pe input pozitiv. "
        f"Findings primite: {[f['rule_id'] for f in findings]}"
    )


@pytest.mark.parametrize("rule_id,scan_type,_mutator", RULE_TRIGGERS, ids=lambda v: v if isinstance(v, str) else "")
def test_rule_does_not_fire_on_clean_system(make_scan, rule_id, scan_type, _mutator):
    """Fiecare regula NU trebuie sa trigger pe un scan complet curat la nivelul ei."""
    scan = make_scan(scan_type)
    _, _, findings = evaluate(scan)
    matching = [f for f in findings if f["rule_id"] == rule_id]
    assert not matching, (
        f"Regula {rule_id} a trigger fals pe sistem curat. Finding gresit: {matching}"
    )


@pytest.mark.parametrize("rule_id,scan_type,mutator", RULE_TRIGGERS, ids=lambda v: v if isinstance(v, str) else "")
def test_rule_finding_has_valid_severity(make_scan, rule_id, scan_type, mutator):
    """Severity-ul fiecarui finding trebuie sa fie unul din valorile cunoscute."""
    VALID_SEV = {"critical", "high", "medium", "low", "info"}
    scan = mutator(make_scan(scan_type))
    scan["scan_type"] = scan_type
    _, _, findings = evaluate(scan)
    for f in findings:
        if f["rule_id"] == rule_id:
            assert f["severity"] in VALID_SEV, (
                f"Rule {rule_id} returned invalid severity: {f['severity']!r}"
            )
