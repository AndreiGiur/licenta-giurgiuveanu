"""Teste pentru fix-urile de false-pozitiv din scan #5 (real-world).

Acopera:
- REG-HIJACK-1: Winlogon.Userinit default Windows nu trigger.
- WMI-PERSIST-1: subscriptii built-in (command vid, nume cunoscute) nu trigger.
- CERT-UNTRUSTED-1: certificate Blizzard / Steam / etc. legit nu trigger.
- NET-ESTABLISHED-1: Chrome/Opera/AnyDesk + port 5228 (Google FCM) nu trigger.
- HOSTS-TAMPERED-1: kubernetes.docker.internal + linii cu BOM/comentariu nu trigger.
"""
from server.app.rules import evaluate


def _base_deep() -> dict:
    return {
        "scan_type": "deep",
        "device_uid": "x",
        "os": {"system": "Windows", "release": "11", "version": "10",
               "machine": "AMD64", "hostname": "h", "is_admin": False, "username": "u"},
        "network": {"open_ports": []},
        "processes": [],
        "software": [],
        "system_info": {},
        "persistence": {},
        "forensics": {},
    }


# ── REG-HIJACK-1 ────────────────────────────────────────────────────────────

def test_reg_hijack_skip_winlogon_default_userinit():
    """Valoarea default Windows (userinit.exe cu trailing comma) NU trigger."""
    scan = _base_deep()
    scan["persistence"]["reg_persistence"] = {
        "Winlogon": {"Userinit": "C:\\WINDOWS\\system32\\userinit.exe,"}
    }
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "REG-HIJACK-1" for f in findings)


def test_reg_hijack_skip_winlogon_default_shell():
    scan = _base_deep()
    scan["persistence"]["reg_persistence"] = {
        "Winlogon": {"Shell": "explorer.exe"}
    }
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "REG-HIJACK-1" for f in findings)


def test_reg_hijack_fires_on_non_default_userinit():
    """Userinit modificat = malware."""
    scan = _base_deep()
    scan["persistence"]["reg_persistence"] = {
        "Winlogon": {"Userinit": "C:\\evil\\malware.exe,"}
    }
    _, _, findings = evaluate(scan)
    assert any(f["rule_id"] == "REG-HIJACK-1" for f in findings)


def test_reg_hijack_fires_on_appinit_dlls():
    """AppInit_DLLs setat = totdeauna suspect."""
    scan = _base_deep()
    scan["persistence"]["reg_persistence"] = {
        "AppInit_DLLs": "C:\\evil.dll"
    }
    _, _, findings = evaluate(scan)
    assert any(f["rule_id"] == "REG-HIJACK-1" for f in findings)


# ── WMI-PERSIST-1 ───────────────────────────────────────────────────────────

def test_wmi_persist_skip_builtin_scm_event_log():
    """SCM Event Log Consumer cu command vid = built-in Windows."""
    scan = _base_deep()
    scan["persistence"]["wmi_subscriptions"] = [
        {"name": "SCM Event Log Consumer", "command": ""}
    ]
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "WMI-PERSIST-1" for f in findings)


def test_wmi_persist_skip_empty_command():
    """Orice subscriptie cu command vid e built-in."""
    scan = _base_deep()
    scan["persistence"]["wmi_subscriptions"] = [
        {"name": "RandomConsumer", "command": ""}
    ]
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "WMI-PERSIST-1" for f in findings)


def test_wmi_persist_fires_on_real_command():
    """Subscriptie WMI cu command real = persistenta malware."""
    scan = _base_deep()
    scan["persistence"]["wmi_subscriptions"] = [
        {"name": "EvilPersist", "command": "powershell.exe -enc AAAA"}
    ]
    _, _, findings = evaluate(scan)
    assert any(f["rule_id"] == "WMI-PERSIST-1" for f in findings)


# ── CERT-UNTRUSTED-1 ────────────────────────────────────────────────────────

def test_cert_untrusted_skip_blizzard():
    scan = _base_deep()
    scan["forensics"]["certificates"] = [{
        "subject": "CN=Blizzard Battle.net Local Cert",
        "issuer": "CN=Blizzard Battle.net Local Cert",
        "thumbprint": "AABBCC",
    }]
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "CERT-UNTRUSTED-1" for f in findings)


def test_cert_untrusted_skip_steam():
    scan = _base_deep()
    scan["forensics"]["certificates"] = [{
        "subject": "CN=Steam CA",
        "issuer": "CN=Valve Corp",
        "thumbprint": "X",
    }]
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "CERT-UNTRUSTED-1" for f in findings)


def test_cert_untrusted_fires_on_unknown_issuer():
    scan = _base_deep()
    scan["forensics"]["certificates"] = [{
        "subject": "CN=SuperShadyRootCA",
        "issuer": "CN=ShadyRoot Inc",
        "thumbprint": "X",
    }]
    _, _, findings = evaluate(scan)
    assert any(f["rule_id"] == "CERT-UNTRUSTED-1" for f in findings)


# ── NET-ESTABLISHED-1 ──────────────────────────────────────────────────────

def test_net_established_skip_chrome():
    scan = _base_deep()
    scan["scan_type"] = "advanced"
    scan["network"]["connections"] = [
        {"remote_ip": "142.250.184.196", "remote_port": 5228, "process": "chrome.exe"}
    ]
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "NET-ESTABLISHED-1" for f in findings)


def test_net_established_skip_anydesk():
    scan = _base_deep()
    scan["scan_type"] = "advanced"
    scan["network"]["connections"] = [
        {"remote_ip": "128.127.122.160", "remote_port": 2897, "process": "AnyDesk.exe"}
    ]
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "NET-ESTABLISHED-1" for f in findings)


def test_net_established_skip_google_fcm_port():
    """Port 5228 (Google FCM) e standard chiar fara process name cunoscut."""
    scan = _base_deep()
    scan["scan_type"] = "advanced"
    scan["network"]["connections"] = [
        {"remote_ip": "142.250.184.196", "remote_port": 5228, "process": "some_app.exe"}
    ]
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "NET-ESTABLISHED-1" for f in findings)


def test_net_established_fires_on_unknown_process_nonstd_port():
    scan = _base_deep()
    scan["scan_type"] = "advanced"
    scan["network"]["connections"] = [
        {"remote_ip": "203.0.113.42", "remote_port": 1337, "process": "unknown_malware.exe"}
    ]
    _, _, findings = evaluate(scan)
    assert any(f["rule_id"] == "NET-ESTABLISHED-1" for f in findings)


# ── HOSTS-TAMPERED-1 ───────────────────────────────────────────────────────

def test_hosts_tampered_skip_docker_kubernetes():
    scan = _base_deep()
    scan["forensics"]["hosts"] = [
        {"ip": "127.0.0.1", "hostname": "kubernetes.docker.internal"}
    ]
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "HOSTS-TAMPERED-1" for f in findings)


def test_hosts_tampered_skip_bom_comment():
    """Linii cu BOM la inceput sau # nu trebuie raportate ca tampered."""
    scan = _base_deep()
    scan["forensics"]["hosts"] = [
        {"ip": "﻿#", "hostname": "Copyright"},  # BOM line din parser bug vechi
        {"ip": "#", "hostname": "comment"},
        {"ip": "", "hostname": "empty"},
    ]
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "HOSTS-TAMPERED-1" for f in findings)


def test_hosts_tampered_fires_on_real_redirect():
    """Redirect IP necunoscut → malware-style entry."""
    scan = _base_deep()
    scan["forensics"]["hosts"] = [
        {"ip": "203.0.113.42", "hostname": "windowsupdate.microsoft.com"}
    ]
    _, _, findings = evaluate(scan)
    assert any(f["rule_id"] == "HOSTS-TAMPERED-1" for f in findings)


# ── AV-DISABLED-1 ──────────────────────────────────────────────────────────

def test_av_disabled_skip_when_third_party_av_active():
    """Daca utilizatorul are Bitdefender/Kaspersky/etc. activ, Defender disabled
    e comportamentul normal Windows — nu raportam ca probleme."""
    scan = _base_deep()
    scan["system_info"]["defender"] = {
        "enabled": False,
        "signature_age_days": 0,
        "mode": "Not running",
        "third_party_av": [{"name": "Bitdefender Antivirus", "product_state": 266240}],
    }
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "AV-DISABLED-1" for f in findings)


def test_av_disabled_fires_when_no_third_party_and_defender_off():
    """Defender off + nici un alt AV = expunere reala."""
    scan = _base_deep()
    scan["system_info"]["defender"] = {
        "enabled": False,
        "signature_age_days": 0,
        "mode": "Not running",
        "third_party_av": [],
    }
    _, _, findings = evaluate(scan)
    assert any(f["rule_id"] == "AV-DISABLED-1" for f in findings)


def test_av_disabled_skip_when_defender_on():
    scan = _base_deep()
    scan["system_info"]["defender"] = {
        "enabled": True,
        "signature_age_days": 2,
        "mode": "Normal",
        "third_party_av": [],
    }
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "AV-DISABLED-1" for f in findings)


# ── NET-OPEN-PORTS-1 (virtual adapter awareness) ───────────────────────────

def test_net_open_ports_high_when_on_wildcard_bind():
    """RDP bind pe 0.0.0.0 = expunere reala (severity high)."""
    scan = _base_deep()
    scan["network"]["open_ports"] = [3389]
    scan["network"]["port_bindings"] = [{"port": 3389, "ip": "0.0.0.0"}]
    _, _, findings = evaluate(scan)
    risky = [f for f in findings if f["rule_id"] == "NET-OPEN-PORTS-1"]
    assert len(risky) == 1
    assert risky[0]["severity"] == "high"


def test_net_open_ports_low_when_only_on_wsl_vswitch():
    """Port 139 expus DOAR pe 172.25.x.x (WSL vSwitch) = low/info, nu high."""
    scan = _base_deep()
    scan["network"]["open_ports"] = [139]
    scan["network"]["port_bindings"] = [{"port": 139, "ip": "172.25.48.1"}]
    _, _, findings = evaluate(scan)
    risky = [f for f in findings if f["rule_id"] == "NET-OPEN-PORTS-1"]
    assert len(risky) == 1
    assert risky[0]["severity"] == "low"
    assert "virtuale" in risky[0]["title"].lower()


def test_net_open_ports_high_when_mixed_real_and_virtual():
    """Daca portul are si bind pe 0.0.0.0 si pe virtual, prevaleaza high."""
    scan = _base_deep()
    scan["network"]["open_ports"] = [139]
    scan["network"]["port_bindings"] = [
        {"port": 139, "ip": "172.25.48.1"},
        {"port": 139, "ip": "0.0.0.0"},
    ]
    _, _, findings = evaluate(scan)
    risky = [f for f in findings if f["rule_id"] == "NET-OPEN-PORTS-1"]
    assert len(risky) == 1
    assert risky[0]["severity"] == "high"


def test_net_open_ports_fallback_high_when_no_bindings():
    """Backward compat: scan-uri vechi fara port_bindings → severity high (cum era inainte)."""
    scan = _base_deep()
    scan["network"]["open_ports"] = [3389, 445]
    # Nu includem port_bindings -> fallback
    _, _, findings = evaluate(scan)
    risky = [f for f in findings if f["rule_id"] == "NET-OPEN-PORTS-1"]
    assert len(risky) == 1
    assert risky[0]["severity"] == "high"
