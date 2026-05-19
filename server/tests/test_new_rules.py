"""Cele 16 reguli noi: 2 standard + 6 advanced + 8 deep."""
from server.app.rules import evaluate


def _base(scan_type: str) -> dict:
    return {
        "scan_type": scan_type,
        "device_uid": "x",
        "os": {
            "system": "Windows", "release": "11", "version": "10.0.22000",
            "is_admin": False, "username": "alice",
        },
        "system_info": {},
        "network": {"open_ports": []},
        "processes": [],
        "software": [],
        "persistence": None,
        "forensics": None,
    }


def _ids(findings: list[dict]) -> set[str]:
    return {f["rule_id"] for f in findings}


# ── Standard ─────────────────────────────────────────────────────────────────


def test_fw_disabled_fires_on_public_off():
    scan = _base("standard")
    scan["system_info"] = {"firewall": {"profiles": {"domain": True, "private": True, "public": False}}}
    _, _, findings = evaluate(scan)
    assert "FW-DISABLED-1" in _ids(findings)


def test_fw_disabled_does_not_fire_when_all_on():
    scan = _base("standard")
    scan["system_info"] = {"firewall": {"profiles": {"domain": True, "private": True, "public": True}}}
    _, _, findings = evaluate(scan)
    assert "FW-DISABLED-1" not in _ids(findings)


def test_user_admin_fires_on_extra_admin():
    scan = _base("standard")
    scan["system_info"] = {"local_users": [
        {"name": "Administrator", "is_admin": True},
        {"name": "alice", "is_admin": True},
        {"name": "hacker", "is_admin": True},
    ]}
    _, _, findings = evaluate(scan)
    f = next(f for f in findings if f["rule_id"] == "USER-ADMIN-1")
    assert "hacker" in f["evidence"]["extra_admin_accounts"]
    assert "Administrator" not in f["evidence"]["extra_admin_accounts"]
    assert "alice" not in f["evidence"]["extra_admin_accounts"]


# ── Advanced ─────────────────────────────────────────────────────────────────


def test_startup_suspicious_fires_on_temp_path():
    scan = _base("advanced")
    scan["persistence"] = {"startup": [
        {"key": "Updater", "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe"},
    ]}
    _, _, findings = evaluate(scan)
    assert "STARTUP-SUSPICIOUS-1" in _ids(findings)


def test_task_suspicious_fires_on_encoded_command():
    scan = _base("advanced")
    scan["persistence"] = {"tasks": [
        {"name": "UpdateCheck", "action": "powershell.exe -EncodedCommand SGVsbG8="},
    ]}
    _, _, findings = evaluate(scan)
    assert "TASK-SUSPICIOUS-1" in _ids(findings)


def test_svc_suspicious_fires_on_nonstandard_path():
    scan = _base("advanced")
    scan["persistence"] = {"services": [
        {"name": "EvilSvc", "status": "running", "binary_path": "C:\\Users\\Public\\evil.exe"},
    ]}
    _, _, findings = evaluate(scan)
    assert "SVC-SUSPICIOUS-1" in _ids(findings)


def test_net_share_excludes_admin_default():
    scan = _base("advanced")
    scan["network"] = {"open_ports": [], "shares": [
        {"name": "ADMIN$", "path": "C:\\Windows"},
        {"name": "MyShare", "path": "C:\\Public"},
    ]}
    _, _, findings = evaluate(scan)
    f = next(f for f in findings if f["rule_id"] == "NET-SHARE-1")
    names = [s["name"] for s in f["evidence"]["shares"]]
    assert "MyShare" in names
    assert "ADMIN$" not in names


def test_ps_policy_fires_on_bypass():
    scan = _base("advanced")
    scan["persistence"] = {"ps_policy": "Bypass"}
    _, _, findings = evaluate(scan)
    assert "PS-POLICY-1" in _ids(findings)


def test_ps_policy_does_not_fire_on_remote_signed():
    scan = _base("advanced")
    scan["persistence"] = {"ps_policy": "RemoteSigned"}
    _, _, findings = evaluate(scan)
    assert "PS-POLICY-1" not in _ids(findings)


def test_net_established_fires_on_external_nonstd_port():
    scan = _base("advanced")
    scan["network"] = {"open_ports": [], "connections": [
        {"remote_ip": "203.0.113.5", "remote_port": 4444, "local_port": 50000, "process": "x.exe"},
    ]}
    _, _, findings = evaluate(scan)
    assert "NET-ESTABLISHED-1" in _ids(findings)


def test_net_established_ignores_private_ips():
    scan = _base("advanced")
    scan["network"] = {"open_ports": [], "connections": [
        {"remote_ip": "192.168.1.1", "remote_port": 4444, "local_port": 50000, "process": "x.exe"},
    ]}
    _, _, findings = evaluate(scan)
    assert "NET-ESTABLISHED-1" not in _ids(findings)


# ── Deep ─────────────────────────────────────────────────────────────────────


def test_reg_hijack_fires_on_appinit_dlls():
    scan = _base("deep")
    scan["persistence"] = {"reg_persistence": {"AppInit_DLLs": "C:\\evil.dll"}}
    _, _, findings = evaluate(scan)
    assert "REG-HIJACK-1" in _ids(findings)


def test_wmi_persist_fires_on_any_subscription():
    scan = _base("deep")
    scan["persistence"] = {"wmi_subscriptions": [{"name": "Evil", "command": "cmd.exe"}]}
    _, _, findings = evaluate(scan)
    assert "WMI-PERSIST-1" in _ids(findings)


def test_cert_untrusted_fires_on_unknown_issuer():
    scan = _base("deep")
    scan["forensics"] = {"certificates": [
        {"subject": "Evil Root CA", "issuer": "Evil Root CA", "thumbprint": "abc"},
    ]}
    _, _, findings = evaluate(scan)
    assert "CERT-UNTRUSTED-1" in _ids(findings)


def test_cert_untrusted_skips_microsoft():
    scan = _base("deep")
    scan["forensics"] = {"certificates": [
        {"subject": "Microsoft Root", "issuer": "Microsoft Corp", "thumbprint": "abc"},
    ]}
    _, _, findings = evaluate(scan)
    assert "CERT-UNTRUSTED-1" not in _ids(findings)


def test_av_disabled_fires_when_off():
    scan = _base("deep")
    scan["system_info"] = {"defender": {"enabled": False, "signature_age_days": 1}}
    _, _, findings = evaluate(scan)
    assert "AV-DISABLED-1" in _ids(findings)


def test_av_disabled_fires_on_old_signatures():
    scan = _base("deep")
    scan["system_info"] = {"defender": {"enabled": True, "signature_age_days": 15}}
    _, _, findings = evaluate(scan)
    assert "AV-DISABLED-1" in _ids(findings)


def test_eventlog_bruteforce_fires_on_10_failures():
    scan = _base("deep")
    scan["forensics"] = {"event_log": [{"event_id": 4625, "account": "alice"} for _ in range(12)]}
    _, _, findings = evaluate(scan)
    assert "EVENTLOG-BRUTEFORCE-1" in _ids(findings)


def test_eventlog_bruteforce_does_not_fire_on_few():
    scan = _base("deep")
    scan["forensics"] = {"event_log": [{"event_id": 4625, "account": "alice"} for _ in range(3)]}
    _, _, findings = evaluate(scan)
    assert "EVENTLOG-BRUTEFORCE-1" not in _ids(findings)


def test_eventlog_privesc_fires_on_non_system_account():
    scan = _base("deep")
    scan["forensics"] = {"event_log": [{"event_id": 4672, "account": "alice"}]}
    _, _, findings = evaluate(scan)
    assert "EVENTLOG-PRIVESC-1" in _ids(findings)


def test_eventlog_privesc_ignores_system():
    scan = _base("deep")
    scan["forensics"] = {"event_log": [{"event_id": 4672, "account": "SYSTEM"}]}
    _, _, findings = evaluate(scan)
    assert "EVENTLOG-PRIVESC-1" not in _ids(findings)


def test_hosts_tampered_fires_on_non_default():
    scan = _base("deep")
    scan["forensics"] = {"hosts": [{"ip": "1.2.3.4", "hostname": "microsoft.com"}]}
    _, _, findings = evaluate(scan)
    assert "HOSTS-TAMPERED-1" in _ids(findings)


def test_hosts_tampered_ignores_localhost():
    scan = _base("deep")
    scan["forensics"] = {"hosts": [{"ip": "127.0.0.1", "hostname": "localhost"}]}
    _, _, findings = evaluate(scan)
    assert "HOSTS-TAMPERED-1" not in _ids(findings)


def test_bitlocker_off_fires_on_c_drive_unprotected():
    scan = _base("deep")
    scan["system_info"] = {"bitlocker": [{"volume": "C:", "protection_status": "off"}]}
    _, _, findings = evaluate(scan)
    assert "BITLOCKER-OFF-1" in _ids(findings)


def test_bitlocker_off_does_not_fire_when_on():
    scan = _base("deep")
    scan["system_info"] = {"bitlocker": [{"volume": "C:", "protection_status": "on"}]}
    _, _, findings = evaluate(scan)
    assert "BITLOCKER-OFF-1" not in _ids(findings)
