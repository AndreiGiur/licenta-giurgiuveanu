"""Teste pozitiv/negativ pentru cele 15 reguli noi (rules_extended.py)."""
from server.app.rules import evaluate


def _scan(scan_type="standard", **sections):
    base = {"scan_type": scan_type, "os": {"system": "Windows", "release": "11"}}
    base.update(sections)
    return base


def _rule_ids(scan):
    _, _, findings = evaluate(scan)
    return {f["rule_id"] for f in findings}


# -- OS-UPTIME-1 --------------------------------------------------------------

def test_uptime_fires_over_30_days():
    scan = _scan(os={"system": "Windows", "release": "11", "uptime_seconds": 31 * 86400})
    assert "OS-UPTIME-1" in _rule_ids(scan)


def test_uptime_quiet_under_threshold():
    scan = _scan(os={"system": "Windows", "release": "11", "uptime_seconds": 5 * 86400})
    assert "OS-UPTIME-1" not in _rule_ids(scan)


def test_uptime_cross_platform_fires_on_linux():
    scan = _scan(os={"system": "Linux", "release": "6.8", "uptime_seconds": 90 * 86400})
    assert "OS-UPTIME-1" in _rule_ids(scan)


# -- UAC-DISABLED-1 -----------------------------------------------------------

def test_uac_fires_when_enable_lua_off():
    scan = _scan(system_info={"uac": {"enable_lua": False}})
    assert "UAC-DISABLED-1" in _rule_ids(scan)


def test_uac_fires_on_silent_elevation():
    scan = _scan(system_info={"uac": {"enable_lua": True, "consent_prompt_admin": 0}})
    assert "UAC-DISABLED-1" in _rule_ids(scan)


def test_uac_quiet_when_enabled():
    scan = _scan(system_info={"uac": {"enable_lua": True, "consent_prompt_admin": 5}})
    assert "UAC-DISABLED-1" not in _rule_ids(scan)


# -- AUTOLOGON-PASSWORD-1 -----------------------------------------------------

def test_autologon_fires_on_password_present():
    scan = _scan(system_info={"autologon": {
        "enabled": True, "default_username": "andrei", "password_present": True}})
    ids = _rule_ids(scan)
    assert "AUTOLOGON-PASSWORD-1" in ids


def test_autologon_quiet_without_password():
    scan = _scan(system_info={"autologon": {
        "enabled": False, "default_username": "", "password_present": False}})
    assert "AUTOLOGON-PASSWORD-1" not in _rule_ids(scan)


def test_autologon_finding_is_critical():
    scan = _scan(system_info={"autologon": {
        "enabled": True, "default_username": "andrei", "password_present": True}})
    _, _, findings = evaluate(scan)
    f = next(x for x in findings if x["rule_id"] == "AUTOLOGON-PASSWORD-1")
    assert f["severity"] == "critical"
    # privacy: parola nu apare nicaieri in finding
    assert "password_value" not in str(f.get("evidence", {}))


# -- SMB-LEGACY-1 -----------------------------------------------------------

def test_smb1_fires_only_on_explicit_true():
    assert "SMB-LEGACY-1" in _rule_ids(_scan(system_info={"smb1_enabled": True}))


def test_smb1_quiet_on_false_or_missing():
    assert "SMB-LEGACY-1" not in _rule_ids(_scan(system_info={"smb1_enabled": False}))
    assert "SMB-LEGACY-1" not in _rule_ids(_scan(system_info={}))


# -- USER-GUEST-ENABLED-1 -----------------------------------------------------

def test_guest_enabled_fires():
    scan = _scan(system_info={"local_users": [
        {"name": "Guest", "enabled": True, "password_required": True, "is_admin": False},
    ]})
    assert "USER-GUEST-ENABLED-1" in _rule_ids(scan)


def test_passwordless_account_fires():
    scan = _scan(system_info={"local_users": [
        {"name": "kiosk", "enabled": True, "password_required": False, "is_admin": False},
    ]})
    assert "USER-GUEST-ENABLED-1" in _rule_ids(scan)


def test_guest_disabled_quiet():
    scan = _scan(system_info={"local_users": [
        {"name": "Guest", "enabled": False, "password_required": False, "is_admin": False},
        {"name": "andrei", "enabled": True, "password_required": True, "is_admin": True},
    ]})
    assert "USER-GUEST-ENABLED-1" not in _rule_ids(scan)


# -- PROC-ENCODED-CMDLINE-1 (advanced) ----------------------------------------

def test_encoded_cmdline_fires():
    scan = _scan("advanced", processes=[
        {"pid": 1, "name": "powershell.exe",
         "cmdline": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA..."},
    ])
    assert "PROC-ENCODED-CMDLINE-1" in _rule_ids(scan)


def test_encoded_cmdline_quiet_on_normal_powershell():
    scan = _scan("advanced", processes=[
        {"pid": 1, "name": "powershell.exe", "cmdline": "powershell.exe -File deploy.ps1"},
    ])
    assert "PROC-ENCODED-CMDLINE-1" not in _rule_ids(scan)


def test_encoded_cmdline_ignores_non_powershell():
    scan = _scan("advanced", processes=[
        {"pid": 1, "name": "python.exe", "cmdline": "python -c \"print('iex(')\""},
    ])
    assert "PROC-ENCODED-CMDLINE-1" not in _rule_ids(scan)


def test_encoded_cmdline_not_at_standard_level():
    scan = _scan("standard", processes=[
        {"pid": 1, "name": "powershell.exe", "cmdline": "powershell -enc AAA"},
    ])
    assert "PROC-ENCODED-CMDLINE-1" not in _rule_ids(scan)


# -- WIFI-INSECURE-1 (advanced) -----------------------------------------------

def test_wifi_open_fires_high():
    scan = _scan("advanced", network={"wifi_profiles": [
        {"ssid": "CafeFree", "authentication": "open"},
        {"ssid": "Acasa", "authentication": "WPA2PSK"},
    ]})
    _, _, findings = evaluate(scan)
    f = next(x for x in findings if x["rule_id"] == "WIFI-INSECURE-1")
    assert f["severity"] == "high"
    ssids = [p["ssid"] for p in f["evidence"]["profiles"]]
    assert ssids == ["CafeFree"]


def test_wifi_wpa1_fires_medium():
    scan = _scan("advanced", network={"wifi_profiles": [
        {"ssid": "VechiRouter", "authentication": "WPAPSK"},
    ]})
    _, _, findings = evaluate(scan)
    f = next(x for x in findings if x["rule_id"] == "WIFI-INSECURE-1")
    assert f["severity"] == "medium"


def test_wifi_all_secure_quiet():
    scan = _scan("advanced", network={"wifi_profiles": [
        {"ssid": "Acasa", "authentication": "WPA2PSK"},
        {"ssid": "Birou", "authentication": "WPA3SAE"},
    ]})
    assert "WIFI-INSECURE-1" not in _rule_ids(scan)


# -- PASS-POLICY-WEAK-1 (advanced) --------------------------------------------

def test_password_policy_weak_fires():
    scan = _scan("advanced", system_info={"password_policy": {
        "min_password_length": 0, "max_password_age_days": 42, "lockout_threshold": 0,
    }})
    assert "PASS-POLICY-WEAK-1" in _rule_ids(scan)


def test_password_policy_never_expires_fires():
    scan = _scan("advanced", system_info={"password_policy": {
        "min_password_length": 12, "max_password_age_days": -1, "lockout_threshold": 5,
    }})
    assert "PASS-POLICY-WEAK-1" in _rule_ids(scan)


def test_password_policy_strong_quiet():
    scan = _scan("advanced", system_info={"password_policy": {
        "min_password_length": 12, "max_password_age_days": 90, "lockout_threshold": 5,
    }})
    assert "PASS-POLICY-WEAK-1" not in _rule_ids(scan)


def test_password_policy_absent_quiet():
    assert "PASS-POLICY-WEAK-1" not in _rule_ids(_scan("advanced", system_info={}))


# -- SVC-UNQUOTED-PATH-1 (advanced) ---------------------------------------------

def test_unquoted_service_path_fires():
    scan = _scan("advanced", persistence={"services": [
        {"name": "EvilSvc", "status": "running",
         "binary_path": r"C:\Program Files\My App\service.exe -k netsvcs"},
    ]})
    assert "SVC-UNQUOTED-PATH-1" in _rule_ids(scan)


def test_quoted_service_path_quiet():
    scan = _scan("advanced", persistence={"services": [
        {"name": "GoodSvc", "status": "running",
         "binary_path": r'"C:\Program Files\My App\service.exe" -k netsvcs'},
    ]})
    assert "SVC-UNQUOTED-PATH-1" not in _rule_ids(scan)


def test_unquoted_path_without_spaces_quiet():
    scan = _scan("advanced", persistence={"services": [
        {"name": "Svc", "status": "running", "binary_path": r"C:\Windows\system32\svchost.exe -k x y"},
    ]})
    assert "SVC-UNQUOTED-PATH-1" not in _rule_ids(scan)


def test_old_agent_munged_quoted_shape_quiet():
    # regresie scan 29 (2026-06-11): agentii vechi faceau strip('"') si lasau
    # ghilimeaua interioara -- serviciul era CORECT citat, nu trebuie flag-uit
    scan = _scan("advanced", persistence={"services": [
        {"name": "AnyDesk", "status": "running",
         "binary_path": 'C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe" --service'},
        {"name": "edgeupdate", "status": "running",
         "binary_path": 'C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe" /svc'},
    ]})
    assert "SVC-UNQUOTED-PATH-1" not in _rule_ids(scan)


# -- PORT-PROCESS-SUSPECT-1 (advanced) ------------------------------------------

def test_listener_from_temp_fires():
    scan = _scan("advanced", network={"port_processes": [
        {"port": 8888, "pid": 4242, "process": "evil.exe",
         "exe": r"C:\Users\x\AppData\Local\Temp\evil.exe"},
    ]})
    assert "PORT-PROCESS-SUSPECT-1" in _rule_ids(scan)


def test_listener_from_program_files_quiet():
    scan = _scan("advanced", network={"port_processes": [
        {"port": 5432, "pid": 100, "process": "postgres.exe",
         "exe": r"C:\Program Files\PostgreSQL\16\bin\postgres.exe"},
    ]})
    assert "PORT-PROCESS-SUSPECT-1" not in _rule_ids(scan)


def test_listener_without_exe_info_quiet():
    scan = _scan("advanced", network={"port_processes": [
        {"port": 8080, "pid": 1, "process": "x.exe", "exe": ""},
    ]})
    assert "PORT-PROCESS-SUSPECT-1" not in _rule_ids(scan)


# -- SVC-UNQUOTED-PATH-1: contract verbatim cu colectorul ----------------------

def test_quoted_with_args_collector_shape_quiet():
    # forma VERBATIM trimisa de colector pentru un serviciu corect citat cu argumente
    scan = _scan("advanced", persistence={"services": [
        {"name": "GoodSvc", "status": "running",
         "binary_path": '"C:\\Program Files\\My App\\service.exe" -k netsvcs'},
    ]})
    assert "SVC-UNQUOTED-PATH-1" not in _rule_ids(scan)


def test_extensionless_path_quiet():
    scan = _scan("advanced", persistence={"services": [
        {"name": "Drv", "status": "running", "binary_path": r"C:\Program Files\App\driver"},
    ]})
    assert "SVC-UNQUOTED-PATH-1" not in _rule_ids(scan)


def test_pwsh_encoded_cmdline_fires():
    scan = _scan("advanced", processes=[
        {"pid": 9, "name": "pwsh.exe", "cmdline": "pwsh.exe -EncodedCommand QQBC"},
    ])
    assert "PROC-ENCODED-CMDLINE-1" in _rule_ids(scan)


# -- DEFENDER-EXCLUSIONS-1 (deep) ----------------------------------------------

def test_defender_exclusion_root_fires():
    scan = _scan("deep", system_info={"defender": {"enabled": True, "exclusions": {
        "paths": ["C:\\", "C:\\dev\\proiect"], "processes": [], "extensions": [],
    }}})
    assert "DEFENDER-EXCLUSIONS-1" in _rule_ids(scan)


def test_defender_exclusion_powershell_process_fires():
    scan = _scan("deep", system_info={"defender": {"enabled": True, "exclusions": {
        "paths": [], "processes": ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"],
        "extensions": [],
    }}})
    assert "DEFENDER-EXCLUSIONS-1" in _rule_ids(scan)


def test_defender_narrow_exclusion_quiet():
    scan = _scan("deep", system_info={"defender": {"enabled": True, "exclusions": {
        "paths": ["C:\\dev\\proiect\\node_modules"], "processes": ["msbuild.exe"],
        "extensions": [],
    }}})
    assert "DEFENDER-EXCLUSIONS-1" not in _rule_ids(scan)


# -- ARP-SPOOF-1 (deep) ---------------------------------------------------------

def test_arp_duplicate_mac_fires():
    scan = _scan("deep", forensics={"arp_table": [
        {"ip": "192.168.1.1", "mac": "aa-bb-cc-dd-ee-ff"},
        {"ip": "192.168.1.50", "mac": "aa-bb-cc-dd-ee-ff"},
        {"ip": "192.168.1.7", "mac": "11-22-33-44-55-66"},
    ]})
    assert "ARP-SPOOF-1" in _rule_ids(scan)


def test_arp_broadcast_and_multicast_ignored():
    scan = _scan("deep", forensics={"arp_table": [
        {"ip": "192.168.1.255", "mac": "ff-ff-ff-ff-ff-ff"},
        {"ip": "224.0.0.22", "mac": "01-00-5e-00-00-16"},
        {"ip": "224.0.0.251", "mac": "01-00-5e-00-00-fb"},
        {"ip": "192.168.1.1", "mac": "aa-bb-cc-dd-ee-ff"},
    ]})
    assert "ARP-SPOOF-1" not in _rule_ids(scan)


# -- DNS-SUSPICIOUS-1 (deep) ------------------------------------------------------

def test_dns_punycode_fires():
    scan = _scan("deep", forensics={"dns_cache": [
        {"name": "xn--pple-43d.com", "ip": "1.2.3.4"},
    ]})
    assert "DNS-SUSPICIOUS-1" in _rule_ids(scan)


def test_dns_abused_tld_fires():
    scan = _scan("deep", forensics={"dns_cache": [
        {"name": "login-update.tk", "ip": "5.6.7.8"},
    ]})
    assert "DNS-SUSPICIOUS-1" in _rule_ids(scan)


def test_dns_dga_label_fires():
    scan = _scan("deep", forensics={"dns_cache": [
        {"name": "xkcdqwrtzpsdfghjklbnmvcxzqwrt.com", "ip": "9.9.9.9"},
    ]})
    assert "DNS-SUSPICIOUS-1" in _rule_ids(scan)


def test_dns_normal_domains_quiet():
    scan = _scan("deep", forensics={"dns_cache": [
        {"name": "www.google.com", "ip": "142.250.1.1"},
        {"name": "github.com", "ip": "140.82.1.1"},
        {"name": "fastapi.tiangolo.com", "ip": "1.1.1.1"},
    ]})
    assert "DNS-SUSPICIOUS-1" not in _rule_ids(scan)


# -- RECENT-SYSTEM-FILES-1 (deep) --------------------------------------------------

def test_recent_executable_in_system32_fires():
    scan = _scan("deep", forensics={"recent_files": [
        {"path": "C:\\Windows\\System32\\evil.dll", "modified": "2026-06-10T12:00:00"},
    ]})
    assert "RECENT-SYSTEM-FILES-1" in _rule_ids(scan)


def test_recent_non_executable_quiet():
    scan = _scan("deep", forensics={"recent_files": [
        {"path": "C:\\Windows\\System32\\config.log", "modified": "2026-06-10T12:00:00"},
    ]})
    assert "RECENT-SYSTEM-FILES-1" not in _rule_ids(scan)


# -- AUDIT-POLICY-OFF-1 (deep) -----------------------------------------------------

def test_audit_logon_off_fires():
    scan = _scan("deep", system_info={"audit_policy": {
        "audit_logon": 0, "audit_account_manage": 3,
    }})
    assert "AUDIT-POLICY-OFF-1" in _rule_ids(scan)


def test_audit_all_on_quiet():
    scan = _scan("deep", system_info={"audit_policy": {
        "audit_logon": 3, "audit_account_manage": 3,
    }})
    assert "AUDIT-POLICY-OFF-1" not in _rule_ids(scan)


def test_audit_absent_quiet():
    assert "AUDIT-POLICY-OFF-1" not in _rule_ids(_scan("deep", system_info={}))


# -- nivel: regulile deep nu ruleaza la advanced ------------------------------------

def test_deep_rules_skipped_at_advanced():
    scan = _scan("advanced",
                 system_info={"audit_policy": {"audit_logon": 0}},
                 forensics={"dns_cache": [{"name": "a.tk", "ip": "1.1.1.1"}]})
    ids = _rule_ids(scan)
    assert "AUDIT-POLICY-OFF-1" not in ids
    assert "DNS-SUSPICIOUS-1" not in ids
