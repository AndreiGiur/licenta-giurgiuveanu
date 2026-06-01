"""Reguli de detectie specifice Linux (os="linux").

Modul DEDICAT — separat de `rules.py` (care ramane pentru Windows + cross-platform)
ca sa nu se amestece codul celor doua platforme. Regulile se inregistreaza automat
in `rules._RULES` prin decoratorul `@rule` (importat din `rules`), la importul acestui
modul (vezi importul de la finalul `rules.py`).

Toate consuma `scan["linux"]` (produs de `agent/collectors/linux_audit.py`).
"""
from __future__ import annotations

import re
from typing import Any

from .rules import rule, VULNERABLE_SOFTWARE


def _lx(scan: dict[str, Any]) -> dict:
    return scan.get("linux") or {}


# ── critical_risk ────────────────────────────────────────────────────────────

@rule("LNX-SSH-ROOT-LOGIN-1", min_level="standard", category="critical_risk",
      weight=1.5, compliance=["CIS-5.2.8", "NIST-PR.AC-4"], os="linux")
def rule_lnx_ssh_root_login(scan):
    if (_lx(scan).get("ssh") or {}).get("permit_root_login") == "yes":
        return {"rule_id": "LNX-SSH-ROOT-LOGIN-1", "severity": "high",
                "title": "SSH permite login direct ca root (PermitRootLogin yes)",
                "evidence": {"PermitRootLogin": "yes"},
                "recommendation": "Seteaza PermitRootLogin no (sau prohibit-password) in /etc/ssh/sshd_config."}
    return None


@rule("LNX-SSH-EMPTY-PASSWORDS-1", min_level="standard", category="critical_risk",
      weight=2.0, compliance=["CIS-5.2.9", "NIST-PR.AC-1"], os="linux")
def rule_lnx_ssh_empty_passwords(scan):
    if (_lx(scan).get("ssh") or {}).get("permit_empty_passwords") == "yes":
        return {"rule_id": "LNX-SSH-EMPTY-PASSWORDS-1", "severity": "critical",
                "title": "SSH accepta parole goale (PermitEmptyPasswords yes)",
                "evidence": {"PermitEmptyPasswords": "yes"},
                "recommendation": "Seteaza PermitEmptyPasswords no in /etc/ssh/sshd_config."}
    return None


@rule("LNX-EMPTY-PASSWD-1", min_level="standard", category="critical_risk",
      weight=2.0, compliance=["CIS-5.4.2", "NIST-PR.AC-1"], os="linux")
def rule_lnx_empty_password(scan):
    accts = (_lx(scan).get("users") or {}).get("empty_password_accounts") or []
    if accts:
        return {"rule_id": "LNX-EMPTY-PASSWD-1", "severity": "critical",
                "title": f"Conturi cu parola goala: {', '.join(accts[:5])}",
                "evidence": {"accounts": accts[:20]},
                "recommendation": "Seteaza parole sau blocheaza conturile (passwd -l)."}
    return None


@rule("LNX-UIDZERO-1", min_level="standard", category="critical_risk",
      weight=2.0, compliance=["CIS-5.4.2", "NIST-PR.AC-4"], os="linux")
def rule_lnx_uid0(scan):
    extra = [a for a in ((_lx(scan).get("users") or {}).get("uid0_accounts") or [])
             if a != "root"]
    if extra:
        return {"rule_id": "LNX-UIDZERO-1", "severity": "critical",
                "title": f"Conturi non-root cu UID 0: {', '.join(extra[:5])}",
                "evidence": {"accounts": extra},
                "recommendation": "Doar root ar trebui sa aiba UID 0. Investigheaza/remediaza."}
    return None


@rule("LNX-PKG-VULNERABLE-1", min_level="standard", category="critical_risk",
      weight=1.5, compliance=["CIS-1.9", "NIST-ID.RA-1"], os="linux")
def rule_lnx_pkg_vulnerable(scan):
    pkgs = _lx(scan).get("packages") or []
    names = [f"{p.get('name', '')} {p.get('version', '')}" for p in pkgs]
    out = []
    for r in VULNERABLE_SOFTWARE:
        for n in names:
            if r["name_contains"].lower() in n.lower():
                out.append({"rule_id": "LNX-PKG-VULNERABLE-1", "severity": r["severity"],
                            "title": f"Pachet vulnerabil: {n[:60]}",
                            "evidence": {"package": n, "cve": r["cve"], "note": r["note"]},
                            "recommendation": "Actualizeaza pachetul (apt/dnf upgrade) sau elimina-l."})
    return out or None


@rule("LNX-SUID-UNCOMMON-1", min_level="deep", category="critical_risk",
      weight=1.2, confidence=0.7, compliance=["CIS-6.1", "NIST-PR.AC-6"], os="linux")
def rule_lnx_suid_uncommon(scan):
    suid = _lx(scan).get("suid") or []
    if suid:
        return {"rule_id": "LNX-SUID-UNCOMMON-1", "severity": "high",
                "title": f"Binare SUID neobisnuite: {len(suid)}",
                "evidence": {"binaries": suid[:30]},
                "recommendation": "Verifica binarele SUID neasteptate — pot fi vector de privilege escalation."}
    return None


@rule("LNX-SGID-UNCOMMON-1", min_level="deep", category="critical_risk",
      weight=1.0, confidence=0.7, compliance=["CIS-6.1", "NIST-PR.AC-6"], os="linux")
def rule_lnx_sgid_uncommon(scan):
    sgid = _lx(scan).get("sgid") or []
    if sgid:
        return {"rule_id": "LNX-SGID-UNCOMMON-1", "severity": "high",
                "title": f"Binare SGID neobisnuite: {len(sgid)}",
                "evidence": {"binaries": sgid[:30]},
                "recommendation": "Verifica binarele SGID neasteptate (potential privilege escalation)."}
    return None


# ── network_exposure ─────────────────────────────────────────────────────────

@rule("LNX-FW-DISABLED-1", min_level="standard", category="network_exposure",
      weight=1.2, compliance=["CIS-3.5", "NIST-PR.AC-5"], os="linux")
def rule_lnx_fw_disabled(scan):
    fw = _lx(scan).get("firewall") or {}
    if fw and fw.get("active") is False:
        return {"rule_id": "LNX-FW-DISABLED-1", "severity": "high",
                "title": f"Firewall inactiv ({fw.get('tool', 'necunoscut')})",
                "evidence": {"tool": fw.get("tool"), "active": False},
                "recommendation": "Activeaza firewall-ul (ex: ufw enable) si restrictioneaza inbound."}
    return None


@rule("LNX-SSH-PASSWORD-AUTH-1", min_level="standard", category="network_exposure",
      compliance=["CIS-5.2.10", "NIST-PR.AC-7"], os="linux")
def rule_lnx_ssh_password_auth(scan):
    if (_lx(scan).get("ssh") or {}).get("password_auth") == "yes":
        return {"rule_id": "LNX-SSH-PASSWORD-AUTH-1", "severity": "medium",
                "title": "SSH accepta autentificare cu parola (suprafata brute-force)",
                "evidence": {"PasswordAuthentication": "yes"},
                "recommendation": "Prefera chei SSH: PasswordAuthentication no."}
    return None


# ── hygiene ──────────────────────────────────────────────────────────────────

@rule("LNX-SUDO-NOPASSWD-1", min_level="standard", category="hygiene",
      compliance=["CIS-5.3.4", "NIST-PR.AC-4"], os="linux")
def rule_lnx_sudo_nopasswd(scan):
    entries = (_lx(scan).get("users") or {}).get("sudo_nopasswd") or []
    if entries:
        return {"rule_id": "LNX-SUDO-NOPASSWD-1", "severity": "medium",
                "title": "Reguli sudo NOPASSWD (escaladare fara parola)",
                "evidence": {"entries": entries[:10]},
                "recommendation": "Elimina NOPASSWD din sudoers acolo unde nu e strict necesar."}
    return None


@rule("LNX-WORLD-WRITABLE-1", min_level="deep", category="hygiene",
      confidence=0.8, compliance=["CIS-1.1", "NIST-PR.AC-4"], os="linux")
def rule_lnx_world_writable(scan):
    ww = _lx(scan).get("world_writable") or []
    if ww:
        return {"rule_id": "LNX-WORLD-WRITABLE-1", "severity": "medium",
                "title": f"Fisiere world-writable in zone sensibile: {len(ww)}",
                "evidence": {"files": ww[:30]},
                "recommendation": "Restrictioneaza permisiunile (chmod o-w)."}
    return None


@rule("LNX-SYSCTL-IPFWD-1", min_level="standard", category="hygiene",
      confidence=0.7, compliance=["CIS-3.1", "NIST-PR.PT-4"], os="linux")
def rule_lnx_sysctl_ipfwd(scan):
    if (_lx(scan).get("sysctl") or {}).get("ip_forward") == "1":
        return {"rule_id": "LNX-SYSCTL-IPFWD-1", "severity": "low",
                "title": "IP forwarding activ (net.ipv4.ip_forward=1)",
                "evidence": {"ip_forward": "1"},
                "recommendation": "Dezactiveaza daca masina nu e router: sysctl -w net.ipv4.ip_forward=0."}
    return None


@rule("LNX-ASLR-WEAK-1", min_level="standard", category="hygiene",
      compliance=["CIS-1.5.3", "NIST-PR.IP-1"], os="linux")
def rule_lnx_aslr_weak(scan):
    aslr = (_lx(scan).get("sysctl") or {}).get("aslr")
    if aslr is not None and aslr in ("0", "1"):
        return {"rule_id": "LNX-ASLR-WEAK-1", "severity": "medium",
                "title": f"ASLR slabit (kernel.randomize_va_space={aslr})",
                "evidence": {"randomize_va_space": aslr},
                "recommendation": "Seteaza kernel.randomize_va_space=2 pentru ASLR complet."}
    return None


@rule("LNX-COREDUMP-1", min_level="standard", category="hygiene",
      compliance=["CIS-1.5.1", "NIST-PR.IP-1"], os="linux")
def rule_lnx_coredump(scan):
    if (_lx(scan).get("sysctl") or {}).get("suid_dumpable") == "1":
        return {"rule_id": "LNX-COREDUMP-1", "severity": "medium",
                "title": "Core dumps pentru binare SUID activate (fs.suid_dumpable=1)",
                "evidence": {"suid_dumpable": "1"},
                "recommendation": "Seteaza fs.suid_dumpable=0 (core dumps pot scurge secrete)."}
    return None


@rule("LNX-AUTOUPDATE-OFF-1", min_level="standard", category="hygiene",
      compliance=["CIS-1.9", "NIST-PR.IP-12"], os="linux")
def rule_lnx_autoupdate_off(scan):
    if _lx(scan).get("auto_updates") is False:
        return {"rule_id": "LNX-AUTOUPDATE-OFF-1", "severity": "low",
                "title": "Actualizari automate dezactivate (unattended-upgrades)",
                "evidence": {"auto_updates": False},
                "recommendation": "Activeaza unattended-upgrades pentru patch-uri automate."}
    return None


@rule("LNX-KERNEL-EOL-1", min_level="standard", category="hygiene",
      weight=1.2, compliance=["CIS-1.9", "NIST-ID.RA-1"], os="linux")
def rule_lnx_kernel_eol(scan):
    kernel = str(_lx(scan).get("kernel") or "")
    m = re.match(r"(\d+)\.(\d+)", kernel)
    if m and int(m.group(1)) <= 3:
        return {"rule_id": "LNX-KERNEL-EOL-1", "severity": "high",
                "title": f"Kernel Linux EOL: {kernel}",
                "evidence": {"kernel": kernel},
                "recommendation": "Kernel-urile 2.x/3.x sunt EOL — actualizeaza distributia."}
    return None


@rule("LNX-PASS-AGING-1", min_level="standard", category="hygiene",
      compliance=["CIS-5.5.1.1", "NIST-PR.AC-1"], os="linux")
def rule_lnx_pass_aging(scan):
    if (_lx(scan).get("login_defs") or {}).get("pass_max_days") == "99999":
        return {"rule_id": "LNX-PASS-AGING-1", "severity": "low",
                "title": "Parolele nu expira (PASS_MAX_DAYS 99999)",
                "evidence": {"PASS_MAX_DAYS": "99999"},
                "recommendation": "Seteaza o expirare rezonabila (ex: PASS_MAX_DAYS 365) in /etc/login.defs."}
    return None


@rule("LNX-UMASK-WEAK-1", min_level="standard", category="hygiene",
      compliance=["CIS-5.4.5", "NIST-PR.AC-4"], os="linux")
def rule_lnx_umask_weak(scan):
    umask = (_lx(scan).get("login_defs") or {}).get("umask")
    if umask == "000":
        return {"rule_id": "LNX-UMASK-WEAK-1", "severity": "low",
                "title": f"Umask implicit permisiv (UMASK {umask})",
                "evidence": {"UMASK": umask},
                "recommendation": "Seteaza UMASK 027 in /etc/login.defs (fisiere noi nu mai sunt world-writable)."}
    return None


@rule("LNX-SSH-XFORWARD-1", min_level="standard", category="hygiene",
      compliance=["CIS-5.2.6", "NIST-PR.PT-4"], os="linux")
def rule_lnx_ssh_x11fwd(scan):
    if (_lx(scan).get("ssh") or {}).get("x11_forwarding") == "yes":
        return {"rule_id": "LNX-SSH-XFORWARD-1", "severity": "low",
                "title": "SSH X11Forwarding activat",
                "evidence": {"X11Forwarding": "yes"},
                "recommendation": "Dezactiveaza X11Forwarding daca nu e necesar (suprafata de atac)."}
    return None


@rule("LNX-TMP-NOEXEC-1", min_level="standard", category="hygiene",
      confidence=0.8, compliance=["CIS-1.1.2", "NIST-PR.IP-1"], os="linux")
def rule_lnx_tmp_noexec(scan):
    if _lx(scan).get("tmp_missing_noexec") is True:
        return {"rule_id": "LNX-TMP-NOEXEC-1", "severity": "low",
                "title": "/tmp montat fara optiunea noexec",
                "evidence": {"tmp_noexec": False},
                "recommendation": "Monteaza /tmp cu noexec,nosuid,nodev pentru a limita executia de cod."}
    return None


# ── activity ─────────────────────────────────────────────────────────────────

_LNX_CRON_BAD = ("curl", "wget", "|bash", "| bash", "/tmp/", "base64 -d", "/dev/shm")


@rule("LNX-CRON-SUSPICIOUS-1", min_level="advanced", category="activity",
      confidence=0.8, compliance=["CIS-5.1", "NIST-DE.CM-1"], os="linux")
def rule_lnx_cron_suspicious(scan):
    out = []
    for entry in _lx(scan).get("cron") or []:
        line = (entry.get("line") or "").lower()
        if any(p in line for p in _LNX_CRON_BAD):
            out.append({"rule_id": "LNX-CRON-SUSPICIOUS-1", "severity": "high",
                        "title": "Cron job suspect (download/exec)",
                        "evidence": {"source": entry.get("source"),
                                     "line": (entry.get("line") or "")[:200]},
                        "recommendation": "Verifica job-ul cron — pattern tipic de persistenta/malware."})
    return out or None


@rule("LNX-SVC-SUSPICIOUS-1", min_level="advanced", category="activity",
      weight=0.8, compliance=["CIS-2.1", "NIST-DE.CM-1"], os="linux")
def rule_lnx_svc_suspicious(scan):
    out = []
    for svc in _lx(scan).get("services") or []:
        exec_path = (svc.get("exec") or "").lower()
        if any(b in exec_path for b in ("/tmp/", "/home/", "/dev/shm/", "/var/tmp/")):
            out.append({"rule_id": "LNX-SVC-SUSPICIOUS-1", "severity": "high",
                        "title": f"Serviciu systemd din cale neobisnuita: {svc.get('name')}",
                        "evidence": {"name": svc.get("name"), "exec": svc.get("exec")},
                        "recommendation": "Serviciile legitime nu ruleaza din /tmp,/home,/dev/shm. Investigheaza."})
    return out or None
