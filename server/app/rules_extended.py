"""Reguli extinse (2026-06-11): 15 reguli noi, 5 per nivel, Windows + cross.

Modul separat (pattern identic cu rules_linux.py) ca rules.py sa ramana
focusat pe engine + setul initial. Importat la FINALUL rules.py, dupa
definirea decoratorului @rule.
"""
from __future__ import annotations

from .config import MIN_PASSWORD_LENGTH_THRESHOLD, UPTIME_DAYS_THRESHOLD
from .rules import SUSPICIOUS_STARTUP_PATHS, rule

# -- Constante ----------------------------------------------------------------

# Pattern-uri ofensive in cmdline PowerShell (procese RULANTE -- completeaza
# TASK-SUSPICIOUS-1 care se uita doar la task-uri planificate).
PS_OFFENSIVE_CMDLINE_PATTERNS: tuple[str, ...] = (
    "-enc ", "-encodedcommand", "downloadstring", "frombase64string",
    "invoke-expression", "iex(",
)

# Autentificari WiFi nesigure -> severitate. Valorile vin din XML-ul netsh
# (element <authentication>): open/shared = fara protectie / WEP; WPA/WPAPSK = WPA1.
WIFI_INSECURE_AUTH: dict[str, str] = {
    "open": "high", "shared": "high", "wep": "high",
    "wpa": "medium", "wpapsk": "medium",
}

# Radacini de exclusions Defender care anuleaza practic protectia.
SUSPICIOUS_EXCLUSION_ROOTS: frozenset[str] = frozenset({
    "c:", "c:\\users", "c:\\windows", "c:\\programdata", "c:\\temp",
})

# Procese a caror excludere din Defender e tactica clasica de malware.
SUSPICIOUS_EXCLUSION_PROCESSES: frozenset[str] = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
})

# MAC-uri broadcast/multicast -- excluse din analiza ARP (nu sunt spoofing).
BROADCAST_MAC_PREFIXES: tuple[str, ...] = (
    "ff-ff-ff", "ff:ff:ff", "01-00-5e", "01:00:5e", "33-33", "33:33",
)

# TLD-uri cu abuz ridicat (frecvent folosite de phishing/malware C2).
ABUSED_TLDS: tuple[str, ...] = (".tk", ".ml", ".ga", ".cf", ".gq", ".top")

# Extensii de fisiere executabile pentru RECENT-SYSTEM-FILES-1.
SYSTEM_EXECUTABLE_EXTENSIONS: tuple[str, ...] = (".exe", ".dll", ".sys")


# -----------------------------------------------------------------------------
# STANDARD (5)
# -----------------------------------------------------------------------------


@rule("OS-UPTIME-1", min_level="standard", category="hygiene", weight=0.5,
      compliance=["CIS-7.3", "NIST-PR.PS-02"])
def check_uptime(scan: dict) -> dict | None:
    uptime = (scan.get("os", {}) or {}).get("uptime_seconds")
    if not isinstance(uptime, (int, float)):
        return None
    days = int(uptime // 86400)
    if days <= UPTIME_DAYS_THRESHOLD:
        return None
    return {
        "rule_id": "OS-UPTIME-1",
        "title": f"Sistem nerepornit de {days} zile",
        "severity": "low",
        "evidence": {"uptime_days": days, "threshold_days": UPTIME_DAYS_THRESHOLD},
        "recommendation": (
            "Repornirile aplica patch-urile de kernel/OS in asteptare. "
            "Reporneste sistemul si verifica Windows Update / managerul de pachete."
        ),
    }


@rule("UAC-DISABLED-1", min_level="standard", category="hygiene", weight=1.2,
      compliance=["CIS-4.1", "CIS-5.4", "NIST-PR.AA-05"], os="windows")
def check_uac_disabled(scan: dict) -> dict | None:
    uac = (scan.get("system_info", {}) or {}).get("uac", {}) or {}
    issues = []
    if uac.get("enable_lua") is False:
        issues.append("EnableLUA=0 (UAC complet dezactivat)")
    if uac.get("consent_prompt_admin") == 0:
        issues.append("ConsentPromptBehaviorAdmin=0 (elevare fara prompt)")
    if not issues:
        return None
    return {
        "rule_id": "UAC-DISABLED-1",
        "title": "User Account Control dezactivat sau configurat nesigur",
        "severity": "high",
        "evidence": {"issues": issues, "uac": uac},
        "recommendation": (
            "Reactiveaza UAC: seteaza EnableLUA=1 in "
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System "
            "si reporneste. Fara UAC orice proces ruleaza cu drepturi depline."
        ),
    }


@rule("AUTOLOGON-PASSWORD-1", min_level="standard", category="critical_risk", weight=1.5,
      compliance=["CIS-5.2", "CIS-4.1", "NIST-PR.AA-01"], os="windows")
def check_autologon_password(scan: dict) -> dict | None:
    auto = (scan.get("system_info", {}) or {}).get("autologon", {}) or {}
    if not auto.get("password_present"):
        return None
    return {
        "rule_id": "AUTOLOGON-PASSWORD-1",
        "title": "Parola stocata in clar in registry (AutoLogon)",
        "severity": "critical",
        "evidence": {
            "autologon_enabled": bool(auto.get("enabled")),
            "default_username": auto.get("default_username", ""),
        },
        "recommendation": (
            "Sterge valoarea DefaultPassword din "
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon. "
            "Pentru autologon sigur foloseste Sysinternals Autologon (stocheaza ca LSA secret)."
        ),
    }


@rule("SMB-LEGACY-1", min_level="standard", category="network_exposure", weight=1.5,
      compliance=["CIS-4.2", "CIS-4.8", "NIST-PR.PS-01", "NIST-ID.RA-01"], os="windows")
def check_smb1_enabled(scan: dict) -> dict | None:
    if (scan.get("system_info", {}) or {}).get("smb1_enabled") is not True:
        return None
    return {
        "rule_id": "SMB-LEGACY-1",
        "title": "Protocolul SMBv1 este activat",
        "severity": "high",
        "evidence": {"smb1_enabled": True},
        "recommendation": (
            "SMBv1 este vulnerabil la EternalBlue (WannaCry/NotPetya). Dezactiveaza: "
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false"
        ),
    }


@rule("USER-GUEST-ENABLED-1", min_level="standard", category="hygiene", weight=1.0,
      compliance=["CIS-5.2", "CIS-5.3", "NIST-PR.AA-01"], os="windows")
def check_guest_or_passwordless(scan: dict) -> dict | None:
    users = (scan.get("system_info", {}) or {}).get("local_users", []) or []
    flagged = []
    for u in users:
        if u.get("enabled") is not True:
            continue
        name = (u.get("name") or "").strip()
        # limitare cunoscuta: pe Windows localizat contul built-in poate avea alt
        # nume (ex. "Invitat" pe RO); ramura password_required compenseaza partial
        if name.lower() in ("guest", "invitat"):
            flagged.append({"name": name, "reason": "cont Guest activ"})
        elif u.get("password_required") is False:
            flagged.append({"name": name, "reason": "parola neobligatorie"})
    if not flagged:
        return None
    return {
        "rule_id": "USER-GUEST-ENABLED-1",
        "title": "Conturi locale fara protectie adecvata",
        "severity": "medium",
        "evidence": {"accounts": flagged},
        "recommendation": (
            "Dezactiveaza contul Guest (net user Guest /active:no) si seteaza "
            "parole obligatorii pentru toate conturile active."
        ),
    }


# -----------------------------------------------------------------------------
# ADVANCED (5)
# -----------------------------------------------------------------------------


@rule("PROC-ENCODED-CMDLINE-1", min_level="advanced", category="activity",
      weight=1.2, confidence=0.8,
      compliance=["CIS-8.5", "CIS-10.7", "NIST-DE.AE-02"], os="windows")
def check_encoded_cmdline(scan: dict) -> dict | None:
    procs = scan.get("processes", []) or []
    suspicious = []
    for p in procs:
        name = (p.get("name") or "").lower()
        if "powershell" not in name and "pwsh" not in name:
            continue
        cmdline = (p.get("cmdline") or "").lower()
        if any(pat in cmdline for pat in PS_OFFENSIVE_CMDLINE_PATTERNS):
            suspicious.append({
                "pid": p.get("pid"), "name": p.get("name"),
                "cmdline": (p.get("cmdline") or "")[:200],
            })
    if not suspicious:
        return None
    return {
        "rule_id": "PROC-ENCODED-CMDLINE-1",
        "title": "Proces PowerShell rulant cu comanda encodata/ofensiva",
        "severity": "high",
        "evidence": {"processes": suspicious[:10]},
        "recommendation": (
            "Comenzile -EncodedCommand/IEX/DownloadString sunt tipice payload-urilor "
            "ofensive. Investigheaza procesul parinte si opreste procesul daca nu e legitim."
        ),
    }


@rule("WIFI-INSECURE-1", min_level="advanced", category="network_exposure", weight=1.0,
      compliance=["CIS-12.6", "NIST-PR.IR-01"], os="windows")
def check_wifi_insecure(scan: dict) -> dict | None:
    profiles = (scan.get("network", {}) or {}).get("wifi_profiles", []) or []
    flagged = []
    worst = "medium"
    for p in profiles:
        auth = (p.get("authentication") or "").lower()
        sev = WIFI_INSECURE_AUTH.get(auth)
        if sev is None:
            continue
        flagged.append({"ssid": p.get("ssid"), "authentication": p.get("authentication")})
        if sev == "high":
            worst = "high"
    if not flagged:
        return None
    return {
        "rule_id": "WIFI-INSECURE-1",
        "title": "Profile WiFi salvate cu autentificare nesigura",
        "severity": worst,
        "evidence": {"profiles": flagged},
        "recommendation": (
            "Sterge profilele nesigure (netsh wlan delete profile name=\"<SSID>\") "
            "sau reconfigureaza retelele pe WPA2/WPA3. Retelele Open/WEP permit "
            "interceptarea traficului."
        ),
    }


@rule("PASS-POLICY-WEAK-1", min_level="advanced", category="hygiene", weight=1.0,
      compliance=["CIS-5.2", "NIST-PR.AA-01"], os="windows")
def check_password_policy(scan: dict) -> dict | None:
    pol = (scan.get("system_info", {}) or {}).get("password_policy", {}) or {}
    if not pol:
        return None
    issues = []
    mpl = pol.get("min_password_length")
    if isinstance(mpl, int) and mpl < MIN_PASSWORD_LENGTH_THRESHOLD:
        issues.append(
            f"Lungime minima parola: {mpl} (recomandat >= {MIN_PASSWORD_LENGTH_THRESHOLD})")
    lockout = pol.get("lockout_threshold")
    if isinstance(lockout, int) and lockout == 0:
        issues.append("Account lockout dezactivat (LockoutBadCount=0)")
    max_age = pol.get("max_password_age_days")
    if isinstance(max_age, int) and max_age <= 0:
        issues.append("Parolele nu expira niciodata (MaximumPasswordAge <= 0)")
    if not issues:
        return None
    return {
        "rule_id": "PASS-POLICY-WEAK-1",
        "title": "Politica locala de parole este slaba",
        "severity": "medium",
        "evidence": {"issues": issues, "policy": pol},
        "recommendation": (
            "Configureaza in secpol.msc: lungime minima >= 8, "
            "account lockout threshold 5-10 incercari, expirare parola <= 365 zile."
        ),
    }


def _is_unquoted_path_with_spaces(path: str) -> bool:
    """True pentru path de serviciu necitat cu spatii inainte de .exe --
    vectorul clasic 'unquoted service path' de escaladare de privilegii."""
    p = (path or "").strip()
    if not p or p.startswith('"'):
        return False
    low = p.lower()
    idx = low.find(".exe")
    exe_part = p[: idx + 4] if idx != -1 else p
    return " " in exe_part


@rule("SVC-UNQUOTED-PATH-1", min_level="advanced", category="hygiene",
      weight=0.8, confidence=0.9,
      compliance=["CIS-4.1", "NIST-PR.PS-01"], os="windows")
def check_unquoted_service_paths(scan: dict) -> dict | None:
    services = (scan.get("persistence", {}) or {}).get("services", []) or []
    flagged = [
        {"name": s.get("name"), "path": s.get("binary_path")}
        for s in services
        if _is_unquoted_path_with_spaces(s.get("binary_path", ""))
    ]
    if not flagged:
        return None
    return {
        "rule_id": "SVC-UNQUOTED-PATH-1",
        "title": "Servicii cu path necitat continand spatii (unquoted service path)",
        "severity": "medium",
        "evidence": {"services": flagged[:20]},
        "recommendation": (
            "Adauga ghilimele in jurul path-ului executabilului: "
            "sc config <name> binPath= '\"C:\\Program Files\\App\\svc.exe\"'. "
            "Un atacator poate planta C:\\Program.exe pentru escaladare."
        ),
    }


@rule("PORT-PROCESS-SUSPECT-1", min_level="advanced", category="network_exposure", weight=1.2,
      compliance=["CIS-4.5", "CIS-13.5", "NIST-DE.CM-01"], os="windows")
def check_listener_user_writable(scan: dict) -> dict | None:
    listeners = (scan.get("network", {}) or {}).get("port_processes", []) or []
    flagged = [
        {"port": li.get("port"), "process": li.get("process"), "exe": li.get("exe")}
        for li in listeners
        if any(pat in (li.get("exe") or "").lower() for pat in SUSPICIOUS_STARTUP_PATHS)
    ]
    if not flagged:
        return None
    return {
        "rule_id": "PORT-PROCESS-SUSPECT-1",
        "title": "Proces din director user-writable asculta pe retea",
        "severity": "high",
        "evidence": {"listeners": flagged[:20]},
        "recommendation": (
            "Un executabil din Temp/AppData care asculta pe un port este tipic "
            "pentru backdoor-uri. Verifica semnatura si provenienta; opreste "
            "procesul si scaneaza sistemul daca nu il recunosti."
        ),
    }
