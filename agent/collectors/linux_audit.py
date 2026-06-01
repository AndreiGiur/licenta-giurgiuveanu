"""Colector specific Linux (gated). Degradeaza gratios fara root: ce nu e citibil
→ camp gol/None. Surse: fisiere /etc + comenzi (ufw/iptables/sysctl/dpkg/systemctl).

Functiile de parsare (`_parse_*`, `_filter_suid`, etc.) sunt PURE → testabile
fara subprocess. `collect_linux_audit` orchestreaza, gated pe `platform.system()`.
"""
from __future__ import annotations

import platform
import re
import shutil
import subprocess
from pathlib import Path

from agent.core import ScanProfile

# Binare SUID/SGID standard (known-good) — orice in afara listei e flagat.
KNOWN_SUID = {
    "sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "mount",
    "umount", "ping", "ping6", "fusermount", "fusermount3", "pkexec",
    "ssh-keysign", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
    "chrome-sandbox", "snap-confine", "unix_chkpwd", "expiry", "chage",
    "crontab", "wall", "write", "bsd-write", "at", "sg",
}
SENSITIVE_DIRS = ("/etc", "/usr/local/bin", "/usr/local/sbin")
SUID_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
CRON_PATHS = ("/etc/crontab",)
CRON_DIRS = ("/etc/cron.d",)
SVC_BAD_PATHS = ("/tmp/", "/home/", "/dev/shm/", "/var/tmp/")


# ── Helpere I/O ───────────────────────────────────────────────────────────────

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


# ── Parsere PURE (testabile) ──────────────────────────────────────────────────

def _parse_sshd_config(text: str) -> dict:
    out = {"permit_root_login": None, "password_auth": None, "port": None,
           "permit_empty_passwords": None, "x11_forwarding": None}
    keymap = {
        "permitrootlogin": "permit_root_login",
        "passwordauthentication": "password_auth",
        "permitemptypasswords": "permit_empty_passwords",
        "x11forwarding": "x11_forwarding",
    }
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        if len(parts) != 2:
            continue
        key, val = parts[0].lower(), parts[1].strip()
        if key in keymap:
            out[keymap[key]] = val.lower()
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
        "suid_dumpable": vals.get("fs.suid_dumpable"),
    }


def _parse_login_defs(text: str) -> dict:
    out = {"pass_max_days": None, "umask": None}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) >= 2:
            if parts[0] == "PASS_MAX_DAYS":
                out["pass_max_days"] = parts[1]
            elif parts[0] == "UMASK":
                out["umask"] = parts[1]
    return out


def _tmp_missing_noexec(mounts_text: str) -> bool:
    """True daca /tmp e montat fara noexec (sau nu e montat separat)."""
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] == "/tmp":
            opts = parts[3].split(",")
            return "noexec" not in opts
    return False  # /tmp nu e mount separat → nu raportam (ar fi fals-pozitiv)


def _filter_suid(find_output: str) -> list[str]:
    out = []
    for path in find_output.splitlines():
        path = path.strip()
        if not path:
            continue
        name = path.rsplit("/", 1)[-1]
        if name and name not in KNOWN_SUID:
            out.append(path)
    return out[:200]


def _sudo_nopasswd(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "NOPASSWD" in s:
            out.append(s)
    return out


# ── Colectori (impur, subprocess/fs) ──────────────────────────────────────────

def _firewall() -> dict:
    if shutil.which("ufw"):
        out = _run(["ufw", "status"])
        return {"tool": "ufw", "active": "status: active" in out.lower()}
    if shutil.which("iptables"):
        out = _run(["iptables", "-S"])
        active = any(l.startswith("-A") for l in out.splitlines())
        return {"tool": "iptables", "active": active}
    if shutil.which("nft"):
        out = _run(["nft", "list", "ruleset"])
        return {"tool": "nftables", "active": bool(out.strip())}
    return {"tool": "none", "active": False}


def _suid() -> list[str]:
    acc = []
    for d in SUID_DIRS:
        acc.append(_run(["find", d, "-maxdepth", "1", "-perm", "-4000", "-type", "f"], 20))
    return _filter_suid("\n".join(acc))


def _sgid() -> list[str]:
    acc = []
    for d in SUID_DIRS:
        acc.append(_run(["find", d, "-maxdepth", "1", "-perm", "-2000", "-type", "f"], 20))
    return _filter_suid("\n".join(acc))


def _world_writable() -> list[str]:
    out = []
    for d in SENSITIVE_DIRS:
        res = _run(["find", d, "-maxdepth", "2", "-perm", "-0002", "-type", "f"], 20)
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
    res = _run(["systemctl", "list-units", "--type=service", "--all",
                "--no-legend", "--plain"])
    names = [l.split()[0] for l in res.splitlines()
             if l.strip() and l.split()[0].endswith(".service")]
    for name in names[:300]:
        show = _run(["systemctl", "show", "-p", "ExecStart", name])
        m = re.search(r"path=([^\s;]+)", show)
        if m:
            out.append({"name": name, "exec": m.group(1)})
    return out


def _packages() -> list[dict]:
    out = []
    if shutil.which("dpkg-query"):
        res = _run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"], 30)
    elif shutil.which("rpm"):
        res = _run(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"], 30)
    else:
        return out
    for line in res.splitlines():
        p = line.split(None, 1)
        if len(p) == 2:
            out.append({"name": p[0], "version": p[1]})
    return out[:3000]


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
            "sudo_nopasswd": _sudo_nopasswd(
                _read("/etc/sudoers") + "\n" + _read_sudoers_d()),
        }
        data["kernel"] = platform.release()
        data["sysctl"] = _parse_sysctl(_run(
            ["sysctl", "net.ipv4.ip_forward", "kernel.randomize_va_space",
             "fs.suid_dumpable"]))
        data["login_defs"] = _parse_login_defs(_read("/etc/login.defs"))
        data["tmp_missing_noexec"] = _tmp_missing_noexec(_read("/proc/mounts"))
        data["packages"] = _packages()
        au = _run(["systemctl", "is-enabled", "unattended-upgrades"]).strip()
        data["auto_updates"] = (au == "enabled") if au else None
    if cfg.include_linux_jobs:
        data["cron"] = _cron()
        data["services"] = _services()
    if cfg.include_linux_files:
        data["suid"] = _suid()
        data["sgid"] = _sgid()
        data["world_writable"] = _world_writable()
    return data


def _read_sudoers_d() -> str:
    text = ""
    try:
        for f in Path("/etc/sudoers.d").iterdir():
            text += "\n" + _read(str(f))
    except OSError:
        pass
    return text
