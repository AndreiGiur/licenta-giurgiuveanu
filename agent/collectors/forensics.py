"""Colectare forensics: event log, hosts, DNS/ARP, certificate, fisiere recent modificate."""
from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from pathlib import Path

from ..core import ScanProfile


def collect_forensics(cfg: ScanProfile) -> dict:
    if platform.system() != "Windows":
        return {}

    out: dict = {}
    if cfg.include_eventlog:
        out["event_log"] = _event_log()
    if cfg.include_hosts:
        out["hosts"] = _hosts_file()
    if cfg.include_arp_dns:
        out["dns_cache"] = _dns_cache()
        out["arp_table"] = _arp_table()
    if cfg.include_certs:
        out["certificates"] = _root_certs()
    if cfg.include_recent_files:
        out["recent_files"] = _recent_files()
    return out


def _ps(script: str, timeout: int = 60) -> str | None:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return None


def _event_log() -> list[dict]:
    """Last 500 eventuri Security: 4625 (logon failure), 4672 (special priv), 4720 (user created)."""
    out = _ps(
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4672,4720} "
        "-MaxEvents 500 -ErrorAction SilentlyContinue | "
        "ForEach-Object { "
        "  [PSCustomObject]@{ "
        "    Id = $_.Id; "
        "    Account = (($_.Properties | Select-Object -Skip 1 -First 1).Value); "
        "    Time = $_.TimeCreated.ToString('o') "
        "  } "
        "} | ConvertTo-Json -Compress",
        timeout=120,
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [
            {
                "event_id": e.get("Id", 0),
                "account": str(e.get("Account") or ""),
                "timestamp": e.get("Time", ""),
            }
            for e in data
        ]
    except json.JSONDecodeError:
        return []


def _hosts_file() -> list[dict]:
    path = Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    entries: list[dict] = []
    try:
        # utf-8-sig: gestioneaza UTF-8 cu BOM (﻿) la inceput de fisier.
        with path.open(encoding="utf-8-sig", errors="ignore") as f:
            for line in f:
                line = line.strip().lstrip("﻿")  # defensiv: strip BOM si pe linie
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    entries.append({"ip": parts[0], "hostname": parts[1].split()[0]})
    except OSError:
        pass
    return entries


def _dns_cache() -> list[dict]:
    out = _ps(
        "Get-DnsClientCache -ErrorAction SilentlyContinue | "
        "Select-Object Entry, Data | ConvertTo-Json -Compress"
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [{"name": e.get("Entry", ""), "ip": e.get("Data", "")} for e in data[:200]]
    except json.JSONDecodeError:
        return []


def _arp_table() -> list[dict]:
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        entries: list[dict] = []
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] and parts[0][0].isdigit():
                entries.append({"ip": parts[0], "mac": parts[1]})
        return entries[:200]
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        return []


def _root_certs() -> list[dict]:
    out = _ps(
        "Get-ChildItem Cert:\\LocalMachine\\Root -ErrorAction SilentlyContinue | "
        "Select-Object Subject, Issuer, Thumbprint | ConvertTo-Json -Compress",
        timeout=60,
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [
            {
                "subject": c.get("Subject", ""),
                "issuer": c.get("Issuer", ""),
                "thumbprint": c.get("Thumbprint", ""),
            }
            for c in data
        ]
    except json.JSONDecodeError:
        return []


def _recent_files() -> list[dict]:
    cutoff = time.time() - 7 * 86400
    roots = [
        Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32",
        Path("C:\\Program Files"),
    ]
    out: list[dict] = []
    for root in roots:
        if not root.exists():
            continue
        try:
            for entry in root.iterdir():
                try:
                    if entry.is_file():
                        mtime = entry.stat().st_mtime
                        if mtime > cutoff:
                            out.append({
                                "path": str(entry),
                                "modified": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(mtime)),
                            })
                except OSError:
                    continue
        except OSError:
            continue
        if len(out) > 100:
            break
    return out[:100]
