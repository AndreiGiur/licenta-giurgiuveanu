"""Colectare network: porturi LISTEN + (opt) port→proces, conexiuni ESTABLISHED, share-uri, adaptoare."""
from __future__ import annotations

import platform
import subprocess

import psutil

from ..core import ScanProfile


def collect_network(cfg: ScanProfile) -> dict:
    out: dict = {"open_ports": _listen_ports()}

    if cfg.include_port_process:
        out["port_processes"] = _port_processes()
    if cfg.include_connections:
        out["connections"] = _established_connections()
    if cfg.include_shares and platform.system() == "Windows":
        out["shares"] = _network_shares()
    if cfg.include_net_adapters:
        out["adapters"] = _adapters()

    return out


def _listen_ports() -> list[int]:
    ports: list[int] = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                p = conn.laddr.port
                if p not in ports:
                    ports.append(p)
    except (psutil.AccessDenied, PermissionError, Exception):
        pass
    return sorted(ports)


def _port_processes() -> list[dict]:
    out: list[dict] = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != psutil.CONN_LISTEN or not conn.laddr or not conn.pid:
                continue
            try:
                p = psutil.Process(conn.pid)
                out.append({"port": conn.laddr.port, "pid": conn.pid, "process": p.name()})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                out.append({"port": conn.laddr.port, "pid": conn.pid, "process": ""})
    except Exception:
        pass
    return out


def _established_connections() -> list[dict]:
    out: list[dict] = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                continue
            proc_name = ""
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            out.append({
                "local_port": conn.laddr.port if conn.laddr else None,
                "remote_ip": conn.raddr.ip,
                "remote_port": conn.raddr.port,
                "pid": conn.pid,
                "process": proc_name,
            })
    except Exception:
        pass
    return out[:500]


def _network_shares() -> list[dict]:
    """Listare share-uri Windows. Foloseste WMI prin PowerShell pentru output
    structurat (JSON) — `net share` are output dependent de limba sistemului
    si parser-ul whitespace-split confunda textul de header/footer cu share-uri."""
    out: list[dict] = []
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-SmbShare -ErrorAction SilentlyContinue | "
             "Select-Object Name, Path | ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip():
            import json as _json
            data = _json.loads(r.stdout)
            if isinstance(data, dict):
                data = [data]  # un singur share -> dict, nu list
            for item in data:
                name = (item.get("Name") or "").strip()
                path = (item.get("Path") or "").strip()
                if name:
                    out.append({"name": name, "path": path})
            return out
    except (subprocess.SubprocessError, OSError, FileNotFoundError, ValueError):
        pass

    # Fallback: `net share` cu validare stricta — path-ul trebuie sa para o
    # locatie de filesystem (drive letter + ":", "\\", sau "(special)" pentru
    # share-uri admin/IPC$).
    def _looks_like_path(s: str) -> bool:
        if not s:
            return False
        s_low = s.lower()
        # Drive letter (C:\..., D:\...), UNC (\\server\share), sau pseudo (IPC$ are loc vid).
        if len(s) >= 2 and s[1] == ":":
            return True
        if s.startswith("\\\\") or s.startswith("\\"):
            return True
        return False

    try:
        r = subprocess.run(["net", "share"], capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("-"):
                continue
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            name, path = parts[0], parts[1]
            # Accept doar liniile unde "path" este o locatie filesystem valida.
            if not _looks_like_path(path):
                continue
            out.append({"name": name, "path": path})
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return out


def _adapters() -> list[dict]:
    out: list[dict] = []
    try:
        addrs = psutil.net_if_addrs()
        for name, infos in addrs.items():
            entry: dict = {"name": name, "ip": "", "mac": "", "gateway": ""}
            for info in infos:
                fam = getattr(info, "family", None)
                if fam == 2:  # AF_INET
                    entry["ip"] = info.address
                elif fam is not None and (fam == -1 or str(fam).endswith("AF_LINK") or str(fam).endswith("AF_PACKET")):
                    entry["mac"] = info.address
            out.append(entry)
    except Exception:
        pass
    return out
