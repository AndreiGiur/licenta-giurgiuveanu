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
    shares: list[dict] = []
    try:
        r = subprocess.run(["net", "share"], capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("-") or line.lower().startswith("share name") or line.lower().startswith("the command"):
                continue
            parts = line.split(None, 2)
            if len(parts) >= 2:
                shares.append({"name": parts[0], "path": parts[1] if len(parts) > 1 else ""})
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return shares


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
