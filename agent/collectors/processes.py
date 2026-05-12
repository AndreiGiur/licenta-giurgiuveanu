"""Colectare procese: top N dupa RAM (standard) sau toate cu cmdline (advanced/deep)."""
from __future__ import annotations

import psutil

from ..core import ScanProfile


def collect_processes(cfg: ScanProfile) -> list[dict]:
    procs: list[dict] = []
    attrs = ["pid", "name", "memory_percent", "username"]
    if cfg.include_cmdline:
        attrs += ["cmdline", "ppid"]

    for proc in psutil.process_iter(attrs):
        try:
            info = proc.info
            entry: dict = {
                "pid": info.get("pid", 0),
                "name": info.get("name") or "",
                "memory_percent": round(info.get("memory_percent") or 0, 2),
                "username": info.get("username") or "",
            }
            if cfg.include_cmdline:
                cmd = info.get("cmdline") or []
                entry["cmdline"] = " ".join(cmd)[:512]
                entry["ppid"] = info.get("ppid", 0)
            procs.append(entry)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs.sort(key=lambda x: x["memory_percent"], reverse=True)
    if cfg.process_limit is not None:
        procs = procs[: cfg.process_limit]
    return procs
