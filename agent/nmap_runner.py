"""Construirea CLI args + executie nmap subprocess.

Nu importa pywin32 — functioneaza atat in Service mode cat si in GUI mode
single-process fallback.
"""
from __future__ import annotations

import ipaddress
import subprocess
from pathlib import Path
from typing import Optional

from . import core


class NmapRunnerError(Exception):
    """Eroare in pregatire/executie nmap."""


MAX_LAN_HOSTS = 4096  # /20 = 4096 hosts; refuzam mai mult


def validate_cidr(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Valideaza sintactic un CIDR sau single IP. Ridica NmapRunnerError la fail."""
    try:
        return ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError) as e:
        raise NmapRunnerError(f"CIDR invalid: {value} ({e})")


def validate_lan_target(value: str) -> None:
    """Validare LAN: rejects public ranges + huge networks."""
    net = validate_cidr(value)
    if net.is_global:  # public IP
        raise NmapRunnerError(
            f"Target public refuzat (LAN scan permis doar pe retele private): {value}"
        )
    if net.num_addresses > MAX_LAN_HOSTS:
        raise NmapRunnerError(
            f"Subnet prea mare ({net.num_addresses} host-uri); maxim {MAX_LAN_HOSTS}"
        )


def build_nmap_args(
    targets: list[str],
    xml_out: str,
    top_ports: Optional[int] = 1000,
    all_ports: bool = False,
    extra_script_args: Optional[str] = None,
) -> list[str]:
    """Construieste argumentele CLI pentru nmap (fara exe-ul in sine)."""
    args: list[str] = ["-sV", "-O"]
    if all_ports:
        args.append("-p-")
    elif top_ports:
        args.extend(["--top-ports", str(top_ports)])
    args.extend(["--script", "vulnwatch-audit"])
    if extra_script_args:
        args.extend(["--script-args", extra_script_args])
    args.extend(["-oX", xml_out])
    args.extend(targets)
    return args


def run_nmap(
    targets: list[str],
    xml_out: Path,
    top_ports: Optional[int] = 1000,
    all_ports: bool = False,
    timeout_sec: int = 1800,
    log=None,
) -> tuple[int, str]:
    """Ruleaza nmap. Intoarce (exit_code, stderr_text). XML va fi scris la xml_out.

    Ridica NmapRunnerError daca nmap.exe lipseste.
    """
    nmap = core._nmap_path()
    if not nmap:
        raise NmapRunnerError("nmap.exe nu este instalat pe acest sistem")
    args = build_nmap_args(targets=targets, xml_out=str(xml_out),
                           top_ports=top_ports, all_ports=all_ports)
    cmd = [str(nmap)] + args
    if log:
        log(f"nmap: {' '.join(cmd)}", "info")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise NmapRunnerError(f"nmap timeout dupa {timeout_sec}s") from e
    return result.returncode, (result.stderr or "")
