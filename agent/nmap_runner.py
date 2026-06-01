"""Construirea CLI args + executie nmap subprocess.

Nu importa pywin32 — functioneaza atat in Service mode cat si in GUI mode
single-process fallback.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional

from . import core


class NmapRunnerError(Exception):
    """Eroare in pregatire/executie nmap."""


# Regex-uri pentru parsarea liniilor de progres nmap (--stats-every).
_STATS_RE = re.compile(r"About\s+([\d.]+)%\s+done", re.IGNORECASE)
_REMAINING_RE = re.compile(r"\(([\d:]+)\s+remaining\)", re.IGNORECASE)


def parse_nmap_stats_line(line: str) -> tuple[float, str] | None:
    """Extrage (percent, timp_ramas) dintr-o linie de progres nmap.

    nmap cu --stats-every tipareste periodic linii de forma:
      'SYN Stealth Scan Timing: About 45.23% done; ETC: 16:32 (0:00:35 remaining)'
    Intoarce None daca linia nu contine progres.
    """
    m = _STATS_RE.search(line or "")
    if not m:
        return None
    pct = float(m.group(1))
    rem_m = _REMAINING_RE.search(line)
    remaining = rem_m.group(1) if rem_m else ""
    return pct, remaining


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


# ─── Nmap profiles per scan_type ────────────────────────────────────────────
# Args nmap variaza in functie de scan_type. Numarul de porturi si scripturile
# difera intentionat: advanced ramane rapid (~1-3 min), deep e exhaustiv.
# `host_discovery_only_args` (ex. -Pn) se aplica DOAR pe tinta single-host;
# pe un subnet le omitem ca nmap sa descopere host-urile vii intai (altfel ar
# incerca scan complet pe toate cele 256 adrese, inclusiv cele moarte).
NMAP_PROFILES: dict[str, dict] = {
    # USOR — discovery + porturi + versiuni pe subnet, fara -O/-A. ~2-5 min /24.
    "advanced": {
        "base_args": [
            "-sV",                          # version detection
            "-T4",                          # aggressive timing
            "--version-intensity", "5",     # intensitate medie
        ],
        "single_host_args": [],             # advanced nu foloseste -Pn
        "scripts": "vulnwatch-audit",
        "top_ports": 1000,
        "timeout_sec": 900,                 # 15 min
    },
    # AGRESIV — full -A + vuln. Pe subnet: discovery intai. ~10-30 min /24.
    "deep": {
        "base_args": [
            "-A",                           # = -sV -O --script=default --traceroute
            "-T4",                          # aggressive timing
            "--version-intensity", "9",     # intensitate maxima
        ],
        "single_host_args": ["-Pn"],        # skip discovery DOAR pe single-host
        # vulnwatch-audit + scripts default + vuln (CVE detection) + auth + banner grab
        "scripts": "vulnwatch-audit,vuln,default,auth,banner",
        "top_ports": 5000,
        "timeout_sec": 2400,                # 40 min
    },
}


def build_nmap_args(
    targets: list[str],
    xml_out: str,
    top_ports: Optional[int] = 1000,
    all_ports: bool = False,
    extra_script_args: Optional[str] = None,
    profile: str = "legacy",
    nse_script_path: Optional[str] = None,
    subnet_scan: bool = False,
) -> list[str]:
    """Construieste argumentele CLI pentru nmap (fara exe-ul in sine).

    Daca profile e setat la 'advanced' sau 'deep', foloseste NMAP_PROFILES
    (args + scripturi + top_ports preconfigurate). 'legacy' = comportamentul
    initial (-sV -O --script vulnwatch-audit) pentru backwards compat.

    `nse_script_path`: daca e dat, referinta `vulnwatch-audit` (dupa nume) e
    inlocuita cu calea absoluta a scriptului (`/cale/vulnwatch-audit.nse`).
    Asa nmap il gaseste fara sa-l copiem in scripts dir-ul de sistem (care pe
    Linux cere root) — nmap accepta cai absolute in `--script`."""
    def _scripts(s: str) -> str:
        if nse_script_path:
            return s.replace("vulnwatch-audit", nse_script_path)
        return s

    if profile in NMAP_PROFILES:
        prof = NMAP_PROFILES[profile]
        args: list[str] = list(prof["base_args"])
        # Argumente single-host (ex. -Pn) doar cand NU scanam un subnet.
        if not subnet_scan:
            args.extend(prof.get("single_host_args", []))
        # all_ports overrides top_ports din profil
        if all_ports:
            args.append("-p-")
        else:
            args.extend(["--top-ports", str(prof["top_ports"])])
        args.extend(["--script", _scripts(prof["scripts"])])
        # Progres periodic pe stdout/stderr pentru afisare real-time in UI.
        args.extend(["--stats-every", "2s"])
    else:
        # Legacy path — pastram comportamentul vechi pentru testele existente
        args = ["-sV", "-O"]
        if all_ports:
            args.append("-p-")
        elif top_ports:
            args.extend(["--top-ports", str(top_ports)])
        args.extend(["--script", _scripts("vulnwatch-audit")])
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
    profile: str = "legacy",
    progress_cb: Optional[Callable[[float, str], None]] = None,
    nse_script_path: Optional[str] = None,
    subnet_scan: bool = False,
    log=None,
) -> tuple[int, str]:
    """Ruleaza nmap. Intoarce (exit_code, output_text). XML va fi scris la xml_out.

    Daca profile e 'advanced' sau 'deep', timeout_sec din profil are prioritate
    peste param. Daca `progress_cb` e dat, liniile de progres nmap (--stats-every)
    sunt parsate si raportate live: `progress_cb(percent, timp_ramas)`.
    Ridica NmapRunnerError daca nmap.exe lipseste.
    """
    nmap = core._nmap_path()
    if not nmap:
        raise NmapRunnerError("nmap.exe nu este instalat pe acest sistem")
    if profile in NMAP_PROFILES:
        timeout_sec = NMAP_PROFILES[profile]["timeout_sec"]
    args = build_nmap_args(targets=targets, xml_out=str(xml_out),
                           top_ports=top_ports, all_ports=all_ports,
                           profile=profile, nse_script_path=nse_script_path,
                           subnet_scan=subnet_scan)
    cmd = [str(nmap)] + args
    if log:
        log(f"nmap: {' '.join(cmd)}", "info")

    start = time.time()
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except OSError as e:
        raise NmapRunnerError(f"nmap nu a putut porni: {e}") from e

    output: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        output.append(line)
        if progress_cb:
            parsed = parse_nmap_stats_line(line)
            if parsed:
                pct, remaining = parsed
                try:
                    progress_cb(pct, remaining)
                except Exception:
                    pass
        if time.time() - start > timeout_sec:
            proc.kill()
            raise NmapRunnerError(f"nmap timeout dupa {timeout_sec}s")
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
    return proc.returncode or 0, "".join(output)
