"""Colectare network: porturi LISTEN + (opt) port→proces, conexiuni ESTABLISHED, share-uri, adaptoare."""
from __future__ import annotations

import ipaddress
import os
import platform
import socket
import subprocess
from pathlib import Path

import psutil

from ..core import ScanProfile


def collect_network(cfg: ScanProfile) -> dict:
    ports, bindings = _listen_ports_with_bindings()
    out: dict = {"open_ports": ports, "port_bindings": bindings}

    # Identitatea de retea a dispozitivului (IP + MAC interfata principala).
    # Date cu caracter personal — colectam DOAR interfata activa (minimizare).
    identity = collect_network_identity()
    if identity:
        out["identity"] = identity

    if cfg.include_port_process:
        out["port_processes"] = _port_processes()
    if cfg.include_connections:
        out["connections"] = _established_connections()
    if cfg.include_shares and platform.system() == "Windows":
        out["shares"] = _network_shares()
    if cfg.include_net_adapters:
        out["adapters"] = _adapters()
    if cfg.include_wifi_profiles and platform.system() == "Windows":
        out["wifi_profiles"] = _wifi_profiles()

    return out


def collect_network_identity() -> dict:
    """IP + MAC ale interfetei active principale (up, non-loopback, IPv4 privata).

    Intoarce `{iface, local_ip, mac}` sau `{}` daca nu gaseste. Colectam doar o
    singura interfata (minimizarea datelor cu caracter personal — IP/MAC).
    MAC-ul provine din adresa AF_LINK (psutil) a aceleiasi interfete.
    """
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
    except Exception:
        return {}
    for name, snics in addrs.items():
        st = stats.get(name)
        if st is None or not st.isup:
            continue
        if name.lower().startswith(("lo", "loopback")):
            continue
        local_ip = ""
        for snic in snics:
            if snic.family == socket.AF_INET and snic.address and not snic.address.startswith("127."):
                try:
                    if ipaddress.ip_address(snic.address).is_private:
                        local_ip = snic.address
                        break
                except ValueError:
                    continue
        if not local_ip:
            continue
        mac = ""
        for snic in snics:
            # AF_LINK / AF_PACKET = adresa MAC (numele difera intre OS-uri).
            if snic.family == getattr(psutil, "AF_LINK", -1) and snic.address:
                mac = snic.address
                break
        return {"iface": name, "local_ip": local_ip, "mac": mac}
    return {}


def _listen_ports_with_bindings() -> tuple[list[int], list[dict]]:
    """Returneaza:
      - lista porturilor unice (compat backward cu vechiul `open_ports`)
      - lista bindings [(port, bind_ip), ...] pentru analiza adresei locale
    """
    ports: list[int] = []
    bindings: list[dict] = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                p = conn.laddr.port
                ip = conn.laddr.ip or ""
                bindings.append({"port": p, "ip": ip})
                if p not in ports:
                    ports.append(p)
    except (psutil.AccessDenied, PermissionError, Exception):
        pass
    return sorted(ports), bindings


def _port_processes() -> list[dict]:
    out: list[dict] = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != psutil.CONN_LISTEN or not conn.laddr or not conn.pid:
                continue
            try:
                p = psutil.Process(conn.pid)
                try:
                    exe = p.exe()
                except (psutil.AccessDenied, OSError):
                    exe = ""
                out.append({"port": conn.laddr.port, "pid": conn.pid,
                            "process": p.name(), "exe": exe})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                out.append({"port": conn.laddr.port, "pid": conn.pid,
                            "process": "", "exe": ""})
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


_WLAN_NS = "{http://www.microsoft.com/networking/WLAN/profile/v1}"


def _parse_wifi_profile_xml(xml_text: str) -> dict | None:
    """Extrage {ssid, authentication} din XML-ul netsh (schema fixa, imuna la
    localizare). NU citeste keyMaterial -- exportul se face FARA key=clear."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    name_el = root.find(f"{_WLAN_NS}name")
    auth_el = root.find(
        f"{_WLAN_NS}MSM/{_WLAN_NS}security/{_WLAN_NS}authEncryption/{_WLAN_NS}authentication"
    )
    if name_el is None or auth_el is None:
        return None
    return {"ssid": (name_el.text or "").strip(),
            "authentication": (auth_el.text or "").strip()}


def _wifi_profiles() -> list[dict]:
    """Exporta profilele WiFi salvate (XML, fara chei) si le parseaza."""
    import tempfile
    profiles: list[dict] = []
    try:
        with tempfile.TemporaryDirectory() as td:
            r = subprocess.run(
                ["netsh", "wlan", "export", "profile", f"folder={td}"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode != 0:
                return []
            for fname in os.listdir(td):
                if not fname.lower().endswith(".xml"):
                    continue
                try:
                    text = (Path(td) / fname).read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    continue
                parsed = _parse_wifi_profile_xml(text)
                if parsed:
                    profiles.append(parsed)
    except (subprocess.SubprocessError, OSError):
        return []
    return profiles[:50]
