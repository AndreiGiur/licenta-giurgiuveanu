"""Parse XML output de la nmap (-oX) într-un dict structurat VulnWatch."""
from __future__ import annotations

import json
from xml.etree import ElementTree as ET


class NmapParseError(Exception):
    """Eroare în parsarea XML nmap."""


def parse_nmap_xml(xml_text: str) -> dict:
    """Convertește XML nmap în dict cu schema:

    {
      "version": "7.94",
      "scan_time_sec": float | None,
      "hosts": [
        {
          "ip": "127.0.0.1",
          "hostname": "localhost",
          "state": "up",
          "os_guess": "Microsoft Windows 11 (95% confidence)",
          "ports": [{"port": 445, "proto": "tcp", "state": "open",
                     "service": "microsoft-ds", "version": "Windows 10",
                     "cpe": ""}],
          "vulnwatch_findings": [...],   # deserializat din script id="vulnwatch-audit"
          "topology": {...}
        }
      ]
    }
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise NmapParseError(f"XML invalid: {e}") from e

    if root.tag != "nmaprun":
        raise NmapParseError(f"Element root nu este nmaprun: {root.tag}")

    out: dict = {
        "version": root.get("version", ""),
        "scan_time_sec": None,
        "hosts": [],
    }
    start = root.get("start")
    if start:
        runstats = root.find("runstats/finished")
        if runstats is not None and runstats.get("time"):
            try:
                out["scan_time_sec"] = float(runstats.get("time")) - float(start)
            except ValueError:
                pass

    for host_el in root.findall("host"):
        out["hosts"].append(_parse_host(host_el))

    return out


def _parse_host(host_el: ET.Element) -> dict:
    host: dict = {
        "ip": "",
        "hostname": "",
        "state": "",
        "os_guess": "",
        "ports": [],
        "vulnwatch_findings": [],
        "topology": {},
    }
    # IP
    addr = host_el.find("address[@addrtype='ipv4']")
    if addr is None:
        addr = host_el.find("address[@addrtype='ipv6']")
    if addr is not None:
        host["ip"] = addr.get("addr", "")
    # State
    status = host_el.find("status")
    if status is not None:
        host["state"] = status.get("state", "")
    # Hostname
    hostname = host_el.find("hostnames/hostname")
    if hostname is not None:
        host["hostname"] = hostname.get("name", "")
    # OS
    osmatch = host_el.find("os/osmatch")
    if osmatch is not None:
        accuracy = osmatch.get("accuracy", "0")
        host["os_guess"] = f"{osmatch.get('name', 'Unknown')} ({accuracy}% confidence)"
    # Ports
    for port_el in host_el.findall("ports/port"):
        host["ports"].append(_parse_port(port_el))
    # vulnwatch-audit script output
    script = host_el.find("hostscript/script[@id='vulnwatch-audit']")
    if script is None:
        # Could be at port level for some scripts; check there too
        for port_el in host_el.findall("ports/port"):
            s = port_el.find("script[@id='vulnwatch-audit']")
            if s is not None:
                script = s
                break
    if script is not None:
        output = script.get("output", "")
        try:
            parsed = json.loads(output)
            host["vulnwatch_findings"] = parsed.get("findings", [])
            host["topology"] = parsed.get("topology", {})
        except (json.JSONDecodeError, ValueError):
            pass
    return host


def _parse_port(port_el: ET.Element) -> dict:
    port = {
        "port": int(port_el.get("portid", "0")),
        "proto": port_el.get("protocol", "tcp"),
        "state": "",
        "service": "",
        "version": "",
        "cpe": "",
    }
    state = port_el.find("state")
    if state is not None:
        port["state"] = state.get("state", "")
    svc = port_el.find("service")
    if svc is not None:
        port["service"] = svc.get("name", "")
        product = svc.get("product", "")
        version = svc.get("version", "")
        port["version"] = f"{product} {version}".strip()
        cpe = svc.find("cpe")
        if cpe is not None and cpe.text:
            port["cpe"] = cpe.text
    return port
