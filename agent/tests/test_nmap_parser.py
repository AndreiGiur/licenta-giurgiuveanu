"""Tests parsare XML nmap → dict + extract vulnwatch-audit JSON."""
import json
from pathlib import Path

import pytest

from agent.nmap_parser import parse_nmap_xml, NmapParseError

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_localhost():
    xml = (FIXTURES / "nmap_localhost.xml").read_text()
    result = parse_nmap_xml(xml)
    assert result["version"] == "7.94"
    assert len(result["hosts"]) == 1
    host = result["hosts"][0]
    assert host["ip"] == "127.0.0.1"
    assert host["hostname"] == "localhost"
    assert host["state"] == "up"
    assert "Microsoft Windows 11" in host["os_guess"]
    assert len(host["ports"]) == 2
    port_445 = next(p for p in host["ports"] if p["port"] == 445)
    assert port_445["service"] == "microsoft-ds"
    # vulnwatch-audit JSON deserialized
    findings = host["vulnwatch_findings"]
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "NMAP-CVE-2017-0144"
    assert findings[0]["severity"] == "critical"
    assert host["topology"]["role"] == "workstation"
    assert host["topology"]["risk_score"] == 65


def test_parse_extracts_mac_and_vendor():
    """Host cu adresa MAC (acelasi segment L2) → mac + vendor in payload."""
    xml = """<?xml version="1.0"?><nmaprun version="7.94" start="1">
<host><status state="up"/>
<address addr="192.168.1.50" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Intel Corporate"/>
<hostnames><hostname name="printer.lan"/></hostnames>
<distance value="1"/>
<ports></ports></host></nmaprun>"""
    host = parse_nmap_xml(xml)["hosts"][0]
    assert host["ip"] == "192.168.1.50"
    assert host["mac"] == "AA:BB:CC:DD:EE:FF"
    assert host["vendor"] == "Intel Corporate"
    assert host["distance"] == 1


def test_parse_no_mac_keeps_empty():
    """Host fara MAC (ex. localhost) → mac/vendor goale, fara crash."""
    xml = """<?xml version="1.0"?><nmaprun version="7.94" start="1">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<ports></ports></host></nmaprun>"""
    host = parse_nmap_xml(xml)["hosts"][0]
    assert host["mac"] == ""
    assert host["vendor"] == ""
    assert host["distance"] is None


def test_parse_invalid_xml_raises():
    with pytest.raises(NmapParseError):
        parse_nmap_xml("not xml at all")


def test_parse_missing_vulnwatch_script_returns_empty_findings():
    """Dacă scriptul nostru nu rulează (LSE missing), parser nu crash."""
    xml = """<?xml version="1.0"?><nmaprun version="7.94" start="1">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<ports></ports></host></nmaprun>"""
    result = parse_nmap_xml(xml)
    assert result["hosts"][0]["vulnwatch_findings"] == []
    assert result["hosts"][0]["topology"] == {}
