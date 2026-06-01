"""SCAN_PROFILES valid + colectori returneaza structuri asteptate.

Note: testele ruleaza pe Windows (dev machine); pe non-Windows, colectorii
Windows-only returneaza dict/list goala — sectiunile relevante sunt protejate
cu `if platform.system() == 'Windows'`."""
import platform
import socket
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent.core import ScanProfile, SCAN_PROFILES, collect_system_data  # noqa: E402
from agent import collectors  # noqa: E402
from agent.collectors import network as net_collector  # noqa: E402


def _snic(family, address, netmask=None):
    return types.SimpleNamespace(family=family, address=address,
                                 netmask=netmask, broadcast=None, ptp=None)


def _stats(isup=True):
    return types.SimpleNamespace(isup=isup, duplex=0, speed=0, mtu=1500, flags="")


def test_network_identity_returns_ip_and_mac(monkeypatch):
    import psutil
    af_link = getattr(psutil, "AF_LINK")
    monkeypatch.setattr(net_collector.psutil, "net_if_stats",
                        lambda: {"lo": _stats(), "eth0": _stats()})
    monkeypatch.setattr(net_collector.psutil, "net_if_addrs", lambda: {
        "lo": [_snic(socket.AF_INET, "127.0.0.1", "255.0.0.0")],
        "eth0": [_snic(socket.AF_INET, "192.168.1.141", "255.255.255.0"),
                 _snic(af_link, "08:00:27:ab:cd:ef")],
    })
    ident = net_collector.collect_network_identity()
    assert ident["iface"] == "eth0"
    assert ident["local_ip"] == "192.168.1.141"
    assert ident["mac"] == "08:00:27:ab:cd:ef"


def test_network_identity_empty_when_only_loopback(monkeypatch):
    monkeypatch.setattr(net_collector.psutil, "net_if_stats", lambda: {"lo": _stats()})
    monkeypatch.setattr(net_collector.psutil, "net_if_addrs", lambda: {
        "lo": [_snic(socket.AF_INET, "127.0.0.1", "255.0.0.0")],
    })
    assert net_collector.collect_network_identity() == {}


def test_scan_profiles_have_three_levels():
    assert set(SCAN_PROFILES.keys()) == {"standard", "advanced", "deep"}


def test_standard_profile_minimal():
    p = SCAN_PROFILES["standard"]
    assert isinstance(p, ScanProfile)
    assert p.process_limit == 30
    assert p.include_cmdline is False
    assert p.include_software is True
    assert p.include_persistence is False
    assert p.include_forensics is False


def test_advanced_profile_includes_persistence():
    p = SCAN_PROFILES["advanced"]
    assert p.process_limit is None
    assert p.include_cmdline is True
    assert p.include_persistence is True
    assert p.include_services is True
    assert p.include_startup is True
    assert p.include_tasks is True
    assert p.include_forensics is False


def test_deep_profile_includes_forensics():
    p = SCAN_PROFILES["deep"]
    assert p.include_forensics is True
    assert p.include_wmi is True
    assert p.include_bitlocker is True
    assert p.include_defender is True
    assert p.include_eventlog is True
    assert p.include_hosts is True


def test_collect_network_returns_open_ports_list():
    cfg = SCAN_PROFILES["standard"]
    data = collectors.collect_network(cfg)
    assert "open_ports" in data
    assert isinstance(data["open_ports"], list)


def test_collect_network_advanced_includes_connections_key():
    cfg = SCAN_PROFILES["advanced"]
    data = collectors.collect_network(cfg)
    assert "connections" in data
    assert isinstance(data["connections"], list)


def test_collect_processes_respects_limit():
    cfg = SCAN_PROFILES["standard"]
    procs = collectors.collect_processes(cfg)
    assert isinstance(procs, list)
    assert len(procs) <= 30
    if procs:
        assert "pid" in procs[0]
        assert "memory_percent" in procs[0]
        assert "cmdline" not in procs[0]


def test_collect_processes_advanced_has_cmdline():
    cfg = SCAN_PROFILES["advanced"]
    procs = collectors.collect_processes(cfg)
    if procs:
        assert "cmdline" in procs[0]
        assert "ppid" in procs[0]


def test_collect_system_has_basic_fields():
    cfg = SCAN_PROFILES["standard"]
    data = collectors.collect_system(cfg)
    for k in ("system", "release", "hostname", "is_admin", "uptime_seconds"):
        assert k in data


def test_collect_system_data_standard_structure():
    data = collect_system_data("test-uid", scan_type="standard")
    assert data["scan_type"] == "standard"
    assert data["device_uid"] == "test-uid"
    assert "os" in data and "system" in data["os"]
    assert "network" in data
    assert isinstance(data["network"].get("open_ports"), list)
    assert data["persistence"] is None
    assert data["forensics"] is None


def test_collect_system_data_advanced_includes_persistence():
    data = collect_system_data("test-uid", scan_type="advanced")
    assert data["scan_type"] == "advanced"
    if platform.system() == "Windows":
        assert data["persistence"] is not None
    assert data["forensics"] is None


def test_collect_system_data_deep_includes_forensics():
    data = collect_system_data("test-uid", scan_type="deep")
    assert data["scan_type"] == "deep"
    if platform.system() == "Windows":
        assert data["persistence"] is not None
        assert data["forensics"] is not None


def test_collect_system_data_progress_callback_called():
    calls: list[tuple[int, str]] = []
    collect_system_data("x", scan_type="standard",
                        progress_cb=lambda p, ph: calls.append((p, ph)))
    assert len(calls) > 0
    assert all(0 <= p <= 100 for p, _ in calls)
    # Faza finala trebuie sa fie "Finalizare" cu progres >= 90
    assert any(ph == "Finalizare" for _, ph in calls)
