"""Teste pentru instalarea nmap din agent (OS-aware: winget / apt/dnf/pacman/zypper)."""
from agent import core


def test_detect_package_manager_apt(monkeypatch):
    monkeypatch.setattr(core.shutil, "which",
                        lambda x: "/usr/bin/apt-get" if x == "apt-get" else None)
    assert core.detect_package_manager() == "apt-get"


def test_detect_package_manager_pacman(monkeypatch):
    monkeypatch.setattr(core.shutil, "which",
                        lambda x: "/usr/bin/pacman" if x == "pacman" else None)
    assert core.detect_package_manager() == "pacman"


def test_detect_package_manager_none(monkeypatch):
    monkeypatch.setattr(core.shutil, "which", lambda x: None)
    assert core.detect_package_manager() is None


def test_build_nmap_install_command_windows(monkeypatch):
    monkeypatch.setattr(core.sys, "platform", "win32")
    cmd = core.build_nmap_install_command()
    assert cmd is not None
    assert "winget" in cmd[0]
    assert "Insecure.Nmap" in cmd


def test_build_nmap_install_command_linux_apt(monkeypatch):
    monkeypatch.setattr(core.sys, "platform", "linux")
    monkeypatch.setattr(core, "detect_package_manager", lambda: "apt-get")
    cmd = core.build_nmap_install_command()
    assert cmd == ["apt-get", "install", "-y", "nmap"]


def test_build_nmap_install_command_linux_pacman(monkeypatch):
    monkeypatch.setattr(core.sys, "platform", "linux")
    monkeypatch.setattr(core, "detect_package_manager", lambda: "pacman")
    cmd = core.build_nmap_install_command()
    assert cmd == ["pacman", "-S", "--noconfirm", "nmap"]


def test_build_nmap_install_command_linux_none(monkeypatch):
    monkeypatch.setattr(core.sys, "platform", "linux")
    monkeypatch.setattr(core, "detect_package_manager", lambda: None)
    assert core.build_nmap_install_command() is None


def test_install_nmap_linux_fallback_to_manual_command(monkeypatch):
    """Fara pkexec/sudo → (False, mesaj cu comanda manuala)."""
    monkeypatch.setattr(core.sys, "platform", "linux")
    monkeypatch.setattr(core, "build_nmap_install_command",
                        lambda: ["apt-get", "install", "-y", "nmap"])
    monkeypatch.setattr(core.shutil, "which", lambda x: None)
    ok, msg = core.install_nmap(log=lambda m, s="info": None)
    assert ok is False
    assert "apt-get install -y nmap" in msg


def test_install_nmap_unknown_os(monkeypatch):
    monkeypatch.setattr(core, "build_nmap_install_command", lambda: None)
    ok, msg = core.install_nmap(log=lambda m, s="info": None)
    assert ok is False
