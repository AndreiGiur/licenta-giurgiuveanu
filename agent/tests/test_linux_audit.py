"""Teste pentru colectorul Linux (parsing pur + gating pe OS). subprocess/fisiere mock."""
from agent.collectors import linux_audit as la


def test_non_linux_returns_empty(monkeypatch):
    monkeypatch.setattr(la.platform, "system", lambda: "Windows")
    from agent.core import SCAN_PROFILES
    assert la.collect_linux_audit(SCAN_PROFILES["deep"]) == {}


def test_parse_sshd_config():
    text = ("PermitRootLogin yes\n#Port 22\nPasswordAuthentication no\n"
            "Port 2222\nPermitEmptyPasswords yes\nX11Forwarding yes\n")
    out = la._parse_sshd_config(text)
    assert out["permit_root_login"] == "yes"
    assert out["password_auth"] == "no"
    assert out["port"] == 2222
    assert out["permit_empty_passwords"] == "yes"
    assert out["x11_forwarding"] == "yes"


def test_uid0_accounts():
    passwd = ("root:x:0:0:root:/root:/bin/bash\n"
              "bob:x:0:0::/home/bob:/bin/sh\n"
              "u:x:1000:1000::/home/u:/bin/sh\n")
    assert la._uid0_accounts(passwd) == ["root", "bob"]


def test_empty_password_accounts():
    shadow = "root:$6$x:19000:0:99999:7:::\nguest::19000:0:99999:7:::\n"
    assert la._empty_password_accounts(shadow) == ["guest"]


def test_parse_sysctl():
    out = la._parse_sysctl("net.ipv4.ip_forward = 1\nkernel.randomize_va_space = 2\n"
                           "fs.suid_dumpable = 1\n")
    assert out["ip_forward"] == "1"
    assert out["aslr"] == "2"
    assert out["suid_dumpable"] == "1"


def test_parse_login_defs():
    text = "PASS_MAX_DAYS\t99999\nUMASK\t022\n"
    out = la._parse_login_defs(text)
    assert out["pass_max_days"] == "99999"
    assert out["umask"] == "022"


def test_tmp_noexec_from_mounts():
    mounts = ("/dev/sda1 / ext4 rw,relatime 0 0\n"
              "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n")
    # /tmp fara noexec → True (problema)
    assert la._tmp_missing_noexec(mounts) is True
    mounts2 = "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n"
    assert la._tmp_missing_noexec(mounts2) is False


def test_suid_filters_known_good():
    # _filter_suid primeste output find si pastreaza doar binarele necunoscute
    find_out = "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/weirdbin\n"
    assert la._filter_suid(find_out) == ["/usr/bin/weirdbin"]
