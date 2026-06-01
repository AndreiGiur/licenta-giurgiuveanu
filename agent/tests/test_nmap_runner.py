"""Tests pentru construire CLI args nmap + validare target."""
import pytest
from agent.nmap_runner import (
    build_nmap_args, validate_cidr, validate_lan_target, NmapRunnerError,
    NMAP_PROFILES, parse_nmap_stats_line,
)


def test_parse_nmap_stats_line_with_percent_and_eta():
    line = ("SYN Stealth Scan Timing: About 45.23% done; "
            "ETC: 16:32 (0:00:35 remaining)")
    res = parse_nmap_stats_line(line)
    assert res is not None
    pct, remaining = res
    assert abs(pct - 45.23) < 0.01
    assert remaining == "0:00:35"


def test_parse_nmap_stats_line_no_match_returns_none():
    assert parse_nmap_stats_line("Starting Nmap 7.99") is None
    assert parse_nmap_stats_line("") is None


def test_build_args_include_stats_every_for_profiles():
    args = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml", profile="deep")
    assert "--stats-every" in args
    assert "2s" in " ".join(args)


def test_nse_script_path_replaces_audit_name():
    """Cand dam calea absoluta, 'vulnwatch-audit' (dupa nume) e inlocuit cu calea
    (nmap o gaseste fara scripts dir-ul de sistem). Pe Linux nu mai cere root."""
    p = "/home/u/vulnwatch-agent/agent/nse/vulnwatch-audit.nse"
    # deep profile (vulnwatch-audit,vuln,default,auth,banner)
    args = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml",
                           profile="deep", nse_script_path=p)
    joined = " ".join(args)
    assert p in joined
    assert "vuln,default,auth,banner" in joined  # built-in scripts raman dupa nume
    # legacy
    args2 = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml", nse_script_path=p)
    assert p in " ".join(args2)


def test_no_nse_path_keeps_audit_by_name():
    """Fara cale (Windows cu deploy), ramane referinta dupa nume 'vulnwatch-audit'."""
    args = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml", profile="deep")
    assert "vulnwatch-audit,vuln,default,auth,banner" in " ".join(args)


def test_build_args_localhost_only():
    args = build_nmap_args(targets=["127.0.0.1"], top_ports=1000,
                           xml_out="result.xml")
    assert "-sV" in args
    assert "-O" in args
    assert "--top-ports" in args
    assert "1000" in args
    assert "--script" in args
    assert "vulnwatch-audit" in args
    assert "-oX" in args
    assert "result.xml" in args
    assert "127.0.0.1" in args


def test_build_args_with_lan():
    args = build_nmap_args(targets=["127.0.0.1", "192.168.1.0/24"],
                           top_ports=1000, xml_out="result.xml")
    assert "127.0.0.1" in args
    assert "192.168.1.0/24" in args


def test_build_args_all_ports():
    args = build_nmap_args(targets=["127.0.0.1"], top_ports=None,
                           all_ports=True, xml_out="result.xml")
    assert "-p-" in args
    assert "--top-ports" not in args


def test_validate_cidr_ok():
    validate_cidr("192.168.1.0/24")  # nu ridica
    validate_cidr("10.0.0.0/24")    # /24, nu /8
    validate_cidr("127.0.0.1")      # single host = /32


def test_validate_lan_target_rejects_public():
    with pytest.raises(NmapRunnerError, match="public"):
        validate_lan_target("8.8.8.0/24")


def test_validate_lan_target_rejects_huge():
    with pytest.raises(NmapRunnerError, match="prea mare"):
        validate_lan_target("10.0.0.0/8")


def test_validate_cidr_rejects_invalid_syntax():
    with pytest.raises(NmapRunnerError, match="invalid"):
        validate_cidr("not.a.cidr")


# ─── Profile-specific tests (advanced + deep) ────────────────────────────


def test_nmap_profiles_exist():
    """NMAP_PROFILES expune advanced + deep cu chei obligatorii."""
    assert "advanced" in NMAP_PROFILES
    assert "deep" in NMAP_PROFILES
    for name, prof in NMAP_PROFILES.items():
        assert "base_args" in prof, f"{name} missing base_args"
        assert "scripts" in prof, f"{name} missing scripts"
        assert "top_ports" in prof, f"{name} missing top_ports"
        assert "timeout_sec" in prof, f"{name} missing timeout_sec"


def test_profile_advanced_moderate_args():
    """Profilul advanced foloseste -sV moderat, fara -A/-O, top 1000."""
    args = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml",
                           profile="advanced")
    assert "-sV" in args
    assert "-A" not in args, "advanced nu trebuie sa fie aggressive (-A)"
    assert "-O" not in args, "advanced nu face OS detection (-O)"
    assert "--top-ports" in args
    assert "1000" in args
    assert "-T4" in args
    assert "vulnwatch-audit" in " ".join(args)
    # advanced foloseste DOAR vulnwatch-audit, fara vuln/default scripts
    assert "vuln,default" not in " ".join(args)


def test_deep_subnet_scan_drops_pn():
    """Pe subnet, deep NU foloseste -Pn (lasa nmap sa descopere host-urile vii)."""
    args = build_nmap_args(targets=["192.168.1.0/24"], xml_out="x.xml",
                           profile="deep", subnet_scan=True)
    assert "-A" in args
    assert "-Pn" not in args, "deep pe subnet nu trebuie sa sara discovery-ul"


def test_deep_single_host_keeps_pn():
    """Pe un singur host, deep pastreaza -Pn (host-ul e mereu considerat up)."""
    args = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml",
                           profile="deep", subnet_scan=False)
    assert "-Pn" in args


def test_advanced_never_uses_pn():
    """advanced nu foloseste -Pn nici pe host, nici pe subnet."""
    single = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml",
                             profile="advanced", subnet_scan=False)
    subnet = build_nmap_args(targets=["192.168.1.0/24"], xml_out="x.xml",
                             profile="advanced", subnet_scan=True)
    assert "-Pn" not in single
    assert "-Pn" not in subnet


def test_profile_deep_aggressive_args():
    """Profilul deep foloseste -A + -Pn + vuln + version-intensity 9 + toate porturile (-p-)."""
    args = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml",
                           profile="deep")
    assert "-A" in args, "deep trebuie sa includa -A (aggressive)"
    assert "-Pn" in args, "deep trebuie sa includa -Pn (skip host discovery)"
    assert "-T4" in args
    assert "--version-intensity" in args
    assert "9" in args
    # deep scaneaza TOATE porturile (-p-), nu doar top-N
    assert "-p-" in args, "deep trebuie sa scaneze toate porturile (-p-)"
    assert "--top-ports" not in args, "deep nu mai limiteaza la top-ports"
    # Scripturi extinse: vulnwatch-audit + vuln (CVE) + default + auth + banner
    script_str = " ".join(args)
    assert "vulnwatch-audit" in script_str
    assert "vuln" in script_str
    assert "default" in script_str
    assert "auth" in script_str
    assert "banner" in script_str


def test_profile_deep_more_aggressive_than_advanced():
    """Comparativ: deep are mai multe scripturi si flag-uri decat advanced."""
    adv = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml",
                          profile="advanced")
    deep = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml",
                           profile="deep")
    # deep are -A si -Pn pe care advanced NU le are
    assert "-A" not in adv and "-A" in deep
    assert "-Pn" not in adv and "-Pn" in deep
    # scripturile deep includ toate cele advanced + mai multe
    adv_scripts = NMAP_PROFILES["advanced"]["scripts"]
    deep_scripts = NMAP_PROFILES["deep"]["scripts"]
    assert adv_scripts in deep_scripts


def test_profile_legacy_backwards_compat():
    """Fara profile, build_nmap_args pastreaza comportamentul vechi (-sV -O)."""
    args = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml")  # no profile
    assert "-sV" in args
    assert "-O" in args
    assert "-A" not in args
    # Doar vulnwatch-audit, fara vuln/default
    assert "vuln,default" not in " ".join(args)


def test_profile_unknown_falls_back_to_legacy():
    """Profile invalid trece pe legacy path fara eroare."""
    args = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml",
                           profile="unknown_xyz")
    assert "-sV" in args
    assert "-O" in args  # legacy include -O


def test_profile_advanced_timeout_shorter_than_deep():
    """Advanced are timeout mai mic (e mai rapid)."""
    assert NMAP_PROFILES["advanced"]["timeout_sec"] < NMAP_PROFILES["deep"]["timeout_sec"]


def test_profile_all_ports_overrides_top_ports():
    """Daca all_ports=True, -p- inlocuieste --top-ports din profil."""
    args = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml",
                           profile="deep", all_ports=True)
    assert "-p-" in args
    assert "--top-ports" not in args
