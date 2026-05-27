"""Snapshot tests pentru scorul agregat exact.

Spre deosebire de testele care verifica doar `score > 0` sau `score >= 60`,
acestea fixeaza valoarea exacta a scorului pentru combinatii de finding-uri
cunoscute. Asta detecteaza orice schimbare neintentionata de:
  - ponderi categorii (CATEGORY_AGGREGATE_WEIGHT)
  - weight per regula
  - severity values (SEVERITY_WEIGHT)
  - logica de agregare in evaluate()

Daca un test esueaza dupa o modificare deliberata, recalculeaza valoarea
asteptata cu formula:
    cat_raw[cat] = Σ severity_weight × rule_weight × rule_confidence
    breakdown[cat] = min(100, round(cat_raw[cat]))
    score = round(Σ aggregate_weight[cat] × breakdown[cat])
"""
import pytest
from server.app.rules import evaluate


# ── Snapshots: o singura regula activa, sistem altfel curat ──────────────


def test_score_clean_system(make_scan):
    """Sistem fara findings → scor 0 exact."""
    score, breakdown, findings = evaluate(make_scan())
    assert score == 0
    assert findings == []
    assert all(v == 0 for v in breakdown.values())


def test_score_winxp_only(make_scan):
    """WinXP (critical_risk, sev=critical=40, w=1.5, conf=1.0):
    cat_raw = 40 * 1.5 * 1.0 = 60
    breakdown.critical_risk = 60
    score = 0.40 * 60 = 24"""
    scan = make_scan()
    scan["os"]["release"] = "XP"
    score, breakdown, _ = evaluate(scan)
    assert breakdown["critical_risk"] == 60
    assert breakdown["network_exposure"] == 0
    assert breakdown["hygiene"] == 0
    assert breakdown["activity"] == 0
    assert score == 24


def test_score_ie11_only(make_scan):
    """Internet Explorer 11 (critical_risk, sev=high=20, w=1.5, conf=1.0):
    cat_raw = 20 * 1.5 = 30 → score = 0.40 * 30 = 12"""
    scan = make_scan()
    scan["software"] = [{"name": "Internet Explorer 11"}]
    score, breakdown, _ = evaluate(scan)
    assert breakdown["critical_risk"] == 30
    assert score == 12


def test_score_adobe_flash_only(make_scan):
    """Adobe Flash (critical_risk, sev=critical=40, w=1.5, conf=1.0):
    cat_raw = 40 * 1.5 = 60 → score = 0.40 * 60 = 24"""
    scan = make_scan()
    scan["software"] = [{"name": "Adobe Flash Player"}]
    score, breakdown, _ = evaluate(scan)
    assert breakdown["critical_risk"] == 60
    assert score == 24


def test_score_mimikatz_only(make_scan):
    """Mimikatz (critical_risk, sev=high=20, w=1.5, conf=1.0):
    cat_raw = 20 * 1.5 = 30 → score = 0.40 * 30 = 12"""
    scan = make_scan()
    scan["processes"] = [{"pid": 1, "name": "mimikatz.exe"}]
    score, breakdown, _ = evaluate(scan)
    assert breakdown["critical_risk"] == 30
    assert score == 12


def test_score_rdp_open_real(make_scan):
    """RDP pe 0.0.0.0 (network_exposure, sev=high=20, w=1.5):
    cat_raw = 30 → score = 0.30 * 30 = 9"""
    scan = make_scan()
    scan["network"]["open_ports"] = [3389]
    scan["network"]["port_bindings"] = [{"port": 3389, "ip": "0.0.0.0"}]
    score, breakdown, _ = evaluate(scan)
    assert breakdown["network_exposure"] == 30
    assert score == 9


def test_score_rdp_only_on_wsl_vswitch(make_scan):
    """RDP pe vSwitch WSL (network_exposure, severity DEGRADAT la low=3, w=1.5):
    cat_raw = 3 * 1.5 = 4.5 → round = 4 → score = 0.30 * 4 = 1.2 → round = 1"""
    scan = make_scan()
    scan["network"]["open_ports"] = [3389]
    scan["network"]["port_bindings"] = [{"port": 3389, "ip": "172.25.48.1"}]
    score, breakdown, _ = evaluate(scan)
    # Conform regulii, downgrade severitate -> 'low' (sev_weight=3)
    assert breakdown["network_exposure"] == 4  # round(3 * 1.5) = round(4.5) = 4 (banker's rounding)
    assert score == 1


def test_score_firewall_off_both_profiles(make_scan):
    """Firewall dezactivat (hygiene, sev=high=20, w=1.2):
    cat_raw = 24 → score = 0.20 * 24 = 4.8 → round = 5"""
    scan = make_scan()
    scan["system_info"]["firewall"] = {"profiles": {"domain": False, "public": False}}
    score, breakdown, _ = evaluate(scan)
    assert breakdown["hygiene"] == 24
    assert score == 5


def test_score_admin_session_only(make_scan):
    """Sesiune admin (hygiene, sev=medium=10, w=0.8):
    cat_raw = 8 → score = 0.20 * 8 = 1.6 → round = 2"""
    scan = make_scan()
    scan["os"]["is_admin"] = True
    score, breakdown, _ = evaluate(scan)
    assert breakdown["hygiene"] == 8
    assert score == 2


def test_score_powershell_only(make_scan):
    """PowerShell activ (activity, sev=low=3, w=0.3, conf=1.0):
    cat_raw = 0.9 → round = 1 → score = 0.10 * 1 = 0.1 → round = 0"""
    scan = make_scan()
    scan["processes"] = [{"pid": 1, "name": "powershell.exe"}]
    score, breakdown, _ = evaluate(scan)
    assert breakdown["activity"] == 1
    assert score == 0  # rotunjit din 0.1


def test_score_combined_winxp_plus_firewall(make_scan):
    """Combinatie WinXP + firewall off:
    - critical_risk = 60 → 0.40 * 60 = 24
    - hygiene = 24 → 0.20 * 24 = 4.8
    - Total = 28.8 → round = 29"""
    scan = make_scan()
    scan["os"]["release"] = "XP"
    scan["system_info"]["firewall"] = {"profiles": {"domain": False, "public": False}}
    score, breakdown, _ = evaluate(scan)
    assert breakdown["critical_risk"] == 60
    assert breakdown["hygiene"] == 24
    assert score == 29
