"""Teste pentru noul sistem de scoring multidimensional.

Verifica:
  - structura breakdown dict (4 categorii fixe)
  - cap per categorie la 100
  - aggregat ponderat 0.40/0.30/0.20/0.10
  - weight + confidence per regula sunt aplicate
  - findings primesc metadata `category`, `rule_weight`, `rule_confidence`
"""
from server.app.rules import (
    evaluate, CATEGORIES, CATEGORY_AGGREGATE_WEIGHT, SEVERITY_WEIGHT,
    _RULES, rule,
)


def _empty(scan_type: str = "standard") -> dict:
    return {
        "scan_type": scan_type,
        "device_uid": "x",
        "os": {"system": "Windows", "release": "11", "version": "10",
               "machine": "AMD64", "hostname": "h", "is_admin": False, "username": "u"},
        "network": {"open_ports": []},
        "processes": [],
        "software": [],
        "system_info": {},
        "persistence": None,
        "forensics": None,
    }


def test_evaluate_returns_three_tuple():
    score, breakdown, findings = evaluate(_empty())
    assert isinstance(score, int)
    assert isinstance(breakdown, dict)
    assert isinstance(findings, list)


def test_breakdown_has_all_4_categories():
    _, breakdown, _ = evaluate(_empty())
    assert set(breakdown.keys()) == set(CATEGORIES)
    for c in CATEGORIES:
        assert breakdown[c] == 0


def test_categories_constant_is_4_entries():
    assert len(CATEGORIES) == 4
    assert CATEGORIES == ("critical_risk", "network_exposure", "hygiene", "activity")


def test_aggregate_weights_sum_to_one():
    assert abs(sum(CATEGORY_AGGREGATE_WEIGHT.values()) - 1.0) < 1e-9


def test_per_category_score_capped_at_100():
    """Daca dam multe findings critice in aceeasi categorie, scor cap la 100."""
    scan = _empty()
    scan["os"]["release"] = "XP"  # critical_risk, sev=critical, w=1.5 → 60
    scan["software"] = [
        {"name": "Adobe Flash Player"},  # critical_risk, sev=critical, w=1.5 → 60
        {"name": "Internet Explorer 11"},  # critical_risk, sev=high, w=1.5 → 30
        {"name": "Java 6 Update 1"},  # critical_risk, sev=high, w=1.5 → 30
    ]
    scan["processes"] = [{"name": "mimikatz.exe", "pid": 1}]  # critical_risk
    _, breakdown, _ = evaluate(scan)
    assert breakdown["critical_risk"] == 100  # cap


def test_aggregate_score_uses_weights():
    """1 finding high in critical_risk vs 1 in activity → diferenta clara."""
    # critical_risk: SW-VULNERABLE Internet Explorer 11 → sev=high (20) * w=1.5 = 30
    # aggregate = 0.40 * 30 = 12
    scan = _empty()
    scan["software"] = [{"name": "Internet Explorer 11"}]
    score_cr, breakdown_cr, _ = evaluate(scan)
    assert breakdown_cr["critical_risk"] == 30
    assert breakdown_cr["network_exposure"] == 0
    assert score_cr == round(0.40 * 30)  # = 12

    # activity: PROC-POWERSHELL → sev=low (3) * w=0.3 = 0.9 → round = 1
    # aggregate = 0.10 * 1 = 0.1 → 0
    scan2 = _empty()
    scan2["processes"] = [{"name": "powershell.exe", "pid": 1}]
    score_act, breakdown_act, _ = evaluate(scan2)
    assert breakdown_act["activity"] == 1
    assert score_act == 0  # rotunjit din 0.1


def test_findings_decorated_with_category_metadata():
    scan = _empty()
    scan["network"]["open_ports"] = [3389, 445]
    _, _, findings = evaluate(scan)
    assert len(findings) >= 1
    f = findings[0]
    assert "category" in f
    assert "rule_weight" in f
    assert "rule_confidence" in f
    assert f["category"] in CATEGORIES


def test_confidence_penalty_applied():
    """STARTUP-SUSPICIOUS are confidence=0.7 — verifica ca scorul tine cont."""
    scan = _empty("advanced")
    scan["persistence"] = {
        "startup": [{"key": "Run", "path": "C:\\Users\\x\\AppData\\Local\\Temp\\evil.exe"}]
    }
    _, breakdown, findings = evaluate(scan)
    suspicious = [f for f in findings if f["rule_id"] == "STARTUP-SUSPICIOUS-1"]
    assert len(suspicious) == 1
    assert suspicious[0]["rule_confidence"] == 0.7
    # sev=high (20) * w=0.7 * conf=0.7 = 9.8 → round → 10
    assert breakdown["activity"] == 10


def test_severity_weights_updated():
    """Noua paleta de severitati."""
    assert SEVERITY_WEIGHT == {"critical": 40, "high": 20, "medium": 10, "low": 3, "info": 0}


def test_all_rules_have_category():
    """Toate regulile inregistrate au atribute valide pentru noul scoring."""
    for fn in _RULES:
        assert hasattr(fn, "_category")
        assert fn._category in CATEGORIES
        assert hasattr(fn, "_weight") and fn._weight > 0
        assert hasattr(fn, "_confidence") and 0 < fn._confidence <= 1


def test_rule_decorator_rejects_invalid_category():
    try:
        @rule("TEST-INVALID", category="nonexistent")
        def _fake(scan):
            return None
        assert False, "should have raised"
    except ValueError as e:
        assert "category invalid" in str(e)


def test_rule_decorator_rejects_invalid_confidence():
    try:
        @rule("TEST-INVALID-CONF", category="hygiene", confidence=1.5)
        def _fake(scan):
            return None
        assert False, "should have raised"
    except ValueError as e:
        assert "confidence" in str(e)
