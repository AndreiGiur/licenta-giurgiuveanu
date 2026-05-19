"""Filtrarea regulilor dupa scan_type + ordinea LEVEL_ORDER."""
from server.app.rules import evaluate, _RULES, LEVEL_ORDER


def _empty_scan(scan_type: str = "standard") -> dict:
    return {
        "scan_type": scan_type,
        "device_uid": "x",
        "os": {"system": "Windows", "release": "11", "version": "10.0.22000", "is_admin": False},
        "system_info": {},
        "network": {"open_ports": []},
        "processes": [],
        "software": [],
        "persistence": None,
        "forensics": None,
    }


def test_standard_runs_only_standard_rules():
    """Pentru scan_type='standard', nicio regula advanced/deep nu trebuie sa
    poata gasi findings (chiar daca am avea date — care nu exista oricum)."""
    score, _, findings = evaluate(_empty_scan("standard"))
    assert score == 0
    assert findings == []


def test_advanced_can_fire_advanced_rules():
    scan = _empty_scan("advanced")
    scan["network"]["shares"] = [{"name": "MyShare", "path": "C:\\Public"}]
    score, _, findings = evaluate(scan)
    assert any(f["rule_id"] == "NET-SHARE-1" for f in findings)


def test_standard_ignores_advanced_data():
    """Chiar daca trimitem date advanced intr-un scan standard, regulile
    advanced NU ruleaza."""
    scan = _empty_scan("standard")
    scan["network"]["shares"] = [{"name": "MyShare", "path": "C:\\Public"}]
    _, _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "NET-SHARE-1" for f in findings)


def test_deep_can_fire_deep_rules():
    scan = _empty_scan("deep")
    scan["persistence"] = {"wmi_subscriptions": [{"name": "Evil", "command": "cmd.exe"}]}
    _, _, findings = evaluate(scan)
    assert any(f["rule_id"] == "WMI-PERSIST-1" for f in findings)


def test_level_order_constants():
    assert LEVEL_ORDER["standard"] == 0
    assert LEVEL_ORDER["advanced"] == 1
    assert LEVEL_ORDER["deep"] == 2


def test_rules_registered_have_min_level():
    """Toate regulile inregistrate prin @rule trebuie sa aiba _min_level."""
    assert len(_RULES) > 0
    for fn in _RULES:
        assert hasattr(fn, "_rule_id")
        assert hasattr(fn, "_min_level")
        assert fn._min_level in LEVEL_ORDER
