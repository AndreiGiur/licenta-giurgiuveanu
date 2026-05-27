"""Rule contract tests — verifica metadata pe toate regulile inregistrate.

Acestea sunt 'guardrails' pentru orice regula noua adaugata la motor: previn
regresia in calitate (e.g. compliance lipsa, weight 0, confidence > 1, rule_id
duplicat). Daca un test esueaza, regula respectiva are metadata invalida.
"""
import inspect
import re

import pytest

from server.app.rules import (
    _RULES,
    CATEGORIES,
    LEVEL_ORDER,
)


def test_all_rules_have_unique_rule_id():
    """Toate regulile inregistrate trebuie sa aiba `rule_id` unic."""
    ids = [fn._rule_id for fn in _RULES]
    duplicates = [rid for rid in ids if ids.count(rid) > 1]
    assert not duplicates, f"Rule IDs duplicate detectate: {sorted(set(duplicates))}"


def test_all_rules_have_compliance_refs():
    """Fiecare regula trebuie sa aiba cel putin 1 referinta la standard de securitate.
    Aceasta e o cerinta a designului — toate regulile sunt mapate la CIS Controls v8
    sau NIST CSF 2.0."""
    missing = [fn._rule_id for fn in _RULES if not getattr(fn, "_compliance", None)]
    assert not missing, f"Reguli fara compliance refs: {missing}"


def test_all_rules_have_valid_category():
    """Category-ul trebuie sa fie unul din CATEGORIES (critical_risk / network_exposure
    / hygiene / activity)."""
    bad = [(fn._rule_id, fn._category) for fn in _RULES if fn._category not in CATEGORIES]
    assert not bad, f"Reguli cu category invalida: {bad}"


def test_all_rules_have_valid_min_level():
    """min_level trebuie sa fie unul din LEVEL_ORDER (standard / advanced / deep)."""
    bad = [(fn._rule_id, fn._min_level) for fn in _RULES if fn._min_level not in LEVEL_ORDER]
    assert not bad, f"Reguli cu min_level invalid: {bad}"


def test_all_rules_have_reasonable_weight():
    """Weight trebuie sa fie pozitiv si rezonabil (0.1 - 5.0). Valori dincolo
    de acest interval indica fie regula prea agresiva (weight > 5), fie efectiv
    inutila (weight < 0.1)."""
    bad = [(fn._rule_id, fn._weight) for fn in _RULES if not (0.1 <= fn._weight <= 5.0)]
    assert not bad, f"Reguli cu weight in afara intervalului [0.1, 5.0]: {bad}"


def test_all_rules_have_valid_confidence():
    """Confidence trebuie sa fie in [0, 1]. Valori < 0.5 indica regula cu fals-pozitivi
    foarte frecventi — flag pentru review manual."""
    bad = [(fn._rule_id, fn._confidence) for fn in _RULES if not (0.0 <= fn._confidence <= 1.0)]
    assert not bad, f"Reguli cu confidence in afara [0, 1]: {bad}"


def test_compliance_refs_format():
    """Referintele de compliance trebuie sa aiba format `<FRAMEWORK>-<CONTROL>`,
    unde FRAMEWORK e CIS sau NIST (cu sub-prefixe acceptate)."""
    pattern = re.compile(r"^(CIS|NIST)-[\w.\-]+$")
    bad: list[tuple[str, str]] = []
    for fn in _RULES:
        for ref in fn._compliance:
            if not pattern.match(ref):
                bad.append((fn._rule_id, ref))
    assert not bad, f"Refs compliance cu format invalid (asteptat CIS-X.Y sau NIST-XX.YY-NN): {bad}"


def test_rule_id_naming_convention():
    """Rule ID-urile trebuie sa urmeze formatul UPPER-CASE cu dash-uri si suffix numeric.
    Exemplu: NET-OPEN-PORTS-1, REG-HIJACK-1, EVENTLOG-BRUTEFORCE-1.
    Asta asigura sortarea predictibila si filtrarea usoara in UI."""
    pattern = re.compile(r"^[A-Z]+(-[A-Z]+)*-\d+$")
    bad = [fn._rule_id for fn in _RULES if not pattern.match(fn._rule_id)]
    assert not bad, f"Rule IDs care nu respecta formatul UPPER-CASE-WITH-N: {bad}"


def test_all_rule_functions_have_correct_signature():
    """Toate functiile de regula trebuie sa accepte un singur parametru `scan: dict`
    (pe langa decorator). Asta asigura ca motorul le poate invoca uniform."""
    bad = []
    for fn in _RULES:
        sig = inspect.signature(fn)
        params = list(sig.parameters.values())
        if len(params) != 1:
            bad.append((fn._rule_id, f"got {len(params)} params, expected 1"))
            continue
        first = params[0]
        if first.name != "scan":
            bad.append((fn._rule_id, f"first param name='{first.name}', expected 'scan'"))
    assert not bad, f"Functii cu signature gresit: {bad}"


@pytest.mark.parametrize("rule_fn", _RULES, ids=lambda fn: fn._rule_id)
def test_rule_returns_valid_type_on_empty_scan(rule_fn, make_scan):
    """Fiecare regula trebuie sa returneze None / dict / list[dict] cand
    primeste un scan curat (nu trebuie sa arunce exceptii sau sa intoarca tipuri
    aleatorii)."""
    # Folosim scan_type=deep ca toate regulile sa aiba sansa de a rula
    scan = make_scan(scan_type="deep")
    result = rule_fn(scan)
    if result is None:
        return
    if isinstance(result, dict):
        # Trebuie sa contina campurile minime
        assert "rule_id" in result
        assert "severity" in result
        assert "title" in result
        return
    if isinstance(result, list):
        for item in result:
            assert isinstance(item, dict)
            assert "rule_id" in item
        return
    pytest.fail(f"Rule {rule_fn._rule_id} returned invalid type: {type(result).__name__}")


def test_rules_count_matches_expectation():
    """Pragul de regularitate — daca cineva sterge accidental o regula, prinde aici.
    Actualmente: 24 reguli active. Cresterea e OK (adaugare). Scaderea trebuie verificata."""
    assert len(_RULES) >= 24, f"Numarul de reguli a scazut: {len(_RULES)} (minim asteptat 24)"


def test_categories_coverage_balanced():
    """Toate cele 4 categorii trebuie sa aiba cel putin 2 reguli. Asta asigura ca
    nicio dimensiune a scorului nu e total degradata daca o regula esueaza/e dezactivata."""
    from collections import Counter
    counts = Counter(fn._category for fn in _RULES)
    for cat in CATEGORIES:
        assert counts.get(cat, 0) >= 2, f"Categoria {cat!r} are doar {counts.get(cat, 0)} reguli (min 2)"
