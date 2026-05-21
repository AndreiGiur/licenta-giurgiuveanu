"""Teste pentru noile endpoint-uri profile + trend + scan diff + compliance."""
import secrets

from fastapi.testclient import TestClient
from server.app.main import app


def _login_as_new_user(client: TestClient) -> dict:
    """Inregistreaza + logheaza un user nou. Returneaza headers cu cookie + email."""
    email = f"u{secrets.token_hex(6)}@example.com"
    pwd = "abcd1234"
    client.post("/api/v1/auth/register", json={"email": email, "password": pwd})
    r = client.post("/api/v1/auth/login", json={"email": email, "password": pwd})
    assert r.status_code == 200
    token = r.json()["session_token"]
    return {"email": email, "headers": {"X-Session-Token": token}}


def _enroll_device(client: TestClient, headers: dict, uid: str = "dev1") -> dict:
    """Inregistreaza un device si returneaza (uid, plain_token, name)."""
    plain = secrets.token_urlsafe(48)
    import hashlib
    token_hash = hashlib.sha256(plain.encode()).hexdigest()
    r = client.post(
        "/api/v1/devices",
        json={"device_uid": uid, "name": "Test Device", "token_hash": token_hash},
        headers=headers,
    )
    assert r.status_code == 200
    return {"uid": uid, "token": plain, "name": "Test Device"}


# ── PATCH /me ──────────────────────────────────────────────────────────────

def test_patch_me_updates_first_last_name(client):
    u = _login_as_new_user(client)
    r = client.patch(
        "/api/v1/me",
        json={"first_name": "Andrei", "last_name": "Giurgiuveanu"},
        headers=u["headers"],
    )
    assert r.status_code == 200
    data = r.json()
    assert data["first_name"] == "Andrei"
    assert data["last_name"] == "Giurgiuveanu"


def test_patch_me_partial_update(client):
    u = _login_as_new_user(client)
    # Doar first_name
    client.patch("/api/v1/me", json={"first_name": "X"}, headers=u["headers"])
    # Apoi doar last_name
    r = client.patch("/api/v1/me", json={"last_name": "Y"}, headers=u["headers"])
    data = r.json()
    assert data["first_name"] == "X"
    assert data["last_name"] == "Y"


def test_patch_me_default_scan_type(client):
    u = _login_as_new_user(client)
    r = client.patch(
        "/api/v1/me",
        json={"default_scan_type": "deep"},
        headers=u["headers"],
    )
    assert r.status_code == 200
    assert r.json()["default_scan_type"] == "deep"


def test_patch_me_rejects_invalid_scan_type(client):
    u = _login_as_new_user(client)
    r = client.patch(
        "/api/v1/me",
        json={"default_scan_type": "invalid"},
        headers=u["headers"],
    )
    assert r.status_code == 422


def test_patch_me_requires_auth(client):
    # Folosim un client nou ca sa nu mostenim cookie-uri din alte teste din session.
    fresh = TestClient(app)
    r = fresh.patch("/api/v1/me", json={"first_name": "x"})
    assert r.status_code == 401


def test_auth_me_includes_new_fields(client):
    u = _login_as_new_user(client)
    client.patch("/api/v1/me", json={"first_name": "Test"}, headers=u["headers"])
    r = client.get("/api/v1/auth/me", headers=u["headers"])
    data = r.json()
    assert "first_name" in data
    assert "last_name" in data
    assert "default_scan_type" in data
    assert data["first_name"] == "Test"
    assert data["default_scan_type"] == "standard"  # default


# ── Score trend endpoint ──────────────────────────────────────────────────

def test_score_trend_empty_for_no_scans(client):
    u = _login_as_new_user(client)
    d = _enroll_device(client, u["headers"])
    r = client.get(f"/api/v1/devices/{d['uid']}/score-trend", headers=u["headers"])
    assert r.status_code == 200
    assert r.json() == []


def test_score_trend_returns_chronological_points(client):
    u = _login_as_new_user(client)
    d = _enroll_device(client, u["headers"])
    # Submit 2 scans via POST /scans direct.
    for _ in range(2):
        r = client.post(
            "/api/v1/scans",
            json={
                "device_uid": d["uid"],
                "os": {"system": "Windows", "release": "11", "hostname": "h",
                       "version": "10", "machine": "AMD64", "is_admin": False},
                "network": {"open_ports": [80]},
                "processes": [], "software": [],
            },
            headers={"X-Device-Token": d["token"]},
        )
        assert r.status_code == 200
    r = client.get(f"/api/v1/devices/{d['uid']}/score-trend", headers=u["headers"])
    data = r.json()
    assert len(data) == 2
    # Ordine cronologica.
    assert data[0]["scan_id"] < data[1]["scan_id"]
    for p in data:
        assert "exposure_score" in p
        assert "scan_type" in p


def test_score_trend_404_for_unknown_device(client):
    u = _login_as_new_user(client)
    r = client.get("/api/v1/devices/nope/score-trend", headers=u["headers"])
    assert r.status_code == 404


def test_score_trend_isolated_per_user(client):
    u1 = _login_as_new_user(client)
    d = _enroll_device(client, u1["headers"], uid="ud1")
    u2 = _login_as_new_user(client)
    # User 2 incearca sa vada trend-ul lui user 1.
    r = client.get(f"/api/v1/devices/{d['uid']}/score-trend", headers=u2["headers"])
    assert r.status_code == 404


# ── Scan diff endpoint ────────────────────────────────────────────────────

def test_scan_diff_auto_picks_previous(client):
    u = _login_as_new_user(client)
    d = _enroll_device(client, u["headers"])

    # Scan 1: niciun finding.
    r1 = client.post(
        "/api/v1/scans",
        json={
            "device_uid": d["uid"],
            "os": {"system": "Windows", "release": "11", "hostname": "h",
                   "version": "10", "machine": "AMD64", "is_admin": False},
            "network": {"open_ports": []},
            "processes": [], "software": [],
        },
        headers={"X-Device-Token": d["token"]},
    )
    scan1_id = r1.json()["scan_id"]

    # Scan 2: cu finding NET-OPEN-PORTS (port 3389).
    r2 = client.post(
        "/api/v1/scans",
        json={
            "device_uid": d["uid"],
            "os": {"system": "Windows", "release": "11", "hostname": "h",
                   "version": "10", "machine": "AMD64", "is_admin": False},
            "network": {"open_ports": [3389]},
            "processes": [], "software": [],
        },
        headers={"X-Device-Token": d["token"]},
    )
    scan2_id = r2.json()["scan_id"]

    # Diff fara previous specified → backend cauta automat scan1.
    r = client.get(f"/api/v1/scans/{scan2_id}/diff", headers=u["headers"])
    assert r.status_code == 200
    data = r.json()
    assert data["from_scan_id"] == scan1_id
    assert data["to_scan_id"] == scan2_id
    assert any(f["rule_id"] == "NET-OPEN-PORTS-1" for f in data["added"])
    assert data["fixed"] == []
    assert data["delta"] > 0  # regresie: scor mai mare


def test_scan_diff_explicit_previous(client):
    u = _login_as_new_user(client)
    d = _enroll_device(client, u["headers"])
    # Doua scan-uri identice.
    ids = []
    for _ in range(2):
        r = client.post(
            "/api/v1/scans",
            json={
                "device_uid": d["uid"],
                "os": {"system": "Windows", "release": "11", "hostname": "h",
                       "version": "10", "machine": "AMD64", "is_admin": False},
                "network": {"open_ports": [3389]},
                "processes": [], "software": [],
            },
            headers={"X-Device-Token": d["token"]},
        )
        ids.append(r.json()["scan_id"])
    r = client.get(
        f"/api/v1/scans/{ids[1]}/diff?previous={ids[0]}",
        headers=u["headers"],
    )
    data = r.json()
    assert data["from_scan_id"] == ids[0]
    assert data["to_scan_id"] == ids[1]
    assert data["delta"] == 0  # acelasi scor
    assert data["added"] == []
    assert data["fixed"] == []
    assert len(data["unchanged"]) >= 1  # NET-OPEN-PORTS in ambele


def test_scan_diff_404_no_previous(client):
    u = _login_as_new_user(client)
    d = _enroll_device(client, u["headers"])
    r = client.post(
        "/api/v1/scans",
        json={
            "device_uid": d["uid"],
            "os": {"system": "Windows", "release": "11", "hostname": "h",
                   "version": "10", "machine": "AMD64", "is_admin": False},
            "network": {"open_ports": []},
            "processes": [], "software": [],
        },
        headers={"X-Device-Token": d["token"]},
    )
    sid = r.json()["scan_id"]
    r = client.get(f"/api/v1/scans/{sid}/diff", headers=u["headers"])
    assert r.status_code == 404


# ── Compliance metadata in findings ───────────────────────────────────────

def test_findings_include_compliance_refs(client):
    u = _login_as_new_user(client)
    d = _enroll_device(client, u["headers"])
    r = client.post(
        "/api/v1/scans",
        json={
            "device_uid": d["uid"],
            "os": {"system": "Windows", "release": "11", "hostname": "h",
                   "version": "10", "machine": "AMD64", "is_admin": False},
            "network": {"open_ports": [3389]},  # NET-OPEN-PORTS-1
            "processes": [], "software": [],
        },
        headers={"X-Device-Token": d["token"]},
    )
    findings = r.json()["findings"]
    net_finding = next(f for f in findings if f["rule_id"] == "NET-OPEN-PORTS-1")
    assert "compliance" in net_finding
    assert any(c.startswith("CIS-") for c in net_finding["compliance"])
    assert any(c.startswith("NIST-") for c in net_finding["compliance"])
