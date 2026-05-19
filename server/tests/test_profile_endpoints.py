"""Tests pentru /me/sessions, /me/password, /me/stats si /admin/stats."""
from fastapi.testclient import TestClient

from server.app.main import app


def _make_token_pair():
    from conftest import make_token_pair
    return make_token_pair()


def test_me_stats_empty(auth_client):
    c, headers = auth_client["client"], auth_client["headers"]
    r = c.get("/api/v1/me/stats", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["device_count"] == 0
    assert body["scan_count"] == 0
    assert body["avg_exposure_score"] is None
    assert body["last_scan_at"] is None


def test_me_stats_with_devices_and_scans(auth_client):
    c, headers = auth_client["client"], auth_client["headers"]
    plain, h = _make_token_pair()
    c.post("/api/v1/devices", headers=headers,
           json={"device_uid": "stats-pc", "name": "Stats PC", "token_hash": h})
    c.post("/api/v1/scans", headers={"X-Device-Token": plain},
           json={"device_uid": "stats-pc",
                 "os": {"system": "Linux", "release": "6.5", "version": "1",
                        "machine": "x86_64", "hostname": "h", "is_admin": False},
                 "network": {"open_ports": [22]},
                 "processes": [], "software": []})

    r = c.get("/api/v1/me/stats", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["device_count"] >= 1
    assert body["scan_count"] >= 1
    assert body["last_scan_at"] is not None


def test_me_sessions_lists_current(auth_client):
    c, headers = auth_client["client"], auth_client["headers"]
    r = c.get("/api/v1/me/sessions", headers=headers)
    assert r.status_code == 200, r.text
    sessions = r.json()
    assert len(sessions) >= 1
    assert any(s["is_current"] for s in sessions)


def test_me_revoke_other_session(fresh_db_client):
    c = fresh_db_client
    # Register + login
    c.post("/api/v1/auth/register",
           json={"email": "sess@x.com", "password": "passwd123456"})
    c.post("/api/v1/auth/login",
           json={"email": "sess@x.com", "password": "passwd123456"})

    # Login alta sesiune (alt TestClient -> alt cookie)
    other = TestClient(app)
    other.post("/api/v1/auth/login",
               json={"email": "sess@x.com", "password": "passwd123456"})

    sessions = c.get("/api/v1/me/sessions").json()
    # Identifica sesiunea care NU e current — o revocam
    other_session_id = next(s["id"] for s in sessions if not s["is_current"])

    r = c.delete(f"/api/v1/me/sessions/{other_session_id}")
    assert r.status_code == 204

    # Other client trebuie sa primeasca 401 acum
    r2 = other.get("/api/v1/auth/me")
    assert r2.status_code == 401


def test_me_change_password(fresh_db_client):
    c = fresh_db_client
    c.post("/api/v1/auth/register",
           json={"email": "pw@x.com", "password": "oldpass123"})
    c.post("/api/v1/auth/login",
           json={"email": "pw@x.com", "password": "oldpass123"})

    r = c.post("/api/v1/me/password",
               json={"old_password": "oldpass123", "new_password": "newpass456"})
    assert r.status_code == 200, r.text

    # Login cu noua parola trebuie sa mearga
    c.delete("/api/v1/auth/logout")
    r = c.post("/api/v1/auth/login",
               json={"email": "pw@x.com", "password": "newpass456"})
    assert r.status_code == 200


def test_me_change_password_wrong_old(fresh_db_client):
    c = fresh_db_client
    c.post("/api/v1/auth/register",
           json={"email": "pw2@x.com", "password": "oldpass123"})
    c.post("/api/v1/auth/login",
           json={"email": "pw2@x.com", "password": "oldpass123"})

    r = c.post("/api/v1/me/password",
               json={"old_password": "wrongpass", "new_password": "newpass456"})
    assert r.status_code == 401


def test_admin_platform_stats(fresh_db_client):
    c = fresh_db_client
    # First = admin
    c.post("/api/v1/auth/register",
           json={"email": "adm@x.com", "password": "passwd123456"})
    c.post("/api/v1/auth/login",
           json={"email": "adm@x.com", "password": "passwd123456"})

    r = c.get("/api/v1/admin/stats")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_users"] >= 1
    assert body["total_devices"] >= 0
    assert body["scans_total"] >= 0


def test_admin_stats_forbidden_for_regular_user(fresh_db_client):
    c = fresh_db_client
    c.post("/api/v1/auth/register",
           json={"email": "adm@x.com", "password": "passwd123456"})
    c.delete("/api/v1/auth/logout")
    c.post("/api/v1/auth/register",
           json={"email": "reg@x.com", "password": "passwd123456"})
    c.post("/api/v1/auth/login",
           json={"email": "reg@x.com", "password": "passwd123456"})

    r = c.get("/api/v1/admin/stats")
    assert r.status_code == 403
