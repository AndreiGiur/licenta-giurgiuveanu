"""Tests pentru endpoints /api/v1/admin/* cu require_admin."""


def _register_login(c, email, pw="passwd123456"):
    c.post("/api/v1/auth/register", json={"email": email, "password": pw})
    c.post("/api/v1/auth/login", json={"email": email, "password": pw})


def test_admin_can_list_all_users(fresh_db_client):
    c = fresh_db_client
    _register_login(c, "admin@x.com")  # first → admin
    r = c.get("/api/v1/admin/users")
    assert r.status_code == 200, r.text
    users = r.json()
    assert len(users) >= 1
    assert any(u["email"] == "admin@x.com" and u["role"] == "admin" for u in users)


def test_regular_user_forbidden_admin(fresh_db_client):
    c = fresh_db_client
    _register_login(c, "admin@x.com")
    c.delete("/api/v1/auth/logout")
    _register_login(c, "regular@x.com")

    r = c.get("/api/v1/admin/users")
    assert r.status_code == 403


def test_admin_promote_demote(fresh_db_client):
    c = fresh_db_client
    _register_login(c, "admin@x.com")
    c.delete("/api/v1/auth/logout")
    _register_login(c, "regular@x.com")
    c.delete("/api/v1/auth/logout")
    _register_login(c, "admin@x.com")

    users = c.get("/api/v1/admin/users").json()
    target = next(u for u in users if u["email"] == "regular@x.com")

    r = c.post(f"/api/v1/admin/users/{target['id']}/role",
               json={"role": "admin"})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "admin"


def test_admin_cannot_demote_self(fresh_db_client):
    c = fresh_db_client
    _register_login(c, "admin@x.com")
    me = c.get("/api/v1/auth/me").json()

    r = c.post(f"/api/v1/admin/users/{me['id']}/role",
               json={"role": "user"})
    assert r.status_code == 400


def test_admin_cannot_delete_self(fresh_db_client):
    c = fresh_db_client
    _register_login(c, "admin@x.com")
    me = c.get("/api/v1/auth/me").json()

    r = c.delete(f"/api/v1/admin/users/{me['id']}")
    assert r.status_code == 400


def test_admin_reset_password_invalidates_sessions(fresh_db_client):
    c = fresh_db_client
    _register_login(c, "admin@x.com")
    c.delete("/api/v1/auth/logout")
    _register_login(c, "regular@x.com")
    me = c.get("/api/v1/auth/me").json()
    target_id = me["id"]
    c.delete("/api/v1/auth/logout")
    _register_login(c, "admin@x.com")

    r = c.post(f"/api/v1/admin/users/{target_id}/reset-password",
               json={"new_password": "newpasswd123"})
    assert r.status_code == 200, r.text

    # Login cu vechea parola → fail
    c.delete("/api/v1/auth/logout")
    r = c.post("/api/v1/auth/login",
               json={"email": "regular@x.com", "password": "passwd123456"})
    assert r.status_code == 401

    # Login cu noua parola → OK
    r = c.post("/api/v1/auth/login",
               json={"email": "regular@x.com", "password": "newpasswd123"})
    assert r.status_code == 200


def test_admin_delete_user(fresh_db_client):
    c = fresh_db_client
    _register_login(c, "admin@x.com")
    c.delete("/api/v1/auth/logout")
    _register_login(c, "regular@x.com")
    me = c.get("/api/v1/auth/me").json()
    target_id = me["id"]
    c.delete("/api/v1/auth/logout")
    _register_login(c, "admin@x.com")

    r = c.delete(f"/api/v1/admin/users/{target_id}")
    assert r.status_code == 204

    users = c.get("/api/v1/admin/users").json()
    assert not any(u["id"] == target_id for u in users)


def test_admin_list_devices_includes_other_users(fresh_db_client):
    c = fresh_db_client
    _register_login(c, "admin@x.com")
    c.delete("/api/v1/auth/logout")
    _register_login(c, "regular@x.com")
    c.post("/api/v1/devices",
           json={"device_uid": "regular-pc", "name": "Regular PC",
                 "token_hash": "a" * 64})
    c.delete("/api/v1/auth/logout")
    _register_login(c, "admin@x.com")

    r = c.get("/api/v1/admin/devices")
    assert r.status_code == 200, r.text
    devices = r.json()
    assert any(d["device_uid"] == "regular-pc" and d["owner_email"] == "regular@x.com"
               for d in devices)


def test_admin_list_scans_paginated(fresh_db_client):
    c = fresh_db_client
    _register_login(c, "admin@x.com")
    r = c.get("/api/v1/admin/scans?limit=20&offset=0")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "items" in body
    assert "total" in body
    assert body["limit"] == 20
    assert body["offset"] == 0
