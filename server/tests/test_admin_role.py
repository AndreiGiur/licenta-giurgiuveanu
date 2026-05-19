"""Tests pentru User.role + first-user-admin logic."""


def test_first_registered_user_is_admin(fresh_db_client):
    c = fresh_db_client
    r = c.post("/api/v1/auth/register",
               json={"email": "first@x.com", "password": "passwd123456"})
    assert r.status_code == 200

    r = c.post("/api/v1/auth/login",
               json={"email": "first@x.com", "password": "passwd123456"})
    assert r.status_code == 200

    r = c.get("/api/v1/auth/me")
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "admin"


def test_second_user_is_regular(fresh_db_client):
    c = fresh_db_client
    # First user → admin
    c.post("/api/v1/auth/register",
           json={"email": "first@x.com", "password": "passwd123456"})
    c.post("/api/v1/auth/logout")

    # Second user
    r = c.post("/api/v1/auth/register",
               json={"email": "second@x.com", "password": "passwd123456"})
    assert r.status_code == 200

    c.post("/api/v1/auth/login",
           json={"email": "second@x.com", "password": "passwd123456"})
    r = c.get("/api/v1/auth/me")
    assert r.json()["role"] == "user"
