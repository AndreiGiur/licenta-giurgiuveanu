def test_register_login_logout(client):
    email = "test-auth-1@example.com"
    password = "password123"

    r = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert r.status_code == 200, r.text

    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    data = r.json()
    assert "session_token" in data
    token = data["session_token"]

    r = client.get("/api/v1/auth/me", headers={"X-Session-Token": token})
    assert r.status_code == 200, r.text
    assert r.json()["email"] == email

    r = client.delete("/api/v1/auth/logout", headers={"X-Session-Token": token})
    assert r.status_code == 200, r.text

    r = client.get("/api/v1/auth/me", headers={"X-Session-Token": token})
    assert r.status_code == 401


def test_login_invalid_credentials(client):
    r = client.post("/api/v1/auth/login",
                    json={"email": "nonexistent@example.com", "password": "wrongpass123"})
    assert r.status_code == 401

    r = client.post("/api/v1/auth/register",
                    json={"email": "user2@example.com", "password": "correctpass"})
    assert r.status_code == 200

    r = client.post("/api/v1/auth/login",
                    json={"email": "user2@example.com", "password": "wrongpass123"})
    assert r.status_code == 401


def test_register_invalid_email_format(client):
    """EmailStr trebuie sa respinga adrese invalide."""
    r = client.post("/api/v1/auth/register",
                    json={"email": "not-an-email", "password": "password123"})
    assert r.status_code == 422


def test_register_short_password(client):
    r = client.post("/api/v1/auth/register",
                    json={"email": "shortpw@example.com", "password": "short"})
    assert r.status_code == 422


def test_logout_is_idempotent(client):
    """Logout fara token sau cu token invalid trebuie sa intoarca 200, nu 401."""
    r = client.delete("/api/v1/auth/logout")
    assert r.status_code == 200
    r = client.delete("/api/v1/auth/logout", headers={"X-Session-Token": "invalid-token"})
    assert r.status_code == 200


def test_login_sets_cookie(client):
    """Backend trebuie sa seteze cookie-ul HttpOnly de sesiune la login."""
    email = "cookie-test@example.com"
    password = "password123"
    r = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert r.status_code == 200

    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200

    # TestClient-ul stocheaza cookie-urile automat — verificam ca s-a primit unul.
    set_cookie = r.headers.get("set-cookie", "")
    assert "vw_session=" in set_cookie
    assert "HttpOnly" in set_cookie or "httponly" in set_cookie.lower()
