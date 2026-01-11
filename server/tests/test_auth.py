def test_register_login_logout(client):
    # Register
    r = client.post("/api/v1/auth/register", json={"email": "test@example.com", "password": "password123"})
    assert r.status_code == 200, r.text

    # Login
    r = client.post("/api/v1/auth/login", json={"email": "test@example.com", "password": "password123"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert "session_token" in data
    token = data["session_token"]

    # Me
    r = client.get("/api/v1/auth/me", headers={"X-Session-Token": token})
    assert r.status_code == 200, r.text
    me = r.json()
    assert me["email"] == "test@example.com"

    # Logout
    r = client.delete("/api/v1/auth/logout", headers={"X-Session-Token": token})
    assert r.status_code == 200, r.text

    # Me should now fail
    r = client.get("/api/v1/auth/me", headers={"X-Session-Token": token})
    assert r.status_code == 401


def test_login_invalid_credentials(client):
    # Try login with non-existent user
    r = client.post("/api/v1/auth/login", json={"email": "nonexistent@example.com", "password": "wrongpass123"})
    assert r.status_code == 401
    
    # Register a user
    r = client.post("/api/v1/auth/register", json={"email": "user2@example.com", "password": "correctpass"})
    assert r.status_code == 200
    
    # Try login with wrong password
    r = client.post("/api/v1/auth/login", json={"email": "user2@example.com", "password": "wrongpass123"})
    assert r.status_code == 401
