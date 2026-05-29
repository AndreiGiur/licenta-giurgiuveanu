"""Teste pentru endpoint-urile de download agent."""
from pathlib import Path

from fastapi.testclient import TestClient

from server.app.main import app


def _make_user_client(suffix: str) -> TestClient:
    c = TestClient(app)
    email = f"dl-{suffix}@example.com"
    password = "password123"
    c.post("/api/v1/auth/register", json={"email": email, "password": password})
    c.post("/api/v1/auth/login", json={"email": email, "password": password})
    return c


def test_download_info_when_artifact_missing(tmp_path, monkeypatch):
    """Daca .exe nu exista, info raporteaza available=False."""
    # Pointam spre o locatie goala temporara
    from server.app.routes import _helpers
    monkeypatch.setattr(_helpers, "_AGENT_BUILD_LOCATIONS", (tmp_path,))

    c = _make_user_client("info-empty")
    r = c.get("/api/v1/agent/download/info")
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is False
    assert body["platform"] == "windows"


def test_download_404_when_artifact_missing(tmp_path, monkeypatch):
    from server.app.routes import _helpers
    monkeypatch.setattr(_helpers, "_AGENT_BUILD_LOCATIONS", (tmp_path,))

    c = _make_user_client("dl-empty")
    r = c.get("/api/v1/agent/download/windows")
    assert r.status_code == 404
    assert "build" in r.json()["detail"].lower()


def test_download_serves_file_when_present(tmp_path, monkeypatch):
    """Cand artifactul exista, endpoint-ul il serveste cu mime corect."""
    from server.app.routes import _helpers
    artifact = tmp_path / "VulnWatchAgent.exe"
    artifact.write_bytes(b"MZ\x90\x00fake-pe-binary-content")
    monkeypatch.setattr(_helpers, "_AGENT_BUILD_LOCATIONS", (tmp_path,))

    c = _make_user_client("dl-ok")

    info = c.get("/api/v1/agent/download/info").json()
    assert info["available"] is True
    assert info["size_bytes"] == artifact.stat().st_size

    r = c.get("/api/v1/agent/download/windows")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/vnd.microsoft.portable-executable"
    assert "VulnWatchAgent.exe" in r.headers.get("content-disposition", "")
    assert r.content == artifact.read_bytes()


def test_download_requires_auth():
    c = TestClient(app)
    c.cookies.clear()
    r = c.get("/api/v1/agent/download/info")
    assert r.status_code == 401
    r = c.get("/api/v1/agent/download/windows")
    assert r.status_code == 401


def test_google_enroll_requires_token_hash(monkeypatch):
    """Endpoint-ul /agent/google-enroll cere token_hash in body, NU returneaza device_token."""
    from server.app import google_auth
    from conftest import make_token_pair

    fake_payload = {"email": "newgoogle@example.com", "sub": "google-sub-newgoogle-001", "picture": None}
    monkeypatch.setattr(google_auth, "verify_id_token", lambda *a, **kw: fake_payload)

    c = TestClient(app)
    _, hash1 = make_token_pair()

    # Lipsa token_hash → 422
    r = c.post("/api/v1/agent/google-enroll", json={
        "id_token": "fake", "device_uid": "g-pc", "device_name": "G PC",
    })
    assert r.status_code == 422, r.text

    # Cu token_hash → 200, NU contine device_token in raspuns
    r = c.post("/api/v1/agent/google-enroll", json={
        "id_token": "fake", "device_uid": "g-pc", "device_name": "G PC",
        "token_hash": hash1,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "device_token" not in body
    assert body["device_uid"] == "g-pc"
    assert body["user_email"] == "newgoogle@example.com"
