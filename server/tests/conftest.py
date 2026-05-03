import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

# 1) DB temporara SQLite per rulare de teste — inainte de import-ul aplicatiei.
_db_file = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
os.environ["DATABASE_URL"] = f"sqlite:///{_db_file.name}"

# 2) Asiguram ca radacina repo-ului e in sys.path (pentru `from server.app...`).
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from server.app.main import app  # noqa: E402
from server.app.db import Base, engine  # noqa: E402

Base.metadata.create_all(bind=engine)


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth_client(client):
    """Creeaza un user nou unic si intoarce (client, email, session_token, headers)."""
    import uuid
    email = f"u-{uuid.uuid4().hex[:8]}@example.com"
    password = "password123"

    r = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert r.status_code == 200, r.text

    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    token = r.json()["session_token"]

    headers = {"X-Session-Token": token}
    return {
        "client": client,
        "email": email,
        "password": password,
        "token": token,
        "headers": headers,
    }
