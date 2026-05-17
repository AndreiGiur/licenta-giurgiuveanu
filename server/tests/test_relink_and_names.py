"""Teste pentru smart re-link (GET by-uid + POST relink) si pentru
expunerea `device_name` in toate raspunsurile relevante."""
from fastapi.testclient import TestClient

from server.app.main import app


def _new_user_client(suffix: str) -> TestClient:
    c = TestClient(app)
    email = f"rel-{suffix}@example.com"
    password = "password123"
    c.post("/api/v1/auth/register", json={"email": email, "password": password})
    c.post("/api/v1/auth/login", json={"email": email, "password": password})
    return c


def _enroll(c: TestClient, uid: str = "host-1", name: str = "My Host") -> dict:
    from conftest import make_token_pair
    plain, h = make_token_pair()
    r = c.post("/api/v1/devices",
               json={"device_uid": uid, "name": name, "token_hash": h})
    assert r.status_code == 200, r.text
    body = r.json()
    body["device_token"] = plain
    return body


def _agent_client(token: str) -> TestClient:
    c = TestClient(app)
    c.headers.update({"X-Device-Token": token})
    return c


def _sample_scan(uid: str) -> dict:
    return {
        "device_uid": uid,
        "os": {"system": "Linux", "release": "6.5", "version": "1",
               "machine": "x86_64", "hostname": "h", "is_admin": False},
        "network": {"open_ports": [22]},
        "processes": [],
        "software": [],
    }


# ── Smart re-link: GET /devices/by-uid/{uid} ─────────────────────────────────

def test_get_device_by_uid_returns_existing():
    c = _new_user_client("by-uid-ok")
    enrolled = _enroll(c, "laptop-1", "My Laptop")
    r = c.get(f"/api/v1/devices/by-uid/{enrolled['device_uid']}")
    assert r.status_code == 200
    body = r.json()
    assert body["device_uid"] == "laptop-1"
    assert body["name"] == "My Laptop"
    # Tokenul NU trebuie sa apara in raspuns (e doar lookup info)
    assert "device_token" not in body


def test_get_device_by_uid_returns_404_when_missing():
    c = _new_user_client("by-uid-404")
    r = c.get("/api/v1/devices/by-uid/never-enrolled")
    assert r.status_code == 404


def test_get_device_by_uid_isolates_users():
    """User A nu poate vedea device-ul lui B chiar daca stie UID-ul."""
    a = _new_user_client("iso-a")
    b = _new_user_client("iso-b")
    _enroll(a, "shared-uid-name", "Owned by A")
    r = b.get("/api/v1/devices/by-uid/shared-uid-name")
    assert r.status_code == 404  # B nu vede device-ul lui A


# ── POST /devices/{uid}/relink ─────────────────────────────────────────────────

def test_relink_issues_new_token_and_invalidates_old():
    from conftest import make_token_pair
    c = _new_user_client("relink")
    enrolled = _enroll(c, "relink-host")
    old_token = enrolled["device_token"]

    # Vechiul token functioneaza
    agent_old = _agent_client(old_token)
    r = agent_old.post("/api/v1/scans", json=_sample_scan("relink-host"))
    assert r.status_code == 200

    # Re-link cu un nou token generat local
    new_plain, new_hash = make_token_pair()
    r = c.post("/api/v1/devices/relink-host/relink", json={"token_hash": new_hash})
    assert r.status_code == 200
    assert "device_token" not in r.json()
    assert new_plain != old_token

    # Vechiul token NU mai functioneaza
    r = agent_old.post("/api/v1/scans", json=_sample_scan("relink-host"))
    assert r.status_code == 401

    # Noul token functioneaza
    agent_new = _agent_client(new_plain)
    r = agent_new.post("/api/v1/scans", json=_sample_scan("relink-host"))
    assert r.status_code == 200


def test_relink_preserves_historical_scans():
    """Scan-urile facute inainte de re-link raman atasate de device."""
    from conftest import make_token_pair
    c = _new_user_client("relink-history")
    enrolled = _enroll(c, "history-host")
    old_agent = _agent_client(enrolled["device_token"])

    r1 = old_agent.post("/api/v1/scans", json=_sample_scan("history-host"))
    scan_id_before = r1.json()["scan_id"]

    _, new_hash = make_token_pair()
    c.post("/api/v1/devices/history-host/relink", json={"token_hash": new_hash})

    r = c.get(f"/api/v1/devices/history-host/scans")
    assert r.status_code == 200
    items = r.json()
    assert any(it["scan_id"] == scan_id_before for it in items)


def test_relink_404_for_missing_device():
    from conftest import make_token_pair
    c = _new_user_client("relink-missing")
    _, h = make_token_pair()
    r = c.post("/api/v1/devices/never-enrolled/relink", json={"token_hash": h})
    assert r.status_code == 404


def test_relink_isolates_users():
    """User-ul B nu poate face relink pe device-ul lui A."""
    from conftest import make_token_pair
    a = _new_user_client("relink-iso-a")
    b = _new_user_client("relink-iso-b")
    _enroll(a, "victim-host")

    _, h = make_token_pair()
    r = b.post("/api/v1/devices/victim-host/relink", json={"token_hash": h})
    assert r.status_code == 404


# ── device_name in scan responses ─────────────────────────────────────────────

def test_scan_create_response_includes_device_name():
    c = _new_user_client("name-create")
    enrolled = _enroll(c, "named-host", "Pretty Name")
    agent = _agent_client(enrolled["device_token"])
    r = agent.post("/api/v1/scans", json=_sample_scan("named-host"))
    assert r.status_code == 200
    body = r.json()
    assert body["device_uid"] == "named-host"
    assert body["device_name"] == "Pretty Name"


def test_scan_detail_response_includes_device_name():
    c = _new_user_client("name-detail")
    enrolled = _enroll(c, "detail-host", "Detail Friendly")
    agent = _agent_client(enrolled["device_token"])
    scan = agent.post("/api/v1/scans", json=_sample_scan("detail-host")).json()
    r = c.get(f"/api/v1/scans/{scan['scan_id']}")
    assert r.status_code == 200
    body = r.json()
    assert body["device_name"] == "Detail Friendly"


def test_scan_job_response_includes_device_name():
    c = _new_user_client("name-job")
    enrolled = _enroll(c, "job-host", "Job Friendly")
    job = c.post(f"/api/v1/devices/{enrolled['device_uid']}/scan-jobs").json()
    assert job["device_name"] == "Job Friendly"

    # Polling-ul agentului include si device_name
    agent = _agent_client(enrolled["device_token"])
    r = c.get(f"/api/v1/scan-jobs/{job['job_id']}")
    assert r.json()["device_name"] == "Job Friendly"

    # Dupa finalizare, raspunsul ramane cu nume
    agent.get("/api/v1/agent/jobs/next")
    final = agent.post(
        f"/api/v1/agent/jobs/{job['job_id']}/result",
        json={"os": _sample_scan("job-host")["os"], "network": {"open_ports": []},
              "processes": [], "software": []},
    ).json()
    assert final["device_name"] == "Job Friendly"


def test_scan_job_list_includes_device_name():
    c = _new_user_client("name-list")
    enrolled = _enroll(c, "list-host", "List Friendly")
    c.post(f"/api/v1/devices/{enrolled['device_uid']}/scan-jobs")
    items = c.get(f"/api/v1/devices/{enrolled['device_uid']}/scan-jobs").json()
    assert items
    assert all(it["device_name"] == "List Friendly" for it in items)
