"""Teste pentru flow-ul de scan-on-demand (job queue + agent pull).

Acopera:
- happy path: user creeaza job, agent il ridica, agent trimite rezultat
- atomicitate: doi useri/agenti nu pot ridica acelasi job de doua ori
- state machine: tranzitii valide, respingere tranzitii invalide
- izolarea multi-tenant: user-ul A nu poate vedea/citi job-uri ale lui B
- deduplication: cererile rapide consecutive nu duplica job-uri pending
"""
from fastapi.testclient import TestClient

from server.app.main import app


# ── Fixtures helpers ──────────────────────────────────────────────────────────

def _new_user_client(suffix: str) -> TestClient:
    c = TestClient(app)
    email = f"jobs-{suffix}@example.com"
    password = "password123"
    c.post("/api/v1/auth/register", json={"email": email, "password": password})
    c.post("/api/v1/auth/login", json={"email": email, "password": password})
    return c


def _enroll(c: TestClient, uid: str = "host-1", name: str = "Host 1") -> dict:
    from conftest import make_token_pair
    plain, h = make_token_pair()
    r = c.post("/api/v1/devices",
               json={"device_uid": uid, "name": name, "token_hash": h})
    assert r.status_code == 200, r.text
    body = r.json()
    body["device_token"] = plain  # backend nu mai returneaza tokenul; il avem local
    return body


def _agent_client(token: str) -> TestClient:
    """Un client care simuleaza agentul: nu are cookie de sesiune,
    foloseste doar X-Device-Token in headere."""
    c = TestClient(app)
    c.headers.update({"X-Device-Token": token})
    return c


def _sample_payload() -> dict:
    return {
        "os": {"system": "Linux", "release": "6.5", "version": "1",
               "machine": "x86_64", "hostname": "h", "is_admin": False},
        "network": {"open_ports": [22, 445]},  # 445 = riscant → minim un finding
        "processes": [],
        "software": [],
    }


# ── Happy path ────────────────────────────────────────────────────────────────

def test_full_scan_job_flow():
    user_c = _new_user_client("happy")
    dev = _enroll(user_c, "happy-host")
    agent_c = _agent_client(dev["device_token"])

    # 1. User cere scanare
    r = user_c.post(f"/api/v1/devices/{dev['device_uid']}/scan-jobs")
    assert r.status_code == 200, r.text
    job = r.json()
    assert job["status"] == "pending"
    job_id = job["job_id"]

    # 2. Agent ridica jobul
    r = agent_c.get("/api/v1/agent/jobs/next")
    assert r.status_code == 200, r.text
    picked = r.json()
    assert picked["job_id"] == job_id
    assert picked["device_uid"] == dev["device_uid"]

    # 2b. Status devine running
    r = user_c.get(f"/api/v1/scan-jobs/{job_id}")
    assert r.status_code == 200
    assert r.json()["status"] == "running"

    # 3. Agent trimite rezultatul
    r = agent_c.post(
        f"/api/v1/agent/jobs/{job_id}/result",
        json=_sample_payload(),
    )
    assert r.status_code == 200, r.text
    final = r.json()
    assert final["status"] == "done"
    assert final["scan_id"] is not None
    assert final["exposure_score"] is not None

    # 4. Scanul produs e accesibil pentru user
    r = user_c.get(f"/api/v1/scans/{final['scan_id']}")
    assert r.status_code == 200
    detail = r.json()
    assert any(f["rule_id"] == "NET-OPEN-PORTS-1" for f in detail["findings"])


def test_no_jobs_returns_204():
    user_c = _new_user_client("idle")
    dev = _enroll(user_c, "idle-host")
    agent_c = _agent_client(dev["device_token"])

    r = agent_c.get("/api/v1/agent/jobs/next")
    assert r.status_code == 204


# ── Atomicitate la pickup ─────────────────────────────────────────────────────

def test_two_polls_pick_different_jobs():
    """Doua poll-uri consecutive ridica fiecare alt job — niciun job nu este
    procesat de doua ori."""
    user_c = _new_user_client("atomic")
    dev = _enroll(user_c, "atomic-host")
    agent_c = _agent_client(dev["device_token"])

    # User cere 2 scanari pentru acelasi device — dar deduplication face ca
    # a doua sa returneze acelasi job. Inserezi al doilea direct dupa ce
    # primul devine running (nu mai e candidat de dedupe).
    r1 = user_c.post(f"/api/v1/devices/{dev['device_uid']}/scan-jobs")
    job1_id = r1.json()["job_id"]

    # Agent ridica primul (devine running)
    picked1 = agent_c.get("/api/v1/agent/jobs/next").json()
    assert picked1["job_id"] == job1_id

    # User cere alta scanare → job nou pending
    r2 = user_c.post(f"/api/v1/devices/{dev['device_uid']}/scan-jobs")
    job2_id = r2.json()["job_id"]
    assert job2_id != job1_id  # NU e dedupe pentru ca primul e running

    # Al doilea poll ridica al doilea job
    picked2 = agent_c.get("/api/v1/agent/jobs/next").json()
    assert picked2["job_id"] == job2_id

    # Al treilea poll → 204 (nimic in coada)
    assert agent_c.get("/api/v1/agent/jobs/next").status_code == 204


def test_request_dedupe_for_pending_job():
    """Daca user-ul apasa de 2x pe Scan now in succesiune, nu se creeaza 2 joburi."""
    user_c = _new_user_client("dedupe")
    dev = _enroll(user_c, "dedupe-host")

    r1 = user_c.post(f"/api/v1/devices/{dev['device_uid']}/scan-jobs").json()
    r2 = user_c.post(f"/api/v1/devices/{dev['device_uid']}/scan-jobs").json()
    assert r1["job_id"] == r2["job_id"]
    assert r1["status"] == "pending"


# ── State machine: tranzitii invalide ─────────────────────────────────────────

def test_cannot_submit_result_for_pending_job():
    """Agentul nu poate trimite rezultate pentru un job care nu a trecut prin
    'running' — tranzitia pending → done direct e respinsa."""
    user_c = _new_user_client("bad-state")
    dev = _enroll(user_c, "bad-state-host")
    agent_c = _agent_client(dev["device_token"])

    job = user_c.post(f"/api/v1/devices/{dev['device_uid']}/scan-jobs").json()
    # NU ridicam jobul; il lasam pending
    r = agent_c.post(f"/api/v1/agent/jobs/{job['job_id']}/result",
                     json=_sample_payload())
    assert r.status_code == 409


def test_cannot_submit_result_twice():
    user_c = _new_user_client("twice")
    dev = _enroll(user_c, "twice-host")
    agent_c = _agent_client(dev["device_token"])

    user_c.post(f"/api/v1/devices/{dev['device_uid']}/scan-jobs")
    picked = agent_c.get("/api/v1/agent/jobs/next").json()
    job_id = picked["job_id"]

    r1 = agent_c.post(f"/api/v1/agent/jobs/{job_id}/result",
                      json=_sample_payload())
    assert r1.status_code == 200

    # A doua submisie → 409 (jobul e done, nu running)
    r2 = agent_c.post(f"/api/v1/agent/jobs/{job_id}/result",
                      json=_sample_payload())
    assert r2.status_code == 409


def test_agent_can_report_failure():
    user_c = _new_user_client("fail")
    dev = _enroll(user_c, "fail-host")
    agent_c = _agent_client(dev["device_token"])

    user_c.post(f"/api/v1/devices/{dev['device_uid']}/scan-jobs")
    picked = agent_c.get("/api/v1/agent/jobs/next").json()
    job_id = picked["job_id"]

    r = agent_c.post(f"/api/v1/agent/jobs/{job_id}/fail",
                     json={"error_message": "AccessDenied la net_connections"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "failed"
    assert "AccessDenied" in body["error_message"]


# ── Multi-tenant izolare ──────────────────────────────────────────────────────

def test_user_cannot_create_job_on_other_users_device():
    a = _new_user_client("iso-a")
    b = _new_user_client("iso-b")
    dev_a = _enroll(a, "device-a")

    r = b.post(f"/api/v1/devices/{dev_a['device_uid']}/scan-jobs")
    assert r.status_code == 404


def test_user_cannot_poll_other_users_job():
    a = _new_user_client("poll-a")
    b = _new_user_client("poll-b")
    dev_a = _enroll(a, "device-a")
    job = a.post(f"/api/v1/devices/{dev_a['device_uid']}/scan-jobs").json()

    r = b.get(f"/api/v1/scan-jobs/{job['job_id']}")
    assert r.status_code == 404


def test_agent_token_only_sees_its_own_jobs():
    """Agent-ul lui A nu poate ridica jobul lui B chiar daca jobul e pending."""
    a = _new_user_client("agent-iso-a")
    b = _new_user_client("agent-iso-b")
    dev_a = _enroll(a, "device-a")
    dev_b = _enroll(b, "device-b")

    # User B creeaza un job pe device-ul lui
    b.post(f"/api/v1/devices/{dev_b['device_uid']}/scan-jobs")

    # Agent-ul lui A polleaza → 204 (nu e jobul lui)
    agent_a = _agent_client(dev_a["device_token"])
    r = agent_a.get("/api/v1/agent/jobs/next")
    assert r.status_code == 204

    # Agent-ul lui B polleaza → primeste jobul
    agent_b = _agent_client(dev_b["device_token"])
    r = agent_b.get("/api/v1/agent/jobs/next")
    assert r.status_code == 200


def test_agent_cannot_submit_to_other_devices_job():
    """Defense-in-depth: chiar daca cineva afla job_id, nu poate inchide
    jobul cu un token de la alt device."""
    a = _new_user_client("submit-a")
    b = _new_user_client("submit-b")
    dev_a = _enroll(a, "device-a")
    dev_b = _enroll(b, "device-b")

    # B creeaza job + agent-ul lui ridica
    b.post(f"/api/v1/devices/{dev_b['device_uid']}/scan-jobs")
    picked = _agent_client(dev_b["device_token"]).get("/api/v1/agent/jobs/next").json()

    # Agent-ul lui A incearca sa trimita rezultat pentru jobul lui B
    r = _agent_client(dev_a["device_token"]).post(
        f"/api/v1/agent/jobs/{picked['job_id']}/result",
        json=_sample_payload(),
    )
    assert r.status_code == 404


# ── Listare istoric ──────────────────────────────────────────────────────────

def test_list_scan_jobs_returns_recent_first():
    user_c = _new_user_client("history")
    dev = _enroll(user_c, "history-host")
    agent_c = _agent_client(dev["device_token"])

    # Creem 3 joburi finalizate
    job_ids: list[int] = []
    for _ in range(3):
        j = user_c.post(f"/api/v1/devices/{dev['device_uid']}/scan-jobs").json()
        job_ids.append(j["job_id"])
        agent_c.get("/api/v1/agent/jobs/next")
        agent_c.post(f"/api/v1/agent/jobs/{j['job_id']}/result", json=_sample_payload())

    r = user_c.get(f"/api/v1/devices/{dev['device_uid']}/scan-jobs")
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 3
    # Sortat descrescator dupa id
    assert [it["job_id"] for it in items] == list(reversed(job_ids))
    assert all(it["status"] == "done" for it in items)
