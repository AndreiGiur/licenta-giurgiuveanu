"""Test E2E al fluxului scan-on-demand: UI <-> backend <-> agent.

Aceste teste strabat INTREG lantul intr-un singur scenariu, traversand toate
modulele server-side (auth -> devices -> scan_jobs -> agent -> rules ->
persistenta -> citire UI). Spre deosebire de testele unitare care valideaza
fiecare endpoint izolat, aici simulam agentul real la granita HTTP: foloseste
exact aceleasi endpoint-uri si acelasi header `X-Device-Token` pe care le
foloseste executabilul.

Lifecycle:
  UI    register + login                       (cookie / session)
  Agent POST /devices            (enroll, trimite token_hash)
  Agent POST /agent/heartbeat    (device online)
  UI    POST /devices/{uid}/scan-jobs          (job pending)
  Agent GET  /agent/jobs/next    (pickup -> running)
  Agent POST /agent/jobs/{id}/progress
  Agent POST /agent/jobs/{id}/result           (scoring -> Scan + Findings)
  UI    GET  /scan-jobs/{id}                    (done + scan_id + score)
  UI    GET  /scans/{scan_id}                   (findings vizibile)
"""
import uuid

from conftest import make_token_pair


def _register_and_login(client) -> dict:
    email = f"e2e-{uuid.uuid4().hex[:8]}@example.com"
    r = client.post("/api/v1/auth/register", json={"email": email, "password": "password123"})
    assert r.status_code == 200, r.text
    r = client.post("/api/v1/auth/login", json={"email": email, "password": "password123"})
    assert r.status_code == 200, r.text
    return {"email": email, "headers": {"X-Session-Token": r.json()["session_token"]}}


def _agent_scan_payload() -> dict:
    """Payload in forma pe care o trimite agentul (JobResultIn), construit ca sa
    declanseze findings cunoscute: porturi riscante + OS EOL + software vulnerabil."""
    return {
        "os": {
            "system": "Windows", "release": "XP", "version": "5.1",
            "machine": "x86", "hostname": "victim-pc", "is_admin": True,
        },
        "system_info": {"firewall": {"profiles": {"domain": False, "public": False}}},
        "network": {"open_ports": [445, 3389, 23]},
        "processes": [{"pid": 1, "name": "explorer.exe", "memory_mb": 50}],
        "software": [{"name": "Adobe Flash Player", "version": "32.0"}],
        "persistence": None,
        "forensics": None,
        "nmap": None,
    }


def test_full_scan_on_demand_lifecycle(client):
    ui = _register_and_login(client)
    headers = ui["headers"]

    # ── Agent enroll: creeaza device cu token_hash (token plain ramane local) ──
    token_plain, token_hash = make_token_pair()
    device_uid = f"e2e-dev-{uuid.uuid4().hex[:6]}"
    r = client.post("/api/v1/devices", headers=headers, json={
        "device_uid": device_uid, "name": "E2E Box", "token_hash": token_hash,
    })
    assert r.status_code == 200, r.text
    dev_headers = {"X-Device-Token": token_plain}

    # ── Agent heartbeat → device online ──
    r = client.post("/api/v1/agent/heartbeat", headers=dev_headers, json={
        "agent_version": "1.0.0", "capabilities": ["standard", "advanced"],
        "os_version": "Windows XP 5.1",
    })
    assert r.status_code == 204, r.text

    # ── UI cere scanare on-demand ──
    r = client.post(f"/api/v1/devices/{device_uid}/scan-jobs", headers=headers,
                    json={"scan_type": "standard"})
    assert r.status_code == 200, r.text
    job = r.json()
    job_id = job["job_id"]
    assert job["status"] == "pending"

    # ── UI polleaza → inca pending ──
    r = client.get(f"/api/v1/scan-jobs/{job_id}", headers=headers)
    assert r.status_code == 200 and r.json()["status"] == "pending"

    # ── Agent ridica jobul (atomic pending -> running) ──
    r = client.get("/api/v1/agent/jobs/next", headers=dev_headers)
    assert r.status_code == 200, r.text
    picked = r.json()
    assert picked["job_id"] == job_id
    assert picked["scan_type"] == "standard"
    assert picked["device_uid"] == device_uid

    # ── Agent raporteaza progres ──
    r = client.post(f"/api/v1/agent/jobs/{job_id}/progress", headers=dev_headers,
                    json={"progress": 50, "phase": "Procese"})
    assert r.status_code == 204
    r = client.get(f"/api/v1/scan-jobs/{job_id}", headers=headers)
    assert r.json()["status"] == "running" and r.json()["progress"] == 50

    # ── Agent trimite rezultatul → scoring + Scan + Findings ──
    r = client.post(f"/api/v1/agent/jobs/{job_id}/result", headers=dev_headers,
                    json=_agent_scan_payload())
    assert r.status_code == 200, r.text
    done = r.json()
    assert done["status"] == "done"
    assert done["scan_id"] is not None
    assert done["exposure_score"] is not None and done["exposure_score"] > 0
    scan_id = done["scan_id"]

    # ── UI polleaza → vede done + scan_id ──
    r = client.get(f"/api/v1/scan-jobs/{job_id}", headers=headers)
    assert r.json()["status"] == "done" and r.json()["scan_id"] == scan_id

    # ── UI deschide detaliul scan-ului → findings propagate prin tot lantul ──
    r = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert r.status_code == 200, r.text
    detail = r.json()
    rule_ids = {f["rule_id"] for f in detail["findings"]}
    assert "NET-OPEN-PORTS-1" in rule_ids   # 445/3389/23 riscante
    assert "OS-EOL-1" in rule_ids           # Windows XP
    assert "SW-VULNERABLE-1" in rule_ids    # Adobe Flash
    assert detail["exposure_score"] == done["exposure_score"]

    # ── UI vede scan-ul in lista device-ului ──
    r = client.get(f"/api/v1/devices/{device_uid}/scans", headers=headers)
    assert r.status_code == 200
    assert any(s["scan_id"] == scan_id for s in r.json())


def test_e2e_agent_job_failure_flow(client):
    """Agentul ridica jobul, dar raporteaza esec → job failed cu mesaj."""
    ui = _register_and_login(client)
    headers = ui["headers"]
    token_plain, token_hash = make_token_pair()
    device_uid = f"e2e-fail-{uuid.uuid4().hex[:6]}"
    client.post("/api/v1/devices", headers=headers, json={
        "device_uid": device_uid, "name": "Fail Box", "token_hash": token_hash,
    })
    dev_headers = {"X-Device-Token": token_plain}

    r = client.post(f"/api/v1/devices/{device_uid}/scan-jobs", headers=headers,
                    json={"scan_type": "advanced"})
    job_id = r.json()["job_id"]

    # Pickup
    r = client.get("/api/v1/agent/jobs/next", headers=dev_headers)
    assert r.json()["job_id"] == job_id

    # Fail
    r = client.post(f"/api/v1/agent/jobs/{job_id}/fail", headers=dev_headers,
                    json={"error_message": "nmap a crapat"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "failed"

    # UI vede failed + mesajul
    r = client.get(f"/api/v1/scan-jobs/{job_id}", headers=headers)
    assert r.json()["status"] == "failed"
    assert "nmap" in (r.json()["error_message"] or "")


def test_e2e_wrong_device_token_cannot_pickup_others_job(client):
    """Izolare: tokenul device-ului B nu poate ridica jobul device-ului A."""
    ui = _register_and_login(client)
    headers = ui["headers"]

    # Device A cu un job pending
    tA_plain, tA_hash = make_token_pair()
    uidA = f"e2e-A-{uuid.uuid4().hex[:6]}"
    client.post("/api/v1/devices", headers=headers, json={
        "device_uid": uidA, "name": "A", "token_hash": tA_hash,
    })
    client.post(f"/api/v1/devices/{uidA}/scan-jobs", headers=headers,
                json={"scan_type": "standard"})

    # Device B (acelasi user, alt token) — nu trebuie sa vada jobul lui A
    tB_plain, tB_hash = make_token_pair()
    uidB = f"e2e-B-{uuid.uuid4().hex[:6]}"
    client.post("/api/v1/devices", headers=headers, json={
        "device_uid": uidB, "name": "B", "token_hash": tB_hash,
    })
    r = client.get("/api/v1/agent/jobs/next", headers={"X-Device-Token": tB_plain})
    assert r.status_code == 204  # niciun job pentru device-ul B

    # Token invalid → 401
    r = client.get("/api/v1/agent/jobs/next", headers={"X-Device-Token": "garbage-token"})
    assert r.status_code == 401
