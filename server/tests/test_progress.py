"""Progress + scan_type flow complet: create job -> agent picks -> progress -> result."""
import uuid


def _enroll(auth_client) -> tuple[str, str]:
    from conftest import make_token_pair
    uid = f"dev-{uuid.uuid4().hex[:8]}"
    plain, h = make_token_pair()
    r = auth_client["client"].post(
        "/api/v1/devices",
        json={"device_uid": uid, "name": "Test", "token_hash": h},
        headers=auth_client["headers"],
    )
    assert r.status_code == 200
    return uid, plain


def test_scan_type_propagated_to_agent(auth_client):
    uid, token = _enroll(auth_client)
    client = auth_client["client"]

    r = client.post(
        f"/api/v1/devices/{uid}/scan-jobs",
        json={"scan_type": "deep"},
        headers=auth_client["headers"],
    )
    assert r.status_code == 200
    job = r.json()
    assert job["scan_type"] == "deep"
    assert job["progress"] == 0

    r = client.get("/api/v1/agent/jobs/next", headers={"X-Device-Token": token})
    assert r.status_code == 200
    agent_job = r.json()
    assert agent_job["scan_type"] == "deep"


def test_progress_update_flow(auth_client):
    uid, token = _enroll(auth_client)
    client = auth_client["client"]

    r = client.post(
        f"/api/v1/devices/{uid}/scan-jobs",
        json={"scan_type": "advanced"},
        headers=auth_client["headers"],
    )
    job_id = r.json()["job_id"]

    client.get("/api/v1/agent/jobs/next", headers={"X-Device-Token": token})

    r = client.post(
        f"/api/v1/agent/jobs/{job_id}/progress",
        json={"progress": 45, "phase": "Procese"},
        headers={"X-Device-Token": token},
    )
    assert r.status_code == 204

    r = client.get(f"/api/v1/scan-jobs/{job_id}", headers=auth_client["headers"])
    body = r.json()
    assert body["progress"] == 45
    assert body["phase"] == "Procese"
    assert body["status"] == "running"


def test_progress_keeps_device_online(auth_client):
    """In timpul unui scan lung (deep), heartbeat-ul agentului e blocat de scan,
    dar progresul curge — backend-ul trebuie sa trateze progresul ca semn de
    viata si sa mentina device-ul ONLINE (fix 'fara conexiune' in timpul deep)."""
    uid, token = _enroll(auth_client)
    client = auth_client["client"]
    # Device proaspat enroll-at, fara heartbeat → ar fi offline.
    r = client.get("/api/v1/devices/by-uid/" + uid, headers=auth_client["headers"])
    assert r.json()["is_online"] is False

    r = client.post(f"/api/v1/devices/{uid}/scan-jobs", json={"scan_type": "deep"},
                    headers=auth_client["headers"])
    job_id = r.json()["job_id"]
    client.get("/api/v1/agent/jobs/next", headers={"X-Device-Token": token})

    # Agent raporteaza progres (cum face nmap la fiecare 2s) → device devine online.
    client.post(f"/api/v1/agent/jobs/{job_id}/progress",
                json={"progress": 70, "phase": "Nmap: 15%"},
                headers={"X-Device-Token": token})

    r = client.get("/api/v1/devices/by-uid/" + uid, headers=auth_client["headers"])
    assert r.json()["is_online"] is True


def test_progress_rejected_on_done_job(auth_client):
    uid, token = _enroll(auth_client)
    client = auth_client["client"]

    r = client.post(
        f"/api/v1/devices/{uid}/scan-jobs",
        json={"scan_type": "standard"},
        headers=auth_client["headers"],
    )
    job_id = r.json()["job_id"]

    client.get("/api/v1/agent/jobs/next", headers={"X-Device-Token": token})

    client.post(
        f"/api/v1/agent/jobs/{job_id}/result",
        json={
            "os": {"system": "Windows", "release": "11", "is_admin": False},
            "network": {"open_ports": []},
            "processes": [],
            "software": [],
            "system_info": {},
        },
        headers={"X-Device-Token": token},
    )

    r = client.post(
        f"/api/v1/agent/jobs/{job_id}/progress",
        json={"progress": 100, "phase": "Finalizat"},
        headers={"X-Device-Token": token},
    )
    assert r.status_code == 409


def test_scan_result_evaluates_with_scan_type(auth_client):
    """Un scan deep care contine WMI subscriptions trebuie sa declanseze
    regula WMI-PERSIST-1 (min_level=deep). Acelasi payload trimis ca standard
    nu declanseaza regula."""
    uid, token = _enroll(auth_client)
    client = auth_client["client"]

    r = client.post(
        f"/api/v1/devices/{uid}/scan-jobs",
        json={"scan_type": "deep"},
        headers=auth_client["headers"],
    )
    job_id = r.json()["job_id"]
    client.get("/api/v1/agent/jobs/next", headers={"X-Device-Token": token})

    r = client.post(
        f"/api/v1/agent/jobs/{job_id}/result",
        json={
            "os": {"system": "Windows", "release": "11", "is_admin": False},
            "network": {"open_ports": []},
            "processes": [],
            "software": [],
            "system_info": {},
            "persistence": {"wmi_subscriptions": [{"name": "Evil", "command": "cmd.exe"}]},
            "forensics": {},
        },
        headers={"X-Device-Token": token},
    )
    assert r.status_code == 200
    body = r.json()
    scan_id = body["scan_id"]

    r = client.get(f"/api/v1/scans/{scan_id}", headers=auth_client["headers"])
    detail = r.json()
    assert detail["scan_type"] == "deep"
    assert any(f["rule_id"] == "WMI-PERSIST-1" for f in detail["findings"])
