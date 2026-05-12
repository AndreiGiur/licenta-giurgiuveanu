"""Heartbeat agent + is_online expus pe DeviceOut."""
import uuid


def _enroll(auth_client) -> tuple[str, str]:
    """Creeaza un device si returneaza (device_uid, plain_token)."""
    uid = f"dev-{uuid.uuid4().hex[:8]}"
    r = auth_client["client"].post(
        "/api/v1/devices",
        json={"device_uid": uid, "name": "Test PC"},
        headers=auth_client["headers"],
    )
    assert r.status_code == 200, r.text
    return uid, r.json()["device_token"]


def test_heartbeat_marks_device_online(auth_client):
    uid, token = _enroll(auth_client)
    client = auth_client["client"]

    # Initial: device NU este online (nu a trimis heartbeat).
    r = client.get(f"/api/v1/devices/by-uid/{uid}", headers=auth_client["headers"])
    assert r.status_code == 200
    assert r.json()["is_online"] is False

    # Trimite heartbeat.
    r = client.post(
        "/api/v1/agent/heartbeat",
        json={
            "agent_version": "2.0.0",
            "capabilities": ["standard", "advanced", "deep"],
            "os_version": "Windows 11",
        },
        headers={"X-Device-Token": token},
    )
    assert r.status_code == 204, r.text

    # Acum este online si capabilities sunt expuse.
    r = client.get(f"/api/v1/devices/by-uid/{uid}", headers=auth_client["headers"])
    body = r.json()
    assert body["is_online"] is True
    assert body["agent_version"] == "2.0.0"
    assert "deep" in body["capabilities"]
    assert body["last_heartbeat"] is not None


def test_heartbeat_requires_device_token(auth_client):
    r = auth_client["client"].post(
        "/api/v1/agent/heartbeat",
        json={"agent_version": "x", "capabilities": [], "os_version": "x"},
    )
    assert r.status_code == 401


def test_list_devices_includes_is_online(auth_client):
    uid, token = _enroll(auth_client)
    auth_client["client"].post(
        "/api/v1/agent/heartbeat",
        json={
            "agent_version": "2.0.0",
            "capabilities": ["standard"],
            "os_version": "Windows 11",
        },
        headers={"X-Device-Token": token},
    )
    r = auth_client["client"].get("/api/v1/devices", headers=auth_client["headers"])
    devs = r.json()
    target = next(d for d in devs if d["device_uid"] == uid)
    assert target["is_online"] is True
    assert target["agent_version"] == "2.0.0"
