"""Teste pentru device enrollment, scan submission si izolare multi-tenant."""
from fastapi.testclient import TestClient

from server.app.main import app


def _enroll_device(client, headers, device_uid="my-laptop", name="My Laptop"):
    from conftest import make_token_pair
    plain, h = make_token_pair()
    r = client.post("/api/v1/devices",
                    headers=headers,
                    json={"device_uid": device_uid, "name": name, "token_hash": h})
    assert r.status_code == 200, r.text
    body = r.json()
    body["device_token"] = plain  # backend nu mai returneaza tokenul; il avem local
    return body


def _sample_scan_payload(device_uid: str) -> dict:
    return {
        "device_uid": device_uid,
        "os": {"system": "Linux", "release": "6.5", "version": "1", "machine": "x86_64",
               "hostname": "host", "is_admin": False},
        "network": {"open_ports": [22, 445]},
        "processes": [{"pid": 1, "name": "init", "memory_mb": 5}],
        "software": [],
    }


# ── Devices ──────────────────────────────────────────────────────────────────

def test_create_device_returns_token_only_once(auth_client):
    client, headers = auth_client["client"], auth_client["headers"]
    created = _enroll_device(client, headers, device_uid="dev-1", name="Dev 1")
    assert "device_token" in created
    plain_token = created["device_token"]
    assert len(plain_token) >= 32  # token urlsafe(32)

    # Listarea NU trebuie sa contina tokenul
    r = client.get("/api/v1/devices", headers=headers)
    assert r.status_code == 200
    devices = r.json()
    assert len(devices) == 1
    assert "device_token" not in devices[0]


def test_cannot_create_duplicate_device_uid_for_same_user(auth_client):
    from conftest import make_token_pair
    client, headers = auth_client["client"], auth_client["headers"]
    _enroll_device(client, headers, device_uid="dup")
    _, h = make_token_pair()
    r = client.post("/api/v1/devices",
                    headers=headers,
                    json={"device_uid": "dup", "name": "Other", "token_hash": h})
    assert r.status_code == 400


def test_devices_endpoint_requires_auth(client):
    # TestClient pastreaza cookie-uri intre teste; le stergem ca sa fim cu adevarat anonimi.
    client.cookies.clear()
    r = client.get("/api/v1/devices")
    assert r.status_code == 401


def test_delete_device_cascades(auth_client):
    client, headers = auth_client["client"], auth_client["headers"]
    created = _enroll_device(client, headers, device_uid="del-me")
    token = created["device_token"]

    # trimitem o scanare
    r = client.post("/api/v1/scans",
                    headers={"X-Device-Token": token},
                    json=_sample_scan_payload("del-me"))
    assert r.status_code == 200

    # stergem device-ul
    r = client.delete("/api/v1/devices/del-me", headers=headers)
    assert r.status_code == 204

    # listarea de scan-uri trebuie sa intoarca 404
    r = client.get("/api/v1/devices/del-me/scans", headers=headers)
    assert r.status_code == 404


def test_device_list_includes_scan_count_and_last_score(auth_client):
    client, headers = auth_client["client"], auth_client["headers"]
    created = _enroll_device(client, headers, device_uid="counter-dev")
    token = created["device_token"]
    for _ in range(2):
        r = client.post("/api/v1/scans", headers={"X-Device-Token": token},
                        json=_sample_scan_payload("counter-dev"))
        assert r.status_code == 200
    r = client.get("/api/v1/devices", headers=headers)
    dev = next(d for d in r.json() if d["device_uid"] == "counter-dev")
    assert dev["scan_count"] == 2
    assert dev["last_score"] is not None


def test_scan_diff_auto_previous_same_type_only(auth_client):
    """Diff-ul automat compara doar scanari de ACELASI tip (nu deep cu advanced)."""
    client, headers = auth_client["client"], auth_client["headers"]
    created = _enroll_device(client, headers, device_uid="diff-dev")
    token = created["device_token"]

    def post(scan_type):
        p = _sample_scan_payload("diff-dev")
        p["scan_type"] = scan_type
        r = client.post("/api/v1/scans", headers={"X-Device-Token": token}, json=p)
        assert r.status_code == 200, r.text
        return r.json()["scan_id"]

    standard_id = post("standard")
    deep_a = post("deep")        # intercalat: advanced intre cele doua deep
    post("advanced")
    deep_b = post("deep")

    # diff automat pe deep_b → trebuie sa aleaga deep_a (acelasi tip), NU advanced-ul
    r = client.get(f"/api/v1/scans/{deep_b}/diff", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["from_scan_id"] == deep_a
    assert r.json()["from_scan_id"] != standard_id


# ── Scan submission ──────────────────────────────────────────────────────────

def test_scan_submission_happy_path(auth_client):
    client, headers = auth_client["client"], auth_client["headers"]
    created = _enroll_device(client, headers, device_uid="scan-host")
    token = created["device_token"]

    r = client.post("/api/v1/scans",
                    headers={"X-Device-Token": token},
                    json=_sample_scan_payload("scan-host"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["device_uid"] == "scan-host"
    assert isinstance(body["exposure_score"], int)
    # 445 e port riscant → trebuie sa avem cel putin un finding
    assert any(f["rule_id"] == "NET-OPEN-PORTS-1" for f in body["findings"])


def test_scan_submission_persists_linux_payload_and_fires_rules(auth_client):
    """Regresie: campul `linux` din ScanIn trebuie sa ajunga in evaluate()
    (altfel regulile os='linux' primesc payload gol → 0 findings)."""
    client, headers = auth_client["client"], auth_client["headers"]
    created = _enroll_device(client, headers, device_uid="kali-host")
    token = created["device_token"]

    payload = {
        "device_uid": "kali-host",
        "scan_type": "deep",
        "os": {"system": "Linux", "release": "6.5", "is_admin": False},
        "network": {"open_ports": []},
        "processes": [], "software": [],
        "linux": {
            "ssh": {"permit_root_login": "yes"},
            "users": {"uid0_accounts": ["root", "backdoor"]},
        },
    }
    r = client.post("/api/v1/scans", headers={"X-Device-Token": token}, json=payload)
    assert r.status_code == 200, r.text
    ids = {f["rule_id"] for f in r.json()["findings"]}
    assert "LNX-SSH-ROOT-LOGIN-1" in ids
    assert "LNX-UIDZERO-1" in ids


def test_scan_submission_rejects_missing_token(auth_client):
    client, headers = auth_client["client"], auth_client["headers"]
    _enroll_device(client, headers, device_uid="needs-token")
    r = client.post("/api/v1/scans", json=_sample_scan_payload("needs-token"))
    assert r.status_code == 401


def test_scan_submission_rejects_invalid_token(auth_client):
    client, headers = auth_client["client"], auth_client["headers"]
    _enroll_device(client, headers, device_uid="bad-token")
    r = client.post("/api/v1/scans",
                    headers={"X-Device-Token": "totally-fake-token"},
                    json=_sample_scan_payload("bad-token"))
    assert r.status_code == 401


def test_scan_submission_rejects_token_mismatch_with_uid(auth_client):
    """Defense-in-depth: un token valid pentru device A nu poate scrie scan-uri pentru device B."""
    client, headers = auth_client["client"], auth_client["headers"]
    a = _enroll_device(client, headers, device_uid="dev-a")
    _enroll_device(client, headers, device_uid="dev-b")

    # token-ul lui A folosit cu device_uid=dev-b
    r = client.post("/api/v1/scans",
                    headers={"X-Device-Token": a["device_token"]},
                    json=_sample_scan_payload("dev-b"))
    assert r.status_code == 401


# ── Multi-tenant izolare ──────────────────────────────────────────────────────
#
# Pentru testele multi-tenant folosim instante separate de TestClient, ca sa
# evitam ca cookie-urile sa se amestece intre useri (TestClient persisteaza
# cookie-urile peste cereri).

def _new_client_for_user(suffix: str) -> TestClient:
    c = TestClient(app)
    email = f"tenant-{suffix}@example.com"
    password = "password123"
    c.post("/api/v1/auth/register", json={"email": email, "password": password})
    c.post("/api/v1/auth/login", json={"email": email, "password": password})
    return c


def test_user_cannot_see_other_users_devices():
    from conftest import make_token_pair
    ca = _new_client_for_user("a")
    cb = _new_client_for_user("b")

    _, h = make_token_pair()
    ca.post("/api/v1/devices",
            json={"device_uid": "alice-laptop", "name": "Alice", "token_hash": h})

    r = cb.get("/api/v1/devices")
    assert r.status_code == 200
    uids = [d["device_uid"] for d in r.json()]
    assert "alice-laptop" not in uids


def test_user_cannot_access_other_users_scan():
    from conftest import make_token_pair
    ca = _new_client_for_user("iso-a")
    cb = _new_client_for_user("iso-b")

    plain, h = make_token_pair()
    ca.post("/api/v1/devices",
            json={"device_uid": "iso-dev", "name": "Iso", "token_hash": h})
    token = plain

    # Scan submission foloseste X-Device-Token, nu cookie. Folosim un client curat
    # ca sa fie clar ca nu se bazeaza pe sesiune.
    cscan = TestClient(app)
    scan_resp = cscan.post("/api/v1/scans",
                           headers={"X-Device-Token": token},
                           json=_sample_scan_payload("iso-dev")).json()
    scan_id = scan_resp["scan_id"]

    r = ca.get(f"/api/v1/scans/{scan_id}")
    assert r.status_code == 200

    r = cb.get(f"/api/v1/scans/{scan_id}")
    assert r.status_code == 404

    r = cb.get("/api/v1/devices/iso-dev/scans")
    assert r.status_code == 404


def test_user_cannot_delete_other_users_device():
    from conftest import make_token_pair
    ca = _new_client_for_user("del-a")
    cb = _new_client_for_user("del-b")

    _, h = make_token_pair()
    ca.post("/api/v1/devices",
            json={"device_uid": "victim", "name": "Victim", "token_hash": h})

    r = cb.delete("/api/v1/devices/victim")
    assert r.status_code == 404


def test_create_device_requires_token_hash(auth_client):
    c, headers = auth_client["client"], auth_client["headers"]
    # Lipsa token_hash → 422 Unprocessable Entity
    r = c.post("/api/v1/devices",
               json={"device_uid": "missing-hash", "name": "X"}, headers=headers)
    assert r.status_code == 422, r.text


def test_relink_requires_token_hash(auth_client):
    from conftest import make_token_pair
    c, headers = auth_client["client"], auth_client["headers"]

    _, hash1 = make_token_pair()
    r = c.post("/api/v1/devices",
               json={"device_uid": "relink-target", "name": "R", "token_hash": hash1},
               headers=headers)
    assert r.status_code == 200, r.text

    # Relink fara token_hash → 422
    r = c.post("/api/v1/devices/relink-target/relink", headers=headers)
    assert r.status_code == 422, r.text

    # Relink cu token_hash valid → 200
    _, hash2 = make_token_pair()
    r = c.post("/api/v1/devices/relink-target/relink",
               json={"token_hash": hash2}, headers=headers)
    assert r.status_code == 200, r.text
    assert "device_token" not in r.json()


def test_token_lifecycle_full_flow(auth_client):
    """Verifica ca tokenul plain generat client functioneaza la apeluri agent,
    iar dupa relink, tokenul vechi e respins."""
    from conftest import make_token_pair
    c, headers = auth_client["client"], auth_client["headers"]

    plain1, hash1 = make_token_pair()

    # 1. Creeaza device cu hash1
    r = c.post("/api/v1/devices",
               json={"device_uid": "lifecycle-dev", "name": "L",
                     "token_hash": hash1},
               headers=headers)
    assert r.status_code == 200, r.text

    # 2. Tokenul plain functioneaza la heartbeat (raspuns 204)
    r = c.post("/api/v1/agent/heartbeat",
               json={"agent_version": "1.0", "capabilities": ["standard"],
                     "os_version": "test"},
               headers={"X-Device-Token": plain1})
    assert r.status_code == 204, r.text

    # 3. Un token gresit → 401
    r = c.post("/api/v1/agent/heartbeat",
               json={"agent_version": "1.0", "capabilities": ["standard"],
                     "os_version": "test"},
               headers={"X-Device-Token": "wrong-token"})
    assert r.status_code == 401, r.text

    # 4. Relink cu hash2 nou — tokenul plain1 vechi NU mai functioneaza
    plain2, hash2 = make_token_pair()
    r = c.post("/api/v1/devices/lifecycle-dev/relink",
               json={"token_hash": hash2}, headers=headers)
    assert r.status_code == 200, r.text

    r = c.post("/api/v1/agent/heartbeat",
               json={"agent_version": "1.0", "capabilities": ["standard"],
                     "os_version": "test"},
               headers={"X-Device-Token": plain1})
    assert r.status_code == 401, "tokenul vechi trebuie sa fie invalidat"

    # 5. Tokenul plain2 nou functioneaza
    r = c.post("/api/v1/agent/heartbeat",
               json={"agent_version": "1.0", "capabilities": ["standard"],
                     "os_version": "test"},
               headers={"X-Device-Token": plain2})
    assert r.status_code == 204, r.text
