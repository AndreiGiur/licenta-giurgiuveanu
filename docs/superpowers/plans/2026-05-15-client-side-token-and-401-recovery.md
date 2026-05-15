# Client-side device tokens + auto-recovery 401 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Executabilul agent generează local `device_token` și trimite doar hash-ul SHA-256 la backend; când token-ul devine invalid (401), UI sare automat la pagina Login fără ștergere manuală de config.

**Architecture:** Refactor în două părți strâns legate. (A) Backend acceptă `token_hash` în body la `POST /devices`, `POST /devices/{uid}/relink`, `POST /agent/google-enroll`; nu mai generează tokeni, nu mai returnează `device_token`. (B) Agent introduce `DeviceTokenInvalidError` ridicată din toate funcțiile cu `X-Device-Token` la 401; `daemon_loop` iese imediat la primul 401 și notifică UI prin marker pe queue.

**Tech Stack:** FastAPI + Pydantic 2 (backend schemas), pytest cu TestClient (teste backend), Python stdlib `secrets` + `hashlib` (agent), Tkinter + queue.Queue (agent GUI).

**Spec:** `docs/superpowers/specs/2026-05-15-client-side-token-and-401-recovery-design.md` (commit `6e19cb8`).

**Migration:** ruptură curată. DB e gol. Executabilele compilate anterior trebuie reconstruite. Niciun cod legacy.

---

## Task 1: Helper test `make_token_pair()` în conftest

**Files:**
- Modify: `server/tests/conftest.py:1-58`

- [ ] **Step 1: Adaugă helper `make_token_pair` la sfârșitul `conftest.py`**

```python
def make_token_pair() -> tuple[str, str]:
    """Genereaza un (token_plain, token_hash_hex) pentru fixture-uri de test.

    Echivalent functional cu `agent/core.generate_device_token()` — il duplicam
    aici ca testele backend sa nu importe codul agentului."""
    import hashlib
    import secrets
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, token_hash
```

- [ ] **Step 2: Commit**

```bash
git add server/tests/conftest.py
git commit -m "test(server): adauga helper make_token_pair pentru fixture-uri"
```

---

## Task 2: Schema `DeviceCreateIn` + `DeviceCreateOut` cu `token_hash`

**Files:**
- Modify: `server/app/schemas.py:26-43`
- Test: `server/tests/test_devices_and_scans.py` (test nou)

- [ ] **Step 1: Scrie testul care eșuează — `POST /devices` cere `token_hash`**

Adaugă în `server/tests/test_devices_and_scans.py` (la sfârșit, înainte de orice trailing newline):

```python
def test_create_device_requires_token_hash(auth_client):
    c, headers = auth_client["client"], auth_client["headers"]
    # Lipsa token_hash → 422 Unprocessable Entity
    r = c.post("/api/v1/devices",
               json={"device_uid": "missing-hash", "name": "X"}, headers=headers)
    assert r.status_code == 422, r.text
```

- [ ] **Step 2: Rulează testul — trebuie să eșueze cu HTTP 200 (acceptă încă)**

Run: `cd server && PYTHONPATH=.. python -m pytest tests/test_devices_and_scans.py::test_create_device_requires_token_hash -v`
Expected: FAIL — `assert 200 == 422`

- [ ] **Step 3: Modifică `DeviceCreateIn` în `schemas.py` linia 26-28**

Înlocuiește:

```python
class DeviceCreateIn(BaseModel):
    device_uid: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
```

cu:

```python
class DeviceCreateIn(BaseModel):
    device_uid: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    token_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
```

Și înlocuiește `DeviceCreateOut` (linia 42-43):

```python
class DeviceCreateOut(DeviceOut):
    device_token: str
```

cu:

```python
# DeviceCreateOut: identic cu DeviceOut — backend nu mai returneaza tokenul plain.
# Pastram alias-ul pentru compatibilitate signature in routes.py.
DeviceCreateOut = DeviceOut
```

- [ ] **Step 4: Rulează testul — încă eșuează (endpoint încă apelează `Device.generate_token`)**

Run: `cd server && PYTHONPATH=.. python -m pytest tests/test_devices_and_scans.py::test_create_device_requires_token_hash -v`
Expected: FAIL (acum 422 trece, dar testele existente eșuează)

- [ ] **Step 5: Modifică endpoint `create_device` în `routes.py` liniile 206-231**

Înlocuiește tot block-ul `@router.post("/devices", ...) def create_device(...)`:

```python
@router.post("/devices", response_model=DeviceCreateOut)
def create_device(payload: DeviceCreateIn, db: Session = Depends(get_db), user: User = Depends(require_user)):
    device_uid = payload.device_uid.strip()
    name = payload.name.strip()

    existing = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="device_uid already exists for this user")

    # Client (agent) genereaza tokenul local si trimite doar hash-ul.
    # Backend stocheaza hash-ul ca atare. Tokenul plain nu apare niciodata aici.
    # Prefix-ul (12 chars) este derivat din primele caractere ale hash-ului pentru UI.
    device = Device(
        owner_id=user.id,
        device_uid=device_uid,
        name=name,
        device_token_hash=payload.token_hash,
        device_token_prefix=payload.token_hash[:8],
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    return _device_to_out(device)
```

- [ ] **Step 6: Rulează testul nou — trece**

Run: `cd server && PYTHONPATH=.. python -m pytest tests/test_devices_and_scans.py::test_create_device_requires_token_hash -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add server/app/schemas.py server/app/routes.py server/tests/test_devices_and_scans.py
git commit -m "feat(server): POST /devices accepta token_hash din client"
```

---

## Task 3: Schema `DeviceRelinkIn` + endpoint relink

**Files:**
- Modify: `server/app/schemas.py` (după `DeviceCreateOut`)
- Modify: `server/app/routes.py:268-290`

- [ ] **Step 1: Scrie test failing — relink cere `token_hash`**

Adaugă în `server/tests/test_devices_and_scans.py`:

```python
def test_relink_requires_token_hash(auth_client):
    from .conftest import make_token_pair
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
```

- [ ] **Step 2: Run test — FAIL**

Run: `cd server && PYTHONPATH=.. python -m pytest tests/test_devices_and_scans.py::test_relink_requires_token_hash -v`
Expected: FAIL (relink încă rulează fără body, returnează 200 cu device_token)

- [ ] **Step 3: Adaugă `DeviceRelinkIn` în `schemas.py` (după redefinirea `DeviceCreateOut`)**

```python
class DeviceRelinkIn(BaseModel):
    """Body pentru POST /devices/{uid}/relink — token_hash generat de client."""
    token_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
```

- [ ] **Step 4: Importă `DeviceRelinkIn` în `routes.py`**

În blockul de import-uri schemas (linia 35-58 din routes.py), adaugă `DeviceRelinkIn` în listă.

- [ ] **Step 5: Modifică endpoint `relink_device` în `routes.py:268-290`**

Înlocuiește tot block-ul:

```python
@router.post("/devices/{device_uid}/relink", response_model=DeviceOut)
def relink_device(
    device_uid: str,
    payload: DeviceRelinkIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """Re-emite tokenul pentru un device existent. Clientul trimite noul
    token_hash; backend doar inlocuieste. Scan-urile istorice raman atasate."""
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")

    device.device_token_hash = payload.token_hash
    device.device_token_prefix = payload.token_hash[:8]
    db.commit()
    db.refresh(device)

    return _device_to_out(device)
```

- [ ] **Step 6: Run test — PASS**

Run: `cd server && PYTHONPATH=.. python -m pytest tests/test_devices_and_scans.py::test_relink_requires_token_hash -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add server/app/schemas.py server/app/routes.py server/tests/test_devices_and_scans.py
git commit -m "feat(server): POST /devices/{uid}/relink accepta token_hash din client"
```

---

## Task 4: Schema `GoogleAgentEnrollIn` + endpoint google-enroll

**Files:**
- Modify: `server/app/schemas.py:158-170`
- Modify: `server/app/routes.py:815-864`

- [ ] **Step 1: Scrie test failing folosind mock pentru `google_auth.verify_id_token`**

Adaugă în `server/tests/test_agent_download.py` (sau creează `test_google_enroll.py`):

```python
def test_google_enroll_requires_token_hash(client, monkeypatch):
    from server.app import google_auth
    from .conftest import make_token_pair

    fake_payload = {"email": "newgoogle@example.com", "sub": "google-sub-123", "picture": None}
    monkeypatch.setattr(google_auth, "verify_id_token", lambda *a, **kw: fake_payload)

    _, hash1 = make_token_pair()

    # Lipsa token_hash → 422
    r = client.post("/api/v1/agent/google-enroll", json={
        "id_token": "fake", "device_uid": "g-pc", "device_name": "G PC",
    })
    assert r.status_code == 422, r.text

    # Cu token_hash → 200, NU contine device_token in raspuns
    r = client.post("/api/v1/agent/google-enroll", json={
        "id_token": "fake", "device_uid": "g-pc", "device_name": "G PC",
        "token_hash": hash1,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "device_token" not in body
    assert body["device_uid"] == "g-pc"
    assert body["user_email"] == "newgoogle@example.com"
```

- [ ] **Step 2: Run test — FAIL**

Run: `cd server && PYTHONPATH=.. python -m pytest tests/test_agent_download.py::test_google_enroll_requires_token_hash -v`
Expected: FAIL — 422 nu se ridică încă pentru că schema permite request fără `token_hash`

- [ ] **Step 3: Modifică `GoogleAgentEnrollIn` și `GoogleAgentEnrollOut` în `schemas.py:158-170`**

Înlocuiește:

```python
class GoogleAgentEnrollIn(BaseModel):
    """Agent trimite id_token + device info la /agent/google-enroll."""
    id_token: str = Field(min_length=1, max_length=4096)
    device_uid: str = Field(min_length=1, max_length=128)
    device_name: str = Field(min_length=1, max_length=128)


class GoogleAgentEnrollOut(BaseModel):
    """Raspuns la /agent/google-enroll."""
    device_token: str
    device_uid: str
    device_name: str
    user_email: str
```

cu:

```python
class GoogleAgentEnrollIn(BaseModel):
    """Agent trimite id_token + device info + token_hash la /agent/google-enroll.

    Tokenul plain este generat local de agent si pastrat in config.ini.
    Backend nu vede niciodata tokenul plain."""
    id_token: str = Field(min_length=1, max_length=4096)
    device_uid: str = Field(min_length=1, max_length=128)
    device_name: str = Field(min_length=1, max_length=128)
    token_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class GoogleAgentEnrollOut(BaseModel):
    """Raspuns la /agent/google-enroll — fara device_token (clientul il are deja)."""
    device_uid: str
    device_name: str
    user_email: str
```

- [ ] **Step 4: Modifică endpoint `agent_google_enroll` în `routes.py:815-864`**

Înlocuiește tot block-ul (după liniile cu `_upsert_google_user`):

```python
@router.post("/agent/google-enroll", response_model=GoogleAgentEnrollOut)
def agent_google_enroll(payload: GoogleAgentEnrollIn, db: Session = Depends(get_db)):
    """Agent trimite id_token (deja obtinut prin loopback OAuth) + device info + token_hash.
    Backend verifica id_token-ul, creeaza/gaseste User + Device (upsert), stocheaza
    token_hash-ul ca atare. Tokenul plain ramane pe client."""
    if not config.GOOGLE_CLIENT_ID_DESKTOP:
        raise HTTPException(status_code=503, detail="Google OAuth nu este configurat")
    try:
        google_payload = google_auth.verify_id_token(
            payload.id_token, config.GOOGLE_CLIENT_ID_DESKTOP
        )
    except google_auth.GoogleAuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

    email = google_payload["email"].lower().strip()
    google_sub = google_payload["sub"]
    picture = google_payload.get("picture")

    user = _upsert_google_user(db, email=email, google_sub=google_sub, picture=picture)

    device_uid = payload.device_uid.strip()
    device_name = payload.device_name.strip()

    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if device is None:
        device = Device(
            owner_id=user.id,
            device_uid=device_uid,
            name=device_name,
            device_token_hash=payload.token_hash,
            device_token_prefix=payload.token_hash[:8],
        )
        db.add(device)
    else:
        device.device_token_hash = payload.token_hash
        device.device_token_prefix = payload.token_hash[:8]
        device.name = device_name

    db.commit()
    db.refresh(device)

    return GoogleAgentEnrollOut(
        device_uid=device.device_uid,
        device_name=device.name,
        user_email=user.email,
    )
```

- [ ] **Step 5: Run test — PASS**

Run: `cd server && PYTHONPATH=.. python -m pytest tests/test_agent_download.py::test_google_enroll_requires_token_hash -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add server/app/schemas.py server/app/routes.py server/tests/test_agent_download.py
git commit -m "feat(server): POST /agent/google-enroll accepta token_hash din client"
```

---

## Task 5: Update teste existente care folosesc `device_token` din response

**Files:**
- Modify: `server/tests/test_devices_and_scans.py` (toate testele care fac `c.post("/api/v1/devices", ...)`)
- Modify: `server/tests/test_scan_jobs.py` (idem)

- [ ] **Step 1: Identifică testele care fac POST /devices fără token_hash**

Run: `cd server && PYTHONPATH=.. python -m pytest tests/ -v 2>&1 | tail -30`
Expected: multiple eșecuri (422 pentru lipsa `token_hash`)

- [ ] **Step 2: Patchează `test_devices_and_scans.py` — toate apelurile la `POST /devices`**

Pentru fiecare apel `c.post("/api/v1/devices", json={...})`, transformă conform pattern-ului:

Vechi:
```python
r = client.post("/api/v1/devices",
                json={"device_uid": "uid-x", "name": "X"}, headers=headers)
created = r.json()
token = created["device_token"]
```

Nou:
```python
from .conftest import make_token_pair
plain, h = make_token_pair()
r = client.post("/api/v1/devices",
                json={"device_uid": "uid-x", "name": "X", "token_hash": h},
                headers=headers)
created = r.json()
token = plain   # avem tokenul plain local — backend nu-l mai returneaza
```

Aplică în mod identic pentru `test_create_device_returns_token_only_once` (acum testul trebuie redenumit `test_create_device_does_not_return_token`):

```python
def test_create_device_does_not_return_token(auth_client):
    from .conftest import make_token_pair
    c, headers = auth_client["client"], auth_client["headers"]
    _, h = make_token_pair()

    r = c.post("/api/v1/devices",
               json={"device_uid": "uid-1", "name": "Test"},
               headers=headers)
    assert r.status_code == 422  # lipsa token_hash

    r = c.post("/api/v1/devices",
               json={"device_uid": "uid-1", "name": "Test", "token_hash": h},
               headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "device_token" not in body
    assert body["device_uid"] == "uid-1"

    # Listing devices: niciodata nu returneaza tokenul
    r = c.get("/api/v1/devices", headers=headers)
    assert r.status_code == 200
    assert "device_token" not in r.json()[0]
```

- [ ] **Step 3: Patchează `test_scan_jobs.py` — toate apelurile la `POST /devices`**

Aplică același pattern. Locațiile relevante (liniile 27, 55, 97, 110, 153, etc.) — toate folosesc helper-ul `make_device(c, uid, name)` dacă există, sau direct `c.post`. Verifică:

```bash
grep -n "post.*\\\"/api/v1/devices\\\"\\|device_token" server/tests/test_scan_jobs.py
```

și aplică transformarea peste tot. Dacă există un helper local pentru creare device, modifică-l odată în loc să umbli prin toate testele.

- [ ] **Step 4: Run all tests — PASS**

Run: `cd server && PYTHONPATH=.. python -m pytest tests/ -v`
Expected: toate testele pass (0 failed, 0 errors)

- [ ] **Step 5: Commit**

```bash
git add server/tests/
git commit -m "test(server): adapteaza fixture-uri device la noul flow token_hash"
```

---

## Task 6: Helper `generate_device_token()` în agent core

**Files:**
- Modify: `agent/core.py` (după linia 295, înainte de `# ── HTTP catre backend`)
- Test: `agent/tests/test_core.py`

- [ ] **Step 1: Scrie test în `agent/tests/test_core.py`**

```python
def test_generate_device_token_returns_plain_and_hash():
    import hashlib
    from agent import core

    plain, h = core.generate_device_token()
    assert isinstance(plain, str)
    assert len(plain) > 40  # token_urlsafe(48) ≈ 64 chars
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)
    # Hash-ul corespunde token-ului
    assert hashlib.sha256(plain.encode("utf-8")).hexdigest() == h


def test_generate_device_token_is_random():
    from agent import core
    pairs = [core.generate_device_token() for _ in range(5)]
    plains = {p for p, _ in pairs}
    hashes = {h for _, h in pairs}
    assert len(plains) == 5
    assert len(hashes) == 5
```

- [ ] **Step 2: Run test — FAIL (`generate_device_token` not defined)**

Run: `cd agent && python -m pytest tests/test_core.py::test_generate_device_token_returns_plain_and_hash -v`
Expected: FAIL — AttributeError sau ImportError

- [ ] **Step 3: Adaugă funcția în `agent/core.py` între liniile 295 și 297**

Inserează după `# ── HTTP catre backend ────...` și înainte de `class ApiError`:

```python
def generate_device_token() -> tuple[str, str]:
    """Genereaza un device_token random local + hash-ul SHA-256 hex.

    Returneaza (token_plain, token_hash_hex). Tokenul plain trebuie salvat
    in config-ul local IMEDIAT — nu va putea fi recuperat ulterior."""
    import hashlib
    import secrets
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, token_hash
```

- [ ] **Step 4: Run test — PASS**

Run: `cd agent && python -m pytest tests/test_core.py::test_generate_device_token_returns_plain_and_hash tests/test_core.py::test_generate_device_token_is_random -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent/core.py agent/tests/test_core.py
git commit -m "feat(agent): helper generate_device_token (plain + sha256 hex)"
```

---

## Task 7: Excepție `DeviceTokenInvalidError` + helper detectare 401

**Files:**
- Modify: `agent/core.py:299-326`
- Test: `agent/tests/test_core.py`

- [ ] **Step 1: Scrie test pentru 401 detection**

Adaugă în `agent/tests/test_core.py`:

```python
def test_request_with_device_token_raises_invalid_on_401(monkeypatch):
    from agent import core
    import requests

    class FakeResponse:
        status_code = 401
        text = '{"detail":"invalid device token"}'
        ok = False
        def json(self):
            return {"detail": "invalid device token"}

    def fake_request(method, url, **kw):
        return FakeResponse()

    monkeypatch.setattr(requests, "request", fake_request)

    import pytest
    with pytest.raises(core.DeviceTokenInvalidError):
        core._request_with_device_token("GET", "http://x/foo", device_token="bad")


def test_request_with_device_token_raises_api_error_on_500(monkeypatch):
    from agent import core
    import requests, pytest

    class FakeResponse:
        status_code = 500
        text = "Internal Server Error"
        ok = False
        def json(self):
            raise ValueError()

    monkeypatch.setattr(requests, "request", lambda *a, **kw: FakeResponse())

    with pytest.raises(core.ApiError):
        core._request_with_device_token("GET", "http://x/foo", device_token="any")
```

- [ ] **Step 2: Run test — FAIL (`DeviceTokenInvalidError` / `_request_with_device_token` not defined)**

Run: `cd agent && python -m pytest tests/test_core.py::test_request_with_device_token_raises_invalid_on_401 -v`
Expected: FAIL — AttributeError

- [ ] **Step 3: Modifică `agent/core.py` linia 299 — adaugă noua excepție + helper**

Înlocuiește block-ul existent `class ApiError(Exception)` cu:

```python
class ApiError(Exception):
    """Eroare la nivelul API (HTTP non-2xx, network down, timeout, etc.)."""


class DeviceTokenInvalidError(Exception):
    """Backend a respins device_token-ul cu HTTP 401.

    Daemon-ul trebuie sa se opreasca si UI-ul trebuie sa intoarca la Login.
    Aceasta exceptie e ridicata DOAR de apelurile care folosesc X-Device-Token."""


def _request_with_device_token(method: str, url: str, *, device_token: str,
                                json=None, timeout=15) -> dict:
    """Variant a `_request` care detecteaza 401 specific pentru X-Device-Token
    si arunca `DeviceTokenInvalidError`. Toate celelalte erori → `ApiError`."""
    headers = {"X-Device-Token": device_token, "Content-Type": "application/json"}
    try:
        r = requests.request(method, url, json=json, headers=headers, timeout=timeout)
    except requests.exceptions.ConnectionError:
        raise ApiError(f"Nu ma pot conecta la {url}")
    except requests.exceptions.Timeout:
        raise ApiError(f"Timeout la {url}")
    except requests.exceptions.RequestException as e:
        raise ApiError(str(e))

    if r.status_code == 401:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        raise DeviceTokenInvalidError(f"HTTP 401: {detail}")

    if r.status_code == 204:
        return {}

    if not r.ok:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        raise ApiError(f"HTTP {r.status_code}: {detail}")

    if not r.text:
        return {}
    try:
        return r.json()
    except ValueError:
        return {}
```

- [ ] **Step 4: Run test — PASS**

Run: `cd agent && python -m pytest tests/test_core.py::test_request_with_device_token_raises_invalid_on_401 tests/test_core.py::test_request_with_device_token_raises_api_error_on_500 -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent/core.py agent/tests/test_core.py
git commit -m "feat(agent): DeviceTokenInvalidError + helper _request_with_device_token"
```

---

## Task 8: Refactor `api_*` agent să folosească noul helper

**Files:**
- Modify: `agent/core.py:390-493`

- [ ] **Step 1: Înlocuiește `api_send_scan` (linia 390-395)**

```python
def api_send_scan(api_base: str, device_token: str, payload: dict) -> dict:
    return _request_with_device_token(
        "POST", f"{api_base}/scans",
        device_token=device_token, json=payload,
    )
```

- [ ] **Step 2: Înlocuiește `api_get_next_job` (linia 398-419)**

```python
def api_get_next_job(api_base: str, device_token: str) -> dict | None:
    """Returneaza dict-ul jobului sau None daca nu sunt joburi pending."""
    try:
        result = _request_with_device_token(
            "GET", f"{api_base}/agent/jobs/next", device_token=device_token,
        )
    except DeviceTokenInvalidError:
        raise
    except ApiError:
        raise
    # 204 No Content → dict gol → tratam ca None
    return result if result else None
```

- [ ] **Step 3: Înlocuiește `api_submit_job_result` (linia 422-438)**

```python
def api_submit_job_result(api_base: str, device_token: str, job_id: int, payload: dict) -> dict:
    """Trimite rezultatul scanarii. `system_info`, `persistence` si `forensics`
    sunt optionale (pentru Advanced/Deep)."""
    body = {
        "os": payload.get("os", {}),
        "system_info": payload.get("system_info", {}),
        "network": payload.get("network", {}),
        "processes": payload.get("processes", []),
        "software": payload.get("software", []),
        "persistence": payload.get("persistence"),
        "forensics": payload.get("forensics"),
    }
    return _request_with_device_token(
        "POST", f"{api_base}/agent/jobs/{job_id}/result",
        device_token=device_token, json=body,
    )
```

- [ ] **Step 4: Înlocuiește `api_submit_job_failure` (linia 441-446)**

```python
def api_submit_job_failure(api_base: str, device_token: str, job_id: int, error_message: str) -> dict:
    return _request_with_device_token(
        "POST", f"{api_base}/agent/jobs/{job_id}/fail",
        device_token=device_token, json={"error_message": error_message[:512]},
    )
```

- [ ] **Step 5: Înlocuiește `api_heartbeat` (linia 463-479)**

```python
def api_heartbeat(api_base: str, device_token: str, agent_version: str,
                  capabilities: list[str], os_version: str) -> None:
    """Trimite heartbeat la backend (la fiecare ~10s).

    ATENTIE: nu mai inghite toate exceptiile — DeviceTokenInvalidError propaga
    pentru ca daemon_loop sa poata reactiona. Doar ApiError (network down,
    5xx) ramane best-effort."""
    try:
        _request_with_device_token(
            "POST", f"{api_base}/agent/heartbeat",
            device_token=device_token,
            json={
                "agent_version": agent_version,
                "capabilities": capabilities,
                "os_version": os_version,
            }, timeout=10,
        )
    except ApiError:
        pass  # network, 5xx — best-effort, nu propaga
    # DeviceTokenInvalidError NU e prins aici — daemon_loop il prinde sus.
```

- [ ] **Step 6: Înlocuiește `api_send_progress` (linia 482-493)**

```python
def api_send_progress(api_base: str, device_token: str, job_id: int,
                       progress: int, phase: str) -> None:
    """Trimite progres pentru un job activ. Best-effort pentru ApiError;
    DeviceTokenInvalidError propaga."""
    try:
        _request_with_device_token(
            "POST", f"{api_base}/agent/jobs/{job_id}/progress",
            device_token=device_token,
            json={"progress": int(progress), "phase": phase[:128]},
            timeout=5,
        )
    except ApiError:
        pass
```

- [ ] **Step 7: Run toate testele agent**

Run: `cd agent && python -m pytest tests/ -v`
Expected: PASS (zero regresii — testele existente foloseau mock-uri care nu trigger 401)

- [ ] **Step 8: Commit**

```bash
git add agent/core.py
git commit -m "refactor(agent): api_* device-token folosesc _request_with_device_token"
```

---

## Task 9: `api_create_device` / `api_relink_device` / `api_google_enroll` trimit `token_hash`

**Files:**
- Modify: `agent/core.py:342-371, 449-460`

- [ ] **Step 1: Scrie test failing pentru noul body**

Adaugă în `agent/tests/test_core.py`:

```python
def test_api_create_device_sends_token_hash(monkeypatch):
    from agent import core
    captured = {}
    def fake_request(method, url, **kw):
        captured["json"] = kw.get("json")
        captured["url"] = url
        class R:
            ok = True
            status_code = 200
            text = '{"id": 1}'
            def json(self): return {"id": 1, "device_uid": "x", "name": "N",
                                     "created_at": "2026-01-01"}
        return R()
    monkeypatch.setattr("agent.core.requests.request", fake_request)

    result = core.api_create_device("http://api", "sess", "uid-1", "Test", token_hash="a"*64)
    assert captured["json"]["token_hash"] == "a"*64
    assert captured["json"]["device_uid"] == "uid-1"
```

- [ ] **Step 2: Run test — FAIL (api_create_device nu acceptă `token_hash`)**

Run: `cd agent && python -m pytest tests/test_core.py::test_api_create_device_sends_token_hash -v`
Expected: FAIL — TypeError unexpected keyword argument `token_hash`

- [ ] **Step 3: Modifică `api_create_device` (linia 342-347)**

```python
def api_create_device(api_base: str, session_token: str, device_uid: str, name: str,
                       *, token_hash: str) -> dict:
    """Inrolare device noua. Clientul trimite token_hash; tokenul plain ramane local."""
    return _request(
        "POST", f"{api_base}/devices",
        json={"device_uid": device_uid, "name": name, "token_hash": token_hash},
        headers={"X-Session-Token": session_token},
    )
```

- [ ] **Step 4: Modifică `api_relink_device` (linia 365-371)**

```python
def api_relink_device(api_base: str, session_token: str, device_uid: str,
                      *, token_hash: str) -> dict:
    """Re-emite tokenul pentru un device existent. Clientul trimite noul token_hash."""
    return _request(
        "POST", f"{api_base}/devices/{device_uid}/relink",
        json={"token_hash": token_hash},
        headers={"X-Session-Token": session_token},
    )
```

- [ ] **Step 5: Modifică `api_google_enroll` (linia 449-460)**

```python
def api_google_enroll(api_base: str, id_token: str, device_uid: str,
                      device_name: str, *, token_hash: str) -> dict:
    """Trimite id_token Google + token_hash la backend pentru a crea/relink Device.
    Returneaza dict cu device_uid, device_name, user_email (FARA device_token —
    clientul are deja tokenul plain corespunzator hash-ului trimis)."""
    return _request(
        "POST", f"{api_base}/agent/google-enroll",
        json={
            "id_token": id_token,
            "device_uid": device_uid,
            "device_name": device_name,
            "token_hash": token_hash,
        },
        timeout=15,
    )
```

- [ ] **Step 6: Run test — PASS**

Run: `cd agent && python -m pytest tests/test_core.py::test_api_create_device_sends_token_hash -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add agent/core.py agent/tests/test_core.py
git commit -m "feat(agent): api_create_device/relink/google_enroll trimit token_hash"
```

---

## Task 10: `enroll_device_with_session` generează tokenul local

**Files:**
- Modify: `agent/core.py:630-650`
- Modify: `agent/tests/test_core_relink.py` (dacă există apel direct)

- [ ] **Step 1: Citește current `enroll_device_with_session` și `perform_enrollment`**

Run: `grep -n "enroll_device_with_session\|perform_enrollment" agent/core.py`

- [ ] **Step 2: Modifică `enroll_device_with_session` (linia 630-650)**

Înlocuiește block-ul existent:

```python
def enroll_device_with_session(api_base: str, session_token: str,
                                device_uid: str, device_name: str,
                                relink_if_exists: bool = False,
                                log: LogFn = _noop_log) -> dict:
    """Inroleaza un device folosind un session_token existent.

    Genereaza local (token_plain, token_hash) si trimite doar hash-ul la
    backend. Returneaza dict cu device_uid, name, device_token (plain local).

    Daca `relink_if_exists` si device-ul exista deja → POST /relink (cu noul
    hash). Altfel → POST /devices."""
    token_plain, token_hash = generate_device_token()

    if relink_if_exists:
        existing = api_get_device_by_uid(api_base, session_token, device_uid)
        if existing is not None:
            log(f"Device {device_uid} exista — re-link.", "info")
            result = api_relink_device(api_base, session_token, device_uid,
                                       token_hash=token_hash)
            result["device_token"] = token_plain
            return result

    result = api_create_device(api_base, session_token, device_uid, device_name,
                               token_hash=token_hash)
    result["device_token"] = token_plain
    return result
```

- [ ] **Step 3: Identifică `perform_enrollment` (linia 653-682) și update**

În blockul `perform_enrollment`, după `enroll_device_with_session(...)`, verificarea `if not result.get("device_token")` rămâne validă (acum tokenul vine din `token_plain`, nu din response backend).

Liniile `raise ApiError("Backend-ul nu a returnat device_token")` modifică în:

```python
if not result.get("device_token"):
    raise ApiError("Eroare interna: enroll_device_with_session nu a returnat device_token")
```

(Mesaj actualizat — nu mai e "backend-ul", e helperul local.)

- [ ] **Step 4: Update GUI `_on_google_login` în `agent/gui.py:393-415`**

În worker-ul Google login, înlocuiește:

```python
def worker() -> None:
    try:
        id_tok = google_oauth.login_with_google()
        device_uid = socket.gethostname().lower()
        device_name = socket.gethostname()
        api_base = self._var_api.get().strip().rstrip("/") or core.DEFAULT_API_BASE
        result = core.api_google_enroll(api_base, id_tok, device_uid, device_name)
        core.save_enrollment(
            api_base=api_base,
            device_uid=result["device_uid"],
            device_token=result["device_token"],
            device_name=result["device_name"],
            user_email=result["user_email"],
        )
        ...
```

cu:

```python
def worker() -> None:
    try:
        id_tok = google_oauth.login_with_google()
        device_uid = socket.gethostname().lower()
        device_name = socket.gethostname()
        api_base = self._var_api.get().strip().rstrip("/") or core.DEFAULT_API_BASE

        # Generam tokenul local; backend primeste doar hash-ul.
        token_plain, token_hash = core.generate_device_token()
        result = core.api_google_enroll(
            api_base, id_tok, device_uid, device_name, token_hash=token_hash,
        )

        core.save_enrollment(
            api_base=api_base,
            device_uid=result["device_uid"],
            device_token=token_plain,
            device_name=result["device_name"],
            user_email=result["user_email"],
        )
        ...
```

- [ ] **Step 5: Run testele agent — PASS**

Run: `cd agent && python -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add agent/core.py agent/gui.py agent/tests/
git commit -m "feat(agent): enroll genereaza tokenul local + Google flow patched"
```

---

## Task 11: `daemon_loop` cu callback `on_token_invalid`

**Files:**
- Modify: `agent/core.py:535-595`
- Test: `agent/tests/test_core.py`

- [ ] **Step 1: Scrie test failing**

Adaugă în `agent/tests/test_core.py`:

```python
def test_daemon_loop_calls_on_token_invalid_and_exits(monkeypatch):
    from agent import core

    invalid_called = []
    def fake_heartbeat(*a, **kw):
        raise core.DeviceTokenInvalidError("HTTP 401: invalid")

    monkeypatch.setattr(core, "api_heartbeat", fake_heartbeat)
    monkeypatch.setattr(core, "api_get_next_job", lambda *a, **kw: None)

    iterations = []
    core.daemon_loop(
        "http://api", "uid-1", "token-1",
        poll_interval=0,
        auto_interval=0,
        log=lambda m, s="info": iterations.append((m, s)),
        should_stop=lambda: False,
        should_pause=lambda: False,
        on_token_invalid=lambda: invalid_called.append(True),
    )

    assert invalid_called == [True]
    # Loop-ul a iesit, nu a continuat polling
    # (verificam ca un log de eroare a fost emis)
    assert any("respins" in m.lower() or "401" in m for m, _ in iterations)


def test_daemon_loop_continues_on_api_error(monkeypatch):
    from agent import core

    call_count = [0]
    def fake_heartbeat(*a, **kw):
        call_count[0] += 1
        if call_count[0] >= 3:
            raise SystemExit("done")  # break out artificial
        raise core.ApiError("connection refused")

    monkeypatch.setattr(core, "api_heartbeat", fake_heartbeat)
    monkeypatch.setattr(core, "api_get_next_job", lambda *a, **kw: None)

    invalid_called = []
    try:
        core.daemon_loop(
            "http://api", "uid", "tok",
            poll_interval=0, auto_interval=0,
            log=lambda m, s="info": None,
            should_stop=lambda: call_count[0] >= 3,
            should_pause=lambda: False,
            on_token_invalid=lambda: invalid_called.append(True),
        )
    except SystemExit:
        pass

    # ApiError nu trebuie sa declanseze on_token_invalid
    assert invalid_called == []
    assert call_count[0] >= 3
```

- [ ] **Step 2: Run test — FAIL (daemon_loop nu acceptă `on_token_invalid`)**

Run: `cd agent && python -m pytest tests/test_core.py::test_daemon_loop_calls_on_token_invalid_and_exits -v`
Expected: FAIL — TypeError unexpected keyword

- [ ] **Step 3: Citește `daemon_loop` exhaustiv**

Run: `sed -n '535,600p' agent/core.py`

- [ ] **Step 4: Modifică `daemon_loop`**

Înlocuiește signatura și body-ul `daemon_loop` (~linia 535):

```python
def daemon_loop(
    api_base: str,
    device_uid: str,
    device_token: str,
    poll_interval: int = 3,
    auto_interval: int = 0,
    log: LogFn = _noop_log,
    should_stop: Callable[[], bool] = lambda: False,
    should_pause: Callable[[], bool] = lambda: False,
    on_token_invalid: Callable[[], None] | None = None,
) -> None:
    """Bucla principala daemon. Heartbeat + poll job queue + auto-scan optional.

    Iese imediat daca primeste HTTP 401 (token invalid) din heartbeat sau
    poll — semnalizeaza `on_token_invalid` (daca e setat). Erorile tranzitorii
    (network, 5xx) → retry."""
    capabilities = list(SCAN_PROFILES.keys())
    os_version = f"{platform.system()} {platform.release()}"
    last_auto = 0.0

    while not should_stop():
        if should_pause():
            _interruptible_sleep(1, should_stop)
            continue

        # Heartbeat
        try:
            api_heartbeat(api_base, device_token, AGENT_VERSION, capabilities, os_version)
        except DeviceTokenInvalidError as e:
            log(f"Device token respins de backend (401): {e}", "error")
            if on_token_invalid:
                on_token_invalid()
            return

        # Job poll
        try:
            job = api_get_next_job(api_base, device_token)
        except DeviceTokenInvalidError as e:
            log(f"Device token respins de backend (401): {e}", "error")
            if on_token_invalid:
                on_token_invalid()
            return
        except ApiError as e:
            log(f"Eroare temporara la poll: {e}", "warn")
            job = None

        if job:
            try:
                run_one_job(api_base, device_uid, device_token,
                            job["job_id"], job.get("scan_type", "standard"), log=log)
            except DeviceTokenInvalidError as e:
                log(f"Device token respins de backend (401): {e}", "error")
                if on_token_invalid:
                    on_token_invalid()
                return

        # Auto-scan (legacy, dezactivat default — auto_interval=0)
        if auto_interval > 0 and time.time() - last_auto >= auto_interval:
            try:
                data = collect_system_data(device_uid, "standard")
                api_send_scan(api_base, device_token, data)
                last_auto = time.time()
            except DeviceTokenInvalidError as e:
                log(f"Device token respins de backend (401): {e}", "error")
                if on_token_invalid:
                    on_token_invalid()
                return
            except ApiError as e:
                log(f"Auto-scan esuat: {e}", "warn")

        _interruptible_sleep(poll_interval, should_stop)
```

- [ ] **Step 5: Update `run_one_job` să propage `DeviceTokenInvalidError`**

În `run_one_job` (~linia 502-531), trebuie ca block-urile `try`/`except ApiError` să NU prindă `DeviceTokenInvalidError` (asta moștenește direct din `Exception`, nu din `ApiError`, deci propagă natural). Verifică că niciun `except Exception` larg nu intervine. Dacă există `except Exception as e:` la sfârșit, modifică-l la:

```python
except DeviceTokenInvalidError:
    raise  # propaga catre daemon_loop
except Exception as e:
    log(f"Eroare interna: {e}", "error")
    try:
        api_submit_job_failure(api_base, device_token, job_id, f"agent error: {e}")
    except (ApiError, DeviceTokenInvalidError):
        pass
```

- [ ] **Step 6: Run testele — PASS**

Run: `cd agent && python -m pytest tests/test_core.py::test_daemon_loop_calls_on_token_invalid_and_exits tests/test_core.py::test_daemon_loop_continues_on_api_error -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add agent/core.py agent/tests/test_core.py
git commit -m "feat(agent): daemon_loop iese imediat la 401 + callback on_token_invalid"
```

---

## Task 12: GUI `DaemonRunner` emite eveniment „token invalid" pe queue

**Files:**
- Modify: `agent/gui.py:47-108`

- [ ] **Step 1: Modifică `DaemonRunner._run` (linia 83-95)**

Înlocuiește block-ul `_run` cu:

```python
def _run(self, api_base: str, device_uid: str, device_token: str) -> None:
    self._emit(f"Daemon pornit (poll @3s) pentru {device_uid}.", "ok")
    try:
        core.daemon_loop(
            api_base, device_uid, device_token,
            poll_interval=3,
            auto_interval=0,
            log=self._emit,
            should_stop=self._stop.is_set,
            should_pause=self._pause.is_set,
            on_token_invalid=self._signal_token_invalid,
        )
    finally:
        self._emit("Daemon oprit.", "info")
```

- [ ] **Step 2: Adaugă metoda `_signal_token_invalid` în clasa `DaemonRunner`**

După `_emit` (linia 104-108), adaugă:

```python
def _signal_token_invalid(self) -> None:
    """Apelat de daemon_loop pe thread-ul daemon cand backend a respins
    tokenul cu 401. Trimite un marker special pe queue ca UI-ul (pe Tk thread)
    sa reactioneze."""
    try:
        self.log_queue.put_nowait(("__TOKEN_INVALID__", "error"))
    except queue.Full:
        pass
```

- [ ] **Step 3: Run testele agent — PASS (nu afectează testele existente)**

Run: `cd agent && python -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add agent/gui.py
git commit -m "feat(agent/gui): DaemonRunner semnaleaza __TOKEN_INVALID__ pe queue"
```

---

## Task 13: GUI `_poll_log_queue` interceptează marker + `_handle_token_invalid`

**Files:**
- Modify: `agent/gui.py:823-830, 778-799`

- [ ] **Step 1: Modifică `_poll_log_queue` în `AgentApp` (linia 823-830)**

Înlocuiește:

```python
def _poll_log_queue(self) -> None:
    try:
        while True:
            msg, sev = self.log_queue.get_nowait()
            self._append_log(msg, sev)
    except queue.Empty:
        pass
    self.root.after(100, self._poll_log_queue)
```

cu:

```python
def _poll_log_queue(self) -> None:
    try:
        while True:
            msg, sev = self.log_queue.get_nowait()
            if msg == "__TOKEN_INVALID__":
                self._handle_token_invalid()
                return  # _handle_token_invalid programeaza re-scheduling
            self._append_log(msg, sev)
    except queue.Empty:
        pass
    self.root.after(100, self._poll_log_queue)
```

- [ ] **Step 2: Adaugă `_handle_token_invalid` în `AgentApp` (după `_on_logout`)**

Inserează după linia 799 (după `_on_logout`):

```python
def _handle_token_invalid(self) -> None:
    """Daemon a primit 401 — token-ul nu mai e valid. Force re-login fara
    sa cracheze sau sa lase user-ul intr-o stare confuza."""
    # 1. Opreste daemon-ul curent
    self.daemon.stop()
    if self.tray:
        try:
            self.tray.stop()
        except Exception:
            pass
        self.tray = None
        self._tray_started = False
    self.daemon.join(timeout=2.0)
    self.daemon = DaemonRunner(self.log_queue)

    # 2. Salveaza api_base pentru convenience inainte de clear config
    try:
        saved_api, _, _ = core.get_enrollment()
    except RuntimeError:
        saved_api = core.DEFAULT_API_BASE
    core.clear_config()

    # 3. Re-render Login + mesaj clar
    self._render_login_page()
    self._var_api.set(saved_api)
    self._login_msg.set(
        "Conexiunea cu platforma a expirat (device-ul a fost sters sau "
        "tokenul invalidat). Reconecteaza-te pentru a continua sa primesti "
        "scanari."
    )

    # 4. Reia polling-ul ca sa prinda eventuale evenimente viitoare
    self.root.after(100, self._poll_log_queue)
```

- [ ] **Step 3: Sanity check manual — pornește GUI**

Run: `cd agent && python scan.py gui`
Expected: GUI deschide pagina Login (nu există config). Înainte de a continua, închide GUI cu Ctrl-C în terminal.

- [ ] **Step 4: Commit**

```bash
git add agent/gui.py
git commit -m "feat(agent/gui): auto-recovery la 401 — UI sare la Login cu mesaj clar"
```

---

## Task 14: Test integration end-to-end pentru 401 recovery (agent-side)

**Files:**
- Create: `agent/tests/test_daemon_recovery.py`

- [ ] **Step 1: Creează test nou**

```python
"""Integration tests pentru flow-ul de recovery la 401 in daemon_loop."""
import pytest
from agent import core


def test_daemon_invalid_token_exits_after_first_401(monkeypatch):
    call_log = []
    def fake_heartbeat(*a, **kw):
        call_log.append("heartbeat")
        raise core.DeviceTokenInvalidError("HTTP 401: revoked")
    def fake_get_job(*a, **kw):
        call_log.append("get_job")
        return None

    monkeypatch.setattr(core, "api_heartbeat", fake_heartbeat)
    monkeypatch.setattr(core, "api_get_next_job", fake_get_job)

    triggered = []
    core.daemon_loop(
        "http://api", "uid", "tok",
        poll_interval=0, auto_interval=0,
        log=lambda m, s="info": None,
        should_stop=lambda: False,
        should_pause=lambda: False,
        on_token_invalid=lambda: triggered.append(True),
    )

    assert triggered == [True]
    # Doar primul heartbeat e apelat, nu si get_job (loop iese pe spot)
    assert call_log == ["heartbeat"]


def test_daemon_network_error_keeps_running(monkeypatch):
    """ConnectionError → ApiError → NU declanseaza on_token_invalid."""
    iter_count = [0]
    def fake_heartbeat(*a, **kw):
        iter_count[0] += 1
        raise core.ApiError("connection refused")

    monkeypatch.setattr(core, "api_heartbeat", fake_heartbeat)
    monkeypatch.setattr(core, "api_get_next_job", lambda *a, **kw: None)

    triggered = []
    core.daemon_loop(
        "http://api", "uid", "tok",
        poll_interval=0, auto_interval=0,
        log=lambda m, s="info": None,
        should_stop=lambda: iter_count[0] >= 5,
        should_pause=lambda: False,
        on_token_invalid=lambda: triggered.append(True),
    )

    assert triggered == []
    assert iter_count[0] >= 5
```

- [ ] **Step 2: Run test — PASS**

Run: `cd agent && python -m pytest tests/test_daemon_recovery.py -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add agent/tests/test_daemon_recovery.py
git commit -m "test(agent): daemon recovery la 401 vs ApiError tranzitoriu"
```

---

## Task 15: Backend test integration token lifecycle

**Files:**
- Create sau modify: `server/tests/test_devices_and_scans.py` (test nou la sfârșit)

- [ ] **Step 1: Adaugă test integration token lifecycle**

```python
def test_token_lifecycle_full_flow(auth_client):
    """Verifica ca tokenul plain generat client functioneaza la apeluri agent,
    iar dupa relink, tokenul vechi e respins."""
    from .conftest import make_token_pair
    c, headers = auth_client["client"], auth_client["headers"]

    plain1, hash1 = make_token_pair()

    # 1. Creeaza device cu hash1
    r = c.post("/api/v1/devices",
               json={"device_uid": "lifecycle-dev", "name": "L",
                     "token_hash": hash1},
               headers=headers)
    assert r.status_code == 200, r.text

    # 2. Tokenul plain functioneaza la heartbeat (chiar daca raspunsul e 204)
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
```

- [ ] **Step 2: Run test — PASS**

Run: `cd server && PYTHONPATH=.. python -m pytest tests/test_devices_and_scans.py::test_token_lifecycle_full_flow -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add server/tests/test_devices_and_scans.py
git commit -m "test(server): lifecycle complet token plain → relink → invalidare"
```

---

## Task 16: Update memory.md per folder + CLAUDE.md

**Files:**
- Modify: `agent/memory.md`
- Modify: `agent/tests/memory.md`
- Modify: `server/app/memory.md`
- Modify: `server/tests/memory.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update `agent/memory.md` — secțiunea „Auth flow"**

Înlocuiește secțiunea "Auth flow" cu:

```markdown
## Auth flow (client-generated tokens)

1. **Login local in executabil**: GUI cere email/parola sau buton Google. POST `/auth/login` sau OAuth loopback → primim `session_token` (temporar).
2. **Generare token local**: `core.generate_device_token()` returneaza `(token_plain, token_hash_hex)`. Tokenul plain ramane in RAM-ul executabilului; backend-ul nu-l vede niciodata.
3. **Enrollment**: agent cauta device existent cu `GET /devices/by-uid/{hostname}`.
   - **Found**: POST `/devices/{uid}/relink` cu body `{token_hash}` → backend inlocuieste hash-ul vechi cu cel nou.
   - **Not found**: POST `/devices` cu body `{device_uid, name, token_hash}` → backend stocheaza hash-ul ca atare.
4. **Salveaza `device_token` plain in `~/.vulnwatch/config.ini`** + `DELETE /auth/logout` (renuntam la session_token).
5. **Operare**: doar `device_token` plain in headerele `X-Device-Token`. Backend verifica `sha256(plain) == row.device_token_hash`.

## Auto-recovery la 401

`daemon_loop` ridica `DeviceTokenInvalidError` din toate apelurile care folosesc `X-Device-Token` (heartbeat, get_next_job, submit_result, etc.). La prima eroare 401, daemon iese din loop si apeleaza `on_token_invalid` callback. `gui.DaemonRunner` propaga eventul printr-un marker `__TOKEN_INVALID__` pe `queue.Queue`; `AgentApp._poll_log_queue` il intercepteaza si re-renders pagina Login cu mesaj clar.
```

- [ ] **Step 2: Update `agent/tests/memory.md`**

Adaugă linie nouă pentru `test_daemon_recovery.py`:

```markdown
| `test_daemon_recovery.py` | Test integration daemon_loop: 401 → `on_token_invalid` apelat + loop iese. `ApiError` (network down) → loop continua retry, callback NU apelat. |
```

- [ ] **Step 3: Update `server/app/memory.md` — secțiunea endpoint-uri**

Actualizează rândurile pentru `POST /devices`, `POST /devices/{uid}/relink`, `POST /agent/google-enroll`:

```markdown
| `POST   /api/v1/devices`                              | cookie / X-Session  | Inrolare device nou — body include `token_hash` (SHA-256 hex generat de client). Returneaza metadata fara token plain. |
| `POST   /api/v1/devices/{uid}/relink`                 | cookie / X-Session  | Re-emite token — body include `token_hash` nou. Tokenul vechi devine invalid. |
| `POST   /api/v1/agent/google-enroll`                  | —                   | Agent enrollment cu Google id_token — body include `token_hash`. Upsert User+Device. |
```

- [ ] **Step 4: Update `server/tests/memory.md`**

Adaugă mențiune pentru helper-ul nou + testele integration:

```markdown
| `conftest.py` | ... + helper `make_token_pair() -> (plain, hash)` folosit de toate testele care creeaza device dupa refactorul client-generated tokens. |
| `test_devices_and_scans.py` | ... + `test_token_lifecycle_full_flow`: end-to-end token plain functioneaza → relink → tokenul vechi invalidat. |
```

- [ ] **Step 5: Update `CLAUDE.md` — secțiunea „Authentication"**

În `CLAUDE.md`, secțiunea `### Authentication — two separate systems`, sub `**Agent auth (agent → backend):**`, înlocuiește cu:

```markdown
**Agent auth (agent → backend):**
- Fiecare device are un `device_token` — generat **local** de executabil cu `secrets.token_urlsafe(48)`
- Executabilul trimite la backend doar `token_hash` (SHA-256 hex) → backend stocheaza hash-ul ca atare; tokenul plain nu apare niciodata in raspunsuri HTTP, log-uri, sau heap backend
- Plain token e salvat in `~/.vulnwatch/config.ini` la enrollment si folosit pentru fiecare request urmator in header `X-Device-Token`
- `_device_for_token_or_401()` in `routes.py` valideaza prin `sha256(plain_from_header) == row.device_token_hash`
- **Auto-recovery la 401**: daemon-ul detecteaza HTTP 401 din orice apel device-token, opreste loop-ul si forteaza UI executabil sa revina la pagina Login (fara crash, fara workaround manual)
```

- [ ] **Step 6: Commit**

```bash
git add agent/memory.md agent/tests/memory.md server/app/memory.md server/tests/memory.md CLAUDE.md
git commit -m "docs: memory.md + CLAUDE.md reflecta client-generated tokens + recovery 401"
```

---

## Task 17: Manual integration test (end-to-end) + rebuild .exe

**Files:**
- N/A (verificare manuală)

- [ ] **Step 1: Reset complet DB + restart backend**

```bash
docker compose down -v && docker compose up -d
# Așteaptă Postgres ready
sleep 3
```

Asigură-te că backend-ul rulează (vezi log-ul ultimei sesiuni — task ID dat de Bash).

- [ ] **Step 2: Pornește agent din sursă**

```powershell
cd agent
python scan.py gui
```

- [ ] **Step 3: Login Google (sau email/parolă) și verifică enrollment**

În GUI:
- Click „Continuă cu Google" → consimțământ Google → revine în executabil
- Verifică pagina Status apare cu device_name + email
- Verifică pe http://localhost:5173/devices că device-ul a apărut cu badge online verde pulsat

- [ ] **Step 4: Ștergere device din UI web → verifică auto-recovery**

În browser, pe http://localhost:5173/devices:
- Click pe iconița de ștergere a device-ului → confirmă
- Verifică în executabil: în max 10s (next heartbeat), UI-ul sare automat la pagina Login cu mesajul „Conexiunea cu platforma a expirat (device-ul a fost șters sau tokenul invalidat). Reconectează-te pentru a continua să primești scanări."

- [ ] **Step 5: Re-login → enrollment cu același UID**

Click „Continuă cu Google" din nou → confirmă re-link → device reapare în `/devices` cu același UID dar token nou.

- [ ] **Step 6: Rebuild .exe**

```powershell
powershell -ExecutionPolicy Bypass -File agent\build.ps1
```

Verifică:
- `dist\VulnWatchAgent.exe` produs
- Copiat în `server\app\static\agent\VulnWatchAgent.exe`

- [ ] **Step 7: Sanity check — rulează .exe direct**

```powershell
.\dist\VulnWatchAgent.exe
```

- Dublu-click sau lansare din terminal → GUI Login apare
- Login → enrollment → daemon pornește OK

- [ ] **Step 8: Commit (dacă a fost vreo modificare la .exe în server/app/static)**

```bash
git add server/app/static/agent/VulnWatchAgent.exe
git commit -m "build: rebuild VulnWatchAgent.exe dupa refactor client-generated tokens"
```

(Skip dacă `server/app/static/agent/` e în `.gitignore`.)

---

## Self-Review checklist

După ce ai parcurs toate task-urile, verifică:

- [ ] **Toate testele backend** trec: `cd server && PYTHONPATH=.. python -m pytest tests/ -v` → 0 failures
- [ ] **Toate testele agent** trec: `cd agent && python -m pytest tests/ -v` → 0 failures
- [ ] **Niciun fișier nu mai apelează `Device.generate_token()` din routes.py** — verifică: `grep -n "Device.generate_token\|generate_token()" server/app/routes.py` → 0 results
- [ ] **Niciun test backend nu mai accesează `created["device_token"]` direct fără să fi făcut `make_token_pair()` întâi** — verifică: `grep -n 'created\["device_token"\]\|json()\["device_token"\]' server/tests/` → fiecare apariție e însoțită de tokenul plain generat local
- [ ] **`auth_provider` field în `User` rămâne neschimbat** (nu am atins User model)
- [ ] **Frontend `web/` nu a fost atins** — `git diff main --stat -- web/` → empty
- [ ] **Commits curate** — un commit per task, mesaje în română imperative

---

**Plan complete. Toate cele 17 task-uri au pași explicit codificați, fără placeholder-uri. Fluxul testelor TDD: scrii testul, vezi că eșuează, implementezi minimum, vezi că trece, commit.**
