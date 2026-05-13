# Google OAuth + Warm UI Revamp — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adăugare Google OAuth hibrid (web + agent), eliminare creare device din platform UI, revamp vizual complet către estetica Honey & Plum cu light/dark toggle și animații.

**Architecture:** Web OAuth standard (Authorization Code) cu redirect prin backend. Agent OAuth Loopback Redirect cu PKCE via `google-auth-oauthlib.InstalledAppFlow`. Agentul face exchange-ul cu Google și trimite doar `id_token` la backend. UI revamp în trei pași: foundation (CSS variables + theme system), componente noi, refactor pagini.

**Tech Stack:** Backend — FastAPI + SQLAlchemy 2 + `google-auth>=2.30`. Agent — Python 3.12 + Tkinter + `google-auth-oauthlib>=1.2`. Web — React 18 + TypeScript + Vite + `framer-motion@^11` + Google Fonts (Fraunces + Outfit + JetBrains Mono).

**Spec:** `docs/superpowers/specs/2026-05-13-google-oauth-and-warm-ui-revamp-design.md`

**Git identity:** `user.email = giurgiuveanuandrei21@gmail.com`. **Niciun commit nu conține `Co-Authored-By: Claude`.**

---

## Convenții

- Toate comenzile pytest se rulează din `server/` (cu venv activ) sau `agent/`
- Comenzile git presupun cwd = `E:\Lucrare-de-Licenta-Giurgiuveanu-Andrei`
- Pentru schimbări DB: la finalul Task 1, rulează `docker compose down -v && docker compose up -d` și restart backend
- Fiecare task se commit-uiește separat la final

---

## Pre-flight: Google Cloud setup (manual, NU rulează automat)

Înainte de Task 1, autorul lucrării trebuie să creeze două OAuth Client IDs în [Google Cloud Console](https://console.cloud.google.com/):

1. Proiect nou (sau folosește unul existent)
2. **APIs & Services → OAuth consent screen**:
   - User Type: External
   - App name: "VulnWatch"
   - User support email: `giurgiuveanuandrei21@gmail.com`
   - Scopes: `openid`, `.../auth/userinfo.email`, `.../auth/userinfo.profile`
   - Test users: adaugă propriul email (până la verificare app)
3. **APIs & Services → Credentials → Create Credentials → OAuth client ID**:
   - **Web application**:
     - Name: "VulnWatch Web"
     - Authorized redirect URIs: `http://127.0.0.1:8000/api/v1/auth/google/callback`
   - **Desktop app**:
     - Name: "VulnWatch Agent"
     - (Desktop apps nu cer redirect URIs explicit — Google permite orice port loopback)
4. Notează `Client ID` și `Client Secret` pentru fiecare. Le folosim în Task 1.

---

## Task 1 — Backend: User model + env config + dependencies

**Files:**
- Modify: `server/requirements.txt`
- Modify: `server/app/models.py`
- Create: `server/.env.example` (sau modifică dacă există)
- Modify: `server/memory.md`

- [ ] **Step 1: Adaugă dependențe în `server/requirements.txt`**

Adaugă liniile (păstrează cele existente):

```
google-auth>=2.30
httpx>=0.27
```

Run: `cd server && .venv/Scripts/activate && pip install -r requirements.txt`
Expected: instalează `google-auth`, `httpx` și dependențele lor.

- [ ] **Step 2: Modifică `server/app/models.py` — User**

Înlocuiește definiția clasei `User`:

```python
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    # PBKDF2 fields — NULLABLE pentru utilizatorii Google-only
    password_salt: Mapped[str | None] = mapped_column(String(64), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Google OAuth fields
    google_sub: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True, index=True)
    google_picture_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    auth_provider: Mapped[str] = mapped_column(String(16), default="password")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    sessions: Mapped[list["Session"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    devices: Mapped[list["Device"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
```

- [ ] **Step 3: Verifică sintaxa și că importurile încă funcționează**

Run: `cd server && python -c "from app.models import User; print(User.__table__.columns.keys())"`
Expected output include `'google_sub'`, `'google_picture_url'`, `'auth_provider'`, `'password_salt'`, `'password_hash'`.

- [ ] **Step 4: Update `server/.env.example` cu variabilele Google**

Adaugă la finalul fișierului (creează dacă nu există):

```
# Google OAuth — Web app (folosit pentru login pe platforma)
GOOGLE_CLIENT_ID_WEB=
GOOGLE_CLIENT_SECRET_WEB=
GOOGLE_REDIRECT_URI_WEB=http://127.0.0.1:8000/api/v1/auth/google/callback

# Google OAuth — Desktop app (folosit pentru a verifica id_token primit de la agent)
GOOGLE_CLIENT_ID_DESKTOP=

# Frontend URL — backend face redirect aici dupa callback OAuth
FRONTEND_BASE_URL=http://localhost:5173
```

- [ ] **Step 5: Update `server/memory.md` — adaugă `User.google_sub/google_picture_url/auth_provider` (parola nullable) și menționează env vars noi.**

- [ ] **Step 6: Recrează DB Postgres**

Run: `docker compose down -v && docker compose up -d`
Expected: volumul vechi șters, container nou pornit.

- [ ] **Step 7: Rulează testele existente — toate trec (SQLite recreează schema la fiecare run)**

Run: `cd server && python -m pytest`
Expected: PASS pentru toate testele existente.

- [ ] **Step 8: Commit**

```bash
git add server/requirements.txt server/app/models.py server/.env.example server/memory.md
git commit -m "models: User cu google_sub/picture/auth_provider + parola nullable"
```

---

## Task 2 — Backend: Schemas Google OAuth

**Files:**
- Modify: `server/app/schemas.py`
- Modify: `server/app/memory.md`

- [ ] **Step 1: Adaugă schemas la finalul `server/app/schemas.py`**

```python
# ── Google OAuth ─────────────────────────────────────────────────────────────


class GoogleAuthUrlOut(BaseModel):
    """Returnat de GET /auth/google/url — frontend redirect-uieste user-ul."""
    auth_url: str
    state: str


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

- [ ] **Step 2: Update `MeOut` să includă info Google**

Înlocuiește `MeOut`:

```python
class MeOut(BaseModel):
    id: int
    email: str
    google_picture_url: str | None = None
    auth_provider: str = "password"
```

- [ ] **Step 3: Verifică sintaxa**

Run: `cd server && python -c "from app.schemas import GoogleAuthUrlOut, GoogleAgentEnrollIn, GoogleAgentEnrollOut, MeOut; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Rulează testele existente**

Run: `cd server && python -m pytest`
Expected: PASS.

- [ ] **Step 5: Update `server/app/memory.md`** — schemas.py: noile `GoogleAuthUrlOut`, `GoogleAgentEnrollIn`, `GoogleAgentEnrollOut`; `MeOut` extins cu `google_picture_url` și `auth_provider`.

- [ ] **Step 6: Commit**

```bash
git add server/app/schemas.py server/app/memory.md
git commit -m "schemas: Google OAuth DTOs + MeOut cu auth_provider/picture"
```

---

## Task 3 — Backend: Modul `google_auth.py`

**Files:**
- Create: `server/app/google_auth.py`
- Test: `server/tests/test_google_auth.py`
- Modify: `server/tests/memory.md`

- [ ] **Step 1: Scrie testul (failing)**

Creează `server/tests/test_google_auth.py`:

```python
"""Verificare id_token + exchange code cu Google (mocked)."""
from unittest import mock

import pytest

from server.app import google_auth


def test_verify_id_token_returns_payload_when_valid():
    fake_payload = {
        "iss": "https://accounts.google.com",
        "sub": "1234567890",
        "email": "test@example.com",
        "email_verified": True,
        "name": "Test User",
        "picture": "https://example.com/pic.jpg",
    }
    with mock.patch("server.app.google_auth.id_token.verify_oauth2_token",
                    return_value=fake_payload):
        result = google_auth.verify_id_token("fake-token", "fake-client-id")
    assert result["email"] == "test@example.com"
    assert result["sub"] == "1234567890"


def test_verify_id_token_raises_on_invalid():
    with mock.patch("server.app.google_auth.id_token.verify_oauth2_token",
                    side_effect=ValueError("invalid token")):
        with pytest.raises(google_auth.GoogleAuthError):
            google_auth.verify_id_token("bad-token", "fake-client-id")


@pytest.mark.asyncio
async def test_exchange_code_returns_id_token():
    fake_resp = {
        "id_token": "fake.id.token",
        "access_token": "fake-access",
        "token_type": "Bearer",
    }
    with mock.patch("httpx.AsyncClient.post") as mock_post:
        mock_post.return_value = mock.MagicMock(
            status_code=200,
            json=mock.MagicMock(return_value=fake_resp),
            raise_for_status=mock.MagicMock(),
        )
        result = await google_auth.exchange_code_for_token(
            code="fake-code",
            client_id="client",
            client_secret="secret",
            redirect_uri="http://127.0.0.1/cb",
        )
    assert result["id_token"] == "fake.id.token"
```

- [ ] **Step 2: Adaugă `pytest-asyncio` dacă lipsește**

Run: `cd server && python -c "import pytest_asyncio" 2>&1`
Dacă apare `ModuleNotFoundError`, adaugă la `requirements.txt`:

```
pytest-asyncio>=0.23
```

Apoi: `pip install -r requirements.txt`.

În `server/pyproject.toml` (sau `pytest.ini`), adaugă (creează `pytest.ini` în `server/` dacă lipsește):

```ini
[pytest]
asyncio_mode = auto
```

Run: `cd server && python -m pytest tests/test_google_auth.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'server.app.google_auth'`.

- [ ] **Step 3: Implementează `server/app/google_auth.py`**

```python
"""Verificare ID tokens Google + exchange code → token.

Centralizam interactiunea cu Google ca sa fie usor de mock-uit in teste."""
from __future__ import annotations

from typing import Any

import httpx
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token


class GoogleAuthError(Exception):
    """Eroare la verificare token sau exchange cu Google."""


GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"


def verify_id_token(token: str, client_id: str) -> dict[str, Any]:
    """Verifica un id_token Google. Returneaza payload-ul decodat.

    Arunca GoogleAuthError daca tokenul e invalid, expirat sau pentru alt aud."""
    try:
        payload = id_token.verify_oauth2_token(
            token, google_requests.Request(), client_id
        )
    except (ValueError, Exception) as e:
        raise GoogleAuthError(f"id_token invalid: {e}") from e
    return payload


async def exchange_code_for_token(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code_verifier: str | None = None,
) -> dict[str, Any]:
    """POST la token endpoint Google. Returneaza dict cu id_token, access_token, etc.
    Daca dam code_verifier (PKCE), client_secret poate fi gol pentru desktop apps."""
    data = {
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    if client_secret:
        data["client_secret"] = client_secret
    if code_verifier:
        data["code_verifier"] = code_verifier

    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(GOOGLE_TOKEN_ENDPOINT, data=data, timeout=15)
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise GoogleAuthError(f"exchange code esuat: {e}") from e
        return r.json()


def build_authorization_url(
    client_id: str,
    redirect_uri: str,
    state: str,
    scopes: list[str] | None = None,
) -> str:
    """Construieste URL-ul de autorizare Google pentru flow-ul web."""
    if scopes is None:
        scopes = ["openid", "email", "profile"]
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    from urllib.parse import urlencode
    return f"{GOOGLE_AUTH_ENDPOINT}?{urlencode(params)}"
```

- [ ] **Step 4: Rulează testul**

Run: `cd server && python -m pytest tests/test_google_auth.py -v`
Expected: PASS (3 teste).

- [ ] **Step 5: Rulează toate testele — niciunul nu regresează**

Run: `cd server && python -m pytest`
Expected: PASS.

- [ ] **Step 6: Update `server/tests/memory.md`** — `test_google_auth.py`: 3 teste mock pentru verify_id_token + exchange_code.

- [ ] **Step 7: Commit**

```bash
git add server/app/google_auth.py server/tests/test_google_auth.py server/requirements.txt server/tests/memory.md
git status | grep -E "pytest.ini|pyproject" && git add server/pytest.ini server/pyproject.toml 2>/dev/null
git commit -m "google_auth: verify_id_token + exchange_code + build_auth_url"
```

---

## Task 4 — Backend: Endpoint-uri Web OAuth

**Files:**
- Modify: `server/app/main.py` (sau creează `server/app/config.py` dacă vrei să separi)
- Modify: `server/app/routes.py`
- Test: `server/tests/test_google_web_oauth.py`
- Modify: `server/memory.md`
- Modify: `server/app/memory.md`

- [ ] **Step 1: Adaugă citire env vars Google la pornire (în `server/app/main.py`)**

Adaugă în top of file, după importuri:

```python
import os

GOOGLE_CLIENT_ID_WEB = os.environ.get("GOOGLE_CLIENT_ID_WEB", "")
GOOGLE_CLIENT_SECRET_WEB = os.environ.get("GOOGLE_CLIENT_SECRET_WEB", "")
GOOGLE_REDIRECT_URI_WEB = os.environ.get(
    "GOOGLE_REDIRECT_URI_WEB",
    "http://127.0.0.1:8000/api/v1/auth/google/callback",
)
GOOGLE_CLIENT_ID_DESKTOP = os.environ.get("GOOGLE_CLIENT_ID_DESKTOP", "")
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "http://localhost:5173")
```

Exportă-le în `server/app/__init__.py` dacă vrei import facil, sau lasă-le în `main` și importă-le din `routes` cu `from .main import ...`. **Cleanest: creează `server/app/config.py`:**

Înlocuiește pasul de mai sus — creează `server/app/config.py`:

```python
"""Configuratie aplicatie citita din env."""
import os

GOOGLE_CLIENT_ID_WEB = os.environ.get("GOOGLE_CLIENT_ID_WEB", "")
GOOGLE_CLIENT_SECRET_WEB = os.environ.get("GOOGLE_CLIENT_SECRET_WEB", "")
GOOGLE_REDIRECT_URI_WEB = os.environ.get(
    "GOOGLE_REDIRECT_URI_WEB",
    "http://127.0.0.1:8000/api/v1/auth/google/callback",
)
GOOGLE_CLIENT_ID_DESKTOP = os.environ.get("GOOGLE_CLIENT_ID_DESKTOP", "")
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "http://localhost:5173")
```

- [ ] **Step 2: Scrie testele (failing)**

Creează `server/tests/test_google_web_oauth.py`:

```python
"""Web OAuth flow: /auth/google/url + /auth/google/callback (mock Google)."""
from unittest import mock

import pytest

from server.app import google_auth


def test_google_url_returns_state_and_auth_url(client):
    r = client.get("/api/v1/auth/google/url")
    assert r.status_code == 200
    body = r.json()
    assert "auth_url" in body
    assert "state" in body
    assert "accounts.google.com" in body["auth_url"]
    assert f"state={body['state']}" in body["auth_url"]


def test_google_callback_creates_user_and_redirects(client):
    # 1. Cerere URL ca sa avem state-ul valid
    r = client.get("/api/v1/auth/google/url")
    state = r.json()["state"]

    fake_id_token = "fake.id.token"
    fake_payload = {
        "iss": "https://accounts.google.com",
        "sub": "google-sub-123",
        "email": "alice@example.com",
        "email_verified": True,
        "name": "Alice",
        "picture": "https://example.com/alice.jpg",
    }

    async def fake_exchange(**kwargs):
        return {"id_token": fake_id_token}

    with mock.patch.object(google_auth, "exchange_code_for_token", side_effect=fake_exchange), \
         mock.patch.object(google_auth, "verify_id_token", return_value=fake_payload):
        r = client.get(
            f"/api/v1/auth/google/callback?code=fake-code&state={state}",
            follow_redirects=False,
        )

    assert r.status_code in (302, 307)
    assert "/dashboard" in r.headers["location"]
    # Cookie de sesiune e setat
    assert "vw_session" in r.headers.get("set-cookie", "")

    # User-ul a fost creat
    r2 = client.get("/api/v1/auth/me")
    assert r2.status_code == 200
    me = r2.json()
    assert me["email"] == "alice@example.com"
    assert me["auth_provider"] == "google"
    assert me["google_picture_url"] == "https://example.com/alice.jpg"


def test_google_callback_invalid_state_rejected(client):
    r = client.get(
        "/api/v1/auth/google/callback?code=fake-code&state=bogus-state",
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_google_callback_links_existing_email_account(client, auth_client):
    """Un cont existent cu email/parola devine 'both' dupa login cu Google la acelasi email."""
    email = auth_client["email"]

    # Cerere URL noua (sesiune curata)
    r = client.get("/api/v1/auth/google/url")
    state = r.json()["state"]

    fake_payload = {
        "iss": "https://accounts.google.com",
        "sub": "google-sub-456",
        "email": email,
        "email_verified": True,
        "name": "Existing User",
        "picture": "https://example.com/x.jpg",
    }

    async def fake_exchange(**kwargs):
        return {"id_token": "fake-token"}

    with mock.patch.object(google_auth, "exchange_code_for_token", side_effect=fake_exchange), \
         mock.patch.object(google_auth, "verify_id_token", return_value=fake_payload):
        r = client.get(
            f"/api/v1/auth/google/callback?code=fake-code&state={state}",
            follow_redirects=False,
        )

    assert r.status_code in (302, 307)

    # Verifica ca user-ul existent a primit auth_provider=both si google_sub
    r2 = client.get("/api/v1/auth/me")
    me = r2.json()
    assert me["email"] == email
    assert me["auth_provider"] == "both"
```

- [ ] **Step 3: Rulează testele — toate cad**

Run: `cd server && python -m pytest tests/test_google_web_oauth.py -v`
Expected: FAIL pentru toate (endpoint-uri inexistente).

- [ ] **Step 4: Adaugă endpoint-urile în `server/app/routes.py`**

În top of file, după importurile existente, adaugă:

```python
import secrets
import time
from urllib.parse import urlencode

from fastapi.responses import RedirectResponse

from . import config, google_auth
from .schemas import GoogleAuthUrlOut, GoogleAgentEnrollIn, GoogleAgentEnrollOut
```

**State store in-memory** (TTL 5 minute) — adaugă imediat după importuri, la nivel de modul:

```python
_OAUTH_STATE_STORE: dict[str, float] = {}
_OAUTH_STATE_TTL = 300  # 5 minute


def _store_state(state: str) -> None:
    """Salveaza state CSRF + curata stari expirate."""
    now = time.time()
    expired = [s for s, t in _OAUTH_STATE_STORE.items() if now - t > _OAUTH_STATE_TTL]
    for s in expired:
        del _OAUTH_STATE_STORE[s]
    _OAUTH_STATE_STORE[state] = now


def _consume_state(state: str) -> bool:
    """Verifica state si il sterge. True daca e valid si neexpirat."""
    if state not in _OAUTH_STATE_STORE:
        return False
    ts = _OAUTH_STATE_STORE.pop(state)
    return (time.time() - ts) <= _OAUTH_STATE_TTL
```

Adaugă endpoint-urile la finalul `routes.py`:

```python
# ──────────────────────────────────────────────────────────────────────────────
# Google OAuth — web flow
# ──────────────────────────────────────────────────────────────────────────────


@router.get("/auth/google/url", response_model=GoogleAuthUrlOut)
def google_auth_url():
    """Frontend ia URL-ul si redirect-uieste user-ul catre Google."""
    if not config.GOOGLE_CLIENT_ID_WEB:
        raise HTTPException(status_code=503, detail="Google OAuth nu este configurat")
    state = secrets.token_urlsafe(32)
    _store_state(state)
    url = google_auth.build_authorization_url(
        client_id=config.GOOGLE_CLIENT_ID_WEB,
        redirect_uri=config.GOOGLE_REDIRECT_URI_WEB,
        state=state,
    )
    return GoogleAuthUrlOut(auth_url=url, state=state)


@router.get("/auth/google/callback")
async def google_auth_callback(
    code: str,
    state: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """Google a redirectionat user-ul aici. Schimbam code → id_token,
    creem User (sau il gasim), setam cookie, redirect spre frontend."""
    if not _consume_state(state):
        raise HTTPException(status_code=400, detail="State invalid sau expirat")

    try:
        tokens = await google_auth.exchange_code_for_token(
            code=code,
            client_id=config.GOOGLE_CLIENT_ID_WEB,
            client_secret=config.GOOGLE_CLIENT_SECRET_WEB,
            redirect_uri=config.GOOGLE_REDIRECT_URI_WEB,
        )
        payload = google_auth.verify_id_token(
            tokens["id_token"], config.GOOGLE_CLIENT_ID_WEB
        )
    except google_auth.GoogleAuthError as e:
        raise HTTPException(status_code=400, detail=str(e))

    email = payload["email"].lower().strip()
    google_sub = payload["sub"]
    picture = payload.get("picture")

    user = _upsert_google_user(db, email=email, google_sub=google_sub, picture=picture)

    token = create_session(
        db, user.id,
        user_agent=request.headers.get("user-agent"),
        ip=request.client.host if request.client else None,
    )
    redirect_url = f"{config.FRONTEND_BASE_URL}/dashboard"
    resp = RedirectResponse(url=redirect_url, status_code=302)
    set_session_cookie(resp, token)
    return resp


def _upsert_google_user(db: Session, email: str, google_sub: str, picture: str | None) -> User:
    """User upsert pe baza email-ului. Daca exista, lipeste google_sub."""
    user = get_user_by_email(db, email)
    if user is None:
        user = User(
            email=email,
            google_sub=google_sub,
            google_picture_url=picture,
            auth_provider="google",
        )
        db.add(user)
    else:
        if user.google_sub is None:
            user.google_sub = google_sub
        user.google_picture_url = picture
        if user.password_hash is None:
            user.auth_provider = "google"
        else:
            user.auth_provider = "both"
    db.commit()
    db.refresh(user)
    return user
```

- [ ] **Step 5: Update `/auth/me` să returneze `google_picture_url` și `auth_provider`**

Înlocuiește endpoint-ul `me`:

```python
@router.get("/auth/me", response_model=MeOut)
def me(user: User = Depends(require_user)):
    return MeOut(
        id=user.id,
        email=user.email,
        google_picture_url=user.google_picture_url,
        auth_provider=user.auth_provider,
    )
```

- [ ] **Step 6: Setează env vars pentru rularea testelor**

În `server/tests/conftest.py`, după linia `os.environ["DATABASE_URL"] = ...`, adaugă:

```python
os.environ.setdefault("GOOGLE_CLIENT_ID_WEB", "test-client-id-web")
os.environ.setdefault("GOOGLE_CLIENT_SECRET_WEB", "test-secret-web")
os.environ.setdefault("GOOGLE_CLIENT_ID_DESKTOP", "test-client-id-desktop")
os.environ.setdefault("FRONTEND_BASE_URL", "http://localhost:5173")
```

- [ ] **Step 7: Rulează testele**

Run: `cd server && python -m pytest tests/test_google_web_oauth.py -v`
Expected: PASS (4 teste).

- [ ] **Step 8: Toate testele trec**

Run: `cd server && python -m pytest`
Expected: PASS pentru toate.

- [ ] **Step 9: Update `server/memory.md` (endpoint-uri noi) + `server/app/memory.md` (config.py + routes Google) + `server/tests/memory.md` (test_google_web_oauth.py)**

- [ ] **Step 10: Commit**

```bash
git add server/app/config.py server/app/routes.py server/tests/conftest.py server/tests/test_google_web_oauth.py server/memory.md server/app/memory.md server/tests/memory.md
git commit -m "routes: Google OAuth web flow (url + callback) + MeOut cu auth_provider/picture"
```

---

## Task 5 — Backend: Endpoint `/agent/google-enroll`

**Files:**
- Modify: `server/app/routes.py`
- Test: `server/tests/test_google_agent_enroll.py`
- Modify: `server/tests/memory.md`

- [ ] **Step 1: Scrie testul (failing)**

Creează `server/tests/test_google_agent_enroll.py`:

```python
"""Agent Google enrollment: POST /agent/google-enroll."""
from unittest import mock

import pytest

from server.app import google_auth


def test_google_enroll_creates_user_and_device(client):
    fake_payload = {
        "sub": "google-sub-789",
        "email": "bob@example.com",
        "email_verified": True,
        "name": "Bob",
        "picture": "https://example.com/bob.jpg",
    }
    with mock.patch.object(google_auth, "verify_id_token", return_value=fake_payload):
        r = client.post(
            "/api/v1/agent/google-enroll",
            json={
                "id_token": "fake-token",
                "device_uid": "DESKTOP-XYZ",
                "device_name": "Bob's PC",
            },
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_email"] == "bob@example.com"
    assert body["device_uid"] == "DESKTOP-XYZ"
    assert body["device_name"] == "Bob's PC"
    assert len(body["device_token"]) > 20  # token plain returnat


def test_google_enroll_relinks_existing_device(client):
    fake_payload = {
        "sub": "google-sub-789",
        "email": "carol@example.com",
        "email_verified": True,
        "name": "Carol",
        "picture": None,
    }
    with mock.patch.object(google_auth, "verify_id_token", return_value=fake_payload):
        # Prima inrolare
        r1 = client.post(
            "/api/v1/agent/google-enroll",
            json={"id_token": "t", "device_uid": "UID-1", "device_name": "PC1"},
        )
        token1 = r1.json()["device_token"]

        # A doua inrolare (acelasi UID) — token nou
        r2 = client.post(
            "/api/v1/agent/google-enroll",
            json={"id_token": "t", "device_uid": "UID-1", "device_name": "PC1"},
        )
        token2 = r2.json()["device_token"]

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert token1 != token2  # token re-emis (relink)


def test_google_enroll_rejects_invalid_token(client):
    with mock.patch.object(
        google_auth, "verify_id_token",
        side_effect=google_auth.GoogleAuthError("invalid"),
    ):
        r = client.post(
            "/api/v1/agent/google-enroll",
            json={"id_token": "bad", "device_uid": "UID", "device_name": "PC"},
        )
    assert r.status_code == 401
```

- [ ] **Step 2: Rulează testul — cad**

Run: `cd server && python -m pytest tests/test_google_agent_enroll.py -v`
Expected: FAIL — endpoint-ul nu există.

- [ ] **Step 3: Adaugă endpoint-ul la finalul `server/app/routes.py`**

```python
@router.post("/agent/google-enroll", response_model=GoogleAgentEnrollOut)
def agent_google_enroll(payload: GoogleAgentEnrollIn, db: Session = Depends(get_db)):
    """Agent trimite id_token (deja obtinut prin loopback OAuth) + device info.
    Backend verifica tokenul, creeaza/gaseste User + Device, returneaza device_token."""
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

    # Device upsert by (owner, uid). Daca exista, re-emite token (echivalent relink).
    device_uid = payload.device_uid.strip()
    device_name = payload.device_name.strip()
    plain_token = Device.generate_token()

    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if device is None:
        device = Device(
            owner_id=user.id,
            device_uid=device_uid,
            name=device_name,
            device_token_hash=hash_token(plain_token),
            device_token_prefix=plain_token[:8],
        )
        db.add(device)
    else:
        device.device_token_hash = hash_token(plain_token)
        device.device_token_prefix = plain_token[:8]
        device.name = device_name  # update name daca s-a schimbat

    db.commit()
    db.refresh(device)

    return GoogleAgentEnrollOut(
        device_token=plain_token,
        device_uid=device.device_uid,
        device_name=device.name,
        user_email=user.email,
    )
```

- [ ] **Step 4: Rulează testele**

Run: `cd server && python -m pytest tests/test_google_agent_enroll.py -v`
Expected: PASS (3 teste).

- [ ] **Step 5: Toate testele**

Run: `cd server && python -m pytest`
Expected: PASS.

- [ ] **Step 6: Update `server/tests/memory.md`** — adaugă `test_google_agent_enroll.py`.

- [ ] **Step 7: Commit**

```bash
git add server/app/routes.py server/tests/test_google_agent_enroll.py server/tests/memory.md
git commit -m "routes: POST /agent/google-enroll cu verify id_token + device upsert"
```

---

## Task 6 — Agent: Modul `google_oauth.py`

**Files:**
- Create: `agent/google_oauth.py`
- Create: `agent/google_config.py.example`
- Modify: `agent/requirements.txt`
- Modify: `.gitignore`
- Modify: `agent/memory.md`

- [ ] **Step 1: Adaugă dependență în `agent/requirements.txt`**

Adaugă liniile:

```
google-auth-oauthlib>=1.2
google-auth>=2.30
```

Run: `cd agent && pip install -r requirements.txt`
Expected: instalează lib-urile.

- [ ] **Step 2: Creează `agent/google_config.py.example`**

```python
"""Configuratie OAuth pentru agent — copiaza la `google_config.py` si completeaza.

Pentru build-ul production .exe, `build.ps1` genereaza acest fisier inainte de PyInstaller."""

# OAuth Client ID de tip "Desktop app" din Google Cloud Console.
GOOGLE_CLIENT_ID = ""
```

- [ ] **Step 3: Adaugă `agent/google_config.py` în `.gitignore`**

Editează `.gitignore` (rădăcină proiect) — adaugă:

```
# Agent Google OAuth — local config (nu committe-uim client_id real)
agent/google_config.py
```

- [ ] **Step 4: Creează `agent/google_config.py` local (din example)**

Run (PowerShell): `Copy-Item agent/google_config.py.example agent/google_config.py`

Editează `agent/google_config.py` și pune Client ID-ul real (de tip Desktop) din Google Cloud Console.

- [ ] **Step 5: Creează `agent/google_oauth.py`**

```python
"""Loopback OAuth flow pentru desktop.

`InstalledAppFlow.run_local_server(port=0)` face toata coregrafia:
- genereaza PKCE code_verifier + challenge
- porneste local server pe port random (0 = OS alege)
- deschide browserul cu URL Google
- prinde codul de pe redirect
- face exchange cu Google
- returneaza Credentials cu id_token deja obtinut"""
from __future__ import annotations

import os

try:
    from .google_config import GOOGLE_CLIENT_ID
except ImportError:
    # Fallback: env var pentru dev cand google_config.py lipseste
    GOOGLE_CLIENT_ID = os.environ.get("AGENT_GOOGLE_CLIENT_ID", "")

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]


class GoogleOAuthError(Exception):
    """Esec in flow-ul OAuth desktop."""


def is_configured() -> bool:
    return bool(GOOGLE_CLIENT_ID)


def login_with_google(success_message: str = "Te poti intoarce la VulnWatch Agent.") -> str:
    """Deschide browserul, asteapta autentificare, returneaza id_token.

    Functia e BLOCANTA — apeleaz-o intr-un thread daca esti pe Tk main loop."""
    if not GOOGLE_CLIENT_ID:
        raise GoogleOAuthError(
            "GOOGLE_CLIENT_ID lipseste. Configureaza agent/google_config.py "
            "sau seteaza AGENT_GOOGLE_CLIENT_ID."
        )
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError as e:
        raise GoogleOAuthError(
            "google-auth-oauthlib nu este instalat. Ruleaza pip install -r requirements.txt."
        ) from e

    flow = InstalledAppFlow.from_client_config(
        {
            "installed": {
                "client_id": GOOGLE_CLIENT_ID,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://127.0.0.1"],
            }
        },
        scopes=SCOPES,
    )
    try:
        flow.run_local_server(
            port=0,
            open_browser=True,
            success_message=success_message,
        )
    except Exception as e:
        raise GoogleOAuthError(f"flow OAuth esuat: {e}") from e

    id_tok = getattr(flow.credentials, "id_token", None)
    if not id_tok:
        raise GoogleOAuthError("Google nu a returnat id_token. Verifica scope-urile.")
    return id_tok
```

- [ ] **Step 6: Verifică sintaxa**

Run: `cd .. && python -c "from agent.google_oauth import is_configured, login_with_google, GoogleOAuthError; print('OK')"`
Expected: `OK`.

- [ ] **Step 7: Update `agent/memory.md`** — adaugă `google_oauth.py` (loopback OAuth via google-auth-oauthlib) + `google_config.py` (gitignored, conține Client ID).

- [ ] **Step 8: Commit**

```bash
git add agent/google_oauth.py agent/google_config.py.example agent/requirements.txt .gitignore agent/memory.md
git commit -m "agent: google_oauth module cu InstalledAppFlow + config gitignored"
```

---

## Task 7 — Agent: `api_google_enroll` în core.py

**Files:**
- Modify: `agent/core.py`
- Test: `agent/tests/test_google_oauth.py`
- Modify: `agent/tests/memory.md`

- [ ] **Step 1: Scrie testul (failing)**

Creează `agent/tests/test_google_oauth.py`:

```python
"""Test api_google_enroll cu mock HTTP."""
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent import core


def test_api_google_enroll_returns_device_token():
    fake_response = {
        "device_token": "vw-abc123",
        "device_uid": "DESKTOP-Z",
        "device_name": "Test PC",
        "user_email": "test@example.com",
    }
    with mock.patch.object(core, "_request", return_value=fake_response) as m:
        result = core.api_google_enroll(
            api_base="http://api/v1",
            id_token="fake-id-token",
            device_uid="DESKTOP-Z",
            device_name="Test PC",
        )
    assert result["device_token"] == "vw-abc123"
    assert result["user_email"] == "test@example.com"
    m.assert_called_once()
    args, kwargs = m.call_args
    assert args[0] == "POST"
    assert "/agent/google-enroll" in args[1]
    assert kwargs["json"]["id_token"] == "fake-id-token"


def test_api_google_enroll_propagates_api_error():
    with mock.patch.object(core, "_request", side_effect=core.ApiError("401")):
        with pytest.raises(core.ApiError):
            core.api_google_enroll("http://api", "bad", "uid", "name")
```

- [ ] **Step 2: Rulează testul — cade**

Run: `cd agent && python -m pytest tests/test_google_oauth.py -v`
Expected: FAIL — `AttributeError: module 'agent.core' has no attribute 'api_google_enroll'`.

- [ ] **Step 3: Adaugă funcția în `agent/core.py`** — după `api_submit_job_failure` și înainte de `api_heartbeat`:

```python
def api_google_enroll(api_base: str, id_token: str, device_uid: str, device_name: str) -> dict:
    """Trimite id_token Google la backend pentru a crea Device.
    Returneaza dict cu device_token, device_uid, device_name, user_email."""
    return _request(
        "POST", f"{api_base}/agent/google-enroll",
        json={
            "id_token": id_token,
            "device_uid": device_uid,
            "device_name": device_name,
        },
        timeout=15,
    )
```

- [ ] **Step 4: Rulează testul**

Run: `python -m pytest tests/test_google_oauth.py -v`
Expected: PASS (2 teste).

- [ ] **Step 5: Toate testele agent**

Run: `python -m pytest`
Expected: PASS.

- [ ] **Step 6: Update `agent/tests/memory.md`** — adaugă `test_google_oauth.py` (2 teste mock pentru api_google_enroll).

- [ ] **Step 7: Commit**

```bash
cd .. && git add agent/core.py agent/tests/test_google_oauth.py agent/tests/memory.md
git commit -m "agent: api_google_enroll cu mock tests"
```

---

## Task 8 — Agent GUI: Buton Google pe pagina Login

**Files:**
- Modify: `agent/gui.py`
- Modify: `agent/memory.md`

- [ ] **Step 1: Identifică unde se randează pagina Login**

Run: `grep -n "_render_login\|def _on_login\|password.*pack" agent/gui.py | head -10`

- [ ] **Step 2: Adaugă imports în `agent/gui.py`**

În partea de top a fișierului, după `from . import autostart, core`, adaugă:

```python
import socket
import threading

from . import google_oauth
```

(Adaugă doar dacă lipsesc — `socket`/`threading` probabil există deja.)

- [ ] **Step 3: Adaugă metoda `_on_google_login` în clasa `AgentApp`**

Identifică metoda `_on_login` (handler-ul pentru form-ul email/parolă). Adaugă imediat după ea:

```python
def _on_google_login(self) -> None:
    """Flow OAuth desktop: deschide browserul, primeste id_token, enroll."""
    if not google_oauth.is_configured():
        messagebox.showerror(
            "Google OAuth neconfigurat",
            "agent/google_config.py nu contine GOOGLE_CLIENT_ID. "
            "Vezi google_config.py.example pentru setup."
        )
        return

    # Disable butonul si arata progres
    self._google_btn.configure(state="disabled", text="Se deschide browserul...")
    self._login_error_var.set("")

    def worker() -> None:
        try:
            id_tok = google_oauth.login_with_google()
            device_uid = socket.gethostname()
            device_name = device_uid  # user-ul poate sa-l schimbe in viitor
            api_base = self._api_base
            result = core.api_google_enroll(api_base, id_tok, device_uid, device_name)
            core.save_enrollment(
                api_base=api_base,
                device_uid=result["device_uid"],
                device_token=result["device_token"],
                device_name=result["device_name"],
                user_email=result["user_email"],
            )
            self.root.after(0, self._on_google_login_success)
        except google_oauth.GoogleOAuthError as e:
            self.root.after(0, lambda err=str(e): self._on_google_login_error(err))
        except core.ApiError as e:
            self.root.after(0, lambda err=str(e): self._on_google_login_error(err))
        except Exception as e:
            self.root.after(0, lambda err=str(e): self._on_google_login_error(f"Eroare: {err}"))

    threading.Thread(target=worker, daemon=True).start()


def _on_google_login_success(self) -> None:
    self._google_btn.configure(state="normal", text="Continuă cu Google")
    self._auto_start_daemon()
    self._render_status_page()


def _on_google_login_error(self, error: str) -> None:
    self._google_btn.configure(state="normal", text="Continuă cu Google")
    self._login_error_var.set(error)
```

- [ ] **Step 4: Identifică `_render_login_page` și adaugă butonul Google deasupra formularului**

Caută în `gui.py` blocul care creează inputurile email/parolă în `_render_login_page`. Imediat înainte de form (deasupra labelului „Email"), adaugă:

```python
# ── Buton Continua cu Google ────────────────────────────────────────────
self._google_btn = ttk.Button(
    parent, text="Continuă cu Google",
    style="Accent.TButton",
    command=self._on_google_login,
)
self._google_btn.pack(fill="x", pady=(0, 12))

# Separator "sau"
sep_frame = ttk.Frame(parent, style="TFrame")
sep_frame.pack(fill="x", pady=(0, 12))
ttk.Separator(sep_frame, orient="horizontal").pack(side="left", fill="x", expand=True, padx=(0, 8))
ttk.Label(sep_frame, text="sau", style="Dim.TLabel").pack(side="left")
ttk.Separator(sep_frame, orient="horizontal").pack(side="left", fill="x", expand=True, padx=(8, 0))
```

`parent` este variabila Frame-ul care wrap-uiește login-ul — confirmă numele real în codul tău (probabil `wrap` sau `frame`). Folosește același nume ca în blocul existent.

- [ ] **Step 5: Verifică că GUI-ul se importă fără erori**

Run: `cd .. && python -c "from agent import gui; print('OK')"`
Expected: `OK`.

- [ ] **Step 6: Test manual GUI (opțional dar recomandat)**

Run: `cd agent && python scan.py gui`
Expected: fereastra Tkinter — vezi „Continuă cu Google" + separator + form email/parolă. Click pe buton fără Client ID configurat → messagebox cu eroare clară.

- [ ] **Step 7: Update `agent/memory.md`** — gui.py: Login page are buton „Continuă cu Google" + separator deasupra formularului email/parolă. Handler-ul rulează `google_oauth.login_with_google()` într-un thread și apelează `api_google_enroll`.

- [ ] **Step 8: Commit**

```bash
git add agent/gui.py agent/memory.md
git commit -m "agent gui: buton 'Continua cu Google' pe pagina Login + flow async"
```

---

## Task 9 — Platform UI: Elimin form create device

**Files:**
- Modify: `web/src/pages/Devices.tsx`
- Modify: `web/src/pages/memory.md`

- [ ] **Step 1: Identifică blocurile de șters în `Devices.tsx`**

Pasajele de șters:
- Stările: `newDeviceUid`, `newDeviceName`, `createdToken`, `createdUid`, `copied`
- Funcția `handleCreate`
- Funcția `copyToken`
- Form-ul JSX cu „Înregistrează dispozitiv nou"
- Token success banner JSX
- `<CopyIcon>` dacă nu mai e folosit altundeva

- [ ] **Step 2: Editează `web/src/pages/Devices.tsx`**

Șterge importurile nefolosite (`apiPost`, `API_BASE_URL` rămân dacă sunt folosite în restul fișierului — verifică).

Șterge state-urile:

```typescript
// Șterge aceste linii (caută-le și elimină-le):
const [creating, setCreating] = useState(false);
const [newDeviceUid, setNewDeviceUid] = useState("");
const [newDeviceName, setNewDeviceName] = useState("");
const [createdToken, setCreatedToken] = useState<string | null>(null);
const [createdUid, setCreatedUid] = useState<string | null>(null);
const [copied, setCopied] = useState(false);
```

Șterge funcția `handleCreate(e)` (~20 linii) și `copyToken()` (~8 linii).

Șterge `<CopyIcon>` componenta (dacă nu mai e folosită).

În JSX, șterge blocul „Token success banner" (`{createdToken && (...)}`) și blocul cu form (coloana stânga din grid `{/* ── Enroll form ── */}`).

Refactorizează grid-ul container — elimină `gridTemplateColumns: "340px 1fr"`, lasă lista de device-uri să ocupe toată lățimea.

- [ ] **Step 3: Adaugă empty state nou când nu există device-uri**

În locul vechiului empty state simplu, înlocuiește:

```typescript
{!loading && devices.length === 0 && (
  <div className="empty-state" style={{ padding: 48, textAlign: "center" }}>
    <div style={{ fontSize: 48, marginBottom: 16 }}>📡</div>
    <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>
      Niciun dispozitiv conectat încă
    </div>
    <div style={{ fontSize: 13, color: "var(--text-muted)", maxWidth: 420, margin: "0 auto 20px" }}>
      Pentru a conecta primul dispozitiv, descarcă agentul VulnWatch și
      autentifică-te din aplicație.
    </div>
    {agentInfo?.available && (
      <a href={`${API_BASE_URL}/agent/download/windows`} className="btn btn-accent" style={{ textDecoration: "none" }}>
        ↓ Descarcă VulnWatch Agent
      </a>
    )}
  </div>
)}
```

- [ ] **Step 4: TypeScript check**

Run: `cd web && npx tsc --noEmit`
Expected: 0 erori.

- [ ] **Step 5: Update `web/src/pages/memory.md`** — Devices.tsx: eliminată funcționalitatea de create (form + token banner + handleCreate). Empty state nou cu link spre download agent. Singura sursă de creare device = agent .exe.

- [ ] **Step 6: Commit**

```bash
cd .. && git add web/src/pages/Devices.tsx web/src/pages/memory.md
git commit -m "web/Devices: elimina form create device — enrollment doar prin agent"
```

---

## Task 10 — Web: Install Framer Motion + Google Fonts

**Files:**
- Modify: `web/package.json`
- Modify: `web/index.html`

- [ ] **Step 1: Install framer-motion**

Run: `cd web && npm install framer-motion`
Expected: adăugat în `package.json` la versiune `^11.x` sau mai nou.

- [ ] **Step 2: Adaugă Google Fonts în `web/index.html`**

În `<head>`, înainte de `<title>`, adaugă:

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,500;9..144,700&family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
```

- [ ] **Step 3: Test build**

Run: `cd web && npm run build`
Expected: build se completează fără erori.

- [ ] **Step 4: Commit**

```bash
cd .. && git add web/package.json web/package-lock.json web/index.html
git commit -m "web: install framer-motion + Google Fonts (Fraunces, Outfit, JetBrains Mono)"
```

---

## Task 11 — Web: Theme system foundation (CSS variables + ThemeProvider)

**Files:**
- Modify: `web/src/index.css` (REWRITE complet a secțiunii `:root`)
- Create: `web/src/components/ThemeProvider.tsx`
- Modify: `web/src/main.tsx`

- [ ] **Step 1: Rescrie blocul `:root` din `web/src/index.css`**

Identifică blocul `:root { ... }` existent. Înlocuiește-l (păstrând restul fișierului — clasele specifice rămân) cu:

```css
:root,
[data-theme="light"] {
  /* Fonts */
  --font-display: 'Fraunces', Georgia, serif;
  --font-body: 'Outfit', system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', Consolas, monospace;

  /* Surface */
  --bg-base:       #fefaf2;
  --bg-elevated:   #fff8e6;
  --bg-hover:      #fdf4d8;
  --surface:       #ffffff;

  /* Borders */
  --border:        #f0e4cc;
  --border-strong: #e8d4a8;

  /* Text */
  --text-primary:   #2d1b3d;
  --text-secondary: #5a3a6e;
  --text-muted:     #8a7458;
  --text-inverse:   #fff8e6;

  /* Brand */
  --accent:        #f4c95d;
  --accent-strong: #d4a73d;
  --accent-soft:   #fff4d0;

  /* Severity */
  --severity-critical: #5a2d6e;
  --severity-high:     #b8456e;
  --severity-medium:   #d4a73d;
  --severity-low:      #a8639a;
  --severity-info:     #8a7458;

  /* Status */
  --success: #7a9a5a;
  --danger:  #c44b4b;
  --warning: #e8a23d;

  /* Shadows (plum-tinted) */
  --shadow-sm: 0 1px 2px rgba(45,27,61,0.06), 0 2px 6px rgba(45,27,61,0.04);
  --shadow-md: 0 4px 12px rgba(45,27,61,0.08), 0 8px 24px rgba(45,27,61,0.04);
  --shadow-lg: 0 12px 32px rgba(45,27,61,0.12), 0 20px 60px rgba(45,27,61,0.08);

  /* Radius */
  --radius-xs: 6px;
  --radius-sm: 10px;
  --radius-md: 16px;
  --radius-lg: 24px;
  --radius-xl: 32px;
  --radius-full: 999px;
}

[data-theme="dark"] {
  --bg-base:       #1a0e22;
  --bg-elevated:   #2d1b3d;
  --bg-hover:      #3d2a4f;
  --surface:       #4a3458;

  --border:        #4a3458;
  --border-strong: #6a4a78;

  --text-primary:   #fff8e6;
  --text-secondary: #e8d8b8;
  --text-muted:     #a89880;
  --text-inverse:   #2d1b3d;

  --accent:        #f4c95d;
  --accent-strong: #ffd97a;
  --accent-soft:   #3d2a4f;

  --severity-critical: #ff7aa8;
  --severity-high:     #ff9a73;
  --severity-medium:   #ffd97a;
  --severity-low:      #c8a3d8;
  --severity-info:     #a89880;

  --success: #a8c285;
  --danger:  #e88a8a;
  --warning: #ffd97a;

  --shadow-sm: 0 1px 2px rgba(0,0,0,0.20), 0 2px 6px rgba(0,0,0,0.12);
  --shadow-md: 0 4px 12px rgba(0,0,0,0.30), 0 8px 24px rgba(0,0,0,0.20);
  --shadow-lg: 0 12px 32px rgba(0,0,0,0.40), 0 20px 60px rgba(0,0,0,0.30);
}

body {
  font-family: var(--font-body);
  background: var(--bg-base);
  color: var(--text-primary);
  margin: 0;
  transition: background-color 0.3s ease, color 0.3s ease;
}

h1, h2, h3, .display {
  font-family: var(--font-display);
  font-weight: 500;
  letter-spacing: -0.01em;
}

* {
  transition: background-color 0.25s ease, color 0.25s ease, border-color 0.25s ease;
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

**Atenție**: păstrează restul `index.css` (clasele specifice pentru `.device-card`, `.scan-detail-page`, etc.) — vor fi actualizate în task-uri ulterioare. Doar înlocuiește blocul de variabile globale + body + animations.

- [ ] **Step 2: Creează `web/src/components/ThemeProvider.tsx`**

```typescript
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

type Theme = "light" | "dark";

type ThemeContextValue = {
  theme: Theme;
  toggle: () => void;
  setTheme: (t: Theme) => void;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

function getInitialTheme(): Theme {
  if (typeof window === "undefined") return "light";
  const stored = localStorage.getItem("vw-theme");
  if (stored === "light" || stored === "dark") return stored;
  if (window.matchMedia?.("(prefers-color-scheme: dark)").matches) return "dark";
  return "light";
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(getInitialTheme);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("vw-theme", theme);
  }, [theme]);

  const toggle = () => setThemeState(prev => (prev === "light" ? "dark" : "light"));
  const setTheme = (t: Theme) => setThemeState(t);

  return (
    <ThemeContext.Provider value={{ theme, toggle, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used inside <ThemeProvider>");
  return ctx;
}
```

- [ ] **Step 3: Wrap App cu ThemeProvider în `web/src/main.tsx`**

Citește `web/src/main.tsx`. Înlocuiește:

```typescript
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { ThemeProvider } from "./components/ThemeProvider";
import App from "./App";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <ThemeProvider>
        <App />
      </ThemeProvider>
    </BrowserRouter>
  </React.StrictMode>
);
```

(Adaptează imports-urile existente — nu duplica linii, doar adaugă ThemeProvider în jurul lui App.)

- [ ] **Step 4: TypeScript + smoke run**

Run: `cd web && npx tsc --noEmit`
Expected: 0 erori.

Run: `cd web && npm run dev` (în alt terminal sau background)
Deschide browser-ul la `http://localhost:5173`.
Expected: tema light se aplică (fundal crem). Schimbă manual în DevTools `<html data-theme="dark">` — fundalul devine plum profund.

- [ ] **Step 5: Update `web/src/memory.md` și `web/src/components/memory.md`**

În `web/src/components/memory.md`, adaugă entry pentru `ThemeProvider.tsx`.

- [ ] **Step 6: Commit**

```bash
cd .. && git add web/src/index.css web/src/components/ThemeProvider.tsx web/src/main.tsx web/src/memory.md web/src/components/memory.md
git commit -m "web/theme: ThemeProvider + CSS variables Honey&Plum (light/dark) + Fraunces/Outfit fonts"
```

---

## Task 12 — Web: ThemeToggle component

**Files:**
- Create: `web/src/components/ThemeToggle.tsx`
- Test: `web/src/components/__tests__/ThemeToggle.test.tsx` (smoke)
- Modify: `web/src/components/memory.md`

- [ ] **Step 1: Verifică dacă există framework de testare**

Run: `cd web && grep -E '"vitest"|"jest"|"@testing-library"' package.json`
Dacă nu există nimic, sărim peste teste pentru frontend (project actual nu are setup). Notează în memory că testele frontend sunt manuale.

Dacă ai vitest, scrie testul. Altfel mergi direct la implementare.

- [ ] **Step 2: Creează `web/src/components/ThemeToggle.tsx`**

```typescript
import { motion } from "framer-motion";
import { useTheme } from "./ThemeProvider";

export function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const isDark = theme === "dark";

  return (
    <button
      type="button"
      onClick={toggle}
      className="theme-toggle"
      title={isDark ? "Trece la light mode" : "Trece la dark mode"}
      aria-label={isDark ? "Trece la light mode" : "Trece la dark mode"}
    >
      <motion.svg
        width="20" height="20" viewBox="0 0 24 24"
        animate={{ rotate: isDark ? 0 : 180 }}
        transition={{ duration: 0.4, ease: "easeOut" }}
        fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
      >
        {isDark ? (
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
        ) : (
          <>
            <circle cx="12" cy="12" r="5"/>
            <line x1="12" y1="1" x2="12" y2="3"/>
            <line x1="12" y1="21" x2="12" y2="23"/>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
            <line x1="1" y1="12" x2="3" y2="12"/>
            <line x1="21" y1="12" x2="23" y2="12"/>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
          </>
        )}
      </motion.svg>
    </button>
  );
}
```

- [ ] **Step 3: Adaugă CSS pentru `.theme-toggle` în `web/src/index.css`** (la finalul fișierului):

```css
.theme-toggle {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: var(--radius-full);
  border: 1px solid var(--border);
  background: var(--bg-elevated);
  color: var(--text-primary);
  cursor: pointer;
  transition: background 0.2s ease, transform 0.2s ease, border-color 0.2s ease;
}
.theme-toggle:hover {
  background: var(--bg-hover);
  border-color: var(--border-strong);
  transform: translateY(-1px);
}
.theme-toggle:active { transform: translateY(0); }
```

- [ ] **Step 4: TypeScript + manual test**

Run: `cd web && npx tsc --noEmit`
Expected: 0 erori.

Dev server activ: `npm run dev`. Vom integra butonul în Navbar la Task 16; deocamdată îl putem testa adăugându-l temporar oriunde.

- [ ] **Step 5: Update `web/src/components/memory.md`** — adaugă `ThemeToggle.tsx`.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/ThemeToggle.tsx web/src/components/memory.md
git commit -m "web: ThemeToggle component cu animatie rotire sun/moon (Framer Motion)"
```

---

## Task 13 — Web: GoogleButton + UserAvatar componente

**Files:**
- Create: `web/src/components/GoogleButton.tsx`
- Create: `web/src/components/UserAvatar.tsx`
- Modify: `web/src/api/auth.ts`
- Modify: `web/src/api/types.ts`
- Modify: `web/src/components/memory.md`
- Modify: `web/src/api/memory.md`

- [ ] **Step 1: Adaugă `getGoogleAuthUrl` în `web/src/api/auth.ts`**

În capătul fișierului `web/src/api/auth.ts`, adaugă:

```typescript
import { apiGet } from "./http";

export function getGoogleAuthUrl() {
  return apiGet<{ auth_url: string; state: string }>("/auth/google/url");
}
```

(Importurile pot fi deja prezente — verifică, nu duplica.)

- [ ] **Step 2: Update `Me` type în `web/src/api/types.ts`**

În `web/src/api/types.ts`, dacă există tipul `Me` sau `User`, extinde-l:

```typescript
export type Me = {
  id: number;
  email: string;
  google_picture_url?: string | null;
  auth_provider?: "password" | "google" | "both";
};
```

Dacă tipul nu există încă (folosit doar prin generics), ignoră acest pas.

- [ ] **Step 3: Creează `web/src/components/GoogleButton.tsx`**

```typescript
import { getGoogleAuthUrl } from "../api/auth";
import { useState } from "react";

type Props = {
  label?: string;
  fullWidth?: boolean;
  onError?: (msg: string) => void;
};

export function GoogleButton({
  label = "Continuă cu Google",
  fullWidth = true,
  onError,
}: Props) {
  const [loading, setLoading] = useState(false);

  async function handleClick() {
    setLoading(true);
    try {
      const { auth_url } = await getGoogleAuthUrl();
      window.location.href = auth_url;
    } catch (e) {
      onError?.(e instanceof Error ? e.message : "Eroare Google login");
      setLoading(false);
    }
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      disabled={loading}
      className="google-button"
      style={{ width: fullWidth ? "100%" : undefined }}
    >
      <svg width="18" height="18" viewBox="0 0 24 24" style={{ flexShrink: 0 }}>
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
      </svg>
      <span>{loading ? "Se redirecționează..." : label}</span>
    </button>
  );
}
```

- [ ] **Step 4: Creează `web/src/components/UserAvatar.tsx`**

```typescript
type Props = {
  email: string;
  pictureUrl?: string | null;
  size?: number;
};

export function UserAvatar({ email, pictureUrl, size = 32 }: Props) {
  const initial = email.charAt(0).toUpperCase();
  const style = {
    width: size,
    height: size,
    borderRadius: "50%",
    fontSize: Math.max(11, size * 0.4),
  };

  if (pictureUrl) {
    return (
      <img
        src={pictureUrl}
        alt={email}
        className="user-avatar"
        style={style}
        referrerPolicy="no-referrer"
      />
    );
  }
  return (
    <div className="user-avatar user-avatar-initial" style={style}>
      {initial}
    </div>
  );
}
```

- [ ] **Step 5: Adaugă CSS în `web/src/index.css`** (la final):

```css
.google-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 12px 18px;
  background: var(--surface);
  color: var(--text-primary);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  font-family: var(--font-body);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  box-shadow: var(--shadow-sm);
  transition: transform 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
}
.google-button:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: var(--shadow-md);
  background: var(--bg-hover);
}
.google-button:active:not(:disabled) { transform: translateY(0); }
.google-button:disabled { opacity: 0.6; cursor: wait; }

.user-avatar {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: var(--accent);
  color: var(--text-inverse);
  font-family: var(--font-body);
  font-weight: 600;
  object-fit: cover;
  flex-shrink: 0;
  overflow: hidden;
}
.user-avatar-initial { background: var(--accent); color: var(--text-inverse); }
```

- [ ] **Step 6: TypeScript check**

Run: `cd web && npx tsc --noEmit`
Expected: 0 erori.

- [ ] **Step 7: Update `web/src/components/memory.md` și `web/src/api/memory.md`**

În `web/src/components/memory.md`: adaugă `GoogleButton.tsx` (buton cu logo SVG oficial Google) și `UserAvatar.tsx` (poză Google sau inițială pe fundal accent).

În `web/src/api/memory.md`: adaugă `getGoogleAuthUrl` în `auth.ts`.

- [ ] **Step 8: Commit**

```bash
git add web/src/components/GoogleButton.tsx web/src/components/UserAvatar.tsx web/src/api/auth.ts web/src/api/types.ts web/src/index.css web/src/components/memory.md web/src/api/memory.md
git commit -m "web: GoogleButton (logo oficial G) + UserAvatar + getGoogleAuthUrl"
```

---

## Task 14 — Web: ScoreGauge component animat

**Files:**
- Create: `web/src/components/ScoreGauge.tsx`
- Modify: `web/src/index.css`
- Modify: `web/src/components/memory.md`

- [ ] **Step 1: Creează `web/src/components/ScoreGauge.tsx`**

```typescript
import { useEffect, useState } from "react";
import { animate, motion, useMotionValue, useTransform } from "framer-motion";

type Props = {
  value: number;
  size?: number;
  strokeWidth?: number;
  label?: string;
};

export function ScoreGauge({ value, size = 160, strokeWidth = 12, label }: Props) {
  const count = useMotionValue(0);
  const [display, setDisplay] = useState(0);
  const dashLength = useTransform(count, [0, 100], [0, 1]);

  const radius = (size - strokeWidth) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * radius;

  useEffect(() => {
    const controls = animate(count, value, {
      duration: 1.2,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (latest) => setDisplay(Math.round(latest)),
    });
    return controls.stop;
  }, [value, count]);

  const severity = value >= 70 ? "high" : value >= 40 ? "medium" : value > 0 ? "low" : "none";

  return (
    <div className={`score-gauge score-${severity}`} style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={cx} cy={cy} r={radius}
          fill="none"
          stroke="var(--border)"
          strokeWidth={strokeWidth}
        />
        <motion.circle
          cx={cx} cy={cy} r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          style={{
            pathLength: dashLength,
            strokeDasharray: circumference,
          }}
          transform={`rotate(-90 ${cx} ${cy})`}
        />
      </svg>
      <div className="score-gauge-center">
        <div className="score-gauge-value">{display}</div>
        <div className="score-gauge-label">{label ?? "/ 100"}</div>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Adaugă CSS în `web/src/index.css`**

(Înlocuiește dacă există stiluri vechi `.score-gauge` din task-ul scan-types — păstrează prefixele `.score-gauge.score-high` etc. dar mută culorile pe noile variabile):

```css
.score-gauge {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--accent);
}
.score-gauge.score-high { color: var(--severity-critical); }
.score-gauge.score-medium { color: var(--severity-medium); }
.score-gauge.score-low { color: var(--severity-low); }
.score-gauge.score-none { color: var(--success); }

.score-gauge-center {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  pointer-events: none;
}
.score-gauge-value {
  font-family: var(--font-display);
  font-size: 44px;
  font-weight: 500;
  line-height: 1;
  color: var(--text-primary);
}
.score-gauge-label {
  font-size: 11px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-top: 4px;
}
```

- [ ] **Step 3: TypeScript**

Run: `cd web && npx tsc --noEmit`
Expected: 0 erori.

- [ ] **Step 4: Update `web/src/components/memory.md`** — adaugă `ScoreGauge.tsx`.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/ScoreGauge.tsx web/src/index.css web/src/components/memory.md
git commit -m "web: ScoreGauge cu animatie tween numar + inel SVG (Framer Motion)"
```

---

## Task 15 — Web: Navbar revamp (theme toggle + avatar)

**Files:**
- Modify: `web/src/components/Navbar.tsx`
- Modify: `web/src/index.css`
- Modify: `web/src/components/memory.md`

- [ ] **Step 1: Identifică structura curentă a Navbar**

Run: `cat web/src/components/Navbar.tsx`

- [ ] **Step 2: Refactor Navbar — adaugă ThemeToggle + UserAvatar**

Înlocuiește conținutul `web/src/components/Navbar.tsx`:

```typescript
import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { fetchMe, logoutUser } from "../api/auth";
import { ThemeToggle } from "./ThemeToggle";
import { UserAvatar } from "./UserAvatar";

type Me = {
  id: number;
  email: string;
  google_picture_url?: string | null;
};

export default function Navbar() {
  const [me, setMe] = useState<Me | null>(null);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    let cancel = false;
    fetchMe()
      .then((data) => { if (!cancel) setMe(data as Me); })
      .catch(() => { if (!cancel) setMe(null); });
    return () => { cancel = true; };
  }, [location.pathname]);

  async function handleLogout() {
    try { await logoutUser(); } catch { /* ignore */ }
    setMe(null);
    navigate("/login");
  }

  return (
    <nav className="navbar">
      <div className="navbar-inner">
        <Link to="/dashboard" className="navbar-brand">
          <span className="navbar-brand-mark">●</span>
          <span className="navbar-brand-text">VulnWatch</span>
        </Link>

        <div className="navbar-links">
          <Link to="/dashboard" className={`navbar-link ${location.pathname.startsWith("/dashboard") ? "active" : ""}`}>
            Dashboard
          </Link>
          <Link to="/devices" className={`navbar-link ${location.pathname.startsWith("/devices") ? "active" : ""}`}>
            Dispozitive
          </Link>
        </div>

        <div className="navbar-actions">
          <ThemeToggle />
          {me && (
            <>
              <UserAvatar email={me.email} pictureUrl={me.google_picture_url ?? undefined} size={32} />
              <button onClick={handleLogout} className="btn btn-ghost btn-sm" style={{ border: "1px solid var(--border)" }}>
                Logout
              </button>
            </>
          )}
        </div>
      </div>
    </nav>
  );
}
```

- [ ] **Step 3: Adaugă CSS pentru Navbar în `web/src/index.css`**

(Înlocuiește orice stil `.navbar*` existent):

```css
.navbar {
  position: sticky;
  top: 0;
  z-index: 50;
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(8px);
}
.navbar-inner {
  max-width: 1280px;
  margin: 0 auto;
  padding: 12px 24px;
  display: flex;
  align-items: center;
  gap: 24px;
}
.navbar-brand {
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: var(--font-display);
  font-size: 19px;
  font-weight: 700;
  color: var(--text-primary);
  text-decoration: none;
  letter-spacing: -0.01em;
}
.navbar-brand-mark { color: var(--accent); font-size: 14px; }
.navbar-links { display: flex; gap: 4px; flex: 1; }
.navbar-link {
  padding: 8px 14px;
  border-radius: var(--radius-sm);
  font-size: 14px;
  color: var(--text-secondary);
  text-decoration: none;
  font-weight: 500;
  transition: background 0.2s ease, color 0.2s ease;
}
.navbar-link:hover { background: var(--bg-hover); color: var(--text-primary); }
.navbar-link.active {
  background: var(--accent-soft);
  color: var(--text-primary);
}
.navbar-actions { display: flex; align-items: center; gap: 12px; }
```

- [ ] **Step 4: TypeScript + smoke test în browser**

Run: `cd web && npx tsc --noEmit`
Expected: 0 erori.

Dev server activ → reload page. Verifică:
- Navbar are theme toggle (sun/moon icon dreapta)
- Click → schimbă theme
- Avatar apare după login

- [ ] **Step 5: Update `web/src/components/memory.md`** — Navbar refactor cu ThemeToggle + UserAvatar + linkuri active.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/Navbar.tsx web/src/index.css web/src/components/memory.md
git commit -m "web/Navbar: refactor cu theme toggle, user avatar, links active state"
```

---

## Task 16 — Web: Login page revamp + Google button

**Files:**
- Modify: `web/src/pages/Login.tsx`
- Modify: `web/src/index.css`
- Modify: `web/src/pages/memory.md`

- [ ] **Step 1: Rewrite `web/src/pages/Login.tsx`**

```typescript
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { loginUser } from "../api/auth";
import { GoogleButton } from "../components/GoogleButton";

export default function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await loginUser(email, password);
      navigate("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login eșuat");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-page">
      <motion.div
        className="auth-card"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      >
        <div className="auth-header">
          <h1 className="auth-title">Bine ai venit înapoi</h1>
          <p className="auth-subtitle">Conectează-te la VulnWatch</p>
        </div>

        <GoogleButton onError={setError} />

        <div className="auth-divider">
          <span>sau</span>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="form-group">
            <label className="form-label">Email</label>
            <input
              type="email"
              className="form-input"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
          </div>
          <div className="form-group">
            <label className="form-label">Parolă</label>
            <input
              type="password"
              className="form-input"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
          </div>

          {error && (
            <div className="auth-error">{error}</div>
          )}

          <button type="submit" disabled={loading} className="btn btn-primary auth-submit">
            {loading
              ? <span className="loading-dots"><span /><span /><span /></span>
              : "Autentifică-te"}
          </button>
        </form>

        <p className="auth-switch">
          Nu ai cont? <Link to="/register" className="auth-link">Înregistrează-te</Link>
        </p>
      </motion.div>
    </div>
  );
}
```

- [ ] **Step 2: Adaugă CSS pentru auth pages în `web/src/index.css`**

```css
.auth-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background:
    radial-gradient(ellipse at top left, var(--accent-soft) 0%, transparent 50%),
    radial-gradient(ellipse at bottom right, var(--bg-hover) 0%, transparent 50%),
    var(--bg-base);
}
.auth-card {
  width: 100%;
  max-width: 420px;
  padding: 40px 36px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
}
.auth-header { text-align: center; margin-bottom: 28px; }
.auth-title {
  font-family: var(--font-display);
  font-size: 28px;
  font-weight: 500;
  margin: 0 0 6px;
  color: var(--text-primary);
  letter-spacing: -0.01em;
}
.auth-subtitle { margin: 0; color: var(--text-muted); font-size: 14px; }

.auth-divider {
  display: flex;
  align-items: center;
  gap: 12px;
  color: var(--text-muted);
  font-size: 12px;
  margin: 20px 0;
}
.auth-divider::before, .auth-divider::after {
  content: "";
  flex: 1;
  height: 1px;
  background: var(--border);
}

.auth-form { display: flex; flex-direction: column; gap: 16px; }
.form-label {
  display: block;
  font-size: 12px;
  font-weight: 500;
  color: var(--text-secondary);
  margin-bottom: 6px;
}
.form-input {
  width: 100%;
  padding: 11px 14px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-family: var(--font-body);
  font-size: 14px;
  color: var(--text-primary);
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
  box-sizing: border-box;
}
.form-input:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(244,201,93,0.20);
}

.auth-error {
  padding: 10px 14px;
  background: rgba(196,75,75,0.10);
  color: var(--danger);
  border-radius: var(--radius-sm);
  font-size: 13px;
  border-left: 3px solid var(--danger);
}
.auth-submit { width: 100%; padding: 12px; margin-top: 4px; }
.auth-switch { text-align: center; margin: 20px 0 0; font-size: 13px; color: var(--text-muted); }
.auth-link {
  color: var(--accent-strong);
  text-decoration: none;
  font-weight: 600;
}
.auth-link:hover { text-decoration: underline; }

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 9px 16px;
  border-radius: var(--radius-sm);
  font-family: var(--font-body);
  font-weight: 500;
  font-size: 14px;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.2s ease;
}
.btn-primary {
  background: var(--accent);
  color: var(--text-inverse);
  font-weight: 600;
}
.btn-primary:hover:not(:disabled) {
  background: var(--accent-strong);
  transform: translateY(-1px);
  box-shadow: var(--shadow-md);
}
.btn-primary:disabled { opacity: 0.6; cursor: wait; }
.btn-ghost {
  background: transparent;
  color: var(--text-primary);
}
.btn-ghost:hover { background: var(--bg-hover); }
.btn-sm { padding: 6px 12px; font-size: 13px; }
.btn-accent {
  background: var(--accent);
  color: var(--text-inverse);
  font-weight: 600;
}
.btn-accent:hover:not(:disabled) {
  background: var(--accent-strong);
  transform: translateY(-1px);
}
```

- [ ] **Step 3: TypeScript + manual test**

Run: `cd web && npx tsc --noEmit`
Expected: 0 erori.

Dev server: refresh `/login`. Verifică:
- Card centrat pe fundal gradient cald
- Buton Google sus full-width cu logo
- Divider „sau"
- Form email+parolă
- Switch theme → totul se adaptează smooth

- [ ] **Step 4: Update `web/src/pages/memory.md`** — Login: revamp complet cu Google button + form + auth-card layout cu gradient warm background.

- [ ] **Step 5: Commit**

```bash
cd .. && git add web/src/pages/Login.tsx web/src/index.css web/src/pages/memory.md
git commit -m "web/Login: revamp Honey&Plum cu Google button + form + gradient warm bg"
```

---

## Task 17 — Web: Register page revamp + Google button

**Files:**
- Modify: `web/src/pages/Register.tsx`
- Modify: `web/src/pages/memory.md`

- [ ] **Step 1: Rewrite `web/src/pages/Register.tsx`**

```typescript
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { loginUser, registerUser } from "../api/auth";
import { GoogleButton } from "../components/GoogleButton";

export default function Register() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < 8) {
      setError("Parola trebuie să aibă cel puțin 8 caractere");
      return;
    }
    setLoading(true);
    try {
      await registerUser(email, password);
      await loginUser(email, password);
      navigate("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Înregistrare eșuată");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-page">
      <motion.div
        className="auth-card"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      >
        <div className="auth-header">
          <h1 className="auth-title">Bun venit la VulnWatch</h1>
          <p className="auth-subtitle">Creează un cont nou</p>
        </div>

        <GoogleButton label="Înregistrează-te cu Google" onError={setError} />

        <div className="auth-divider"><span>sau</span></div>

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="form-group">
            <label className="form-label">Email</label>
            <input
              type="email"
              className="form-input"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
          </div>
          <div className="form-group">
            <label className="form-label">Parolă (min. 8 caractere)</label>
            <input
              type="password"
              className="form-input"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              minLength={8}
              autoComplete="new-password"
            />
          </div>

          {error && <div className="auth-error">{error}</div>}

          <button type="submit" disabled={loading} className="btn btn-primary auth-submit">
            {loading
              ? <span className="loading-dots"><span /><span /><span /></span>
              : "Creează contul"}
          </button>
        </form>

        <p className="auth-switch">
          Ai deja cont? <Link to="/login" className="auth-link">Autentifică-te</Link>
        </p>
      </motion.div>
    </div>
  );
}
```

- [ ] **Step 2: TypeScript + browser test**

Run: `cd web && npx tsc --noEmit`
Expected: 0 erori.

Verifică `/register` în browser — aceeași structură ca login.

- [ ] **Step 3: Update `web/src/pages/memory.md`** — Register: idem ca Login, cu titluri „Creează un cont" + buton „Înregistrează-te cu Google".

- [ ] **Step 4: Commit**

```bash
cd .. && git add web/src/pages/Register.tsx web/src/pages/memory.md
git commit -m "web/Register: revamp Honey&Plum cu Google button"
```

---

## Task 18 — Web: Dashboard revamp cu ScoreGauge animat

**Files:**
- Modify: `web/src/pages/Dashboard.tsx`
- Modify: `web/src/index.css`
- Modify: `web/src/pages/memory.md`

- [ ] **Step 1: Adaugă imports în `Dashboard.tsx`**

În top of file:

```typescript
import { motion } from "framer-motion";
import { ScoreGauge } from "../components/ScoreGauge";
```

- [ ] **Step 2: Înlocuiește stat row-ul cu ScoreGauge**

Caută blocul `{detail && (` care conține `stat-grid` cu cele 4 `stat-card` (Exposure Score + High/Medium/Low). Înlocuiește cu:

```typescript
{detail && (
  <motion.div
    className="dashboard-stat-row"
    initial={{ opacity: 0, y: 8 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.4 }}
  >
    <div className="dashboard-score">
      <ScoreGauge value={detail.exposure_score} size={180} />
    </div>
    <div className="dashboard-counts">
      <div className="count-card">
        <div className="count-value" style={{ color: "var(--severity-high)" }}>{highCount}</div>
        <div className="count-label">High / Critical</div>
      </div>
      <div className="count-card">
        <div className="count-value" style={{ color: "var(--severity-medium)" }}>{medCount}</div>
        <div className="count-label">Medium</div>
      </div>
      <div className="count-card">
        <div className="count-value" style={{ color: "var(--severity-low)" }}>{lowCount}</div>
        <div className="count-label">Low</div>
      </div>
    </div>
  </motion.div>
)}
```

- [ ] **Step 3: Wrap restul conținutului în `<motion.div>` pentru animație page-load**

Wrap tot blocul JSX returnat (după `<Navbar />`) într-un `<motion.div>` cu staggered children — sau adăug-o doar la lista de scanări.

Pentru lista de scanări, adaugă-i clase noi `.scan-row` cu hover lift (definite în pasul următor).

- [ ] **Step 4: Adaugă CSS în `web/src/index.css`**

```css
.dashboard-stat-row {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 32px;
  align-items: center;
  padding: 32px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  margin-bottom: 24px;
}
.dashboard-score { display: flex; justify-content: center; }
.dashboard-counts {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}
.count-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 20px;
  text-align: center;
}
.count-value {
  font-family: var(--font-display);
  font-size: 36px;
  font-weight: 500;
  line-height: 1;
}
.count-label {
  font-size: 11px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-top: 6px;
}
```

- [ ] **Step 5: TypeScript + manual test**

Run: `cd web && npx tsc --noEmit`
Expected: 0 erori.

Dev: `/dashboard` cu o scanare. ScoreGauge animă numărul de la 0 la valoare.

- [ ] **Step 6: Update `web/src/pages/memory.md`** — Dashboard: stat row înlocuit cu ScoreGauge animat (180px) + 3 count cards. Animație page-enter cu Framer Motion.

- [ ] **Step 7: Commit**

```bash
cd .. && git add web/src/pages/Dashboard.tsx web/src/index.css web/src/pages/memory.md
git commit -m "web/Dashboard: ScoreGauge animat + count cards + warm layout"
```

---

## Task 19 — Web: Devices page polish (revamp)

**Files:**
- Modify: `web/src/pages/Devices.tsx`
- Modify: `web/src/index.css`
- Modify: `web/src/pages/memory.md`

- [ ] **Step 1: Wrap conținut în `motion.div` cu stagger**

În top of `Devices.tsx`, adaugă:

```typescript
import { motion } from "framer-motion";

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.06 } },
};
const itemVariants = {
  hidden: { opacity: 0, y: 8 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.3 } },
};
```

Convertește `<div className="device-card">` în `<motion.div variants={itemVariants}>` și lista părintească într-un `motion.div initial="hidden" animate="visible" variants={containerVariants}`.

- [ ] **Step 2: Update `.device-card` + `.device-online-badge` în `web/src/index.css`**

Înlocuiește (sau adaugă dacă lipsesc):

```css
.device-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 20px;
  box-shadow: var(--shadow-sm);
  transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}
.device-card:hover {
  transform: translateY(-2px);
  border-color: var(--border-strong);
  box-shadow: var(--shadow-md);
}
.device-uid {
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 600;
  color: var(--accent-strong);
}
.device-name {
  font-family: var(--font-display);
  font-size: 16px;
  font-weight: 500;
  color: var(--text-primary);
  margin-top: 4px;
}
.device-meta { font-size: 12px; color: var(--text-muted); margin-top: 6px; }
.device-meta-inline { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); }

.device-online-badge {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 3px 10px; border-radius: var(--radius-full);
  font-size: 10px; font-weight: 700; letter-spacing: 0.06em;
  text-transform: uppercase;
}
.device-online-badge.online {
  background: rgba(122,154,90,0.15);
  color: var(--success);
}
.device-online-badge.online::before {
  content: "";
  display: inline-block;
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--success);
  animation: pulse-ring 2s infinite;
}
.device-online-badge.offline {
  background: rgba(138,116,88,0.15);
  color: var(--text-muted);
}
@keyframes pulse-ring {
  0%, 100% { box-shadow: 0 0 0 0 rgba(122,154,90,0.5); }
  50%      { box-shadow: 0 0 0 6px rgba(122,154,90,0); }
}

.scan-controls { display: flex; gap: 10px; align-items: center; margin-top: 14px; }
.scan-type-select {
  background: var(--bg-elevated);
  color: var(--text-primary);
  border: 1px solid var(--border);
  padding: 8px 12px;
  border-radius: var(--radius-sm);
  font-family: var(--font-body);
  font-size: 13px;
  flex: 1;
  min-width: 0;
}
.scan-type-select:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(244,201,93,0.20);
}
.scan-type-select:disabled { opacity: 0.5; cursor: not-allowed; }

.job-progress { margin-top: 12px; }
.job-progress-bar {
  width: 100%;
  height: 8px;
  background: var(--bg-elevated);
  border-radius: var(--radius-full);
  overflow: hidden;
  position: relative;
}
.job-progress-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--accent) 0%, var(--accent-strong) 100%);
  transition: width 0.5s cubic-bezier(0.16, 1, 0.3, 1);
  position: relative;
  overflow: hidden;
}
.job-progress-fill::after {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
  animation: shimmer 1.8s infinite;
}
@keyframes shimmer {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(100%); }
}
.job-progress-label {
  display: block;
  font-size: 11px;
  color: var(--text-secondary);
  margin-top: 6px;
}
```

- [ ] **Step 3: TypeScript + browser test**

Run: `cd web && npx tsc --noEmit`
Expected: 0 erori.

Dev: `/devices`. Verifică:
- Carduri device cu hover lift
- Badge online cu pulse animat verde
- Progress bar cu shimmer alunecat când se face scan

- [ ] **Step 4: Update `web/src/pages/memory.md`** — Devices: hover lift pe carduri + pulse animat pe online badge + shimmer pe progress bar + stagger entrance.

- [ ] **Step 5: Commit**

```bash
cd .. && git add web/src/pages/Devices.tsx web/src/index.css web/src/pages/memory.md
git commit -m "web/Devices: warm cards + pulse online badge + progress shimmer + stagger entrance"
```

---

## Task 20 — Web: ScanDetail polish + ScoreGauge integrat

**Files:**
- Modify: `web/src/pages/ScanDetail.tsx`
- Modify: `web/src/index.css`
- Modify: `web/src/pages/memory.md`

- [ ] **Step 1: Import ScoreGauge + Framer Motion în `ScanDetail.tsx`**

```typescript
import { motion } from "framer-motion";
import { ScoreGauge } from "../components/ScoreGauge";
```

- [ ] **Step 2: Înlocuiește vechiul `score-gauge` div cu componenta animată**

Caută blocul `<div className={\`score-gauge ${getScoreClass(data.exposure_score)}\`}>` și înlocuiește cu:

```tsx
<ScoreGauge value={data.exposure_score} size={160} />
```

(Elimină funcția `getScoreClass` dacă nu mai e folosită altundeva în fișier.)

- [ ] **Step 3: Adaugă animație page-enter**

Wrap conținutul principal (după `<Navbar />`) în:

```tsx
<motion.div
  className="container scan-detail-page"
  initial={{ opacity: 0, y: 8 }}
  animate={{ opacity: 1, y: 0 }}
  transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
>
  {/* conținutul existent */}
</motion.div>
```

- [ ] **Step 4: Sidebar categorii — animation cu layoutId pentru indicator slide**

Update lista de categorii din sidebar — wrap fiecare buton într-un container care folosește `layoutId` pentru indicator:

```tsx
{categories.map(cat => {
  const items = findingsByCategory[cat] ?? [];
  const topSev = items[0]?.severity?.toLowerCase() ?? "info";
  const isActive = activeCategory === cat;
  return (
    <button
      key={cat}
      className={`category-item ${isActive ? "active" : ""}`}
      onClick={() => setActiveCategory(cat)}
      style={{ position: "relative" }}
    >
      {isActive && (
        <motion.div
          layoutId="category-indicator"
          className="category-indicator"
          transition={{ type: "spring", stiffness: 350, damping: 30 }}
        />
      )}
      <span className="category-icon" style={{ position: "relative" }}>{CATEGORY_META[cat].icon}</span>
      <span className="category-label" style={{ position: "relative" }}>{CATEGORY_META[cat].label}</span>
      <span className={`category-count severity-${topSev}`} style={{ position: "relative" }}>{items.length}</span>
    </button>
  );
})}
```

- [ ] **Step 5: Update CSS — `.category-indicator` + restul layoutului ScanDetail**

În `web/src/index.css`, înlocuiește toate stilurile `.scan-detail-*`, `.category-*`, `.finding-*` cu (curățenie completă pentru noua paletă):

```css
.scan-detail-page { padding: 24px 32px; max-width: 1400px; margin: 0 auto; }
.scan-detail-topbar { display: flex; align-items: center; gap: 16px; margin-bottom: 24px; }
.scan-detail-meta { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.scan-detail-meta h1 {
  margin: 0;
  font-family: var(--font-display);
  font-size: 24px;
  font-weight: 500;
  color: var(--text-primary);
}
.scan-type-badge {
  padding: 3px 10px; border-radius: var(--radius-xs);
  font-size: 10px; font-weight: 800; letter-spacing: 0.08em;
}
.scan-type-badge.standard { background: rgba(244,201,93,0.18); color: var(--accent-strong); }
.scan-type-badge.advanced { background: rgba(184,69,110,0.18); color: var(--severity-high); }
.scan-type-badge.deep { background: rgba(90,45,110,0.18); color: var(--severity-critical); }
.scan-date { color: var(--text-muted); font-size: 13px; }

.scan-detail-grid { display: grid; grid-template-columns: 260px 1fr; gap: 24px; }
.scan-detail-sidebar { display: flex; flex-direction: column; gap: 16px; }

.score-summary {
  text-align: center;
  font-size: 13px;
  color: var(--text-secondary);
  padding: 4px 8px;
}

.category-nav { display: flex; flex-direction: column; gap: 4px; }
.category-item {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 14px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text-primary);
  cursor: pointer;
  text-align: left;
  font-family: var(--font-body);
  font-size: 13px;
  position: relative;
  transition: background 0.2s ease, border-color 0.2s ease;
}
.category-item:hover { background: var(--bg-hover); }
.category-item.active { background: var(--accent-soft); border-color: var(--accent); }
.category-indicator {
  position: absolute;
  inset: 0;
  background: var(--accent-soft);
  border-radius: var(--radius-sm);
  z-index: 0;
}
.category-icon { font-size: 18px; line-height: 1; }
.category-label { flex: 1; }
.category-count {
  padding: 2px 8px;
  border-radius: var(--radius-full);
  font-size: 11px;
  font-weight: 700;
  background: rgba(138,116,88,0.18);
  color: var(--text-secondary);
}
.category-count.severity-critical { background: rgba(90,45,110,0.20); color: var(--severity-critical); }
.category-count.severity-high { background: rgba(184,69,110,0.20); color: var(--severity-high); }
.category-count.severity-medium { background: rgba(244,201,93,0.20); color: var(--accent-strong); }
.category-count.severity-low { background: rgba(168,99,154,0.20); color: var(--severity-low); }
.no-findings { padding: 24px 12px; text-align: center; color: var(--success); font-size: 13px; }

.scan-detail-main {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 16px;
  align-items: start;
}
.finding-list {
  display: flex; flex-direction: column; gap: 4px;
  max-height: 70vh; overflow-y: auto; padding-right: 4px;
}
.finding-list-item {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 10px 12px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text-primary);
  cursor: pointer; text-align: left;
  font-size: 13px;
  transition: background 0.2s ease, border-color 0.2s ease;
}
.finding-list-item:hover { background: var(--bg-hover); }
.finding-list-item.active { background: var(--accent-soft); border-color: var(--accent); }
.finding-list-title { flex: 1; line-height: 1.4; }
.severity-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; margin-top: 6px; }
.severity-dot.severity-critical { background: var(--severity-critical); }
.severity-dot.severity-high { background: var(--severity-high); }
.severity-dot.severity-medium { background: var(--severity-medium); }
.severity-dot.severity-low { background: var(--severity-low); }
.severity-dot.severity-info { background: var(--text-muted); }

.finding-detail {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 24px 28px;
  box-shadow: var(--shadow-sm);
}
.finding-detail-header { display: flex; align-items: center; gap: 12px; margin-bottom: 18px; flex-wrap: wrap; }
.finding-detail-title {
  margin: 0;
  font-family: var(--font-display);
  font-size: 20px;
  font-weight: 500;
  color: var(--text-primary);
  flex: 1;
}
.finding-detail-id {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
}
.severity-badge {
  padding: 4px 10px;
  border-radius: var(--radius-xs);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.08em;
}
.severity-badge.severity-critical { background: rgba(90,45,110,0.18); color: var(--severity-critical); }
.severity-badge.severity-high { background: rgba(184,69,110,0.18); color: var(--severity-high); }
.severity-badge.severity-medium { background: rgba(244,201,93,0.18); color: var(--accent-strong); }
.severity-badge.severity-low { background: rgba(168,99,154,0.18); color: var(--severity-low); }
.severity-badge.severity-info { background: rgba(138,116,88,0.18); color: var(--text-muted); }

.finding-section { margin-bottom: 18px; }
.finding-section h4 {
  margin: 0 0 8px;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.10em;
  color: var(--text-muted);
  font-weight: 600;
}
.finding-section p {
  margin: 0;
  color: var(--text-primary);
  font-size: 14px;
  line-height: 1.7;
}
.finding-evidence {
  background: var(--bg-base);
  padding: 14px 16px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  font-family: var(--font-mono);
  font-size: 11.5px;
  color: var(--text-secondary);
  overflow-x: auto;
  max-height: 320px;
  margin: 0;
  line-height: 1.6;
}
```

- [ ] **Step 6: TypeScript + manual test**

Run: `cd web && npx tsc --noEmit`
Expected: 0 erori.

Dev: deschide o scanare. Verifică:
- ScoreGauge animă numărul
- Sidebar categorii cu animație slide la schimbare
- Severity dots tinte în culorile noi

- [ ] **Step 7: Update `web/src/pages/memory.md`** — ScanDetail: integrat ScoreGauge animat + indicator slide pe categorii (layoutId) + page-enter motion + paleta nouă pe toate severity tints.

- [ ] **Step 8: Commit**

```bash
cd .. && git add web/src/pages/ScanDetail.tsx web/src/index.css web/src/pages/memory.md
git commit -m "web/ScanDetail: ScoreGauge animat + indicator slide + page-enter motion"
```

---

## Task 21 — Final: rulare tot ce avem + actualizare CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`
- Modify: `memory.md` (rădăcină)

- [ ] **Step 1: Rulează tot test suite-ul backend + agent**

Run (din rădăcină):
```bash
cd server && python -m pytest && cd ..\agent && python -m pytest
```
Expected: PASS pe toate (numerele cresc față de iterația anterioară cu noile teste OAuth).

- [ ] **Step 2: TypeScript build complet**

Run: `cd web && npm run build`
Expected: build success.

- [ ] **Step 3: Smoke test end-to-end manual**

Pornire stack (3 terminale):
```powershell
docker compose up -d
cd server; .\.venv\Scripts\Activate; fastapi dev app/main.py
cd web; npm run dev
```

Browser → `http://localhost:5173/login`:
- ✓ Card centrat pe gradient warm
- ✓ Click „Continuă cu Google" → redirect Google → autentificare → redirect înapoi → ești pe `/dashboard`
- ✓ Avatar Google apare în Navbar
- ✓ Theme toggle (sun/moon) schimbă tema smooth

Agent (al 4-lea terminal):
```powershell
cd agent; python scan.py gui
```
- ✓ Login page agent are buton „Continuă cu Google"
- ✓ Click → browser se deschide → autentificare → tab închis → agent pe Status page
- ✓ Device apare în platform `/devices` cu badge ●Online după ~10s
- ✓ Click „Scanează acum" → progress bar shimmer → scor apare

- [ ] **Step 4: Update `CLAUDE.md`** — la secțiunea „Authentication", adaugă:

```markdown
**Google OAuth (hybrid):**
- Web: `/api/v1/auth/google/url` returnează URL Google; callback la `/api/v1/auth/google/callback` setează sesiune + redirect spre frontend
- Desktop (agent): `google-auth-oauthlib.InstalledAppFlow.run_local_server(port=0)` face Loopback Redirect + PKCE; agent trimite `id_token` la `POST /api/v1/agent/google-enroll` → primește `device_token`
- Cont existent cu email/parolă + login Google la același email → `auth_provider="both"`
- Env vars: `GOOGLE_CLIENT_ID_WEB`, `GOOGLE_CLIENT_SECRET_WEB`, `GOOGLE_CLIENT_ID_DESKTOP`, `GOOGLE_REDIRECT_URI_WEB`, `FRONTEND_BASE_URL`
- Agent: `agent/google_config.py` (gitignored) conține `GOOGLE_CLIENT_ID` (desktop)
```

La secțiunea „Frontend", adaugă:

```markdown
**Theme system:** `<ThemeProvider>` în `web/src/components/ThemeProvider.tsx` — gestionează `data-theme` pe `<html>`, persistă în `localStorage` (`vw-theme`), respectă `prefers-color-scheme` la primul vizit. Toggle prin `<ThemeToggle>` în Navbar.

**Paleta**: Honey & Plum — light (#fefaf2 cream + #f4c95d honey + #2d1b3d plum text) și dark (#1a0e22 plum bg + #f4c95d honey + #fff8e6 cream text). CSS variables în `:root` și `[data-theme="dark"]`. Severity colors warm-tinted (plum/raspberry pentru high/critical, honey pentru medium, lavandă pentru low).

**Tipografie**: `Fraunces` (display serif), `Outfit` (body sans), `JetBrains Mono` (code) — Google Fonts.

**Animații**: Framer Motion pentru page enter, layout transitions, ScoreGauge tween; CSS pentru hover lift, pulse online badge, shimmer progress bar. Respectă `prefers-reduced-motion`.
```

- [ ] **Step 5: Update root `memory.md`** — secțiunea „Flow tipic" — modifică:

```markdown
4. **Scan**: **inițiat din platforma web** (`/devices` → selector tip + "Scanează acum"). Agentul este executor. **Device-urile se creează DOAR din agent** (nu din platformă). Login: hybrid Google OAuth + email/parolă.
```

Adaugă o secțiune nouă „Theme":

```markdown
## UI Theme

- **Paleta**: Honey & Plum cu light + dark mode toggle
- **Fonturi**: Fraunces (display), Outfit (body), JetBrains Mono (cod)
- **Animații**: Framer Motion (page enter, score gauge, sidebar indicator) + CSS (hover lift, pulse, shimmer)
- **Theme persist**: `localStorage.vw-theme` + `prefers-color-scheme` fallback
```

- [ ] **Step 6: Commit final**

```bash
git add CLAUDE.md memory.md
git commit -m "docs: actualizare CLAUDE.md + memory.md root pentru Google OAuth + warm UI revamp"
```

---

## Self-Review

**Spec coverage:**
- §2.1 Hybrid Google + email/password → Task 1 (User schema), Task 4 (web flow), Task 5 (agent flow), Task 16-17 (Login/Register cu GoogleButton)
- §2.2 Setup Google Cloud → Pre-flight section
- §2.3 Web OAuth flow → Task 4 (`/auth/google/url` + callback)
- §2.4 Desktop OAuth flow (PKCE + Loopback) → Task 6 (google_oauth.py) + Task 8 (GUI button)
- §2.5 Endpoint-uri noi → Task 4 + Task 5
- §2.6 Modificări `User` → Task 1
- §2.7 Dependențe → Task 1 (backend) + Task 6 (agent) + Task 10 (web)
- §3.1 Endpoint-uri device → Task 5 (`/agent/google-enroll` nou); restul rămân
- §3.2 Platform UI cleanup → Task 9
- §3.3 Login/Register layout → Task 16-17
- §4.1 Tipografie → Task 10 (fonts loaded) + Task 11 (CSS variables)
- §4.2-4.4 Palette + radius + spacing → Task 11
- §4.5 Animații → Task 12 (theme), Task 14 (ScoreGauge), Task 16-20 (page-enter, hover, shimmer, layoutId)
- §4.6 Componente noi → Task 11 (ThemeProvider), 12 (ThemeToggle), 13 (GoogleButton, UserAvatar), 14 (ScoreGauge)
- §4.7 Pagini revamp → Task 15 (Navbar), 16 (Login), 17 (Register), 18 (Dashboard), 19 (Devices), 20 (ScanDetail)
- §5 Module backend → Task 3 (google_auth), Task 4 (config)
- §6 Module agent → Task 6 (google_oauth)
- §7 DB schema → Task 1 (drop & recreate)
- §8 Teste → Task 3, 4, 5 (backend); Task 7 (agent); Task 21 (smoke E2E)

Toate cerințele acoperite. Nu lipsesc task-uri.

**Placeholder scan:** Nu există „TBD", „TODO" sau placeholdere — fiecare step are cod concret.

**Type consistency:**
- `GoogleAgentEnrollIn.id_token` (Task 2) → folosit în Task 5 ✓
- `api_google_enroll(api_base, id_token, device_uid, device_name)` (Task 7) → apelat din Task 8 ✓
- `_upsert_google_user(db, email, google_sub, picture)` (Task 4) → reutilizat în Task 5 ✓
- `google_auth.verify_id_token(token, client_id)` (Task 3) → folosit în Task 4 + Task 5 ✓
- CSS variables consistente între pagini (Task 11 le definește, restul folosesc) ✓

---

## Execution Handoff

**Plan complet, salvat la `docs/superpowers/plans/2026-05-13-google-oauth-and-warm-ui-revamp.md`. Două opțiuni de execuție:**

**1. Subagent-Driven (recomandat)** — Dispatch fresh subagent pe fiecare task, review între task-uri, iterație rapidă.

**2. Inline Execution** — Execuție task cu task în sesiunea curentă (sau una nouă cu Opus), checkpoints pentru review.

**Care abordare?**
