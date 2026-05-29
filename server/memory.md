# memory.md — server/

Backend FastAPI: API REST `/api/v1/*`, autentificare cookie HttpOnly,
job queue pentru scan-on-demand, motor de reguli pentru calculul scorului.

## Stack

- FastAPI 0.115+ cu Uvicorn pentru serving
- SQLAlchemy 2.0 (sintaxa moderna `Mapped`, `mapped_column`)
- Pydantic 2 cu `EmailStr` pentru validare
- PostgreSQL 16 in productie; SQLite in teste (override prin `DATABASE_URL`)
- Auth: PBKDF2-SHA256 (200k iteratii) + cookie sesiune HttpOnly
- Auth Google OAuth: `google-auth` pentru verificare id_token (web + desktop)

## Continut

| Fisier / folder       | Rol                                                                  |
| --------------------- | -------------------------------------------------------------------- |
| `app/`                | Cod aplicatie (FastAPI app). Vezi `app/memory.md`. **`routes/` e pachet** (sub-routere pe domeniu), nu mai e `routes.py` monolitic. |
| `tests/`              | Pytest end-to-end (TestClient). Vezi `tests/memory.md`.              |
| `alembic/` + `alembic.ini` | **Migrari DB** (additiv, pentru productie). `env.py` citeste `DATABASE_URL` + `Base.metadata`; `versions/` contine migrarea initiala (7 tabele). `alembic upgrade head` in productie; dev/teste raman pe `create_all`. |
| `requirements.txt`    | Dependencies de runtime + dev: `fastapi`, `uvicorn[standard]`, `sqlalchemy`, `alembic`, `psycopg[binary]`, `pydantic[email]`, `google-auth`, `requests` (transport HTTP pentru google-auth), `httpx`, `reportlab`, `slowapi`, `pytest`. |
| `.env.example`        | Template pentru `.env`. Variabile: `DATABASE_URL`, `SESSION_EXPIRE_HOURS`, `CORS_ORIGINS`, `COOKIE_SECURE`, `COOKIE_SAMESITE`, `GOOGLE_CLIENT_ID_WEB`, `GOOGLE_CLIENT_SECRET_WEB`, `GOOGLE_REDIRECT_URI_WEB`, `GOOGLE_CLIENT_ID_DESKTOP`, `FRONTEND_BASE_URL`. |

## Rulare

```powershell
cd server
python -m venv .venv
.\.venv\Scripts\Activate.ps1     # PowerShell — sau venv\bin\activate pe POSIX
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

API disponibil la `http://127.0.0.1:8000/api/v1`. Documentatie auto-generata
OpenAPI/Swagger la `http://127.0.0.1:8000/docs`.

## Endpoint-uri principale

| Metoda + cale                                         | Auth                | Rol                                  |
| ----------------------------------------------------- | ------------------- | ------------------------------------ |
| `POST   /api/v1/auth/register`                        | —                   | Cont nou                             |
| `POST   /api/v1/auth/login`                           | —                   | Login → cookie + session_token       |
| `GET    /api/v1/auth/me`                              | cookie / X-Session  | Profil curent                        |
| `DELETE /api/v1/auth/logout`                          | cookie / X-Session  | Logout idempotent                    |
| `GET    /api/v1/devices`                              | cookie / X-Session  | Listeaza device-urile user-ului      |
| `POST   /api/v1/devices`                              | cookie / X-Session  | Inrolare device nou — body include `token_hash` (SHA-256 hex generat de client). Returneaza metadata FARA token plain. |
| `DELETE /api/v1/devices/{uid}`                        | cookie / X-Session  | Sterge device + cascade scan-uri     |
| `GET    /api/v1/devices/by-uid/{uid}`                 | cookie / X-Session  | Smart re-link lookup                 |
| `POST   /api/v1/devices/{uid}/relink`                 | cookie / X-Session  | Re-emite token — body include `token_hash` nou. Tokenul vechi devine invalid. |
| `GET    /api/v1/devices/{uid}/scans`                  | cookie / X-Session  | Istoric scanari                      |
| `POST   /api/v1/devices/{uid}/scan-jobs`              | cookie / X-Session  | UI cere scan on-demand               |
| `GET    /api/v1/devices/{uid}/scan-jobs`              | cookie / X-Session  | Istoric job-uri pe device            |
| `GET    /api/v1/scan-jobs/{id}`                       | cookie / X-Session  | UI polleaza status job               |
| `POST   /api/v1/scans`                                | X-Device-Token      | Agent push direct (legacy & debug)   |
| `GET    /api/v1/scans/{id}`                           | cookie / X-Session  | Detalii scan + findings              |
| `GET    /api/v1/agent/jobs/next`                      | X-Device-Token      | Agent ridica job (atomic, FOR UPDATE SKIP LOCKED); returneaza `scan_type` |
| `POST   /api/v1/agent/jobs/{id}/result`               | X-Device-Token      | Agent finalizeaza job                |
| `POST   /api/v1/agent/jobs/{id}/fail`                 | X-Device-Token      | Agent raporteaza esec                |
| `POST   /api/v1/agent/jobs/{id}/progress`             | X-Device-Token      | Agent raporteaza progres intre colectori (Advanced/Deep) |
| `POST   /api/v1/agent/heartbeat`                      | X-Device-Token      | Agent → backend la 10s (online status + version + capabilities) |
| `GET    /api/v1/agent/download/info`                  | cookie / X-Session  | Info despre .exe (size, available)   |
| `GET    /api/v1/agent/download/windows`               | cookie / X-Session  | Descarca `VulnWatchAgent.exe`        |
| `GET    /api/v1/auth/google/url`                      | —                   | Returneaza URL Google OAuth + state CSRF |
| `GET    /api/v1/auth/google/callback`                 | —                   | Callback Google dupa login: schimba code -> id_token, creeaza/lipeste User, seteaza cookie, redirect spre frontend `/dashboard` |
| `POST   /api/v1/agent/google-enroll`                  | —                   | Agent enrollment cu Google id_token — body include `token_hash`. Upsert User+Device intr-un singur request, returneaza metadata FARA `device_token`. |

Total endpoint-uri: ~24.
