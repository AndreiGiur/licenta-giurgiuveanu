# memory.md — server/

Backend FastAPI: API REST `/api/v1/*`, autentificare cookie HttpOnly,
job queue pentru scan-on-demand, motor de reguli pentru calculul scorului.

## Stack

- FastAPI 0.115+ cu Uvicorn pentru serving
- SQLAlchemy 2.0 (sintaxa moderna `Mapped`, `mapped_column`)
- Pydantic 2 cu `EmailStr` pentru validare
- PostgreSQL 16 in productie; SQLite in teste (override prin `DATABASE_URL`)
- Auth: PBKDF2-SHA256 (200k iteratii) + cookie sesiune HttpOnly

## Continut

| Fisier / folder       | Rol                                                                  |
| --------------------- | -------------------------------------------------------------------- |
| `app/`                | Cod aplicatie (FastAPI app). Vezi `app/memory.md`.                   |
| `tests/`              | Pytest end-to-end (TestClient). Vezi `tests/memory.md`.              |
| `requirements.txt`    | Dependencies de runtime + dev: `fastapi`, `uvicorn[standard]`, `sqlalchemy`, `psycopg[binary]`, `pydantic[email]`, `pytest`, `httpx`. |
| `.env.example`        | Template pentru `.env`. Variabile: `DATABASE_URL`, `SESSION_EXPIRE_HOURS`, `CORS_ORIGINS`, `COOKIE_SECURE`, `COOKIE_SAMESITE`. |

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
| `POST   /api/v1/devices`                              | cookie / X-Session  | Inrolare device nou (returneaza token plain o data) |
| `DELETE /api/v1/devices/{uid}`                        | cookie / X-Session  | Sterge device + cascade scan-uri     |
| `GET    /api/v1/devices/by-uid/{uid}`                 | cookie / X-Session  | Smart re-link lookup                 |
| `POST   /api/v1/devices/{uid}/relink`                 | cookie / X-Session  | Re-emite token (invalideaza vechiul) |
| `GET    /api/v1/devices/{uid}/scans`                  | cookie / X-Session  | Istoric scanari                      |
| `POST   /api/v1/devices/{uid}/scan-jobs`              | cookie / X-Session  | UI cere scan on-demand               |
| `GET    /api/v1/devices/{uid}/scan-jobs`              | cookie / X-Session  | Istoric job-uri pe device            |
| `GET    /api/v1/scan-jobs/{id}`                       | cookie / X-Session  | UI polleaza status job               |
| `POST   /api/v1/scans`                                | X-Device-Token      | Agent push direct (legacy & debug)   |
| `GET    /api/v1/scans/{id}`                           | cookie / X-Session  | Detalii scan + findings              |
| `GET    /api/v1/agent/jobs/next`                      | X-Device-Token      | Agent ridica job (atomic, FOR UPDATE SKIP LOCKED) |
| `POST   /api/v1/agent/jobs/{id}/result`               | X-Device-Token      | Agent finalizeaza job                |
| `POST   /api/v1/agent/jobs/{id}/fail`                 | X-Device-Token      | Agent raporteaza esec                |
| `GET    /api/v1/agent/download/info`                  | cookie / X-Session  | Info despre .exe (size, available)   |
| `GET    /api/v1/agent/download/windows`               | cookie / X-Session  | Descarca `VulnWatchAgent.exe`        |

Total endpoint-uri: ~22.
