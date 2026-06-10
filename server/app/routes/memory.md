# memory.md — server/app/routes/

Pachet rezultat din refactorizarea fostului `routes.py` monolitic (~1300 LOC)
in sub-routere pe domeniu. Fiecare modul are propriul `APIRouter`; `__init__.py`
le agrega intr-un singur `router` exportat. `main.py` ramane neschimbat
(`from .routes import router` → `app.include_router(router, prefix="/api/v1")`).

Importul oricarui sub-modul incarca `config` (deci `.env`) tranzitiv.

## Fisiere

| Fisier         | Rol                                                                       |
| -------------- | ------------------------------------------------------------------------- |
| `__init__.py`  | Construieste `router = APIRouter()` si include sub-routerele (auth, profile, devices, scans, scan_jobs, agent, admin, scheduler). Ordinea nu conteaza (rute neambigue, segmente literale distincte). |
| `_helpers.py`  | Helperi partajati: `_utcnow`, `_device_to_out`, `_scan_job_to_out`, `_device_for_token_or_401` (auth agent prin `X-Device-Token`), Google OAuth state CSRF **stateless semnat HMAC** (`_make_state`/`_consume_state`, format `nonce.ts.semnatura`, TTL 5 min; secret din `config.SECRET_KEY` cu fallback random per-proces — functioneaza multi-worker daca SECRET_KEY e setat, spre deosebire de vechiul dict in-memory), `_upsert_google_user` (upsert by email + auth_provider both/google), `_find_agent_artifact`/`_AGENT_BUILD_LOCATIONS` (localizare `.exe`). **Testele patch-uiesc `routes._helpers._AGENT_BUILD_LOCATIONS`.** |
| `auth.py`      | `/auth/register` + `/auth/login` (rate-limited 5/min), `/auth/me`, `/auth/logout` (idempotent; cauta sesiunea dupa `hash_token`), `/auth/google/url` + `/auth/google/callback` (web OAuth flow; **rate-limited 10/min**). |
| `profile.py`   | `PATCH /me` (first_name/last_name/default_scan_type), `GET /me/stats`, `GET /me/sessions` (`is_current` compara `hash_token(token_curent)` cu hash-ul din DB), `DELETE /me/sessions/{id}`, `POST /me/password`. |
| `devices.py`   | `POST/GET /devices`, `GET /devices/by-uid/{uid}`, `POST /devices/{uid}/relink` (smart re-link), `GET /devices/{uid}/net-traffic` (serie trafic live din `livestate`), `DELETE /devices/{uid}`. **`list_devices` calculeaza per device `scan_count` + `last_score`** (pentru sidebar-ul dashboard-ului unificat) — `DeviceOut` are aceste campuri optionale (default 0/None in restul endpoint-urilor). |
| `agent.py`     | (update 2026-06-01) `agent_heartbeat` alimenteaza `livestate.record_sample` cand payload-ul contine `net_bytes_sent/recv`. **+ `GET /agent/download/linux`** (serveste **`install.sh`** — installer Linux, text/x-shellscript) + `download/info` raporteaza disponibilitate **per-OS** (`windows`=.exe / `linux`=install.sh), pastrand campurile top-level pentru compat. **Liveness in timpul scanarii:** `agent_update_progress` / `agent_submit_result` / `agent_submit_failure` bumpeaza `device.last_heartbeat` — daemon-ul e single-threaded si nu trimite heartbeat cat ruleaza un scan lung (deep), dar progresul (nmap la 2s) tine device-ul ONLINE (fix 'fara conexiune' in timpul deep). |
| `scans.py`     | `POST /scans` (push direct, X-Device-Token; acum accepta `scan_type` in ScanIn), `GET /devices/{uid}/scans`, `GET /devices/{uid}/score-trend`, `GET /scans/{id}/diff`, `GET /scans/{id}`, `GET /scans/{id}/report.pdf`. **`scan_diff` compara DOAR scanari de acelasi `scan_type`** — auto-previous sare peste tipuri diferite (nu compara deep cu advanced); previous explicit de alt tip → 400. |
| `scan_jobs.py` | Latura UI a scan-on-demand: `GET /devices/{uid}/scan-jobs/preview`, `POST /devices/{uid}/scan-jobs`, `GET /scan-jobs/{id}`, `GET /devices/{uid}/scan-jobs`. |
| `agent.py`     | Latura agent (X-Device-Token): `GET /agent/jobs/next` (pickup atomic SELECT FOR UPDATE SKIP LOCKED), `POST /agent/jobs/{id}/result` (scoring + Scan; **scan_dict include `linux` din 2026-06-01** ca regulile `os="linux"` sa primeasca date), `POST /agent/heartbeat`, `POST /agent/jobs/{id}/progress`, `POST /agent/jobs/{id}/fail`, `GET /agent/download/windows|info`, `POST /agent/google-enroll` (**rate-limited 10/min**). |
| `admin.py`     | `require_admin`: `GET /admin/users`, `DELETE /admin/users/{id}` (block self), `POST /admin/users/{id}/role` (block self-demote), `POST /admin/users/{id}/reset-password`, `GET /admin/devices`, `GET /admin/scans` (paginat), `GET /admin/stats`. |
| `scheduler.py` | `POST/GET /devices/{uid}/schedules`, `PATCH/DELETE /schedules/{id}` (max `MAX_SCHEDULES_PER_USER`). |

## De ce split

`routes.py` ajunsese la ~1300 LOC — greu de navigat, un singur fisier pentru 8
domenii. Split-ul nu schimba niciun contract HTTP (endpoint-uri + tags identice),
doar organizarea interna. Validat cu intreaga suita server (zero regresii).
