# memory.md — server/app/

Pachetul aplicatiei FastAPI. Toate endpoint-urile, modelele, schemas-urile
si motorul de reguli.

## Layered architecture

```
   main.py        (FastAPI app + CORS + create_all)
       │
       ├─► routes.py    (toate endpoint-urile /api/v1/*)
       │     │
       │     ├─► auth.py    (PBKDF2, cookie HttpOnly, dependencies require_user)
       │     ├─► models.py  (User, Session, Device, Scan, Finding, ScanJob)
       │     ├─► schemas.py (Pydantic In/Out)
       │     └─► rules.py   (motor de evaluare → exposure_score + findings)
       │
       └─► db.py        (SQLAlchemy engine + SessionLocal + Base)
```

## Fisiere

| Fisier        | Rol                                                                       |
| ------------- | ------------------------------------------------------------------------- |
| `main.py`     | FastAPI app cu **lifespan handler** care porneste `scheduler_loop` ca asyncio task la startup (skip pe `DISABLE_SCHEDULER=true` in teste); CORS middleware (`allow_credentials=True`, origins din env); `Base.metadata.create_all` la pornire (dev only); include router-ul cu prefix `/api/v1`. |
| `config.py`   | **Env vars centralizate** pentru Google OAuth + frontend redirect. Citeste: `GOOGLE_CLIENT_ID_WEB`, `GOOGLE_CLIENT_SECRET_WEB`, `GOOGLE_REDIRECT_URI_WEB` (default `http://localhost:8000/api/v1/auth/google/callback`), `GOOGLE_CLIENT_ID_DESKTOP`, `FRONTEND_BASE_URL` (default `http://localhost:5173`). |
| `db.py`       | SQLAlchemy engine cu `pool_pre_ping=True`; `SessionLocal` factory; `Base = DeclarativeBase`. URL-ul DB-ului citit din `DATABASE_URL` env var (default postgres dev). |
| `models.py`   | **7 tabele:** `User` (PBKDF2 + Google fields; **+ `role` enum** "user"/"admin", default "user" — primul user inregistrat devine admin automat), `Session`, `Device` (heartbeat + capabilities + `local_subnet` + `nmap_installed`; property `is_online`), `Scan` (payload JSON + `nmap_data` nullable), `Finding`, `ScanJob` (state machine pending→running→done/failed/cancelled; + `scan_type`, `progress`, `phase`, `nmap_target`; **+ `source` "manual"/"scheduled"**), **`ScanSchedule`** (planificari recurente: `frequency` daily/weekly/monthly, `hour` 0-23 UTC, `day_of_week`, `day_of_month`, `enabled`, `next_run_at`, `last_run_at`, `nmap_target`). Constraint `uq_owner_device_uid` pe (owner_id, device_uid). |
| `schemas.py`  | **Pydantic 2 schemas:** `RegisterIn`, `LoginIn`, `TokenOut`, `MeOut` (+ `google_picture_url`, `auth_provider`, **+ `role`**). `DeviceCreateIn/Out`, `ScanIn` (+ `nmap`), `ScanCreateOut`, `ScanDetailOut`, `DeviceScanListItem`, `ScanJobOut/AgentJobOut/JobResultIn/JobFailureIn`, `HeartbeatIn` (+ `local_subnet`), `ScanJobCreateIn` (+ `nmap_target`), `JobProgressIn`, `ScanJobPreviewOut`. **Google OAuth:** `GoogleAuthUrlOut`, `GoogleAgentEnrollIn/Out`. **Admin:** `AdminUserOut/AdminDeviceOut/AdminScanListItem/AdminScansPage`, `AdminRoleChangeIn/AdminResetPasswordIn`, `AdminPlatformStatsOut`. **Profile:** `UserStatsOut`, `SessionOut`, `ChangePasswordIn`. **Scheduler:** `ScheduleIn/Out/UpdateIn`. |
| `auth.py`     | **Auth helpers + FastAPI dependencies.** `_pbkdf2_hash` (200k iteratii, dklen 32), `create_password`, `verify_password` (constant-time `hmac.compare_digest`). `create_session` cu cleanup oportunist sesiuni expirate. `set_session_cookie`/`clear_session_cookie` cu `vw_session` (HttpOnly + SameSite + Secure configurabil). `require_user` accepta cookie sau header `X-Session-Token`. **`require_admin`** (extinde `require_user`) intoarce 403 daca `user.role != "admin"`. Default expirare: 24h (configurabil prin `SESSION_EXPIRE_HOURS`). |
| `routes.py`  | **Toate endpoint-urile** impartite logic in: `/auth/*` (+`/auth/google/url|callback`), `/devices*`, `/scans*` (+ **`GET /scans/{id}/report.pdf`** pentru export PDF, ownership check cu admin bypass), `/scan-jobs*` (+ `GET /devices/{uid}/scan-jobs/preview`), `/agent/jobs/*`, `/agent/download/*`, `/agent/google-enroll`. **Profile (/me/*)**: `GET /me/stats`, `GET /me/sessions`, `DELETE /me/sessions/{id}`, `POST /me/password`. **Scheduler**: `POST/GET /devices/{uid}/schedules`, `PATCH/DELETE /schedules/{id}` (max 5 schedule/user via env `MAX_SCHEDULES_PER_USER`). **Admin (/admin/*)** (require_admin): `GET /admin/users`, `DELETE /admin/users/{id}` (block self), `POST /admin/users/{id}/role` (block self-demote), `POST /admin/users/{id}/reset-password` (invalidate sessions), `GET /admin/devices`, `GET /admin/scans` (paginat), `GET /admin/stats` (platform metrics). Heartbeat updateaza `local_subnet` + `nmap_installed`. Helper-i existenti + register handler care marcheaza first user = admin auto. |
| `rules.py`   | **Motor de reguli cu decorator `@rule(id, min_level)`.** `evaluate(scan_dict) → (score, findings)` filtreaza automat regulile dupa `scan["scan_type"]` (LEVEL_ORDER: standard=0, advanced=1, deep=2). Adaugarea unei reguli noi = decoreaza o functie, zero modificari aiurea. **24 reguli active. Standard (9):** `NET-OPEN-PORTS-1`, `NET-MANY-PORTS-2`, `OS-ADMIN-1`, `PROC-SUSPICIOUS-1`, `PROC-POWERSHELL-2`, `SW-VULNERABLE-1`, `OS-EOL-1`, `FW-DISABLED-1`, `USER-ADMIN-1`. **Advanced (6):** `STARTUP-SUSPICIOUS-1`, `TASK-SUSPICIOUS-1`, `SVC-SUSPICIOUS-1`, `NET-SHARE-1`, `PS-POLICY-1`, `NET-ESTABLISHED-1`. **Deep (9):** `REG-HIJACK-1`, `WMI-PERSIST-1`, `CERT-UNTRUSTED-1`, `AV-DISABLED-1`, `EVENTLOG-BRUTEFORCE-1`, `EVENTLOG-PRIVESC-1`, `HOSTS-TAMPERED-1`, `BITLOCKER-OFF-1`, **`NMAP-LUA-1`** (pass-through pentru findings emise de scriptul NSE `vulnwatch-audit.nse` — severitatea e decisa de Lua/CVE_DB, Python doar adauga `source="nmap-lua"` + `host_ip` in evidence). Scoring: `100 * (1 - e^(-raw/60))`. |
| `reports.py` | **Generator PDF rapoarte scan (reportlab).** Paleta Honey & Plum: PLUM (#2d1b3d), HONEY (#f4c95d), CREAM (#fefaf2). `generate_scan_pdf(scan, device, findings, owner_email)` → `bytes`. 4 sectiuni: Header (device + meta), Score 0-100 + severity breakdown table, Findings detaliate (sortate dupa severity, cu evidence JSON formatat + recomandare), Nmap section (cards per host cu porturi + vulnwatch_findings). |
| `scheduler.py` | **Scheduler logic + background loop.** `compute_next_run(frequency, hour, day_of_week, day_of_month, now)` pure function — returneaza UTC datetime pentru daily/weekly/monthly (day_of_month cap la 28). `scheduler_loop(session_factory, poll_interval=60)` asyncio loop care creeaza ScanJob-uri pentru schedule-uri due (skip daca exista deja job pending/running pe device); advances next_run_at + last_run_at. Pornit la startup via FastAPI lifespan in `main.py` (skip cu `DISABLE_SCHEDULER=true` in teste). |
| `static/`    | Resurse statice servite. Vezi `static/memory.md`.                          |

## Auth model

**Sesiuni de browser**: cookie `vw_session` HttpOnly + SameSite (in productie
si Secure). Browser-ul il trimite automat. JS nu poate citi → safe la XSS.

**Clienti non-browser** (agent, curl, teste): foloseste headerul
`X-Session-Token`. Backend-ul accepta amandoua, cookie are prioritate.

**Agent → backend**: header `X-Device-Token`. Tokenul plain este **generat
client-side** in executabil (`secrets.token_urlsafe(48)`); clientul trimite
doar `token_hash` (SHA-256 hex) in body la `POST /devices`,
`POST /devices/{uid}/relink`, `POST /agent/google-enroll`. Backend stocheaza
hash-ul ca atare — tokenul plain nu trece niciodata prin retea ca raspuns
HTTP si nu apare in log-uri/heap backend. Daca DB e compromis, tokenul nu
poate fi recuperat. Pentru request-uri ulterioare, verificare prin
`sha256(plain_din_header) == row.device_token_hash`.

**Auto-recovery 401 (agent)**: cand backend respinge `X-Device-Token` cu 401
(device sters din UI, DB reset, etc.), daemon-ul agent iese imediat din loop
si UI-ul executabilului sare la pagina Login cu mesaj clar — fara stergere
manuala de config.

## Multi-tenant izolare

Toate query-urile filtreaza prin `owner_id` → `user.id`. Verificat prin teste
dedicate in `server/tests/test_devices_and_scans.py` si `test_scan_jobs.py`
(8+ teste de izolare pe perspective diferite).

**Defense-in-depth la `/scans` si `/agent/jobs/{id}/result`:** atat tokenul
cat si `device_uid` sau `device_id` trebuie sa apartina aceluiasi device. Un
token valid pentru A nu poate scrie scan-uri pe B.
