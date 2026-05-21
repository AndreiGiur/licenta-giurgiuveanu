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
| `models.py`   | **7 tabele:** `User` (PBKDF2 + Google fields; **+ `role` enum** "user"/"admin", default "user" — primul user inregistrat devine admin automat; **+ `first_name` + `last_name` nullable** editabile via PATCH /me; **+ `default_scan_type` default "standard"** preferinta UI), `Session`, `Device` (heartbeat + capabilities + `local_subnet` + `nmap_installed`; property `is_online`), `Scan` (payload JSON + `nmap_data` nullable + **`score_breakdown` JSON nullable** {critical_risk, network_exposure, hygiene, activity}), `Finding`, `ScanJob` (state machine pending→running→done/failed/cancelled; + `scan_type`, `progress`, `phase`, `nmap_target`; **+ `source` "manual"/"scheduled"**), **`ScanSchedule`** (planificari recurente: `frequency` daily/weekly/monthly, `hour` 0-23 UTC, `day_of_week`, `day_of_month`, `enabled`, `next_run_at`, `last_run_at`, `nmap_target`). Constraint `uq_owner_device_uid` pe (owner_id, device_uid). |
| `schemas.py`  | **Pydantic 2 schemas:** `RegisterIn`, `LoginIn`, `TokenOut`, `MeOut` (+ `google_picture_url`, `auth_provider`, **+ `role`**). `DeviceCreateIn/Out`, `ScanIn` (+ `nmap`), `ScanCreateOut` (+ `score_breakdown`), `ScanDetailOut` (+ `score_breakdown`), `DeviceScanListItem`, `ScanJobOut/AgentJobOut/JobResultIn (+ nmap)/JobFailureIn`, `HeartbeatIn` (+ `local_subnet`), `ScanJobCreateIn` (+ `nmap_target`), `JobProgressIn`, `ScanJobPreviewOut`. **+ `ScoreBreakdown`** (critical_risk/network_exposure/hygiene/activity, 0-100). **Google OAuth:** `GoogleAuthUrlOut`, `GoogleAgentEnrollIn/Out`. **Admin:** `AdminUserOut/AdminDeviceOut/AdminScanListItem/AdminScansPage`, `AdminRoleChangeIn/AdminResetPasswordIn`, `AdminPlatformStatsOut`. **Profile:** `UserStatsOut`, `SessionOut`, `ChangePasswordIn`. **Scheduler:** `ScheduleIn/Out/UpdateIn`. |
| `auth.py`     | **Auth helpers + FastAPI dependencies.** `_pbkdf2_hash` (200k iteratii, dklen 32), `create_password`, `verify_password` (constant-time `hmac.compare_digest`). `create_session` cu cleanup oportunist sesiuni expirate. `set_session_cookie`/`clear_session_cookie` cu `vw_session` (HttpOnly + SameSite + Secure configurabil). `require_user` accepta cookie sau header `X-Session-Token`. **`require_admin`** (extinde `require_user`) intoarce 403 daca `user.role != "admin"`. Default expirare: 24h (configurabil prin `SESSION_EXPIRE_HOURS`). |
| `routes.py`  | **Toate endpoint-urile** impartite logic in: `/auth/*` (+`/auth/google/url|callback`), `/devices*`, `/scans*` (+ **`GET /scans/{id}/report.pdf`** pentru export PDF + **`GET /scans/{id}/diff?previous=`** pentru comparatie scan-uri, ownership check cu admin bypass), `/scan-jobs*` (+ `GET /devices/{uid}/scan-jobs/preview`), **`GET /devices/{uid}/score-trend?days=30`** pentru graficul Recharts, `/agent/jobs/*`, `/agent/download/*`, `/agent/google-enroll`. **Profile (/me/* + /me)**: `GET /me/stats`, `GET /me/sessions`, `DELETE /me/sessions/{id}`, `POST /me/password`, **`PATCH /me`** (update first_name/last_name/default_scan_type). **Scheduler**: `POST/GET /devices/{uid}/schedules`, `PATCH/DELETE /schedules/{id}` (max 5 schedule/user via env `MAX_SCHEDULES_PER_USER`). **Admin (/admin/*)** (require_admin): `GET /admin/users`, `DELETE /admin/users/{id}` (block self), `POST /admin/users/{id}/role` (block self-demote), `POST /admin/users/{id}/reset-password` (invalidate sessions), `GET /admin/devices`, `GET /admin/scans` (paginat), `GET /admin/stats` (platform metrics). Heartbeat updateaza `local_subnet` + `nmap_installed`. Helper-i existenti + register handler care marcheaza first user = admin auto. |
| `rules.py`   | **Motor de reguli cu decorator `@rule(id, min_level, category, weight, confidence)`.** `evaluate(scan_dict) → (score, breakdown, findings)` filtreaza automat regulile dupa `scan["scan_type"]` (LEVEL_ORDER: standard=0, advanced=1, deep=2). **Scoring multidimensional (2026-05-19):** fiecare regula are `category` (critical_risk / network_exposure / hygiene / activity), `weight` (default 1.0) si `confidence` (default 1.0). Sub-scor per categorie = `min(100, Σ severity_weight * weight * confidence)`. Scor agregat = `0.40*critical + 0.30*network + 0.20*hygiene + 0.10*activity`. SEVERITY_WEIGHT: critical=40, high=20, medium=10, low=3. **24 reguli active**, clasificate: **critical_risk (6):** PROC-SUSPICIOUS w=1.5, SW-VULNERABLE w=1.5, OS-EOL w=1.5, REG-HIJACK w=2, WMI-PERSIST w=2, NMAP-LUA. **network_exposure (4):** NET-OPEN-PORTS w=1.5, NET-MANY-PORTS, NET-SHARE, NET-ESTABLISHED w=0.7. **hygiene (6):** OS-ADMIN w=0.8, FW-DISABLED w=1.2, USER-ADMIN, CERT-UNTRUSTED, AV-DISABLED w=1.2, BITLOCKER. **activity (8):** PROC-POWERSHELL w=0.3, STARTUP-SUSPICIOUS w=0.7 conf=0.7 (FP frecvent), TASK-SUSPICIOUS, SVC-SUSPICIOUS w=0.8, PS-POLICY w=0.8, EVENTLOG-BRUTEFORCE w=1.2, EVENTLOG-PRIVESC, HOSTS-TAMPERED. Findings primesc `category` + `rule_weight` + `rule_confidence` la output pentru UI breakdown. **FP fixes (2026-05-20):** REG-HIJACK whitelist Winlogon.Userinit/Shell default values; WMI-PERSIST skip subscriptii cu command vid + built-in names (SCM Event Log Consumer etc.); CERT-UNTRUSTED extins cu Blizzard/Steam/Valve/Epic/Riot/OEM (Dell/HP/Lenovo/Intel/AMD/NVIDIA); NET-ESTABLISHED extins STD_PORTS (5228 Google FCM, 5223 XMPP, 3478 STUN, 1935 RTMP, 8009 Chromecast) + KNOWN_PROCS (browsere + AnyDesk + Teams/Slack/Discord/Spotify/Steam/Outlook/OneDrive/Dropbox); HOSTS-TAMPERED whitelist kubernetes/host/gateway.docker.internal + filter linii BOM/comentariu; **AV-DISABLED skip cand `defender.third_party_av` non-vid** (Bitdefender/Kaspersky/Avast/etc. detectat in SecurityCenter2); **NET-OPEN-PORTS severity-aware** — downgrade `high → low` cand portul e bind-uit DOAR pe adaptoare virtuale (172.16-31.x.x / 169.254.x.x / fe80::), fallback pe `high` cand `port_bindings` lipseste (backward compat). **Compliance mapping (2026-05-20):** decorator extins cu `compliance: list[str]` (CIS Controls v8 + NIST CSF 2.0). 24 reguli mapate la 28 controale CIS + 16 subcategorii NIST. Findings includ `compliance` la output; PDF report are sectiune dedicata "Coverage standarde de securitate" cu tabel per framework. |
| `reports.py` | **Generator PDF rapoarte scan (reportlab).** Paleta Honey & Plum: PLUM (#2d1b3d), HONEY (#f4c95d), CREAM (#fefaf2). `generate_scan_pdf(scan, device, findings, owner_email)` → `bytes`. 6 sectiuni: Header (device + meta), Score 0-100 + severity breakdown table, **Score breakdown pe 4 categorii** (tabel cu pondere + sub-scor colorat dupa severitate), **Coverage standarde** (tabel CIS Controls v8 + NIST CSF 2.0 cu controale afectate per regula), Findings detaliate (sortate dupa severity, cu evidence JSON formatat + recomandare), Nmap section (cards per host cu porturi + vulnwatch_findings). Helper `_ascii()` elimina diacritice + caractere non-Latin1 (Helvetica nu le suporta). |
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
