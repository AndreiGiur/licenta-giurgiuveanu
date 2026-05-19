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
| `main.py`     | FastAPI app; CORS middleware (`allow_credentials=True`, origins din env); `Base.metadata.create_all` la pornire (dev only — productie ar folosi Alembic); include router-ul cu prefix `/api/v1`. |
| `config.py`   | **Env vars centralizate** pentru Google OAuth + frontend redirect. Citeste: `GOOGLE_CLIENT_ID_WEB`, `GOOGLE_CLIENT_SECRET_WEB`, `GOOGLE_REDIRECT_URI_WEB` (default `http://localhost:8000/api/v1/auth/google/callback`), `GOOGLE_CLIENT_ID_DESKTOP`, `FRONTEND_BASE_URL` (default `http://localhost:5173`). |
| `db.py`       | SQLAlchemy engine cu `pool_pre_ping=True`; `SessionLocal` factory; `Base = DeclarativeBase`. URL-ul DB-ului citit din `DATABASE_URL` env var (default postgres dev). |
| `models.py`   | **6 tabele:** `User` (PBKDF2 salt + hash **NULLABLE** pentru Google-only users; + `google_sub` unique nullable, `google_picture_url`, `auth_provider` default "password" — valori: "password" / "google"), `Session` (token sesiune cu expirare), `Device` (token hashed SHA-256, prefix de 8 char afisabil; + `last_heartbeat`/`agent_version`/`capabilities` JSON; **+ `local_subnet` (str 64 nullable) si `nmap_installed` (int default 0)** updatate din heartbeat; property `is_online` = last_heartbeat < 30s), `Scan` (payload JSON + exposure_score; **+ `nmap_data` JSON nullable** pentru output nmap deep scan), `Finding` (legat de Scan, are rule_id + severity + evidence + recommendation), `ScanJob` (state machine `pending → running → done/failed/cancelled`; + `scan_type` standard/advanced/deep, `progress` 0-100, `phase`; **+ `nmap_target` str 64 nullable** pentru LAN opt-in). Constraint `uq_owner_device_uid` pe (owner_id, device_uid). Functie `hash_token(t)` pentru SHA-256. |
| `schemas.py`  | **Pydantic 2 schemas:** `RegisterIn`, `LoginIn` (cu `EmailStr`), `TokenOut`, `MeOut` (acum cu `google_picture_url: str \| None` si `auth_provider: str = "password"`), `DeviceCreateIn/Out` (cu `device_token` doar la creare), `ScanIn` (**+ `nmap: Dict[str, Any] \| None`** pentru deep scan), `ScanCreateOut`, `ScanDetailOut` (+`scan_type`), `DeviceScanListItem`, `ScanJobOut` (+`scan_type`/`progress`/`phase`), `AgentJobOut` (+`scan_type`/`nmap_target`), `JobResultIn` (+`system_info`/`persistence`/`forensics`/`nmap`), `JobFailureIn`. **Heartbeat + scan-types:** `HeartbeatIn` (agent_version+capabilities+os_version **+ `local_subnet`**), `ScanJobCreateIn` (Literal scan_type **+ `nmap_target`**), `JobProgressIn` (progress 0-100 + phase), `ScanJobPreviewOut` (`detected_subnet`/`nmap_installed`/`estimated_hosts`/`estimated_duration_sec`). **Google OAuth:** `GoogleAuthUrlOut`, `GoogleAgentEnrollIn`, `GoogleAgentEnrollOut`. `DeviceOut` extins cu `is_online`, `last_heartbeat`, `agent_version`, `capabilities`. |
| `auth.py`     | **Auth helpers + FastAPI dependencies.** `_pbkdf2_hash` (200k iteratii, dklen 32), `create_password`, `verify_password` (constant-time `hmac.compare_digest`). `create_session` cu cleanup oportunist sesiuni expirate. `set_session_cookie`/`clear_session_cookie` cu `vw_session` (HttpOnly + SameSite + Secure configurabil). `require_user` accepta cookie sau header `X-Session-Token`. Default expirare: 24h (configurabil prin `SESSION_EXPIRE_HOURS`). |
| `routes.py`  | **Toate endpoint-urile** (24+) impartite logic in: `/auth/*` (inclusiv `/auth/google/url` + `/auth/google/callback`), `/devices*`, `/scans*`, `/scan-jobs*` (**+ `GET /devices/{uid}/scan-jobs/preview`** care intoarce `detected_subnet`/`nmap_installed`/`estimated_hosts`/`estimated_duration_sec`), `/agent/jobs/*`, `/agent/download/*`, `/agent/google-enroll`. **Heartbeat** updateaza `local_subnet` + seteaza `nmap_installed` din `capabilities`. **POST /scan-jobs** valideaza `nmap_target` CIDR (refuza public, max 4096 hosts). Helper-i: `_scan_job_to_out`, `_device_for_token_or_401`, `_find_agent_artifact`, `_store_state`/`_consume_state`, `_upsert_google_user`. Pickup atomic la `/agent/jobs/next` cu `select.with_for_update(skip_locked=True)`. |
| `rules.py`   | **Motor de reguli cu decorator `@rule(id, min_level)`.** `evaluate(scan_dict) → (score, findings)` filtreaza automat regulile dupa `scan["scan_type"]` (LEVEL_ORDER: standard=0, advanced=1, deep=2). Adaugarea unei reguli noi = decoreaza o functie, zero modificari aiurea. **24 reguli active. Standard (9):** `NET-OPEN-PORTS-1`, `NET-MANY-PORTS-2`, `OS-ADMIN-1`, `PROC-SUSPICIOUS-1`, `PROC-POWERSHELL-2`, `SW-VULNERABLE-1`, `OS-EOL-1`, `FW-DISABLED-1`, `USER-ADMIN-1`. **Advanced (6):** `STARTUP-SUSPICIOUS-1`, `TASK-SUSPICIOUS-1`, `SVC-SUSPICIOUS-1`, `NET-SHARE-1`, `PS-POLICY-1`, `NET-ESTABLISHED-1`. **Deep (9):** `REG-HIJACK-1`, `WMI-PERSIST-1`, `CERT-UNTRUSTED-1`, `AV-DISABLED-1`, `EVENTLOG-BRUTEFORCE-1`, `EVENTLOG-PRIVESC-1`, `HOSTS-TAMPERED-1`, `BITLOCKER-OFF-1`, **`NMAP-LUA-1`** (pass-through pentru findings emise de scriptul NSE `vulnwatch-audit.nse` — severitatea e decisa de Lua/CVE_DB, Python doar adauga `source="nmap-lua"` + `host_ip` in evidence). Scoring: `100 * (1 - e^(-raw/60))`. |
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
