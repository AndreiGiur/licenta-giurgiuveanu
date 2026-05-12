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
| `db.py`       | SQLAlchemy engine cu `pool_pre_ping=True`; `SessionLocal` factory; `Base = DeclarativeBase`. URL-ul DB-ului citit din `DATABASE_URL` env var (default postgres dev). |
| `models.py`   | **6 tabele:** `User` (PBKDF2 salt + hash), `Session` (token sesiune cu expirare), `Device` (token hashed SHA-256, prefix de 8 char afisabil; + `last_heartbeat`/`agent_version`/`capabilities` JSON; property `is_online` = last_heartbeat < 30s), `Scan` (payload JSON + exposure_score), `Finding` (legat de Scan, are rule_id + severity + evidence + recommendation), `ScanJob` (state machine `pending → running → done/failed/cancelled`; + `scan_type` standard/advanced/deep, `progress` 0-100, `phase`). Constraint `uq_owner_device_uid` pe (owner_id, device_uid). Functie `hash_token(t)` pentru SHA-256. |
| `schemas.py`  | **Pydantic 2 schemas:** `RegisterIn`, `LoginIn` (cu `EmailStr`), `TokenOut`, `MeOut`, `DeviceCreateIn/Out` (cu `device_token` doar la creare), `ScanIn`, `ScanCreateOut`, `ScanDetailOut` (+`scan_type`), `DeviceScanListItem`, `ScanJobOut` (+`scan_type`/`progress`/`phase`), `AgentJobOut` (+`scan_type`), `JobResultIn` (+`system_info`/`persistence`/`forensics`), `JobFailureIn`. **Noi:** `HeartbeatIn` (agent_version+capabilities+os_version), `ScanJobCreateIn` (Literal scan_type), `JobProgressIn` (progress 0-100 + phase). `DeviceOut` extins cu `is_online`, `last_heartbeat`, `agent_version`, `capabilities`. |
| `auth.py`     | **Auth helpers + FastAPI dependencies.** `_pbkdf2_hash` (200k iteratii, dklen 32), `create_password`, `verify_password` (constant-time `hmac.compare_digest`). `create_session` cu cleanup oportunist sesiuni expirate. `set_session_cookie`/`clear_session_cookie` cu `vw_session` (HttpOnly + SameSite + Secure configurabil). `require_user` accepta cookie sau header `X-Session-Token`. Default expirare: 24h (configurabil prin `SESSION_EXPIRE_HOURS`). |
| `routes.py`  | **Toate endpoint-urile** (22+) impartite logic in: `/auth/*`, `/devices*`, `/scans*`, `/scan-jobs*`, `/agent/jobs/*`, `/agent/download/*`. Helper-i: `_scan_job_to_out` (serializeaza ScanJob cu device_name), `_device_for_token_or_401`, `_find_agent_artifact` pentru download. Pickup atomic la `/agent/jobs/next` cu `select.with_for_update(skip_locked=True)`. |
| `rules.py`   | **Motor de reguli cu decorator `@rule(id, min_level)`.** `evaluate(scan_dict) → (score, findings)` filtreaza automat regulile dupa `scan["scan_type"]` (LEVEL_ORDER: standard=0, advanced=1, deep=2). Adaugarea unei reguli noi = decoreaza o functie, zero modificari aiurea. **23 reguli active. Standard (9):** `NET-OPEN-PORTS-1`, `NET-MANY-PORTS-2`, `OS-ADMIN-1`, `PROC-SUSPICIOUS-1`, `PROC-POWERSHELL-2`, `SW-VULNERABLE-1`, `OS-EOL-1`, `FW-DISABLED-1`, `USER-ADMIN-1`. **Advanced (6):** `STARTUP-SUSPICIOUS-1`, `TASK-SUSPICIOUS-1`, `SVC-SUSPICIOUS-1`, `NET-SHARE-1`, `PS-POLICY-1`, `NET-ESTABLISHED-1`. **Deep (8):** `REG-HIJACK-1`, `WMI-PERSIST-1`, `CERT-UNTRUSTED-1`, `AV-DISABLED-1`, `EVENTLOG-BRUTEFORCE-1`, `EVENTLOG-PRIVESC-1`, `HOSTS-TAMPERED-1`, `BITLOCKER-OFF-1`. Scoring: `100 * (1 - e^(-raw/60))`. |
| `static/`    | Resurse statice servite. Vezi `static/memory.md`.                          |

## Auth model

**Sesiuni de browser**: cookie `vw_session` HttpOnly + SameSite (in productie
si Secure). Browser-ul il trimite automat. JS nu poate citi → safe la XSS.

**Clienti non-browser** (agent, curl, teste): foloseste headerul
`X-Session-Token`. Backend-ul accepta amandoua, cookie are prioritate.

**Agent → backend**: header `X-Device-Token`. Tokenul plain este stocat doar
in `~/.vulnwatch/config.ini` pe masina agentului. Backend-ul stocheaza
SHA-256(token) — daca DB e compromis, tokenul nu poate fi recuperat.

## Multi-tenant izolare

Toate query-urile filtreaza prin `owner_id` → `user.id`. Verificat prin teste
dedicate in `server/tests/test_devices_and_scans.py` si `test_scan_jobs.py`
(8+ teste de izolare pe perspective diferite).

**Defense-in-depth la `/scans` si `/agent/jobs/{id}/result`:** atat tokenul
cat si `device_uid` sau `device_id` trebuie sa apartina aceluiasi device. Un
token valid pentru A nu poate scrie scan-uri pe B.
