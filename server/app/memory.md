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
| `rules.py`   | **Motor de reguli.** Functie `evaluate(scan_dict) → (score, findings)`. **7 reguli active:** `NET-OPEN-PORTS-1` (porturi riscante 21/23/25/139/445/3389/5900/5985/5986), `NET-MANY-PORTS-2` (>20 porturi → suprafata mare), `OS-ADMIN-1` (sesiune admin), `PROC-SUSPICIOUS-1` (Mimikatz, PsExec, Cobalt Strike, etc.), `PROC-POWERSHELL-2`, `SW-VULNERABLE-1` (Adobe Flash, IE, Java 6/7, OpenSSL 1.0, WinRAR 5, 7-Zip 2), `OS-EOL-1` (Windows XP/Vista/7/8.0, Linux 2.6). Scoring: `100 * (1 - e^(-raw/60))` — saturare exponentiala, evita scoruri liniare. |
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
