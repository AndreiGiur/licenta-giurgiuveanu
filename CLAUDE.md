# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

**VulnWatch** — a self-hosted platform that collects system data (open ports, processes, installed software, OS info), scores exposure with a rules engine, and displays results in a web dashboard.

Three independent components:
- `agent/` — Python daemon that runs on monitored machines and pushes scan data
- `server/` — FastAPI backend with PostgreSQL, rules engine, and REST API
- `web/` — React + TypeScript frontend (Vite)

## Development commands

### Start everything (dev)

```bash
# 1. PostgreSQL (Docker) — credentials: exposure/exposure on 127.0.0.1:5432
docker compose up -d

# 2. Backend — API at http://127.0.0.1:8000/api/v1, docs at /docs
cd server
python -m venv .venv && .\.venv\Scripts\activate   # Windows
pip install -r requirements.txt
# Pe Windows: forțează UTF-8 pentru a evita UnicodeEncodeError din Rich (emoji-uri)
$env:PYTHONUTF8=1; python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# 3. Frontend — UI at http://localhost:5173
cd web
npm install
npm run dev
```

### Tests (backend only — uses SQLite, no Postgres needed)

```bash
cd server
python -m pytest                          # all 26 tests
python -m pytest tests/test_rules.py     # single file
python -m pytest tests/test_rules.py::test_risky_ports  # single test
```

### Build agent .exe (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File agent\build.ps1
# Produces dist\VulnWatchAgent.exe and copies to server/app/static/agent/
```

### Agent CLI

```bash
cd agent
pip install -r requirements.txt
python scan.py enroll      # interactive enrollment, saves ~/.vulnwatch/config.ini
python scan.py daemon      # foreground daemon, polls for scan jobs every 3s
python scan.py scan        # one-shot scan (direct push, no daemon)
python scan.py status      # show config (no token)
python scan.py logout      # delete local config
```

## Architecture

### Authentication — two separate systems

**Browser sessions (UI → backend):**
- Login returns a `session_token` in both the response body AND as an `HttpOnly` cookie
- Frontend relies solely on the browser's automatic cookie handling (`credentials: "include"`)
- Non-browser clients (agent enrollment, tests) pass token via `X-Session-Token` header
- Sessions expire in 24h (`SESSION_EXPIRE_HOURS` env var)

**Agent auth (agent → backend) — client-generated tokens:**
- Fiecare device are un `device_token` — **generat local** de executabil cu `secrets.token_urlsafe(48)`
- Executabilul trimite la backend doar `token_hash` (SHA-256 hex) în body la `POST /devices`, `POST /devices/{uid}/relink`, `POST /agent/google-enroll`
- Backend stochează hash-ul ca atare; tokenul plain nu apare niciodată în răspunsuri HTTP, log-uri sau heap backend
- Plain token e salvat în `~/.vulnwatch/config.ini` la enrollment și folosit pentru fiecare request ulterior în header `X-Device-Token`
- `_device_for_token_or_401()` în `routes.py` validează prin `sha256(plain_from_header) == row.device_token_hash`
- **Auto-recovery la 401**: daemon-ul detectează HTTP 401 din orice apel device-token, oprește loop-ul și forțează UI executabil să revină la pagina Login (fără crash, fără workaround manual)

**Google OAuth (hybrid):**
- **Web**: `GET /api/v1/auth/google/url` returnează URL Google; callback la `GET /api/v1/auth/google/callback` schimbă code → id_token, upsert User by email, setează cookie sesiune, redirect spre `FRONTEND_BASE_URL/dashboard`
- **Desktop (agent)**: `google-auth-oauthlib.InstalledAppFlow.run_local_server(port=0)` face Loopback Redirect + PKCE; agent generează local `(token_plain, token_hash)`, trimite `id_token` + `token_hash` la `POST /api/v1/agent/google-enroll`, primește metadata user/device fără token plain (îl are deja local)
- Cont existent cu email/parolă + login Google la același email → `auth_provider="both"` (account linking automat by email)
- Env vars: `GOOGLE_CLIENT_ID_WEB`, `GOOGLE_CLIENT_SECRET_WEB`, `GOOGLE_REDIRECT_URI_WEB`, `GOOGLE_CLIENT_ID_DESKTOP`, `FRONTEND_BASE_URL` în `server/.env`
- Agent: `agent/google_config.py` (gitignored) conține `GOOGLE_CLIENT_ID` (desktop)
- **Important**: foloseste `localhost` (nu `127.0.0.1`) în redirect URI pentru consistență cu cookie-uri (browserele tratează cele două ca domenii diferite)

**Crearea device-urilor**: NUMAI prin executabil. Platform UI permite doar listare + ștergere. Pentru a conecta un device nou: descarcă agentul → login Google (sau email/parolă) → enrollment automat.

### Scan-on-demand flow (pull model, platform-centric)

The agent never exposes a port — all connections are agent-initiated outbound HTTPS. The platform drives everything: the user picks `scan_type`, watches progress live, sees results. The agent is just the executor.

```
Agent  → POST /agent/heartbeat (every 10s)   → marks device as is_online (last_heartbeat < 30s)
UI     → POST /devices/{uid}/scan-jobs       → creates ScanJob (pending) with scan_type
UI     → GET  /scan-jobs/{id} (every 2s)     → polls status + progress + phase
Agent  → GET  /agent/jobs/next               → atomic pickup (SELECT FOR UPDATE SKIP LOCKED), returns scan_type
Agent  → POST /agent/jobs/{id}/progress      → reports {progress: 0-100, phase: "Sistem & OS"} between collectors
Agent  → POST /agent/jobs/{id}/result        → ScanJob(done) + Scan created
Agent  → POST /agent/jobs/{id}/fail          → ScanJob(failed) on error
```

`ScanJobStatus` state machine: `pending → running → done | failed | cancelled`

### Scan types — Strategy Pattern

Three levels controlled by `SCAN_PROFILES` dict in `agent/core.py`:

- **standard** (~45-90s): ports LISTEN, OS, firewall, local users, top 30 processes, installed software
- **advanced** (~3-8min): all processes + cmdline, port→process binding, ESTABLISHED connections, services, startup keys, scheduled tasks, shares, PS execution policy, network adapters
- **deep** (~10-20min): WMI subscriptions, AppInit_DLLs/IFEO/Winlogon, Security event log (4625/4672/4720), hosts, DNS+ARP, root certificates, BitLocker, Defender, recently modified files in System32/Program Files

Each level is a `ScanProfile` dataclass with boolean flags. The 6 composable collectors in `agent/collectors/` (network, processes, software, system_info, persistence, forensics) check the flags and collect accordingly. **Adding a new level = one dict entry.**

### Rules engine (`server/app/rules.py`) — `@rule` decorator with min_level

`evaluate(scan_dict)` returns `(exposure_score, findings)`. Rules auto-filter by `scan["scan_type"]` via `LEVEL_ORDER` (standard=0 < advanced=1 < deep=2). **Adding a new rule = decorate a function.**

**23 active rules. Standard (9):** `NET-OPEN-PORTS-1`, `NET-MANY-PORTS-2`, `OS-ADMIN-1`, `PROC-SUSPICIOUS-1`, `PROC-POWERSHELL-2`, `SW-VULNERABLE-1`, `OS-EOL-1`, `FW-DISABLED-1`, `USER-ADMIN-1`. **Advanced (6):** `STARTUP-SUSPICIOUS-1`, `TASK-SUSPICIOUS-1`, `SVC-SUSPICIOUS-1`, `NET-SHARE-1`, `PS-POLICY-1`, `NET-ESTABLISHED-1`. **Deep (8):** `REG-HIJACK-1`, `WMI-PERSIST-1`, `CERT-UNTRUSTED-1`, `AV-DISABLED-1`, `EVENTLOG-BRUTEFORCE-1`, `EVENTLOG-PRIVESC-1`, `HOSTS-TAMPERED-1`, `BITLOCKER-OFF-1`.

Exposure score formula with diminishing returns: `score = min(100, round(100 * (1 - e^(-raw/60))))`

### Multi-tenancy

Every query that returns user-owned data filters by `owner_id == user.id`. The `require_user` FastAPI dependency (in `server/app/auth.py`) enforces authentication; routes then explicitly check ownership before returning data.

### Agent internal architecture

`core.py` contains all business logic with no UI dependencies. Functions accept a `log: LogFn` callback (`(msg, severity) → None`) for output — callers supply their own logger. `scan.py` (CLI) and `gui.py` (Tkinter) both call into `core.py`.

### Frontend API client

`web/src/api/http.ts` exports a single `http<T>()` function. All API calls use `credentials: "include"` for cookie auth. The Vite dev server proxies `/api/*` to `http://127.0.0.1:8000` — no CORS issues in dev.

### Theme system (Honey & Plum)

`<ThemeProvider>` în `web/src/components/ThemeProvider.tsx` — gestionează `data-theme` pe `<html>`, persistă în `localStorage` (`vw-theme`), respectă `prefers-color-scheme` la primul vizit. Toggle prin `<ThemeToggle>` în Navbar.

**Paleta**: Honey & Plum — light (#fefaf2 cream + #f4c95d honey + #2d1b3d plum text) și dark (#1a0e22 plum bg + #f4c95d honey + #fff8e6 cream text). CSS variables în `:root,[data-theme="light"]` și `[data-theme="dark"]`. Severity colors warm-tinted: plum/raspberry pentru high/critical, honey pentru medium, lavandă pentru low.

**Tipografie**: `Fraunces` (display serif), `Outfit` (body sans), `JetBrains Mono` (code) — Google Fonts.

**Animații**: Framer Motion v12 pentru page-enter, layout transitions cu `layoutId`, ScoreGauge tween (number animation + SVG ring fill); CSS pentru hover lift, pulse online badge, shimmer progress bar. Respectă `prefers-reduced-motion`.

**Componente reutilizabile**: `<ScoreGauge>`, `<GoogleButton>`, `<UserAvatar>`, `<ThemeToggle>`, `<ThemeProvider>`.

### Database

Tables are created at startup via `Base.metadata.create_all()` (no Alembic). The test suite overrides `DATABASE_URL` to a temp SQLite file in `conftest.py` before importing the app — this is why tests work without a running Postgres.

## memory.md system

Every source folder contains a `memory.md` file that documents all files in that folder. The files exist at:

```
memory.md                        ← root (project overview, components, key commands)
agent/memory.md                  ← core.py, scan.py, gui.py, tray.py, autostart.py, build.ps1
agent/collectors/memory.md       ← network.py, processes.py, software.py, system_info.py, persistence.py, forensics.py
agent/tests/memory.md            ← test_core.py, test_core_relink.py, test_collectors.py
server/memory.md                 ← requirements.txt, .env.example, folder overview
server/app/memory.md             ← main.py, db.py, models.py, schemas.py, auth.py, routes.py, rules.py
server/tests/memory.md           ← conftest.py, test_rules.py, test_auth.py, test_devices_and_scans.py, test_scan_jobs.py, test_agent_download.py
web/memory.md                    ← package.json, vite.config.ts, tsconfig files
web/src/memory.md                ← main.tsx, App.tsx (routing), CSS
web/src/api/memory.md            ← http.ts, client.ts, auth.ts, exposure.ts, types.ts
web/src/components/memory.md     ← Navbar.tsx, ProtectedRoute.tsx
web/src/pages/memory.md          ← Dashboard.tsx, Devices.tsx, Login.tsx, Register.tsx, ScanDetail.tsx
```

**When to update**: after every code change, update the `memory.md` in the same folder as the changed file. If you add a new file, add an entry for it. If you rename or delete a file, update the corresponding entry. If you add a new folder, create a `memory.md` in it following the same format.

**When to read**: before working in any folder, read its `memory.md` first to get context without scanning all files.

## Key env vars (server/.env)

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | SQLite (tests) / requires Postgres (dev) | SQLAlchemy connection string |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated allowed origins |
| `SESSION_EXPIRE_HOURS` | 24 | Session lifetime |
| `COOKIE_SECURE` | false | Set true in production (HTTPS only) |
| `COOKIE_SAMESITE` | lax | Set strict in production |
