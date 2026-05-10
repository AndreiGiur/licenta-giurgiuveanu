# VulnWatch — Platformă de monitorizare a expunerilor

Lucrare de licență — Giurgiuveanu Andrei.

VulnWatch este o platformă self-hosted ce colectează informații despre starea
dispozitivelor (porturi deschise, procese, software instalat, sistem de operare),
le evaluează cu un motor de reguli și produce un *exposure score* + recomandări
acționabile, vizualizabile într-un dashboard web.

## Arhitectură

```
┌──────────────┐  HTTPS / X-Device-Token   ┌──────────────────┐
│   Agent      │ ─────────────────────────►│                  │
│   (Python)   │                            │   Backend API    │
│              │                            │   (FastAPI)      │
└──────────────┘                            │                  │
                                            │  ┌────────────┐  │
┌──────────────┐  HTTPS / cookie HttpOnly   │  │  Reguli    │  │
│   Frontend   │ ◄──────────────────────────┤  │  (rules.py)│  │
│   (React)    │                            │  └────────────┘  │
└──────────────┘                            └─────────┬────────┘
                                                      │
                                                      ▼
                                              ┌──────────────┐
                                              │  PostgreSQL  │
                                              └──────────────┘
```

### Componente

| Folder      | Tehnologie                       | Rol                                                |
| ----------- | -------------------------------- | -------------------------------------------------- |
| `agent/`    | Python 3.10+, psutil, requests   | Colectează date local, trimite scanări la backend  |
| `server/`   | FastAPI, SQLAlchemy 2, Pydantic 2| API REST, motor reguli, autentificare              |
| `web/`      | React 19, TypeScript, Vite       | Dashboard, înrolare dispozitive, vizualizare scan  |

### Modele de date principale

- `User` — cont de utilizator, parolă hashed cu PBKDF2-SHA256 (200k iterații, salt 16B).
- `Session` — token de sesiune random 64B, expiră în 24h, livrat ca cookie HttpOnly.
- `Device` — dispozitiv înrolat de un user. Stochează doar **hash-ul** (SHA-256) al
  tokenului de device — tokenul plain este afișat o singură dată la creare.
- `Scan` — un raport de la agent, conține payload-ul complet și `exposure_score`.
- `Finding` — o vulnerabilitate detectată de o regulă, asociată unui scan.
- `ScanJob` — cerere de scanare on-demand. State machine
  `pending → running → done | failed | cancelled`. Decuplează UI-ul de execuția
  agentului (vezi *Scan-on-demand* mai jos).

### Scan-on-demand (buton "Scan now" în UI)

UI-ul are un buton **Scan now** lângă fiecare device. Click → backend creează un
`ScanJob` în starea `pending`. Agent-ul (rulat ca daemon pe mașina monitorizată)
polează `GET /agent/jobs/next` la fiecare 3 secunde, ridică job-ul, execută
scanarea local și trimite rezultatul la `POST /agent/jobs/{id}/result`.

```
UI ──► POST /devices/{uid}/scan-jobs       (cookie auth)
Agent ──► GET /agent/jobs/next             (X-Device-Token)  → 200 + job sau 204
Agent ──► POST /agent/jobs/{id}/result     (X-Device-Token)
UI ──► GET /scan-jobs/{id}                 (poll status la 2s)
```

**De ce pull, nu push** — agent-ul nu trebuie expus pe rețea (nici un port deschis,
nicio regulă de firewall). Funcționează prin NAT, VPN, rețele de companie. Aceeași
abordare folosesc Wazuh, Microsoft Defender for Endpoint, Datadog Agent.

**Atomicitate la pickup** — `SELECT ... FOR UPDATE SKIP LOCKED` garantează că două
poll-uri concurente nu prind același job de două ori (verificat prin teste).

Pentru a porni agent-ul ca serviciu persistent (Windows Task Scheduler / systemd),
vezi `agent/README.md`.

### Securitate

- Parolele user-ilor: PBKDF2-SHA256, 200 000 iterații, salt random per user.
- Tokens de device: SHA-256, plain-ul nu e recuperabil din DB.
- Sesiuni de browser: cookie HttpOnly + SameSite (recomandat: `Secure` în producție).
- CORS strict: doar origin-ul frontend-ului permis, headere și metode allowlist.
- Multi-tenant: toate query-urile filtrează prin `owner_id` — un user nu poate
  vedea sau modifica resursele altui user. Verificat prin teste dedicate.
- Defense-in-depth la submisiunea de scan: tokenul de device **și** `device_uid`-ul
  trebuie să corespundă aceluiași dispozitiv.

## Rulare end-to-end (development)

### 1. PostgreSQL (Docker)

```bash
docker compose up -d
```

Pornește un PostgreSQL 16 pe `127.0.0.1:5432` cu credentiale `exposure / exposure`.

### 2. Backend

```bash
cd server
python -m venv .venv
.\.venv\Scripts\activate          # Windows PowerShell
# source .venv/bin/activate       # Linux/macOS
pip install -r requirements.txt

cp .env.example .env              # opțional, pentru personalizare
fastapi dev app/main.py           # sau: uvicorn app.main:app --reload
```

API disponibil pe `http://127.0.0.1:8000/api/v1`. Documentație interactivă
auto-generată la `http://127.0.0.1:8000/docs`.

### 3. Frontend

```bash
cd web
npm install
npm run dev
```

UI disponibil pe `http://localhost:5173`. Înregistrează cont, apoi mergi la
`/devices` pentru a înrola un dispozitiv (opțional — vezi pasul 4).

### 4. Agent — varianta zero-terminal (recomandat)

#### O singură dată: build .exe pe mașina cu backend-ul

```powershell
powershell -ExecutionPolicy Bypass -File agent\build.ps1
```

Scriptul produce `dist\VulnWatchAgent.exe` (~30 MB) și îl publică în
`server/app/static/agent/` (servit la `/api/v1/agent/download/windows`).

#### Pe orice mașină de monitorizat

1. Login UI → **Devices** → click **↓ Descarcă .exe** (banner)
2. **Dublu-click** pe `VulnWatchAgent.exe` → flow grafic în 3 pași:
   - **Login**: email + parolă + API URL. Dacă nu ai cont → toggle inline
     "Înregistrează-te".
   - **Enroll device**: dacă PC-ul e nou pe contul tău, completezi UID + nume
     și apeși "Înrolează". Dacă PC-ul a mai fost înrolat (ai reinstalat OS-ul,
     ai șters configul) → primești automat opțiunea "Refolosește device existent"
     (smart re-link, păstrează istoricul scanărilor).
   - **Status**: vezi contul logat, numele device-ului, indicator daemon, log
     live. Butoane: Scan now / Pauză / Open dashboard / Logout.
3. Bifa "Pornește la logon" (default ON) înregistrează agent-ul în
   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` — niciun admin necesar.

Agent-ul rulează în background cu icon în system tray. Apeși **Scan now** în UI
și scanarea e gata în secunde.

### 4b. Agent — varianta CLI (alternativă, fără build)

Dacă preferi să rulezi din sursă (Linux, server, debug):

```bash
cd agent
pip install -r requirements.txt
python scan.py enroll        # interactiv, salvează token automat
python scan.py daemon        # foreground; răspunde la "Scan now"
```

Sau, fără terminal pe Windows, dublu-click direct pe `agent/scan.py` —
deschide aceeași fereastră grafică (necesită Python instalat).

Pentru rulare ca serviciu persistent (Windows Task Scheduler, systemd), vezi
`agent/README.md`.

Alte comenzi utile:

```bash
python scan.py             # scanare unică (push direct, fără daemon)
python scan.py status      # afișează configul curent (fără token)
python scan.py logout      # șterge configul local
```

## Rulare teste

```bash
cd server
python -m pytest
```

Rularea acoperă (70 teste totale):
- motorul de reguli (`test_rules.py` — fiecare regulă + saturarea scorului)
- autentificare (`test_auth.py` — login, logout idempotent, validare email, cookie)
- flow-ul de scanare și izolarea multi-tenant (`test_devices_and_scans.py`)
- scan-on-demand prin job queue (`test_scan_jobs.py` — 12 teste)
- smart re-link + device_name (`test_relink_and_names.py` — 11 teste)
- download .exe (`test_agent_download.py` — 4 teste)
- core agent (`agent/tests/test_core*.py` — 17 teste)

## Documentație internă (memory.md)

Fiecare folder are un `memory.md` cu contextul fișierelor din el. Util pentru
a înțelege rapid o zonă a codebase-ului fără a o citi linie cu linie.

Pornește din `memory.md` (radacina) → urmărește link-urile către `agent/`,
`server/`, `web/`. Fiecare nivel descrie ce e important la nivelul acela.

## Configurare producție

În `server/.env` (sau direct ca variabile de mediu):

```env
DATABASE_URL=postgresql+psycopg://user:pass@host:5432/db
SESSION_EXPIRE_HOURS=24
CORS_ORIGINS=https://app.exemplu.com
COOKIE_SECURE=true
COOKIE_SAMESITE=strict
```

## Layout repo

```
.
├── memory.md             Punct de plecare pentru a înțelege codebase-ul
├── agent/                Agent Python (GUI Tkinter + CLI + tray + autostart)
│   ├── core.py           Logica fără UI (collect, HTTP, daemon loop)
│   ├── scan.py           Entry point — CLI sau GUI după argumente
│   ├── gui.py            Tkinter: Login → Enroll → Status
│   ├── tray.py           System tray (pystray + Pillow)
│   ├── autostart.py      Pornire la logon (HKCU/systemd/launchd)
│   ├── VulnWatchAgent.spec   PyInstaller spec
│   ├── build.ps1         Script one-click pentru build .exe
│   └── tests/            Pytest pentru core (17 teste)
├── server/
│   ├── app/              FastAPI app
│   │   ├── main.py       Aplicație + CORS
│   │   ├── routes.py     Endpoint-uri /api/v1/*  (~22)
│   │   ├── auth.py       Sesiuni, cookie HttpOnly, PBKDF2
│   │   ├── models.py     SQLAlchemy 2 (User, Device, Scan, Finding, ScanJob)
│   │   ├── schemas.py    Pydantic 2 (EmailStr, validări)
│   │   ├── rules.py      Motor de reguli + exposure_score
│   │   ├── db.py         SQLAlchemy engine
│   │   └── static/agent/ VulnWatchAgent.exe (servit la /agent/download/windows)
│   ├── tests/            Pytest (53 teste end-to-end)
│   ├── requirements.txt
│   └── .env.example
├── web/                  Frontend React + TypeScript + Vite
│   ├── src/
│   │   ├── api/          Client HTTP unificat (cookie-based)
│   │   ├── components/   Navbar, ProtectedRoute
│   │   └── pages/        Login, Register, Dashboard, Devices, ScanDetail
│   └── vite.config.ts
└── docker-compose.yml    Postgres pentru dev
```

Pentru detalii pe orice folder, deschide `<folder>/memory.md`.
