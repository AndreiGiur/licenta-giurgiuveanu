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

### 4. Agent — înrolare automată

Pe mașina pe care vrei să o monitorizezi:

```bash
cd agent
pip install -r requirements.txt
python scan.py enroll
```

Comanda `enroll` îți cere email/parolă (același cont ca în UI), apoi:

1. Se autentifică pe backend.
2. Creează dispozitivul (sau folosește hostname-ul ca UID implicit).
3. **Salvează tokenul automat** la `~/.vulnwatch/config.ini` (permisiuni 0600 pe POSIX).

Apoi rulează scanări oricând:

```bash
python scan.py             # rulează o scanare
python scan.py status      # afișează configul curent (fără token)
python scan.py logout      # șterge configul local
```

## Rulare teste

```bash
cd server
python -m pytest
```

Rularea acoperă:
- motorul de reguli (`test_rules.py` — fiecare regulă + saturarea scorului)
- autentificare (`test_auth.py` — login, logout idempotent, validare email, cookie)
- flow-ul de scanare și izolarea multi-tenant (`test_devices_and_scans.py`)

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
├── agent/                Agent Python (CLI: enroll/scan/logout)
├── server/
│   ├── app/              FastAPI app
│   │   ├── main.py       Aplicație + CORS
│   │   ├── routes.py     Endpoint-uri /api/v1/*
│   │   ├── auth.py       Sesiuni, cookie-uri, PBKDF2
│   │   ├── models.py     SQLAlchemy 2 models
│   │   ├── schemas.py    Pydantic 2 (EmailStr, validări)
│   │   ├── rules.py      Motor de reguli + calcul exposure_score
│   │   └── db.py         SQLAlchemy engine
│   ├── tests/            Pytest (26 teste)
│   ├── requirements.txt
│   └── .env.example
├── web/                  Frontend React + TypeScript
│   ├── src/
│   │   ├── api/          Client HTTP unificat (cookie-based)
│   │   ├── components/   Navbar, ProtectedRoute
│   │   └── pages/        Login, Register, Dashboard, Devices, ScanDetail
│   └── vite.config.ts
└── docker-compose.yml    Postgres pentru dev
```
