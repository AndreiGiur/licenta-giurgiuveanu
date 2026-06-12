# memory.md — radacina proiectului

VulnWatch — platforma self-hosted pentru detectia expunerilor de securitate
ale dispozitivelor. Trei componente independente comunica prin HTTP/JSON:

```
agent (Python)  ─►  server (FastAPI + Postgres)  ◄─  web (React + Vite)
```

Lucrare de licenta. Stack: Python 3.10+, SQLAlchemy 2, Pydantic 2, React 19,
TypeScript 5.9, Tkinter, PyInstaller, Docker.

## Continut radacina

| Fisier / folder       | Rol                                                          |
| --------------------- | ------------------------------------------------------------ |
| `README.md`           | Document principal: arhitectura, rulare end-to-end, securitate. Punctul de plecare pentru oricine intra in proiect. |
| `docker-compose.yml`  | Defineste serviciul `db` (PostgreSQL 16) pe `127.0.0.1:5432` cu credentialele dev `exposure / exposure`. Volumul persistent `dbdata`. Singura componenta dockerizata in dev. |
| `agent/`              | Agent Python care colecteaza date locale si le trimite la backend. Are CLI, GUI Tkinter, system tray, autostart, build .exe via PyInstaller. |
| `server/`             | Backend FastAPI: API REST `/api/v1/*`, motor de reguli, autentificare cookie HttpOnly, job queue pentru scan-on-demand. |
| `web/`                | Frontend React + TypeScript + Vite. Dashboard pentru vizualizarea scanarilor, management dispozitive, scan-on-demand din UI. |

## Componentele in detaliu

Fiecare folder are propriul `memory.md` cu detalii. Vezi:
- `agent/memory.md`
- `server/memory.md`
- `web/memory.md`

## Flow tipic de utilizare

1. **Setup once**: `docker compose up -d` → backend porneste → frontend porneste → login UI.
2. **Build agent .exe** (o data per release): `agent/build.ps1` produce `dist/VulnWatchAgent.exe` si il copiaza in `server/app/static/agent/`.
3. **Pe orice masina monitorizata**: descarca .exe din UI → dublu-click → login + enroll → daemon ruleaza in tray. **Heartbeat la 10s** semnaleaza platforma ca agentul e online.
4. **Scan**: **inițiat din platforma web** (`/devices` → selector tip + "Scanează acum"). Agentul este executor: ridica jobul, foloseste `scan_type` pentru a alege profilul de colectare, trimite progress updates intre colectori. **Job queue prin backend**, polling 3s.

## Scan types (3 niveluri)

Strategy Pattern cu `SCAN_PROFILES` dict + decorator `@rule(min_level)`:

| Nivel | Timp estimat | Ce colecteaza in plus fata de nivelul anterior |
| --------- | --- | --- |
| **standard** | 45-90 s | porturi LISTEN, OS, firewall, useri locali (+enabled/password_required), top 30 procese, software instalat, UAC/autologon/SMBv1 din registry |
| **advanced** | 3-8 min | toate procesele + cmdline, port→proces (+exe path), ESTABLISHED connections, servicii (binary_path verbatim), startup, task scheduler, shares, PS execution policy, adaptoare retea, profile WiFi (fara chei), politica de parole (secedit) |
| **deep** | 10-20 min | WMI subscriptions, AppInit_DLLs/IFEO/Winlogon, Event Log Security (4625/4672/4720), hosts file, DNS+ARP, root certificates, BitLocker, Defender (+exclusions), audit policy (secedit), fisiere recent modificate in System32/Program Files |

**61 de reguli totale** (24 Windows/cross + NMAP-LUA-1 inclus, 22 Linux in `rules_linux.py`, 15 extinse in `rules_extended.py` din 2026-06-11): vezi `server/app/memory.md` pentru lista completa.

## Autentificare

**Hybrid: Google OAuth + email/parola.**

- **Google OAuth Web**: `GET /api/v1/auth/google/url` → user redirect spre Google → callback la `/api/v1/auth/google/callback` → cookie sesiune + redirect spre `/dashboard`
- **Google OAuth Desktop (agent)**: `google-auth-oauthlib.InstalledAppFlow.run_local_server(port=0)` cu PKCE → agent trimite `id_token` la `POST /api/v1/agent/google-enroll` → primește `device_token`
- **Email/parola**: păstrat ca alternativa (utilizatori fără Google)
- **Account linking by email**: cont existent cu parola + login Google la același email → `auth_provider="both"`
- **Device creation**: NUMAI prin executabil (eliminat din platform UI). Platform UI permite doar listare + ștergere.

## UI Theme

- **Paleta**: Honey & Plum cu light + dark mode toggle (CSS variables în `[data-theme="light"]` / `[data-theme="dark"]`)
- **Fonturi**: `Fraunces` (display serif), `Outfit` (body sans), `JetBrains Mono` (code) — Google Fonts
- **Animații**: Framer Motion v12 — page-enter, layout transitions cu `layoutId` (sidebar indicator), ScoreGauge tween număr + SVG ring; CSS — hover lift, pulse online badge, shimmer progress bar
- **Theme persist**: `localStorage.vw-theme` + `prefers-color-scheme` fallback
- **Componente cheie**: `<ThemeProvider>`, `<ThemeToggle>`, `<ScoreGauge>`, `<GoogleButton>`, `<UserAvatar>`

## Convenții

- **Limba in cod si comentarii**: romana (cum a cerut autorul lucrarii). Erori si log-uri tot in romana.
- **Naming**: `device_uid` = identificator tehnic stabil (ex: hostname), `device_name` = numele afisabil setat de user.
- **Auth**: cookie HttpOnly `vw_session` pentru browser; header `X-Session-Token` pentru clienti non-browser; header `X-Device-Token` pentru agent → backend.
- **Hash-uri**: parolele user-ilor cu PBKDF2-SHA256 (200k iteratii); device tokens cu SHA-256 simplu; ambele stocate doar ca hash, niciodata in clar.
