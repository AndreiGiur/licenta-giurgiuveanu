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
3. **Pe orice masina monitorizata**: descarca .exe din UI → dublu-click → login + enroll → daemon ruleaza in tray.
4. **Scan**: din UI (`/devices` → "Scan now") sau din .exe ("Scan now" in pagina status). Job queue prin backend, polling 3s.

## Convenții

- **Limba in cod si comentarii**: romana (cum a cerut autorul lucrarii). Erori si log-uri tot in romana.
- **Naming**: `device_uid` = identificator tehnic stabil (ex: hostname), `device_name` = numele afisabil setat de user.
- **Auth**: cookie HttpOnly `vw_session` pentru browser; header `X-Session-Token` pentru clienti non-browser; header `X-Device-Token` pentru agent → backend.
- **Hash-uri**: parolele user-ilor cu PBKDF2-SHA256 (200k iteratii); device tokens cu SHA-256 simplu; ambele stocate doar ca hash, niciodata in clar.
