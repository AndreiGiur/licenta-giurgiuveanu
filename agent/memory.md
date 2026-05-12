# memory.md — agent/

Agent local care colecteaza date despre sistem si le trimite la backend.
Trei moduri de operare: GUI (dublu-click pe .exe), CLI daemon, scan unic.

## Layered architecture

```
   scan.py         (entry point + CLI dispatcher)
       │
       ├─► gui.py        (Tkinter; foloseste core)
       │     └─► tray.py (icon system tray; pystray + Pillow)
       │
       ├─► autostart.py  (registry Windows / systemd / launchd)
       │
       └─► core.py       (logica refolosibila — fara UI)
```

`core.py` nu importa nimic legat de UI — testabil in izolare. `scan.py`
importa lazy `gui` si `tray` doar daca sunt necesare.

## Fisiere

| Fisier                     | Rol                                                               |
| -------------------------- | ----------------------------------------------------------------- |
| `__init__.py`              | Marcheaza `agent` ca pachet Python. Defineste `__version__`.      |
| `core.py`                  | **Logica de baza + Strategy Pattern.** `ScanProfile` dataclass + `SCAN_PROFILES` dict (standard/advanced/deep) — sursa unica de adevar pentru ce colecteaza fiecare nivel. `AGENT_VERSION` constanta. Citire/scriere config (`~/.vulnwatch/config.ini`). `is_admin()` + orchestrator `collect_system_data(device_uid, scan_type, progress_cb)` care apeleaza colectorii composabili din `agent/collectors/` cu progress callback intre etape. Apeluri HTTP (`api_login`, `api_register`, `api_create_device`, `api_get_device_by_uid`, `api_relink_device`, `api_send_scan`, `api_get_next_job`, `api_submit_job_result`, `api_submit_job_failure`, `api_logout`, `api_me`, `api_heartbeat`, `api_send_progress`). Bucla daemon (`daemon_loop`, `run_one_job`) — daemon trimite heartbeat la 10s, run_one_job propaga `scan_type` din job. Helpere de enrollment + PyInstaller. |
| `collectors/`              | **Modul de colectori composabili.** Vezi `collectors/memory.md`. |
| `scan.py`                  | **Entry point.** Cu argumente → CLI (subcomenzi: `enroll`, `scan`, `daemon`, `gui`, `status`, `logout`, `autostart`). Fara argumente → deschide GUI (utile la dublu-click pe `.exe`). |
| `gui.py`                   | **Interfata Tkinter, 3 pagini:** Login (cu toggle inline pentru register), Enroll Device (cu smart re-link daca exista deja device cu acelasi UID), Status (cont + device + nivele suportate + buton **Deschide platforma** / Pauza / Logout; log live cu queue.Queue). **Fara buton "Scan now" — scanarea se initiaza din platforma web.** Daemon ruleaza pe thread separat (`DaemonRunner`). |
| `tray.py`                  | Icon scut in system tray (`pystray` + `Pillow`). Meniu: **Open dashboard / Pauza / Iesire**. Optional — daca pystray lipseste, GUI-ul functioneaza fara icon. |
| `autostart.py`             | **Pornire la logon, fara admin.** Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Linux: `~/.config/systemd/user/vulnwatch-agent.service`. macOS: `~/Library/LaunchAgents/com.vulnwatch.agent.plist`. API public: `enable()`, `disable()`, `status()`, `is_enabled()`. |
| `requirements.txt`         | Runtime deps: `psutil>=5.9`, `requests>=2.31`, `pillow>=10`, `pystray>=0.19.5`. Tkinter este in stdlib (Windows). |
| `requirements-dev.txt`     | Include `requirements.txt` + `pyinstaller>=6.5` pentru build. |
| `VulnWatchAgent.spec`      | **Spec PyInstaller** pentru build `--onefile`, `console=False`. Lista hidden imports pentru `pystray._win32`, `pystray._gtk`, `pystray._darwin`. Excludem `matplotlib`, `numpy`, Qt. |
| `build.ps1`                | **Script one-click pentru build .exe.** Creeaza `.venv-build`, instaleaza dep-urile, ruleaza PyInstaller, copiaza output-ul in `server/app/static/agent/` ca sa fie servit din UI. |
| `README.md`                | Documentatie pentru utilizator. Cele 3 moduri de operare, comenzile CLI complete, instructiuni service Windows/systemd. |
| `tests/`                   | Smoke tests pentru `core.py`. Vezi `tests/memory.md`. |

## Configul local

Stocat la `~/.vulnwatch/config.ini` (creat automat dupa enrollment, permisiuni
0600 pe POSIX). Sectiunea `[agent]` cu cheile:
- `api_base` — URL backend (ex: `http://127.0.0.1:8000/api/v1`)
- `device_uid` — identificatorul tehnic ales la enrollment
- `device_token` — tokenul plain (afisat doar o data de backend la creare)
- `device_name` (optional) — numele afisabil; folosit doar pentru afisare in GUI
- `user_email` (optional) — email-ul user-ului; folosit pentru afisare in pagina status

`device_token` este pe disc; backend-ul stocheaza doar `SHA-256(token)`. Daca
e compromis, user-ul trebuie sa faca **re-link** din UI (POST /devices/{uid}/relink)
care invalideaza tokenul vechi si emite unul nou — istoricul scan-urilor ramane.

## Auth flow

1. **Enrollment**: GUI cere email + parola → `POST /auth/login` (sau register-then-login) → primim `session_token` → cautam device cu `GET /devices/by-uid/{hostname}`:
   - **Found**: oferim "Refoloseste device existent" → `POST /devices/{uid}/relink`
   - **Not found**: form pentru enrollment nou → `POST /devices` cu `{device_uid, name}`
2. **Salveaza `device_token` in config local** + `DELETE /auth/logout` (renuntam la session_token).
3. **Operare**: doar `device_token` in headerele `X-Device-Token`. Tokenul nu expira (decat daca user-ul face re-link sau sterge device-ul din UI).
