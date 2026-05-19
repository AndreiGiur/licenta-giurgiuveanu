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
| `core.py`                  | **Logica de baza + Strategy Pattern.** `ScanProfile` dataclass + `SCAN_PROFILES` dict (standard/advanced/deep) — sursa unica de adevar pentru ce colecteaza fiecare nivel. `AGENT_VERSION` constanta. Citire/scriere config (`~/.vulnwatch/config.ini`). `is_admin()` + orchestrator `collect_system_data(device_uid, scan_type, progress_cb)` care apeleaza colectorii composabili din `agent/collectors/` cu progress callback intre etape. **Functii nmap/NSE**: `_nmap_path()` (cauta nmap.exe in PATH + Program Files), `_bundled_nse_path()` (rezolva calea catre `nse/vulnwatch-audit.nse` din bundle PyInstaller sau dev tree), `deploy_nse_script(log)` (copiaza scriptul in `{nmap_dir}\scripts\` + ruleaza `--script-updatedb`), `agent_capabilities()` (returneaza `["standard", "advanced"]` + `["deep"]` doar daca nmap exista), `_run_nmap_if_deep(job, log, progress_cb)` (executa nmap pentru scan deep cu LAN opt-in via `job.nmap_target`, parseaza XML, intoarce dict). Apeluri HTTP (`api_login`, `api_register`, `api_create_device`, `api_get_device_by_uid`, `api_relink_device`, `api_send_scan`, `api_get_next_job`, `api_submit_job_result`, `api_submit_job_failure`, `api_logout`, `api_me`, `api_heartbeat`, `api_send_progress`). Bucla daemon (`daemon_loop`, `run_one_job`) — daemon trimite heartbeat la 10s, propaga capabilities dinamic, ruleaza `deploy_nse_script()` la startup; `run_one_job` injecteaza `data["nmap"]` pentru scan deep. Helpere de enrollment + PyInstaller. |
| `service.py`               | **Windows Service wrapper (pywin32).** `VulnWatchService` (subclasa `win32serviceutil.ServiceFramework`) — porneste `core.daemon_loop` pe thread, raporteaza la SCM. Public: `install_service()`, `uninstall_service()`, `is_service_installed()`, `is_service_running()`, `run_as_service()` (entry point pentru flag `--service`). Constante: `SERVICE_NAME="VulnWatchSvc"`, display name + description. Gracefully degrades pe non-Windows (`_PYWIN32_AVAILABLE=False`). |
| `ipc.py`                   | **Protocol IPC GUI↔Service via TCP socket localhost (port 47815 default).** Mesaje JSON line-delimited. `IpcServer` (handler + broadcast events catre subscribers, thread-safe lock pe `_subscribers`), `IpcClient` (request/response + `subscribe_events` cu callback). DoS protection: `MAX_BUFFER_SIZE=65536`. Exception isolation pe handler thread. |
| `nmap_runner.py`           | **Construire CLI args nmap + executie subprocess.** `validate_cidr(value)` (sintaxa), `validate_lan_target(value)` (refuza public + subnet > `MAX_LAN_HOSTS=4096`), `build_nmap_args(targets, xml_out, top_ports, all_ports, extra_script_args)`, `run_nmap(targets, xml_out, top_ports, timeout_sec=1800, log)`. Exceptie: `NmapRunnerError`. |
| `nmap_parser.py`           | **Parse XML output nmap → dict VulnWatch.** `parse_nmap_xml(xml_text)` intoarce `{version, scan_time_sec, hosts: [{ip, hostname, state, os_guess, ports, vulnwatch_findings, topology}]}`. Deserializeaza JSON-ul emis de scriptul `vulnwatch-audit` din `<script id="vulnwatch-audit">`. Exceptie: `NmapParseError`. |
| `nse/vulnwatch-audit.nse`  | **Scriptul NSE custom in Lua (~270 LOC).** 3 sub-module embedded: **aggregator** (preia output din scripts vuln NSE built-in), **cve_mapper** (CVE_DB cu 12 entries pentru microsoft-ds, netbios-ssn, http, https, ssh, ftp, telnet, ms-wbt-server, mysql, postgresql, redis, mongodb; pattern matching pe service+version), **topology** (rol gateway/dns/fileserver/workstation + risc 0-100 cu reasons). `hostrule` + `action(host)` → `json.generate(output)`. Deployed la startup in `{nmap_dir}\scripts\` de `core.deploy_nse_script()`. |
| `collectors/`              | **Modul de colectori composabili.** Vezi `collectors/memory.md`. |
| `scan.py`                  | **Entry point.** Cu argumente → CLI (subcomenzi: `enroll`, `scan`, `daemon`, `gui`, `status`, `logout`, `autostart`). Fara argumente → deschide GUI (utile la dublu-click pe `.exe`). |
| `gui.py`                   | **Interfata Tkinter regandita cu paleta Honey & Plum (dark + light, toggle persistat).** 3 pagini: **Login** (Google button outlined + email/parola + toggle Register + footer API URL ✎ + theme toggle ☾/☀), **Enroll consolidat** (sub-stari `new device` vs `relink` in aceeasi pagina, banner contextual cand exista UID, link `[Schimbă]` UID pe new device, link `Vrei să-l înregistrezi ca PC nou? →` pe relink), **Status** (status dot 5 stari `online/degraded/offline/paused/starting` cu glow live + 3 metric cards `SCANĂRI/ULTIMA EXPUNERE/ULTIMA SCANARE` + sectiune Detalii expandabila (state persistat in `[ui] log_expanded`) + meniu ⚙ cu **Pornește la logon / Schimbă cont / Deconectează acest PC / Setări avansate API URL / Despre**). Helpers: `ThemeManager` (toggle + persist), `_make_theme_toggle_button`, `_tick_status_refresh` (refresh la 2s pe baza `daemon.last_heartbeat_ts`), `_format_last_scan_time`, `_build_details_section`, `_render_status_dot`, `_open_api_url_modal` (Toplevel modal cu Salvează/Anulează/Revino default), `_open_about_dialog`, `_open_settings_menu`. `_on_change_account` (păstrează device pe cont + păstrează metrici) vs `_on_disconnect_pc` (resetează metrici). Google login flow async pe thread separat ca inainte. Daemon ruleaza pe thread separat (`DaemonRunner`) cu callbacks `on_heartbeat_ok` (updateaza `last_heartbeat_ts`) + `on_scan_done` (trimite `__SCAN_DONE__` pe queue → `_poll_log_queue` apeleaza `metrics.record_scan` + re-render Status). |
| `tray.py`                  | Icon scut in system tray (`pystray` + `Pillow`). Meniu: **Open dashboard / Pauza / Iesire**. Optional — daca pystray lipseste, GUI-ul functioneaza fara icon. |
| `autostart.py`             | **Pornire la logon, fara admin.** Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Linux: `~/.config/systemd/user/vulnwatch-agent.service`. macOS: `~/Library/LaunchAgents/com.vulnwatch.agent.plist`. API public: `enable()`, `disable()`, `status()`, `is_enabled()`. |
| `requirements.txt`         | Runtime deps: `psutil>=5.9`, `requests>=2.31`, `pillow>=10`, `pystray>=0.19.5`, `google-auth-oauthlib>=1.2`, `google-auth>=2.30`. Tkinter este in stdlib (Windows). |
| `google_oauth.py`          | **Loopback OAuth desktop flow** via `google-auth-oauthlib.InstalledAppFlow`. Citeste `GOOGLE_CLIENT_ID` din `google_config.py` (sau env `AGENT_GOOGLE_CLIENT_ID` ca fallback). Expune `is_configured()` (bool) + `login_with_google()` care deschide browserul, asteapta callback pe `127.0.0.1:0`, face exchange si returneaza `id_token`. Excepție `GoogleOAuthError` pentru orice esec. Scopes: `openid`, `userinfo.email`, `userinfo.profile`. Functia e BLOCANTA — apel din thread separat in GUI. |
| `google_config.py`         | **LOCAL, gitignored.** Contine `GOOGLE_CLIENT_ID` — Desktop OAuth Client ID din Google Cloud Console. NU se committe in repo public. |
| `google_config.py.example` | Template committed cu `GOOGLE_CLIENT_ID = ""`. User-ul copiaza la `google_config.py` si completeaza valoarea reala. |
| `requirements-dev.txt`     | Include `requirements.txt` + `pyinstaller>=6.5` pentru build. |
| `VulnWatchAgent.spec`      | **Spec PyInstaller** pentru build `--onefile`, `console=False`. `datas` include `nse/vulnwatch-audit.nse` → `sys._MEIPASS/nse/vulnwatch-audit.nse`. Hidden imports: `pystray._win32/_gtk/_darwin`, `agent.service/ipc/nmap_runner/nmap_parser`, `win32serviceutil/win32service/win32event/servicemanager/pywintypes`. Excludem `matplotlib`, `numpy`, Qt. |
| `build.ps1`                | **Script one-click pentru build .exe.** Creeaza `.venv-build`, instaleaza dep-urile, ruleaza PyInstaller, copiaza output-ul in `server/app/static/agent/` ca sa fie servit din UI. |
| `README.md`                | Documentatie pentru utilizator. Cele 3 moduri de operare, comenzile CLI complete, instructiuni service Windows/systemd. |
| `tests/`                   | Smoke tests pentru `core.py`. Vezi `tests/memory.md`. |

## Configul local

Stocat la `~/.vulnwatch/config.ini` (creat automat dupa enrollment, permisiuni
0600 pe POSIX). Sectiunile:

- `[agent]` — credentials + identitate device:
  - `api_base` — URL backend (ex: `http://127.0.0.1:8000/api/v1`)
  - `device_uid` — identificator tehnic stabil
  - `device_token` — tokenul plain (generat local; vezi spec client-side tokens)
  - `device_name` (optional) — nume afisabil in GUI
  - `user_email` (optional) — email user pentru afisare in Status
- `[ui]` — preferinte UI persistate intre rulari:
  - `theme` — `dark` (default) sau `light`
  - `log_expanded` — `true` sau `false` (state colapsare sectiunea Detalii pe pagina Status)

`device_token` este pe disc; backend-ul stocheaza doar `SHA-256(token)`. Daca
e compromis, user-ul trebuie sa faca **re-link** din UI (POST /devices/{uid}/relink)
care invalideaza tokenul vechi si emite unul nou — istoricul scan-urilor ramane.

## Cache metrici (`~/.vulnwatch/metrics.json`)

Fisier separat cu istoricul ultimelor 20 scanari + counters lifetime, gestionat
prin clasa `MetricsTracker` din `core.py`. Cheile: `scans_total` (counter),
`last_exposure_score`, `last_scan_at` (ISO ts), `last_scan_type`, `history` (lista
ultimele 20 cu `score`, `scan_type`, `job_id`, `at`). Scriere atomica
(write-to-temp → `os.replace`) pentru a evita corupere la kill SIGKILL. Citire
defensiva: JSON corupt → state gol + log warn, fara crash. Reset doar la
"Deconecteaza acest PC" (nu la "Schimba cont", pentru ca istoria apartine
device-ului fizic, nu user-ului).

## Auth flow (client-generated tokens)

1. **Login local in executabil**: GUI cere email/parola sau buton Google. POST `/auth/login` sau OAuth loopback → primim `session_token` (temporar).
2. **Generare token local**: `core.generate_device_token()` returneaza `(token_plain, token_hash_hex)`. Tokenul plain ramane in RAM-ul executabilului; backend-ul nu-l vede niciodata.
3. **Enrollment**: agent cauta device existent cu `GET /devices/by-uid/{hostname}`.
   - **Found**: POST `/devices/{uid}/relink` cu body `{token_hash}` → backend inlocuieste hash-ul vechi cu cel nou.
   - **Not found**: POST `/devices` cu body `{device_uid, name, token_hash}` → backend stocheaza hash-ul ca atare.
4. **Salveaza `device_token` plain in `~/.vulnwatch/config.ini`** + `DELETE /auth/logout` (renuntam la session_token).
5. **Operare**: doar `device_token` plain in headerele `X-Device-Token`. Backend verifica `sha256(plain) == row.device_token_hash`.

## Auto-recovery la 401

`daemon_loop` ridica `DeviceTokenInvalidError` din toate apelurile care folosesc `X-Device-Token` (heartbeat, get_next_job, submit_result, etc.). La prima eroare 401, daemon iese din loop si apeleaza `on_token_invalid` callback. `gui.DaemonRunner` propaga eventul printr-un marker `__TOKEN_INVALID__` pe `queue.Queue`; `AgentApp._poll_log_queue` il intercepteaza si re-renders pagina Login cu mesaj clar.

## Deep scan flow (nmap + NSE)

- **Prerequisite**: nmap.exe trebuie instalat separat pe device (download din nmap.org). Executabilul VulnWatchAgent NU bundle-uieste nmap (~80 MB) — bundle-uieste doar `nse/vulnwatch-audit.nse`.
- **La startup daemon**: `deploy_nse_script()` copiaza scriptul Lua in `{nmap_dir}\scripts\` si ruleaza `nmap --script-updatedb`. `agent_capabilities()` adauga `"deep"` doar daca `_nmap_path()` returneaza un path.
- **Scan deep cu LAN**: UI POST `/devices/{uid}/scan-jobs` cu `nmap_target=<CIDR>` (validat backend + agent: refuz public, max 4096 hosts). Agent ruleaza nmap pe `["127.0.0.1", nmap_target]` cu top-1000 ports si scriptul NSE → XML parsed → `data["nmap"]` injectat in payload.
- **Backend rule NMAP-LUA-1**: in `server/app/rules.py`, decorat `@rule(min_level="deep")`, pass-through pentru `scan.nmap.hosts[].vulnwatch_findings` cu `source="nmap-lua"` + `host_ip` adaugat in evidence. Severitatea e decisa de Lua (CVE_DB).
- **GUI prompt UAC**: la primul enrollment reusit, daca `service.is_service_installed()` returneaza False, GUI ofera modal `_prompt_install_service` care lanseaza `--install-service` cu `ShellExecuteW(verb="runas")` → UAC. Optiune accesibila si din meniul ⚙ (Instaleaza/Re-instaleaza serviciu Windows).

## Smoke checklist (manual, dupa rebuild .exe)

1. Install nmap → restart agent → capabilities include "deep" in heartbeat
2. UI Devices → selecteaza Deep → apare expander cu checkbox LAN
3. Modal install service la enrollment → UAC → service instalat (`sc.exe query VulnWatchSvc`)
4. Trigger Deep scan fara LAN → 10-15 min → NmapSection in ScanDetail cu host 127.0.0.1
5. Findings nmap apar cu severity + source=nmap-lua
6. Trigger Deep scan cu LAN bifat → confirm modal → multi-host
7. Uninstall nmap → restart service → capabilities NU mai include "deep"
