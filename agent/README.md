# VulnWatch Agent

Agent local care colectează date despre sistem și le trimite către backend.
Suportă **trei moduri** de operare:

| Mod        | Pornire                  | UX                                       |
| ---------- | ------------------------ | ---------------------------------------- |
| GUI        | dublu-click pe `.exe`    | **Zero terminal**. Recomandat.           |
| Daemon CLI | `python scan.py daemon`  | Foreground în terminal                   |
| One-shot   | `python scan.py scan`    | Push direct, ideal pentru cron/Task Sched|

## Modul recomandat — GUI + .exe (zero terminal)

### Pe mașina pe care rulează **backend-ul**, build-uiești `.exe`-ul **o singură dată**

```powershell
powershell -ExecutionPolicy Bypass -File agent\build.ps1
```

Scriptul:
- creează un venv local pentru build (`.venv-build`),
- instalează `pyinstaller`, `pillow`, `pystray`, `requests`, `psutil`,
- produce `dist\VulnWatchAgent.exe` (~30 MB),
- copiază exe-ul în `server/app/static/agent/` ca să fie servit la
  `/api/v1/agent/download/windows`.

### Pe orice mașină pe care vrei să o monitorizezi

1. Login în UI → **Devices** → **↓ Descarcă .exe** (banner deasupra listei).
2. **Dublu-click** pe `VulnWatchAgent.exe` (descărcat din UI).
3. **Pagina 1 — Login**: completezi email + parolă + API URL. Dacă nu ai cont,
   click pe link "Înregistrează-te" (toggle inline; același formular).
4. **Pagina 2 — Enroll device** (după login reușit):
   - **dacă ai mai folosit acest PC pe acest cont** (ai reinstalat OS-ul, ai
     șters configul local etc.) → apare automat opțiunea **"Refolosește device
     existent"** cu detaliile (nume, UID, dată înregistrare). Click → primești
     token nou pentru același device, istoricul scanărilor rămâne.
   - **dacă e PC nou** → completezi UID-ul (default: hostname) + nume afișat,
     bifezi "Pornește automat la logon" (recomandat), apeși **Înrolează acest PC**.
5. **Pagina 3 — Status**: panou cu cont logat + nume device + indicator daemon.
   Butoane: **Scan now** / **Pauză** / **Open dashboard** / **Logout**. Log
   live al joburilor.
6. Iconul în **system tray** (lângă ceas) — chiar dacă închizi fereastra cu X,
   daemon-ul rămâne să răspundă la "Scan now" din UI. Click dreapta pe icon →
   meniu cu Pauză / Open dashboard / Ieșire.
7. La logon următor, agent-ul pornește automat (dacă ai bifat autostart).

**Logout** șterge configul local și revine la pagina de login. Device-ul
rămâne pe contul tău în dashboard — îl poți reactiva oricând cu același cont
(smart re-link automat).

**Totul fără să tastezi vreo comandă.**

## Modul daemon CLI (alternativ, fără .exe)

Dacă preferi terminalul sau ești pe Linux:

```bash
cd agent
pip install -r requirements.txt
python scan.py enroll        # interactiv
python scan.py daemon        # foreground; răspunde la "Scan now"
```

Opțiuni `daemon`:
- `--poll N` — interval polling (default 3s)
- `--auto-interval N` — scan automat la fiecare N sec
- `--once` — procesează un singur job și iese (testare)

## Modul one-shot

`python scan.py scan` — o scanare unică (push direct la `/scans`). Util pentru
cron / Task Scheduler dacă nu vrei daemon persistent.

## Toate comenzile

```
python scan.py                    GUI (dacă fără argumente)
python scan.py gui                GUI explicit
python scan.py enroll             înrolare interactivă în terminal
python scan.py scan               scanare unică, push direct
python scan.py daemon [--poll N --auto-interval N --once]
python scan.py status             config curent (fără token)
python scan.py logout             șterge configul local
python scan.py autostart enable   înregistrează pornirea la logon
python scan.py autostart disable  scoate înregistrarea
python scan.py autostart status
```

## Autostart — cum funcționează

Cross-platform, **fără admin**:

| Platformă | Mecanism                                                                        |
| --------- | ------------------------------------------------------------------------------- |
| Windows   | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (per user, fără elevation) |
| Linux     | `~/.config/systemd/user/vulnwatch-agent.service` + `systemctl --user enable`    |
| macOS     | `~/Library/LaunchAgents/com.vulnwatch.agent.plist` + `launchctl load`           |

Pe Windows, valoarea în registry pointează la `VulnWatchAgent.exe daemon`
(sau `pythonw.exe scan.py daemon` dacă rulezi din sursă fără bundle).

## Layout fișiere (pentru defense)

```
agent/
├── core.py               Logica de bază (collect, HTTP, daemon loop)
├── scan.py               Entry point: dispatcher CLI sau GUI
├── gui.py                Interfața Tkinter (enrollment + status + log live)
├── tray.py               Icon în system tray (pystray + Pillow)
├── autostart.py          HKCU Run / systemd / launchd
├── VulnWatchAgent.spec   PyInstaller spec (--onefile, console=False)
├── build.ps1             Script one-click pentru build .exe
├── requirements.txt      Runtime deps (psutil, requests, pillow, pystray)
└── requirements-dev.txt  + pyinstaller (doar pentru build)
```

`core.py` nu importă nimic legat de UI. `scan.py` nu cunoaște `tkinter`/`pystray`
direct (le importă lazy). Astfel, modul CLI funcționează și pe servere fără X.

## Date colectate

| Categorie | Pe Windows                                            | Pe Linux/macOS               |
| --------- | ----------------------------------------------------- | ---------------------------- |
| OS        | system, release, version, hostname, is_admin          | idem                         |
| Network   | porturi TCP în LISTEN                                 | idem (poate cere root)       |
| Processes | top 50 după consum memorie                            | idem                         |
| Software  | toate programele din `Uninstall` (registry HKLM)      | — (gol)                      |

## Locația configului

`~/.vulnwatch/config.ini` — `api_base`, `device_uid`, `device_token`. Pe POSIX
permisiuni 0600. Folosește `python scan.py logout` sau **Ieșire** + ștergerea
manuală a fișierului pentru reset.
