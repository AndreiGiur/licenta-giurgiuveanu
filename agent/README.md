# VulnWatch Agent

Agent local care colectează date despre sistem și le trimite către backend
pentru evaluare. După înrolare, suportă două moduri de operare:

1. **Daemon (recomandat)** — agent-ul rulează în fundal și execută scanările
   cerute din UI-ul platformei (buton **Scan now** pe pagina `/devices`).
2. **One-shot** — `python scan.py` rulează o singură scanare și iese (util pentru
   debug, scripting sau scheduled tasks).

## Instalare

```bash
cd agent
pip install -r requirements.txt
```

Necesită Python 3.10+.

## Înrolare (o singură dată)

```bash
python scan.py enroll
```

Comanda este interactivă:

1. Cere email și parolă (același cont ca în UI). Dacă contul nu există,
   întreabă dacă să-l creeze.
2. Cere un *device UID* (default: hostname-ul mașinii) și un nume afișat.
3. Creează dispozitivul în backend și **salvează tokenul automat** la
   `~/.vulnwatch/config.ini` (permisiuni `0600` pe POSIX).

User-ul nu copiază tokenul manual — fluxul e complet automatizat.

### Opțiuni non-interactive

```bash
python scan.py enroll --email me@example.com --password '...' \
                       --device-uid laptop-work --name "Work Laptop" \
                       --api http://127.0.0.1:8000/api/v1
```

## Mod daemon (Scan now din UI)

```bash
python scan.py daemon
```

Agentul rămâne în foreground, polează backend-ul la 3 secunde și execută scanări
cerute din UI. Apasă **Ctrl+C** ca să-l oprești.

```
============================================================
 VulnWatch Agent — daemon
============================================================
 API           : http://127.0.0.1:8000/api/v1
 Device UID    : laptop-work
 Poll interval : 3s
 Auto-scan     : dezactivat
 Mode          : loop

Astept joburi de la backend... (Ctrl+C pentru oprire)

[14:32:15] Job #4 primit. Colectez date...
[14:32:18] Job #4 done. Scan #28, score 35/100.
```

### Opțiuni `daemon`

| Flag                         | Descriere                                                |
| ---------------------------- | -------------------------------------------------------- |
| `--poll <sec>`               | Interval polling (default: 3 secunde)                    |
| `--auto-interval <sec>`      | Scan automat la fiecare N sec (default: dezactivat)      |
| `--once`                     | Procesează un singur job și iese (testare)               |

Exemplu cu auto-scan la fiecare oră (în plus față de butonul UI):

```bash
python scan.py daemon --auto-interval 3600
```

### Cum funcționează (pentru defense)

```
UI (browser)             Backend                Agent (daemon)
   │                        │                        │
   │ POST /scan-jobs        │                        │
   │ ─────────────────────► │                        │
   │ ◄─ {job_id, pending}   │                        │
   │                        │  GET /agent/jobs/next  │
   │                        │ ◄──────────────────── │  poll @3s
   │                        │ ── {job_id, uid} ──► │
   │                        │                        │  collect data
   │                        │ POST /agent/jobs/{id}  │
   │                        │       /result          │
   │                        │ ◄──────────────────── │
   │ GET /scan-jobs/{id}    │                        │
   │ ─────────────────────► │ (status: done)         │
```

- **Pull-based**: agent-ul *cere* joburi, backend-ul nu le *trimite*. Asta
  înseamnă că agent-ul nu trebuie expus pe rețea — funcționează prin firewall,
  NAT, VPN. Aceeași strategie folosesc Wazuh, Microsoft Defender for Endpoint,
  Datadog Agent.
- **Job queue**: state machine `pending → running → done | failed`. Backend-ul
  ridică job-ul atomic la `GET /agent/jobs/next` (`SELECT ... FOR UPDATE SKIP
  LOCKED`) — nu pot doi agenți să prindă același job.

## Mod one-shot (push direct)

```bash
python scan.py
# sau explicit:
python scan.py scan
```

Trimite un scan unic la `POST /scans` și iese. Util pentru debug sau pentru a
rula prin Windows Task Scheduler / cron fără daemon persistent.

## Toate comenzile

| Comandă                       | Descriere                                                |
| ----------------------------- | -------------------------------------------------------- |
| `python scan.py enroll`       | Înrolare interactivă (login + creare device)             |
| `python scan.py daemon`       | **Mod foreground**, procesează joburi din UI (recomandat)|
| `python scan.py daemon --once`| Procesează un singur job și iese                         |
| `python scan.py`              | Push direct: o scanare unică                             |
| `python scan.py status`       | Afișează configul curent (fără token)                    |
| `python scan.py logout`       | Șterge configul local                                    |

## Rulare ca serviciu persistent

### Windows — Task Scheduler (la pornirea sistemului)

```powershell
$action = New-ScheduledTaskAction `
    -Execute "python.exe" `
    -Argument "E:\path\to\agent\scan.py daemon" `
    -WorkingDirectory "E:\path\to\agent"

$trigger = New-ScheduledTaskTrigger -AtStartup

Register-ScheduledTask `
    -TaskName "VulnWatchAgent" `
    -Action $action `
    -Trigger $trigger `
    -RunLevel Highest
```

Pentru o variantă cu service-wrapping mai robust, folosește
[NSSM](https://nssm.cc/) (the non-sucking service manager).

### Linux — systemd user service

`~/.config/systemd/user/vulnwatch-agent.service`:

```ini
[Unit]
Description=VulnWatch Agent (daemon)
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /path/to/agent/scan.py daemon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

Apoi:

```bash
systemctl --user enable --now vulnwatch-agent
systemctl --user status vulnwatch-agent
journalctl --user -u vulnwatch-agent -f
```

## Date colectate

| Categorie  | Pe Windows                                                    | Pe Linux/macOS                |
| ---------- | ------------------------------------------------------------- | ----------------------------- |
| OS         | system, release, version, hostname, is_admin                  | idem                          |
| Network    | porturi TCP în LISTEN                                         | idem (poate necesita root)    |
| Processes  | top 50 după consum memorie (PID, nume, MB, user)              | idem                          |
| Software   | toate programele din `Uninstall` (registry HKLM)              | — (gol; placeholder)          |

> **Notă POSIX**: `psutil.net_connections()` poate cere privilegii root pe Linux
> pentru a vedea conexiunile altor utilizatori. Agent-ul tratează `AccessDenied`
> grațios și raportează doar ce poate citi.

## Locația configului

```
~/.vulnwatch/config.ini
```

Conține `api_base`, `device_uid` și `device_token`. Pe sisteme POSIX permisiunile
sunt `0600`. Folosește `python scan.py logout` pentru ștergere.
