# VulnWatch Agent

Agent local care colectează date despre sistem și le trimite către backend
pentru evaluare. Configurat o singură dată cu `enroll`, apoi pornește scanări
oricând cu `scan.py`.

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

User-ul nu mai trebuie să copieze tokenul manual — fluxul e fully automated.

### Opțiuni non-interactive

```bash
python scan.py enroll --email me@example.com --password '...' \
                       --device-uid laptop-work --name "Work Laptop" \
                       --api http://127.0.0.1:8000/api/v1
```

## Rulare scan

```bash
python scan.py
# sau explicit:
python scan.py scan
```

Output exemplu:

```
============================================================
 VulnWatch — scanare
============================================================
 API        : http://127.0.0.1:8000/api/v1
 Device UID : laptop-work
 Timestamp  : 2026-05-03 12:34:56
 Admin      : False

Colectez date sistem...
  OS       : Windows 11
  Hostname : DESKTOP-ABC
  Porturi  : [135, 445, 5040]
  Procese  : 50
  Software : 84 programe

Trimit scanarea...

Scanare trimisa cu succes!
  Scan ID       : 42
  Exposure Score: 38/100
  Findings      : 2

Vulnerabilitati detectate:
  [HIGH]  Porturi cu risc ridicate expuse
           Inchide porturile neutilizate din firewall...
  [MED]   Sesiune activa cu privilegii de administrator
           Foloseste un cont standard pentru activitatile zilnice...

Vezi rezultatele: http://127.0.0.1:5173/dashboard?device=laptop-work
```

## Comenzi disponibile

| Comandă                | Descriere                                     |
| ---------------------- | --------------------------------------------- |
| `python scan.py enroll`| Înregistrare interactivă (login + creare device) |
| `python scan.py`       | Rulează o scanare (implicit)                  |
| `python scan.py scan`  | Idem, explicit                                |
| `python scan.py status`| Afișează configul curent (fără token)         |
| `python scan.py logout`| Șterge configul local                         |

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
