# Design Spec: Deep Scanner + Frontend Redesign

**Data:** 2026-05-10  
**Status:** Aprobat de utilizator

---

## 1. Obiective

1. Extinde agentul cu un scanner multi-nivel (Quick / Standard / Deep) care colectează date de securitate detaliate și le trimite la backend ca executabil `.exe`.
2. Refactorizează motorul de reguli ca sistem plugin-based cu fișiere separate pe categorii.
3. Redesign frontend cu layout sidebar + main, modal de selecție nivel și progress view în timp real.

---

## 2. Platformă țintă

**Windows** (primar). Colectarea pe Linux/macOS rămâne la nivelul existent (Quick implicit). Toate noile metode de colectare folosesc `subprocess` + unelte CLI Windows sau `winreg`/`pywin32` cu hidden imports declarate explicit în `.spec` PyInstaller.

---

## 3. Niveluri de scanare

### Quick (~10s)
Comportamentul existent:
- Porturi TCP în stare LISTEN
- Top 50 procese după RAM
- Software instalat (Windows registry HKLM Uninstall)
- Info OS (system, release, version, machine, hostname, is_admin)

### Standard (~60s)
Quick +
- **Servicii Windows** — `psutil.win_service_iter()`: nume, status, starttype, user (SYSTEM vs user)
- **Conexiuni rețea active** — `psutil.net_connections()` cu ESTABLISHED + LISTEN, cu IP destinație
- **Conturi locale** — `subprocess net user` + `winreg` SAM flags: username, has_password, is_admin, is_active
- **Task-uri programate** — `subprocess schtasks /query /fo CSV /v`: taskname, run_as, task_to_run, status
- **Reguli firewall** — `subprocess netsh advfirewall show allprofiles` + `netsh advfirewall firewall show rule`: profile states, nr reguli custom
- **Autorun entries** — `winreg` HKCU\...\Run + HKLM\...\Run + startup folder: name, path

### Deep (~5min)
Standard +
- **Politică parole** — `subprocess net accounts`: min_length, max_age, complexity, lockout_threshold
- **Share-uri rețea** — `subprocess net share`: share_name, path, permissions
- **Unquoted service paths** — `winreg HKLM\SYSTEM\CurrentControlSet\Services`: ImagePath fără ghilimele cu spații
- **Event logs** — `pywin32 win32evtlog` Security log, ultimele 500 events: failed logons (EventID 4625)
- **Hash fișiere sistem** — `hashlib SHA-256` pe ~20 fișiere critice din `%SystemRoot%\System32` (svchost.exe, lsass.exe, winlogon.exe etc.)
- **Certificate instalate** — `subprocess certutil -store My` + `certutil -store Root`: subject, expiry, issuer
- **Windows Update status** — `subprocess wmic qfe list brief /format:csv`: ultimul update, KB-uri lipsă

---

## 4. Arhitectură agent

### `agent/scanner.py` (fișier nou)

```
class Scanner (base)
    .steps() -> list[str]
    .collect(step: str) -> dict
    .collect_all(progress_cb) -> dict

class QuickScanner(Scanner)
class StandardScanner(Scanner)  # include QuickScanner
class DeepScanner(Scanner)       # include StandardScanner

def make_scanner(level: str) -> Scanner
```

`progress_cb` este apelat după fiecare pas cu `(step, status)` — permite raportarea progresului la backend.

### `agent/core.py` (modificat minimal)

- `run_one_job()` citește `job["level"]` și instanțiază `make_scanner(level)`
- Apelează `api_report_progress(job_id, step, status)` după fiecare pas
- `collect_system_data()` devine `QuickScanner().collect_all()` (compatibilitate backward)

### `agent/build.ps1` + `VulnWatchAgent.spec` (modificate)

```python
# spec: hidden imports adăugate
hiddenimports=['win32evtlog', 'win32api', 'win32con', 'pywintypes']
```

```powershell
# build.ps1: instalare pywin32
pip install pywin32
```

---

## 5. Arhitectură backend

### 5.1 Modificări model de date

**`ScanJob`** — două câmpuri noi:
```python
level: Mapped[str] = mapped_column(String(16), default="quick")
# "quick" | "standard" | "deep"

progress: Mapped[list | None] = mapped_column(JSON, nullable=True)
# [{"step": "ports", "status": "done"},
#  {"step": "event_logs", "status": "running"},
#  {"step": "certificates", "status": "pending"}]
```

**`Scan`** — câmp nou:
```python
level: Mapped[str] = mapped_column(String(16), default="quick")
```

Progresul este inițializat la pickup-ul jobului: toate stepurile din `level` ca `"pending"`. Agentul actualizează unul câte unul prin endpoint-ul de progres.

### 5.2 Modificări API

**`POST /devices/{uid}/scan-jobs`** — body extins:
```python
class ScanJobCreateIn(BaseModel):
    level: str = Field(default="quick", pattern="^(quick|standard|deep)$")
```

**`GET /agent/jobs/next`** — răspuns extins:
```python
class AgentJobOut(BaseModel):
    job_id: int
    device_uid: str
    level: str  # "quick" | "standard" | "deep"
```

**`POST /agent/jobs/{id}/progress`** — endpoint nou:
```python
class ProgressIn(BaseModel):
    step: str = Field(max_length=32)
    status: str = Field(pattern="^(running|done|failed)$")
```
Actualizează `ScanJob.progress[step].status` în DB. Răspunde 200 `{"ok": true}`.

**`ScanJobOut`** — câmpuri noi:
```python
level: str = "quick"
progress: list[dict] | None = None
```

### 5.3 Motor de reguli plugin-based

`server/app/rules/` director în loc de `rules.py`:

```
rules/
├── __init__.py      # registry ALL_RULES + evaluate(scan, level) public
├── base.py          # clasa Rule cu: rule_id, title, severity, min_level, check()
├── network.py       # NET-OPEN-PORTS-1, NET-MANY-PORTS-2
├── process.py       # PROC-SUSPICIOUS-1, PROC-POWERSHELL-2
├── software.py      # SW-VULNERABLE-1
├── os_rules.py      # OS-ADMIN-1, OS-EOL-1
├── services.py      # SVC-UNQUOTED-PATH-1, SVC-SYSTEM-ABUSE-1
├── accounts.py      # USR-NO-PASSWORD-1, USR-MULTIPLE-ADMINS-1
├── firewall.py      # FW-DISABLED-1, FW-EXCESSIVE-RULES-1
├── tasks.py         # TASK-SUSPICIOUS-PATH-1
├── autorun.py       # AUTORUN-SUSPICIOUS-1
├── credentials.py   # PWD-POLICY-WEAK-1, SHARE-OPEN-1
├── events.py        # EVT-FAILED-LOGINS-1
└── integrity.py     # CERT-EXPIRED-1, CERT-SELF-SIGNED-1, UPDATE-MISSING-1
```

**`base.py`:**
```python
class Rule:
    rule_id: str
    title: str
    severity: str      # "critical"|"high"|"medium"|"low"|"info"
    min_level: str     # "quick"|"standard"|"deep"

    def check(self, scan: dict) -> dict | None:
        ...  # returnează finding dict sau None
```

**`__init__.py`:**
```python
LEVEL_ORDER = {"quick": 0, "standard": 1, "deep": 2}

ALL_RULES: list[Rule] = [...]  # importate din toate modulele

def evaluate(scan: dict, level: str = "quick") -> tuple[int, list[dict]]:
    findings = [
        r.check(scan) for r in ALL_RULES
        if LEVEL_ORDER[level] >= LEVEL_ORDER[r.min_level]
        and r.check(scan) is not None
    ]
    # calcul scor existent
    return score, findings
```

**Reguli noi cu severitate și min_level:**

| rule_id | Severitate | min_level | Condiție |
|---------|-----------|-----------|---------|
| SVC-UNQUOTED-PATH-1 | high | standard | ImagePath fără ghilimele și cu spații |
| SVC-SYSTEM-ABUSE-1 | medium | standard | Serviciu non-Microsoft rulând ca SYSTEM |
| USR-NO-PASSWORD-1 | high | standard | Cont local activ fără parolă |
| USR-MULTIPLE-ADMINS-1 | medium | standard | >2 conturi în grupul Administrators |
| FW-DISABLED-1 | high | standard | Firewall oprit pe orice profil (Domain/Private/Public) |
| FW-EXCESSIVE-RULES-1 | low | standard | >100 reguli de firewall custom |
| TASK-SUSPICIOUS-PATH-1 | high | standard | Task din %TEMP%, AppData sau cale neobișnuită |
| AUTORUN-SUSPICIOUS-1 | medium | standard | Autorun entry din locație în afara Program Files/System32 |
| PWD-POLICY-WEAK-1 | medium | deep | Fără expirare parolă SAU complexitate dezactivată |
| SHARE-OPEN-1 | critical | deep | Share cu permisiune Everyone: Full Control |
| EVT-FAILED-LOGINS-1 | medium | deep | >20 EventID 4625 în ultimele 24h |
| CERT-EXPIRED-1 | medium | deep | Certificate expirate în store personal sau root |
| CERT-SELF-SIGNED-1 | high | deep | Certificate self-signed în Trusted Root CA |
| UPDATE-MISSING-1 | medium | deep | Ultimul patch de securitate >30 zile în urmă |

---

## 6. Arhitectură frontend

### 6.1 `ScanDetail.tsx` — redesign complet

**Layout:** sidebar fix (200px) + main area scrollabilă.

**Sidebar secțiuni:**
- *Navigare:* Overview
- *Rezultate:* Rețea, Servicii, Conturi, Tasks, Firewall, Autorun, Software, Sistem
- *Deep only* (vizibil doar dacă `scan.level === "deep"`): Parole, Share-uri, Event Logs, Certificate, Fișiere, Updates

Fiecare item sidebar afișează numărul de findings pentru categoria sa (sau "OK" în verde dacă zero).

**Main area — Overview:**
- Ring SVG cu exposure score (colorat: verde <30, galben 30-69, roșu ≥70)
- 4 stat boxes: Findings totale, Critical, High, Medium/Low
- Grid de category cards (câte issues per categorie + bară de progres vizuală)
- Lista findings prioritare (primele 5, sortate după severitate)

**Main area — categorie specifică** (ex: click "Servicii" în sidebar):
- Tabel sau listă de items colectați (toate serviciile, nu doar cele cu issues)
- Findings specifice categoriei evidențiate cu border colorat
- Date raw colapsabile (pentru referință)

### 6.2 `Devices.tsx` — modal nivel

Butonul "Scan now" deschide un modal cu:
- Titlu: "Pornește o scanare" + numele device-ului
- 3 opțiuni selectabile: Quick (est. 10s), Standard (est. 60s, pre-selectat), Deep (est. 5min)
- Fiecare opțiune: icon + nume + descriere scurtă a ce colectează
- Butoane: Anulează / Pornește {nivel ales}

### 6.3 `Dashboard.tsx` — progress view

Când există un job activ (`status === "running" | "pending"`):
- Înlocuiește spinner-ul simplu cu lista de pași grupați pe nivele (Quick / Standard / Deep)
- Fiecare pas: icon (✓ done | spinner running | ○ pending) + nume + durată dacă done
- Bară de progres globală (pași done / total pași)
- Timer elapsed în timp real (calculat client-side din `job.created_at`)
- Polling la 2s pe `GET /scan-jobs/{id}` (comportament existent)

### 6.4 `api/exposure.ts` — funcție nouă

```typescript
export function reportProgress(jobId: number, step: string, status: string) {
  return apiPost(`/agent/jobs/${jobId}/progress`, { step, status });
}
```

*(Folosit doar de agent, nu de frontend — inclus pentru completitudine.)*

---

## 7. Compatibilitate backward

- `POST /scans` (push direct de la agent fără job queue) rămâne nemodificat — Quick implicit.
- `GET /agent/jobs/next` fără câmpul `level` în răspuns este un breaking change mic — agentul vechi va face Quick implicit dacă nu primește `level` (fallback în `core.py`).
- `rules.py` devine `rules/__init__.py` — `from .rules import evaluate` din `routes.py` rămâne identic.

---

## 8. Modificări `agent/requirements.txt`

```
psutil
requests
pystray
Pillow
pywin32    # NOU — pentru win32evtlog (event logs)
```

---

## 9. Teste noi necesare

**Backend:**
- `test_scan_jobs.py` — teste pentru `level` în creare job și în răspuns agent
- `test_scan_jobs.py` — test pentru `POST /agent/jobs/{id}/progress` (actualizare, validare status)
- `test_rules.py` — teste pentru fiecare regulă nouă (pe pattern-ul existent)
- `test_rules.py` — test că regulile cu `min_level="deep"` nu se evaluează la nivel "quick"

**Agent:**
- `agent/tests/test_scanner.py` — smoke tests pentru `QuickScanner`, `StandardScanner` (fără subprocess real)

---

## 10. Fișiere create / modificate

| Fișier | Acțiune |
|--------|---------|
| `agent/scanner.py` | NOU |
| `agent/core.py` | Modificat: `run_one_job`, `api_report_progress` |
| `agent/requirements.txt` | Modificat: adăugat `pywin32` |
| `agent/VulnWatchAgent.spec` | Modificat: hidden imports |
| `agent/build.ps1` | Modificat: instalare `pywin32` |
| `agent/tests/test_scanner.py` | NOU |
| `server/app/rules/__init__.py` | NOU (din `rules.py`) |
| `server/app/rules/base.py` | NOU |
| `server/app/rules/network.py` | NOU (mutat din `rules.py`) |
| `server/app/rules/process.py` | NOU (mutat din `rules.py`) |
| `server/app/rules/software.py` | NOU (mutat din `rules.py`) |
| `server/app/rules/os_rules.py` | NOU (mutat din `rules.py`) |
| `server/app/rules/services.py` | NOU |
| `server/app/rules/accounts.py` | NOU |
| `server/app/rules/firewall.py` | NOU |
| `server/app/rules/tasks.py` | NOU |
| `server/app/rules/autorun.py` | NOU |
| `server/app/rules/credentials.py` | NOU |
| `server/app/rules/events.py` | NOU |
| `server/app/rules/integrity.py` | NOU |
| `server/app/rules.py` | ȘTERS (înlocuit de `rules/`) |
| `server/app/models.py` | Modificat: `ScanJob.level`, `ScanJob.progress`, `Scan.level` |
| `server/app/schemas.py` | Modificat: `ScanJobCreateIn`, `AgentJobOut`, `ScanJobOut`, `ProgressIn` |
| `server/app/routes.py` | Modificat: `create_scan_job`, `agent_get_next_job`, endpoint nou `/progress` |
| `server/tests/test_scan_jobs.py` | Modificat: teste pentru `level` și progres |
| `server/tests/test_rules.py` | Modificat: teste pentru reguli noi |
| `web/src/pages/ScanDetail.tsx` | Redesign complet |
| `web/src/pages/Devices.tsx` | Modificat: modal nivel |
| `web/src/pages/Dashboard.tsx` | Modificat: progress view |
| `web/src/api/exposure.ts` | Modificat: `requestScan` trimite `level` |
| `web/src/api/types.ts` | Modificat: `ScanJobResponse.level`, `ScanJobResponse.progress` |
