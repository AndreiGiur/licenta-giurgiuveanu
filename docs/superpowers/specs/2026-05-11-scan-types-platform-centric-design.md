# VulnWatch — Scan Types + Arhitectură Platform-Centrică

**Data:** 2026-05-11
**Autor:** Giurgiuveanu Andrei (lucrare de licență)
**Titlu lucrare:** Platformă web pentru detectarea vulnerabilităților pe dispozitivele personale

---

## 1. Context și obiective

VulnWatch este o platformă self-hosted de monitoring securitate. În iterația curentă, scanarea colectează un set fix de date și aplică 7 reguli. Această specificație extinde platforma în trei direcții:

1. **3 niveluri de scanare** (Standard / Advanced / Deep) cu arhitectură Strategy Pattern
2. **Arhitectură platform-centrică** — platforma web conduce tot, agentul este executor transparent
3. **Vizibilitate în timp real** — status agent per dispozitiv, progres scanare pentru sesiuni lungi

Agentul .exe păstrează interfața grafică pentru **login și enrollment** (utilizatorul trebuie să autentifice dispozitivul o singură dată). După enrollment, agentul rulează în fundal și execută comenzile primite de la platformă.

---

## 2. Arhitectura soluției

### 2.1 Principii de design

| Principiu | Aplicare |
|-----------|----------|
| **Strategy Pattern** | `SCAN_PROFILES` dict — o singură sursă de adevăr pentru ce colectează fiecare nivel |
| **Single Responsibility** | 6 colectori independenți, fiecare cu un singur scop |
| **Open/Closed Principle** | Nivel nou = intrare în dict; regulă nouă = decorator `@rule` — codul existent nu se modifică |
| **Platform-centric** | Web UI conduce: alege tipul, lansează, vede progresul; agentul execută și raportează |

### 2.2 Fluxul complet

```
[Agent .exe]                        [Backend FastAPI]              [Web UI]
     │                                      │                          │
     │── POST /agent/heartbeat (10s) ──────►│                          │
     │   {version, capabilities, os}        │── DeviceOut.is_online ──►│ badge ● Online
     │                                      │                          │
     │                                      │◄── POST /devices/{uid}/scan-jobs ──────│
     │                                      │    {scan_type: "deep"}   │ (Scan now)
     │◄── GET /agent/jobs/next ─────────────│                          │
     │    {job_id, scan_type: "deep"}       │                          │
     │                                      │                          │
     │── POST /agent/jobs/{id}/progress ───►│                          │
     │   {progress: 15, phase: "Rețea..."}  │◄── GET /scan-jobs/{id} ──│ progress bar
     │── POST /agent/jobs/{id}/progress ───►│   {progress: 45, ...}    │
     │   {progress: 45, phase: "Forensics"}  │                          │
     │                                      │                          │
     │── POST /agent/jobs/{id}/result ─────►│── evaluate(scan, type) ──│
     │   {payload complet}                  │── ScanJob(done) + Scan   │ rezultate
```

---

## 3. Niveluri de scanare

### 3.1 Definiție niveluri

| Nivel | Timp estimat | Scop recomandat |
|-------|-------------|-----------------|
| **standard** | est. 45–90 s | Verificare zilnică automată |
| **advanced** | est. 3–8 min | Scanare săptămânală completă |
| **deep** | est. 10–20 min | Audit lunar sau investigație incident |

### 3.2 Date colectate per nivel

| Câmp colectat | standard | advanced | deep |
|---------------|:--------:|:--------:|:----:|
| Porturi LISTEN (0–65535) | ✓ | ✓ | ✓ |
| OS: versiune, arhitectură, hostname, uptime, is_admin | ✓ | ✓ | ✓ |
| Procese — top 30 după RAM (nume, PID, RAM%, CPU%) | ✓ | ✓ | ✓ |
| Software instalat — registry (nume + versiune) | ✓ | ✓ | ✓ |
| Conturi locale + drepturi administrator | ✓ | ✓ | ✓ |
| Status Windows Firewall per profil | ✓ | ✓ | ✓ |
| Procese — toate (fără limită) + cmdline + PID parent | — | ✓ | ✓ |
| Port → proces proprietar (binding) | — | ✓ | ✓ |
| Conexiuni ESTABLISHED (IP, port, proces) | — | ✓ | ✓ |
| Servicii Windows — toate + status + tip pornire | — | ✓ | ✓ |
| Startup items — HKCU/HKLM Run + folder Startup | — | ✓ | ✓ |
| Task-uri programate — Task Scheduler | — | ✓ | ✓ |
| Adaptoare rețea — IP, MAC, gateway | — | ✓ | ✓ |
| Foldere partajate în rețea | — | ✓ | ✓ |
| PowerShell Execution Policy | — | ✓ | ✓ |
| Persistențe registry (AppInit_DLLs, IFEO, Winlogon) | — | — | ✓ |
| WMI event subscriptions | — | — | ✓ |
| Certificate root instalate | — | — | ✓ |
| Windows Defender — status + data actualizare semnături | — | — | ✓ |
| Event Log Security (ultimele 500: 4625, 4672, 4720) | — | — | ✓ |
| Conținut hosts file | — | — | ✓ |
| DNS cache local + tabel ARP | — | — | ✓ |
| Status BitLocker per volum | — | — | ✓ |
| Fișiere modificate recent în System32/Program Files (7 zile) | — | — | ✓ |

---

## 4. Reguli de securitate

### 4.1 Reguli existente (7) — rămân neschimbate

| ID | Severitate | Nivel minim |
|----|-----------|------------|
| NET-OPEN-PORTS-1 | high | standard |
| NET-MANY-PORTS-2 | medium | standard |
| OS-ADMIN-1 | medium | standard |
| PROC-SUSPICIOUS-1 | high | standard |
| PROC-POWERSHELL-2 | low | standard |
| SW-VULNERABLE-1 | varies | standard |
| OS-EOL-1 | varies | standard |

### 4.2 Reguli noi (16)

**Nivel standard (2 reguli noi):**

| ID | Severitate | Condiție |
|----|-----------|---------|
| FW-DISABLED-1 | high | Windows Firewall inactiv pe profilul Domain sau Public |
| USER-ADMIN-1 | medium | Conturi locale în grupul Administrators altele decât Administrator și contul curent |

**Nivel advanced (6 reguli noi):**

| ID | Severitate | Condiție |
|----|-----------|---------|
| STARTUP-SUSPICIOUS-1 | high | Cheie Run conține executabil din %TEMP%, %APPDATA% sau path nestandard |
| TASK-SUSPICIOUS-1 | high | Task Scheduler cu acțiune PowerShell -enc / -EncodedCommand |
| SVC-SUSPICIOUS-1 | medium | Serviciu Windows cu executabil din path nestandard (nu System32/Program Files) |
| NET-SHARE-1 | medium | Foldere partajate în rețea (exclus ADMIN$, IPC$, C$ implicite) |
| PS-POLICY-1 | medium | PowerShell Execution Policy = Bypass sau Unrestricted |
| NET-ESTABLISHED-1 | low | Conexiuni ESTABLISHED pe porturi nestandard spre IP-uri externe |

**Nivel deep (8 reguli noi):**

| ID | Severitate | Condiție |
|----|-----------|---------|
| REG-HIJACK-1 | critical | AppInit_DLLs, IFEO sau AppCert DLLs conțin valori nestandard |
| WMI-PERSIST-1 | critical | Subscripții WMI active în root\subscription |
| CERT-UNTRUSTED-1 | high | Certificate root instalate care nu aparțin Microsoft sau CA-uri cunoscute |
| AV-DISABLED-1 | high | Windows Defender dezactivat sau semnături > 7 zile vechime |
| EVENTLOG-BRUTEFORCE-1 | high | ≥ 10 evenimente 4625 (logon failure) în ultimele 24h |
| EVENTLOG-PRIVESC-1 | high | Evenimente 4672 (special privileges) pentru conturi non-Administrator |
| HOSTS-TAMPERED-1 | medium | Hosts file conține înregistrări altele decât localhost / ::1 |
| BITLOCKER-OFF-1 | medium | Volumul de sistem (C:) nu este protejat cu BitLocker |

**Total: 23 reguli** (7 existente + 16 noi)

### 4.3 Mecanismul `@rule` decorator

```python
LEVEL_ORDER = {"standard": 0, "advanced": 1, "deep": 2}
_RULES: list[RuleFn] = []

def rule(id: str, min_level: str = "standard"):
    def decorator(fn):
        fn._rule_id = id
        fn._min_level = min_level
        _RULES.append(fn)
        return fn
    return decorator

def evaluate(scan_dict: dict) -> tuple[int, list[dict]]:
    scan_type = scan_dict.get("scan_type", "standard")
    applicable = [r for r in _RULES
                  if LEVEL_ORDER[r._min_level] <= LEVEL_ORDER[scan_type]]
    # rulează applicable, calculează scor
```

---

## 5. Componentele noi / modificate

### 5.1 Agent (`agent/`)

**`agent/collectors/` (modul nou)**
- `__init__.py`
- `network.py` — `collect_network(cfg: ScanProfile) -> dict`
- `processes.py` — `collect_processes(cfg: ScanProfile) -> list`
- `software.py` — `collect_software(cfg: ScanProfile) -> list`
- `system_info.py` — `collect_system(cfg: ScanProfile) -> dict` (OS, firewall, useri, BitLocker)
- `persistence.py` — `collect_persistence(cfg: ScanProfile) -> dict` (startup, tasks, servicii, WMI)
- `forensics.py` — `collect_forensics(cfg: ScanProfile) -> dict` (event log, hosts, DNS/ARP, certs, fișiere modificate recent în System32/Program Files)

**`agent/core.py` (modificări)**
- `ScanProfile` dataclass + `SCAN_PROFILES` dict
- `collect_system_data(device_uid, scan_type="standard")` — orchestrator, apelează colectorii
- `api_heartbeat(api_base, device_token, payload)` — `POST /agent/heartbeat`
- `api_send_progress(api_base, device_token, job_id, progress, phase)` — `POST /agent/jobs/{id}/progress`
- `daemon_loop` — adaugă heartbeat la fiecare 10s; `run_one_job` trimite progress updates între colectori

**`agent/gui.py` (modificări minore)**
- Pagina **Status** (după enrollment) afișează: email cont, nume device, badge nivel maxim suportat, link „Deschide platforma" → browser. Nu mai are buton „Scan now" propriu (scanarea se lansează din platformă).
- Păstrează: Login, Enroll, Logout, indicator daemon activ/pauză, log live.
- Daemonul continuă să ruleze prin mecanismul existent (`autostart.py` → Task Scheduler / HKCU Run). Nu se migrează la Windows Service.

### 5.2 Backend (`server/app/`)

**`models.py`**
- `Device`: adaugă `last_heartbeat: DateTime | None`, `agent_version: str | None`, `capabilities: JSON | None`
- `is_online` **nu este coloană** — se calculează la query: `last_heartbeat > now() - 30s`. Expus ca proprietate Python pe modelul `Device` și inclus în `DeviceOut`.
- `ScanJob`: adaugă `scan_type: str` (default `"standard"`), `progress: int` (0–100, default 0), `phase: str | None`

**`schemas.py`**
- `HeartbeatIn`: `agent_version: str`, `capabilities: list[str]`, `os_version: str`
- `DeviceOut`: adaugă `is_online: bool`, `last_heartbeat: datetime | None`, `agent_version: str | None`, `capabilities: list[str]`
- `ScanJobCreateIn` (nou): `scan_type: Literal["standard", "advanced", "deep"] = "standard"`
- `ScanJobOut`: adaugă `progress: int`, `phase: str | None`
- `AgentJobOut`: adaugă `scan_type: str`
- `JobProgressIn` (nou): `progress: int` (0–100), `phase: str`

**`routes.py`**
- `POST /agent/heartbeat` — actualizează `Device.last_heartbeat`, `agent_version`, `capabilities`
- `POST /agent/jobs/{id}/progress` — actualizează `ScanJob.progress` și `ScanJob.phase`
- `POST /devices/{uid}/scan-jobs` — acceptă `ScanJobCreateIn` cu `scan_type`
- `GET /agent/jobs/next` — returnează `scan_type` în `AgentJobOut`
- `GET /devices` și `GET /devices/by-uid/{uid}` — includ `is_online` (last_heartbeat < 30s)

**`rules.py`**
- Decorator `@rule(id, min_level)`
- `LEVEL_ORDER` dict pentru comparare nivele
- `evaluate()` filtrează regulile după `scan_type` din payload
- 16 funcții noi de regulă

### 5.3 Frontend (`web/src/`)

**`api/types.ts`**
- `Device`: adaugă `is_online`, `last_heartbeat`, `agent_version`, `capabilities`
- `ScanJobResponse`: adaugă `progress`, `phase`, `scan_type`

**`api/exposure.ts`**
- `requestScan(deviceUid, scanType)` — trimite `scan_type` la `POST /devices/{uid}/scan-jobs`

**`pages/Devices.tsx`**
- Badge `● Online` / `○ Offline` per device (pe baza `is_online`)
- Selector tip scanare (Standard / Advanced / Deep) cu timp estimat afișat sub selector
- Buton „Scan now" dezactivat dacă `is_online === false`
- Tooltip pe buton când offline: „Agentul nu este conectat"

**`pages/Dashboard.tsx`**
- Badge status agent lângă numele device-ului
- Progress bar cu faza curentă pentru scanări Advanced/Deep în curs
- Badge `scan_type` pe ultimele scanări din listă

**`pages/ScanDetail.tsx`** (redesign complet)
- Top bar: device name, scan_type badge, durată, buton scanare nouă
- Layout în două coloane:
  - Stânga (220px): score gauge + breakdown numeric + sidebar categorii cu icoane și badge-uri
  - Dreapta: finding cards pentru categoria selectată
    - Carduri critice expandate implicit (evidențe + recomandare cu comandă)
    - Carduri medium/low compacte cu `▼ detalii`
- Categorii: Persistențe 🔒 / Rețea 🌐 / Sistem & OS 🖥️ / Software 📦 / Procese & Servicii ⚙️ / Event Log 📋

---

## 6. Modificări bază de date

```sql
-- Device
ALTER TABLE devices ADD COLUMN last_heartbeat TIMESTAMP;
ALTER TABLE devices ADD COLUMN agent_version VARCHAR(32);
ALTER TABLE devices ADD COLUMN capabilities JSON;

-- ScanJob
ALTER TABLE scan_jobs ADD COLUMN scan_type VARCHAR(16) NOT NULL DEFAULT 'standard';
ALTER TABLE scan_jobs ADD COLUMN progress INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_jobs ADD COLUMN phase VARCHAR(128);
```

*Tabelele sunt create via `Base.metadata.create_all()` — în development, drop & recreate. Fără Alembic.*

---

## 7. Teste noi

| Fișier | Ce acoperă |
|--------|-----------|
| `server/tests/test_scan_types.py` | scan_type propagat în job→agent→result; evaluate() filtrează corect regulile per nivel |
| `server/tests/test_heartbeat.py` | heartbeat actualizează device; is_online corect la < 30s / > 30s |
| `server/tests/test_progress.py` | progress update acceptat; polling returnează progress curent |
| `server/tests/test_new_rules.py` | cele 16 reguli noi — câte 1-2 teste per regulă |
| `agent/tests/test_collectors.py` | fiecare colector returnează structura corectă; SCAN_PROFILES sunt valide |

---

## 8. Ce NU este în scope

- Notificări email / push (feature separat)
- Scanare periodică automată (scheduler) — va fi adăugat ulterior
- Suport Linux/macOS pentru colectorii Deep (Event Log, BitLocker, registry sunt Windows-only)
- Exportul raportului PDF

---

## 9. Ordine de implementare recomandată

1. **Backend** — modele + migrare + endpoint heartbeat + endpoint progress + scan_type în job
2. **Rules engine** — decorator `@rule`, `evaluate()` actualizat, cele 16 reguli noi
3. **Agent colectori** — modulul `collectors/`, `SCAN_PROFILES`, `collect_system_data()` actualizat
4. **Agent daemon** — heartbeat în loop + progress updates în `run_one_job()`
5. **Agent GUI** — simplificare pagină Status (remove Scan now, add platform link)
6. **Frontend** — `ScanDetail.tsx` redesign, `Devices.tsx` (badge online + scan type selector), `Dashboard.tsx` (progress bar)
7. **Teste** — toate fișierele noi de test
