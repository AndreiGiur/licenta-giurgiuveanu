# Design: Integrare nmap + NSE custom Lua în VulnWatch

**Data:** 2026-05-18
**Autor:** A. Giurgiuveanu (consultat cu profesor coordonator)
**Status:** Aprobat de user, gata pentru `writing-plans`

## 1. Motivație și obiective

VulnWatch colectează în prezent date pasive prin `psutil` (porturi în `LISTEN`, procese, software instalat). E rapid și sigur, dar:

- nu identifică **versiunea exactă a serviciilor** ascultătoare
- nu corelează versiunea cu **CVE-uri cunoscute**
- nu descoperă **host-uri adiționale din rețeaua locală**
- regula `NET-OPEN-PORTS-1` se uită doar la numărul portului, nu la ce rulează pe el

Integrarea nmap + un script NSE custom în Lua rezolvă toate cele patru limitări și aliniază proiectul la o practică reală de pen-testing.

### Scop concret

Profilul `deep` capătă o etapă nouă:
1. nmap rulează cu `-sV -O --top-ports 1000 --script vulnwatch-audit` pe `127.0.0.1`
2. Opțional, cu opt-in explicit din UI, nmap scanează și subnet-ul local (`192.168.x.0/24`)
3. Scriptul NSE custom `vulnwatch-audit.nse` (scris în Lua) agregă findings vuln, corelează servicii cu CVE-uri și mapează topologia
4. Output-ul nmap (XML) e parsat în Python, JSON-ul emis de Lua e extras și merge-uit în payload-ul scan-ului
5. Backend îl stochează pe `Scan.nmap_data`, frontend afișează rezultatele într-o secțiune nouă pe pagina ScanDetail

### Constrângeri non-negociabile (din alegerile user-ului)

- **LAN target:** auto-detect subnet, opt-in **explicit per scan** (checkbox în UI, confirm modal)
- **Distribuție nmap:** **bundle în executabil** (~110 MB total, de la 26 MB)
- **NSE Lua:** **3 sub-module într-un singur `.nse`** (agregator + CVE mapper + topology)
- **Privilegii:** **Windows Service ca LocalSystem** — UAC o singură dată la install
- **Integrare flow:** **nmap doar pe `deep`**, localhost obligatoriu, LAN opt-in
- **Top-1000 ports** default, toggle „all ports" în setări avansate
- **Mapping rules:** **pass-through** (Lua decide severitatea; un singur wrapper rule `NMAP-LUA-1` în `rules.py`)

### Out of scope (YAGNI)

- Multi-host distributed agent fleet
- Vulnerability auto-remediation
- CVE_DB online refresh (lista e statică în Lua script, update = rebuild)
- Live nmap progress streaming per host
- Linux/macOS support pentru Service mode (CLI daemon fallback rămâne pentru aceste platforme)
- Custom NSE update fără rebuild .exe
- Scan history per host LAN (fiecare scan deep e snapshot complet)

## 2. Arhitectura proceselor

```
┌─────────────────────────────────────────────────────────┐
│  User Session                  │   LocalSystem (admin)  │
│                                │                        │
│  VulnWatchAgent.exe            │   VulnWatchAgent.exe   │
│  (Tkinter GUI)                 │   --service flag       │
│  ─────────────                 │   ───────────────────  │
│  • Login/enroll                │   • Heartbeat 10s      │
│  • Status page                 │   • Poll scan jobs     │
│  • Theme, settings ⚙           │   • Run psutil scan    │
│  • IPC client                  │   • Run nmap (deep)    │
│                                │   • IPC server         │
│                                │                        │
│             ↕ Named Pipe ↕                              │
│       \\.\pipe\vulnwatch-status                         │
└─────────────────────────────────────────────────────────┘
```

### Single executable, două moduri de pornire

Un singur `VulnWatchAgent.exe` cu două roluri:
- `VulnWatchAgent.exe` (fără args) → GUI în user session (cum e acum)
- `VulnWatchAgent.exe --service` → daemon LocalSystem (registrat în Service Control Manager)

Decizia se face în `scan.py` pe baza `sys.argv`. Codul daemon-ului din `core.py` rămâne neschimbat semantic; doar punctul de invocare diferă.

### Install / uninstall flow

**Install** (prima rulare după login):
1. User dă dublu-click pe `.exe` în user session
2. La login reușit, GUI verifică dacă serviciul `VulnWatchSvc` e instalat (via `win32serviceutil.QueryServiceStatus`)
3. Dacă nu → modal: „Pentru scan-uri complete (deep cu network audit) e nevoie de instalare ca serviciu Windows. Da/Nu"
4. Da → relaunch executabil cu `--install-service` printr-un proces UAC-elevated (`ShellExecute` cu `runas`)
5. Sub UAC: `win32serviceutil.InstallService(VulnWatchSvc, sys.executable, "--service", startType=SERVICE_AUTO_START)`; apoi `StartService()`
6. Procesul UAC iese; GUI revine în user session și se conectează la serviciu via IPC

**Uninstall** (din meniul ⚙ → „Deconectează acest PC"):
1. GUI cere UAC pentru `--uninstall-service`
2. Serviciu oprit + șters din SCM
3. Config local șters, metrici reset
4. Revine la Login page

### IPC: Named Pipe

Service expune named pipe `\\.\pipe\vulnwatch-status` cu DACL care permite numai user-ului curent (cel autenticat) să se conecteze. Protocol simplu, line-delimited JSON:

| Direcție | Mesaj | Răspuns |
|---|---|---|
| GUI → Service | `{"cmd":"status"}` | `{"running":true, "paused":false, "last_heartbeat":1684512345, "current_job_id":null}` |
| GUI → Service | `{"cmd":"pause"}` | `{"ok":true}` |
| GUI → Service | `{"cmd":"resume"}` | `{"ok":true}` |
| GUI → Service | `{"cmd":"logout"}` | `{"ok":true}` — serviciul șterge config local, oprește scan-uri |
| GUI ← Service | (push) `{"event":"scan_done", "score":42, ...}` | (no reply) |
| GUI ← Service | (push) `{"event":"token_invalid"}` | (no reply) — declanșează relogin în GUI |

Pipe-ul deschis în mod **bidirectional message-mode**. GUI face retry cu backoff dacă pipe-ul e ocupat sau lipsește.

### Fallback dacă user refuză install

Modal: „Pentru scan-uri complete e nevoie de install ca serviciu. Ai refuzat. Continui în mod limitat (doar standard/advanced)?"
- User confirm → agent rulează în-process în GUI ca acum (single-process), deep e disabled în UI
- User refuză → revine la pagina Login

## 3. Bundling nmap + flow scan deep

### Distribuția nmap

**nmap portable Windows** (~80 MB unpacked):
- `nmap.exe`, `*.dll` (OpenSSL, pcap)
- `scripts/` cu ~600 scripts NSE built-in + scriptul nostru `vulnwatch-audit.nse`
- `nselib/` (biblioteci Lua)

**Modificări build:**
- `agent/VulnWatchAgent.spec`: adaug în `datas` întreaga arborescență `nmap-portable/`
- `agent/build.ps1`: pre-build hook care:
  1. Verifică `agent/.build-cache/nmap/nmap.exe` — dacă lipsește, descarcă **nmap-portable** de la nmap.org (versiune pinned, ex: `7.94`)
  2. Despachetează în cache
  3. Copiază `vulnwatch-audit.nse` din `agent/nse/` în `cache/nmap/scripts/`
  4. Rulează `nmap --script-updatedb` pentru a regenera script index
  5. PyInstaller include întreg directorul

**Mărime finală .exe:** ~110 MB (de la 26 MB). Acceptabil pentru distribuție internă/thesis.

**Licență:** nmap e sub NPSL (Nmap Public Source License) — GPL-derived cu restricții pe redistribuție comercială. Pentru lucrare de licență (educational, non-commercial) e ok. Menționăm în README + about dialog: „Include nmap, licensed under Nmap Public Source License — see https://nmap.org/npsl/".

**Resolution path la runtime:**
```python
# agent/core.py
def _nmap_path() -> Path:
    if getattr(sys, "frozen", False):  # rulează din PyInstaller bundle
        return Path(sys._MEIPASS) / "nmap" / "nmap.exe"
    # dev mode: caută în PATH
    found = shutil.which("nmap")
    if not found:
        raise RuntimeError("nmap not in PATH (dev mode requires nmap installed)")
    return Path(found)
```

### Data flow pentru scan deep cu nmap

```
UI (web)                                    SERVICE (LocalSystem)
   │                                                 │
   ▼                                                 │
1. User selectează Deep + bifează                    │
   "Include LAN: 192.168.1.0/24"                     │
   │                                                 │
   ▼                                                 │
2. POST /devices/{uid}/scan-jobs                     │
   {scan_type:"deep", nmap_target:"192.168.1.0/24"}  │
   │                                                 │
   ▼                                                 │
3. Backend creează ScanJob(pending)                  │
   cu coloana nouă scan_jobs.nmap_target             │
   │                                                 │
   │            api_get_next_job                     │
   └──────────────────────────────────────────────►  │
                                                     ▼
                                       4. Service ridică job
                                          │
                                          ▼
                                       5. Run psutil collectors
                                          (network, processes, ...)
                                          [obișnuit, ~5-10 min]
                                          │
                                          ▼
                                       6. Run nmap subprocess:
                                          nmap.exe -sV -O
                                            --top-ports 1000
                                            --script vulnwatch-audit
                                            -oX result.xml
                                            127.0.0.1 192.168.1.0/24
                                          [10-20 min]
                                          │
                                          ▼
                                       7. Parse result.xml (ElementTree)
                                          Extract per-host:
                                            - state, OS, ports
                                            - script id="vulnwatch-audit"
                                              output (JSON Lua-emitted)
                                          │
                                          ▼
                                       8. Merge cu psutil data:
                                          payload = {network:..., nmap:...}
                                          │
                                          ▼
                                       9. POST /agent/jobs/{id}/result
   ◄───────────────────────────────────────────────
   │
   ▼
10. Backend: rules.evaluate(scan)
    Include NMAP-LUA-1 wrapper rule
    care extrage vulnwatch_findings din nmap data
    │
    ▼
11. Scan stored. UI poll status → DONE
    Frontend afișează ScanDetail
    cu secțiune nouă „Network scan (nmap)"
```

### Schema datelor nmap în payload

```python
"nmap": {
    "version": "7.94",
    "scan_time_sec": 127.4,
    "targets": ["127.0.0.1", "192.168.1.0/24"],
    "lan_opt_in": True,
    "lua_errors": [],          # listă mesaje script-err dacă au fost
    "hosts": [
        {
            "ip": "127.0.0.1",
            "hostname": "DESKTOP-ABC",
            "state": "up",
            "os_guess": "Microsoft Windows 11 (95% confidence)",
            "ports": [
                {
                    "port": 445, "proto": "tcp", "state": "open",
                    "service": "microsoft-ds", "version": "Windows SMB",
                    "cpe": "cpe:/o:microsoft:windows"
                }
            ],
            "vulnwatch_findings": [
                {
                    "rule_id": "NMAP-CVE-2017-0144",
                    "severity": "critical",
                    "title": "EternalBlue (MS17-010) SMB RCE",
                    "evidence": {"port": 445, "cve": "CVE-2017-0144",
                                 "source": "vulnwatch-audit/aggregator"}
                }
            ],
            "topology": {
                "role": "workstation",   # gateway | dns | fileserver | workstation
                "risk_score": 65,
                "reasons": ["smb_open", "outdated_os"]
            }
        },
        # ...alte host-uri din LAN dacă opt-in
    ]
}
```

### LAN opt-in UI flow

În `web/src/pages/Devices.tsx`, când scan type = „Deep":
- Apare expander **„🔍 Setări avansate scan deep"**
- Afișează `detected_subnet` (Service raportează în heartbeat; backend îl salvează pe `Device.local_subnet`; UI îl preia via `GET /devices/{uid}/scan-jobs/preview`)
- Checkbox „Include scan LAN: 192.168.1.0/24 (estimat ~25 host-uri)"
- Toggle adițional „Scan toate porturile (1-65535) — lent, ~30+ min/host"
- Confirm modal **dacă bifat**: „Vei scana 254 IP-uri din rețeaua ta locală. Asigură-te că ai autorizare să faci asta. Continui?"
- POST scan-job include `nmap_target: "192.168.1.0/24"` sau `null`

## 4. Scriptul NSE custom `vulnwatch-audit.nse`

Diferențiatorul principal pentru lucrare. **3 sub-module Lua într-un singur fișier `.nse`**, total estimat ~400-500 linii.

### Structura

```lua
description = [[Custom audit script — aggregates vuln findings,
correlates services with known CVEs, maps topology.
Emits structured JSON per host for VulnWatch backend.]]
author = "VulnWatch — A. Giurgiuveanu"
license = "Same as Nmap (NPSL)"
categories = {"safe", "discovery", "vuln"}

local stdnse  = require "stdnse"
local nmap    = require "nmap"
local json    = require "json"
local shortport = require "shortport"

-- ============ SUB-MODUL 1: AGREGATOR ============
local module_aggregator = {}
function module_aggregator.collect(host, port)
  -- Cheamă programatic alte NSE scripts din "vuln" category
  -- (ex: smb-vuln-ms17-010, http-vuln-cve*, ssl-poodle)
  -- Capturează output, normalizează la schema VulnWatch
  return findings
end

-- ============ SUB-MODUL 2: CVE MAPPER ============
-- DB embedded ~30-50 entries pentru servicii frecvent vulnerabile
local CVE_DB = {
  ["microsoft-ds"]       = {...},  -- SMB (CVE-2017-0144 EternalBlue, ...)
  ["http"]               = {...},  -- Apache, nginx version patterns
  ["ssh"]                = {...},  -- OpenSSH (CVE-2018-15473, ...)
  ["ftp"]                = {...},  -- vsftpd, ProFTPD CVEs
  ["telnet"]             = {...},  -- generic
  ["ms-wbt-server"]      = {...},  -- RDP (BlueKeep CVE-2019-0708)
  ["ssl/tls"]            = {...},  -- POODLE, Heartbleed patterns
  ["mysql"]              = {...},  -- MySQL CVE-uri pe versiuni
  ["postgresql"]         = {...},
  ["redis"]              = {...},
  ["mongodb"]            = {...},
  -- listă completă populată în implementare
}

local module_cve_mapper = {}
function module_cve_mapper.correlate(host, port)
  -- Pattern matching service+version în CVE_DB
  -- Returnează list of findings cu severity=high
  return hits
end

-- ============ SUB-MODUL 3: TOPOLOGY MAPPER ============
local module_topology = {}
function module_topology.discover(host)
  -- Detectează rolul host-ului:
  --   • gateway: dacă IP-ul = default gateway al scannerului
  --   • dns: dacă port 53 open + responds la dns-recursion test
  --   • fileserver: dacă port 445 open + accepts null session
  --   • workstation: default
  -- Calculează risk_score 0-100 din:
  --   • #ports open (max 30 puncte)
  --   • OS confidence + outdated (max 30 puncte)
  --   • vuln findings critical/high (max 40 puncte)
  return {role=..., risk_score=..., reasons={...}}
end

-- ============ ENTRY POINT ============
hostrule = function(host) return host.state == "up" end

action = function(host)
  local output = {host_ip=host.ip, findings={}, topology={}}
  for _, port in ipairs(host.ports or {}) do
    if port.state == "open" then
      for _, f in ipairs(module_aggregator.collect(host, port)) do
        table.insert(output.findings, f)
      end
      for _, f in ipairs(module_cve_mapper.correlate(host, port)) do
        table.insert(output.findings, f)
      end
    end
  end
  output.topology = module_topology.discover(host)
  return json.generate(output)
end
```

### Conținutul CVE_DB (generat în implementare)

Lista include ~30-50 entries pentru:
- **SMB** (microsoft-ds): MS17-010 EternalBlue, MS08-067, MS06-040
- **HTTP** servere: Apache 2.4.49 (CVE-2021-41773), nginx 1.10-1.17 DNS bugs, IIS RCEs
- **OpenSSH**: CVE-2018-15473 (username enum), CVE-2016-0777
- **FTP**: vsftpd 2.3.4 backdoor (CVE-2011-2523), ProFTPD CVE-2015-3306
- **RDP** (ms-wbt-server): BlueKeep CVE-2019-0708, CVE-2020-0609
- **SSL/TLS**: Heartbleed (OpenSSL 1.0.1a-f), POODLE, FREAK, DROWN
- **DB-uri**: MySQL pre-8.0.x, PostgreSQL CVE-2018-1058, Redis unauth, MongoDB unauth
- **Mail**: Sendmail OOB, Postfix CVE-2008-2937
- **Java RMI**: JNDI injection patterns
- **Misc**: Telnet (always flagged), VNC unauth

Lista finalizată în task-ul de scriere a `vulnwatch-audit.nse`.

### Cum se invocă

```python
# Service-side
subprocess.run([
    str(_nmap_path()),
    "-sV", "-O",
    "--top-ports", "1000",       # sau "-p-" dacă user a bifat "all ports"
    "--script", "vulnwatch-audit",
    "--script-args", "vulnwatch.timeout=300",
    "-oX", str(xml_out),
    *targets,                    # ["127.0.0.1"] sau ["127.0.0.1", "192.168.1.0/24"]
], timeout=1800, check=False)
```

### Integrare cu rules engine

**Pass-through** confirmat:

```python
# server/app/rules.py
@rule("NMAP-LUA-1", min_level="deep")
def collect_nmap_lua_findings(scan: dict) -> list[dict] | None:
    """Wrapper care extrage findings emise de scriptul NSE custom.
    Lua a decis deja severitatea — Python doar le mută în lista finală
    cu prefix source='nmap-lua'."""
    nmap = scan.get("nmap")
    if not nmap or not nmap.get("hosts"):
        return None
    findings = []
    for host in nmap["hosts"]:
        for f in host.get("vulnwatch_findings", []):
            findings.append({
                **f,
                "evidence": {**f.get("evidence", {}), "host_ip": host["ip"]},
                "source": "nmap-lua",
            })
    return findings or None
```

`rule_engine.evaluate()` **suportă deja** rule-uri care returnează `list[dict]` (vezi `findings.extend(result)` în `rules.py:60`). Zero modificări în iterator.

## 5. Error handling

| Scenariu | Comportament |
|---|---|
| nmap.exe lipsește din bundle | Service log error; deep degradează la psutil-only; payload conține `nmap.error = "nmap_missing"`; UI afișează badge „⚠ nmap indisponibil — scan parțial" |
| nmap timeout (>30 min global) | Subprocess killed; parsare parțială XML; finding sintetic `NMAP-TIMEOUT-1` severity `low` adăugat |
| LAN target unreachable (subnet gol) | Lua returnează `findings: [], topology: {}`; nu e eroare; UI afișează „0 host-uri găsite în 192.168.1.0/24" |
| Lua script crash (sintaxă, runtime) | Nmap loghează `--script-err`; service capturează stderr → atașează la `nmap.lua_errors`; restul scan-ului continuă |
| XML parse error | Fallback la raw stdout + warn; nu blochează submit job |
| Service oprit (manual/crash) | GUI detectează absența pipe-ului → dot status „offline"; user poate „Re-install" din meniul ⚙ |
| IPC pipe broken | GUI retry 3x cu backoff; după eșec persistent → status „degraded"; scan jobs continuă (Service e independent) |
| UAC refuzat la install | Modal „Continui în mod limitat (doar standard/advanced)?"; Deep disabled în UI |
| nmap rulează fără admin (single-process fallback) | Folosește `-sT` (TCP connect) + NSE compatibile; pierde `-O`; UI badge „limited mode" |

## 6. Testing strategy

| Layer | Ce testează | Cum |
|---|---|---|
| `agent/tests/test_nmap_parser.py` (NOU) | Parsing XML nmap, extragerea Lua JSON | Fixtures XML în `agent/tests/fixtures/nmap_*.xml` (localhost OK, multi-host LAN, timeout, parse error) |
| `agent/tests/test_nmap_runner.py` (NOU) | CLI args construction, CIDR validation, timeout enforcement | Mock `subprocess.run` |
| `agent/tests/test_service_install.py` (NOU) | Logica `--install-service` / `--uninstall-service` | Mock `win32serviceutil`, verifică call-uri către SCM |
| `agent/tests/test_ipc.py` (NOU) | Named pipe protocol (PAUSE, RESUME, status JSON) | Localhost TCP socket simulează pipe pentru CI cross-platform |
| Lua tests (cu Busted) | Sub-modulele Lua au logică pură testabilă | `tests/vulnwatch-audit_spec.lua` testează `module_cve_mapper.correlate()` cu input static; rulează doar dacă Lua e instalat (skip cu warn altfel) |
| `server/tests/test_nmap_findings.py` (NOU) | Wrapper rule `NMAP-LUA-1` merge findings | Payload sintetic cu `nmap.hosts[].vulnwatch_findings` |
| Smoke E2E (manual) | Build → install service → trigger deep din UI → confirm findings | Checklist 8 pași în plan |

## 7. Modificări backend

### `server/app/models.py`
- `Scan.nmap_data` JSON column (nullable; populated doar pentru deep scans cu nmap)
- `ScanJob.nmap_target` String column (CIDR sau null)
- `Device.local_subnet` String column (raportat în heartbeat)

### `server/app/schemas.py`
- `ScanIn` schema extinsă cu optional `nmap: dict | None`
- `ScanJobCreate` schema extinsă cu optional `nmap_target: str | None`
- `HeartbeatIn` extinsă cu optional `local_subnet: str | None`

### `server/app/rules.py`
- `@rule("NMAP-LUA-1", min_level="deep")` wrapper pass-through (vezi secțiunea 4)
- Iteratorul `evaluate()` deja suportă rule-uri care returnează `list[dict]` (`rules.py:60`); zero schimbări la engine

### `server/app/routes.py`
- `POST /devices/{uid}/scan-jobs` extins cu validare `nmap_target` (folosește `ipaddress.ip_network()`)
- `GET /devices/{uid}/scan-jobs/preview` (endpoint NOU): returnează `{detected_subnet, estimated_hosts, estimated_duration_sec}` pentru UI
- `/agent/heartbeat` salvează `local_subnet` pe Device

## 8. Modificări frontend

- `web/src/pages/Devices.tsx`: când scan_type = "deep", apare expander cu checkbox LAN + confirm modal (cu fetch preview pentru estimări)
- `web/src/api/types.ts`: extend `ScanResult` cu opțional `nmap: NmapData`
- `web/src/pages/ScanDetail.tsx`: secțiune nouă „Network scan (nmap)" cu listă host-uri, findings, topologie
- `web/src/components/NmapHostCard.tsx` (NOU): card per host (state, OS, ports, CVE findings, risk_score)

## 9. Estimări scope și execuție

| Componenta | LOC nou |
|---|---|
| Agent refactor → Service mode + IPC | ~600 |
| Bundling nmap + integration glue | ~300 |
| NSE Lua custom (3 sub-module) | ~400-500 |
| Backend changes | ~150 |
| Frontend changes | ~250 |
| Tests (Python + Lua) | ~400 |
| **Total** | **~2200-2500 LOC** |

**Execuție recomandată:** `superpowers:writing-plans` produce un plan cu ~10-12 task-uri, executat sub `superpowers:subagent-driven-development` în **2-3 sesiuni**.

## 10. Faze opționale de decompoziție

Dacă scope-ul e prea mare pentru un singur sprint, se poate sparge în:
- **Faza A**: Service install + IPC + bundling nmap + scan localhost (fără LAN, fără NSE custom). Folosește `--script vuln` built-in. Demonstrabil la apărare ca prim milestone.
- **Faza B**: NSE custom `vulnwatch-audit.nse` cu 3 sub-module + integrare în payload + secțiune frontend
- **Faza C**: LAN scanning + subnet detection + UI confirm flow

User-ul poate cere phasing dacă vrea să livreze incremental. Default: toate într-un singur plan.
