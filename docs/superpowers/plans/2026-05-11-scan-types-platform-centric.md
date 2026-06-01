# VulnWatch — Scan Types + Platform-Centric Architecture — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adăugare 3 tipuri de scanare (Standard / Advanced / Deep) cu Strategy Pattern, arhitectură platform-centrică (agentul devine executor), heartbeat agent, progres real-time, 16 reguli noi de securitate și redesign ScanDetail cu sidebar de categorii.

**Architecture:** `SCAN_PROFILES` dict — sursă unică de adevăr pentru ce colectează fiecare nivel; 6 colectori composabili (`network`, `processes`, `software`, `system`, `persistence`, `forensics`); decorator `@rule(id, min_level)` cu auto-filtrare după `scan_type`; agent trimite heartbeat la 10s și progress updates între colectori; platforma web inițiază scanarea și alege tipul.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy, psutil, winreg/subprocess pe Windows, React 18 + TypeScript + Vite.

**Spec:** `docs/superpowers/specs/2026-05-11-scan-types-platform-centric-design.md`

**Git identity:** `user.email = giurgiuveanuandrei21@gmail.com`, `user.name = AndreiGiur`. **Nu se adaugă `Co-Authored-By: Claude` în commits.**

---

## Convenții comune

- Toate comenzile pytest se rulează din `server/` cu venv-ul activ.
- Toate comenzile git presupun working directory `E:\Lucrare-de-Licenta-Giurgiuveanu-Andrei`.
- Tabelele se recreează prin `Base.metadata.create_all()` (fără Alembic). În dev, restart serverul ⇒ tabelele noi se creează automat dacă pornești de la DB gol; dacă DB are date vechi, fă `docker compose down -v && docker compose up -d` o singură dată după Task 1.
- Pentru fiecare task: rulează testele existente după modificări — niciunul nu trebuie să cedeze.

---

## Task 1 — Backend models: heartbeat + scan_type + progress

**Files:**
- Modify: `server/app/models.py`
- Modify: `server/memory.md` (entry pentru models.py)

- [ ] **Step 1: Adaugă coloane `last_heartbeat`, `agent_version`, `capabilities` pe `Device` + property `is_online`**

Editează `server/app/models.py`, în clasa `Device`, după `created_at`:

```python
    last_heartbeat: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    capabilities: Mapped[list | None] = mapped_column(JSON, nullable=True)
```

Adaugă property la finalul clasei `Device` (înainte de `generate_token`):

```python
    @property
    def is_online(self) -> bool:
        """Online = last_heartbeat în ultimele 30s. Se calculează la cerere
        (nu este coloană)."""
        if self.last_heartbeat is None:
            return False
        delta = utcnow() - self.last_heartbeat
        return delta.total_seconds() < 30
```

- [ ] **Step 2: Adaugă coloane `scan_type`, `progress`, `phase` pe `ScanJob`**

În clasa `ScanJob`, după `error_message`:

```python
    scan_type: Mapped[str] = mapped_column(String(16), default="standard")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    phase: Mapped[str | None] = mapped_column(String(128), nullable=True)
```

- [ ] **Step 3: Verifică sintaxa**

Run: `cd server && python -c "from app.models import Device, ScanJob; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Rulează testele existente — toate trebuie să treacă (SQLite recreează tabelele)**

Run: `cd server && python -m pytest`
Expected: PASS (26 teste)

- [ ] **Step 5: Update `server/memory.md`**

Modifică entry-ul pentru `app/models.py` în `server/memory.md` să menționeze noile coloane:
- `Device`: + `last_heartbeat`, `agent_version`, `capabilities` + property `is_online`
- `ScanJob`: + `scan_type`, `progress`, `phase`

- [ ] **Step 6: Recrează DB Postgres în dev (o singură dată)**

Run (PowerShell): `docker compose down -v; docker compose up -d`
Expected: Postgres pornit cu schema goală. Backend-ul (când rulează) creează tabelele noi.

- [ ] **Step 7: Commit**

```bash
git add server/app/models.py server/memory.md
git commit -m "models: heartbeat fields pe Device + scan_type/progress/phase pe ScanJob"
```

---

## Task 2 — Backend schemas: noi DTO-uri + extensii

**Files:**
- Modify: `server/app/schemas.py`
- Modify: `server/memory.md` (entry pentru schemas.py)

- [ ] **Step 1: Importă `Literal` la începutul fișierului**

Modifică linia 2 din `server/app/schemas.py`:

```python
from typing import Any, Dict, List, Literal
```

- [ ] **Step 2: Înlocuiește `DeviceOut` cu versiunea extinsă**

Înlocuiește clasa `DeviceOut` existentă:

```python
class DeviceOut(BaseModel):
    id: int
    device_uid: str
    name: str
    created_at: str
    is_online: bool = False
    last_heartbeat: str | None = None
    agent_version: str | None = None
    capabilities: List[str] = []
```

- [ ] **Step 3: Înlocuiește `ScanJobOut` cu versiunea extinsă**

```python
class ScanJobOut(BaseModel):
    """Snapshot al unui ScanJob — folosit la creare si la polling status."""
    job_id: int
    device_uid: str
    device_name: str
    status: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    scan_id: int | None = None
    exposure_score: int | None = None
    error_message: str | None = None
    scan_type: str = "standard"
    progress: int = 0
    phase: str | None = None
```

- [ ] **Step 4: Înlocuiește `AgentJobOut`**

```python
class AgentJobOut(BaseModel):
    """Job livrat agentului. `scan_type` ii spune ce nivel sa colecteze."""
    job_id: int
    device_uid: str
    scan_type: str = "standard"
```

- [ ] **Step 5: Înlocuiește `JobResultIn` cu suport pentru `system_info`, `persistence`, `forensics`**

```python
class JobResultIn(BaseModel):
    """Rezultatul trimis de agent dupa executia jobului."""
    os: Dict[str, Any]
    network: Dict[str, Any] = {}
    processes: List[Dict[str, Any]] = []
    software: List[Dict[str, Any]] = []
    system_info: Dict[str, Any] = {}
    persistence: Dict[str, Any] | None = None
    forensics: Dict[str, Any] | None = None
```

- [ ] **Step 6: Adaugă schemas noi la finalul fișierului**

```python
# ── Heartbeat + scan-types ───────────────────────────────────────────────────

class HeartbeatIn(BaseModel):
    """Agent → backend la fiecare 10s. Backend marcheaza device-ul ca online."""
    agent_version: str = Field(max_length=32)
    capabilities: List[str] = Field(default_factory=list)
    os_version: str = Field(max_length=128)


class ScanJobCreateIn(BaseModel):
    """UI cere o scanare on-demand de un anumit tip."""
    scan_type: Literal["standard", "advanced", "deep"] = "standard"


class JobProgressIn(BaseModel):
    """Agent raporteaza progres in timpul executiei (intre colectori)."""
    progress: int = Field(ge=0, le=100)
    phase: str = Field(max_length=128)


# ── Scan detail: scan_type expus si la rezultat ──────────────────────────────

# Update la ScanDetailOut: adaugam scan_type (extras din payload).
```

- [ ] **Step 7: Adaugă `scan_type` în `ScanDetailOut`**

Înlocuiește `ScanDetailOut` existent:

```python
class ScanDetailOut(BaseModel):
    scan_id: int
    device_uid: str
    device_name: str
    created_at: str
    exposure_score: int
    findings: List[Dict[str, Any]]
    payload: Dict[str, Any] = {}
    scan_type: str = "standard"
```

- [ ] **Step 8: Verifică sintaxa**

Run: `cd server && python -c "from app.schemas import HeartbeatIn, ScanJobCreateIn, JobProgressIn, DeviceOut, ScanJobOut, AgentJobOut, JobResultIn, ScanDetailOut; print('OK')"`
Expected: `OK`

- [ ] **Step 9: Update `server/memory.md`** — adaugă noile schemas (`HeartbeatIn`, `ScanJobCreateIn`, `JobProgressIn`) și menționează extinderile la `DeviceOut`, `ScanJobOut`, `AgentJobOut`, `JobResultIn`, `ScanDetailOut`.

- [ ] **Step 10: Commit**

```bash
git add server/app/schemas.py server/memory.md
git commit -m "schemas: HeartbeatIn, ScanJobCreateIn, JobProgressIn + scan_type/progress/phase pe Out-uri"
```

---

## Task 3 — Backend routes: heartbeat + progress + scan_type

**Files:**
- Modify: `server/app/routes.py`
- Test: `server/tests/test_heartbeat.py` (new)
- Modify: `server/memory.md`

- [ ] **Step 1: Scrie testul de heartbeat (failing)**

Creează `server/tests/test_heartbeat.py`:

```python
"""Heartbeat agent + is_online expus pe DeviceOut."""
import time
import uuid


def _enroll(auth_client) -> tuple[str, str]:
    """Creeaza un device si returneaza (device_uid, plain_token)."""
    uid = f"dev-{uuid.uuid4().hex[:8]}"
    r = auth_client["client"].post(
        "/api/v1/devices",
        json={"device_uid": uid, "name": "Test PC"},
        headers=auth_client["headers"],
    )
    assert r.status_code == 200, r.text
    return uid, r.json()["device_token"]


def test_heartbeat_marks_device_online(auth_client):
    uid, token = _enroll(auth_client)
    client = auth_client["client"]

    # Initial: device NU este online (nu a trimis heartbeat).
    r = client.get(f"/api/v1/devices/by-uid/{uid}", headers=auth_client["headers"])
    assert r.status_code == 200
    assert r.json()["is_online"] is False

    # Trimite heartbeat.
    r = client.post(
        "/api/v1/agent/heartbeat",
        json={"agent_version": "2.0.0", "capabilities": ["standard", "advanced", "deep"], "os_version": "Windows 11"},
        headers={"X-Device-Token": token},
    )
    assert r.status_code == 204, r.text

    # Acum este online si capabilities sunt expuse.
    r = client.get(f"/api/v1/devices/by-uid/{uid}", headers=auth_client["headers"])
    body = r.json()
    assert body["is_online"] is True
    assert body["agent_version"] == "2.0.0"
    assert "deep" in body["capabilities"]
    assert body["last_heartbeat"] is not None


def test_heartbeat_requires_device_token(auth_client):
    r = auth_client["client"].post(
        "/api/v1/agent/heartbeat",
        json={"agent_version": "x", "capabilities": [], "os_version": "x"},
    )
    assert r.status_code == 401


def test_list_devices_includes_is_online(auth_client):
    uid, token = _enroll(auth_client)
    auth_client["client"].post(
        "/api/v1/agent/heartbeat",
        json={"agent_version": "2.0.0", "capabilities": ["standard"], "os_version": "Windows 11"},
        headers={"X-Device-Token": token},
    )
    r = auth_client["client"].get("/api/v1/devices", headers=auth_client["headers"])
    devs = r.json()
    target = next(d for d in devs if d["device_uid"] == uid)
    assert target["is_online"] is True
    assert target["agent_version"] == "2.0.0"
```

- [ ] **Step 2: Rulează testul — trebuie să cadă (lipsește endpoint-ul)**

Run: `cd server && python -m pytest tests/test_heartbeat.py -v`
Expected: FAIL — toate trei testele cad (404 sau missing field).

- [ ] **Step 3: Update imports în `routes.py`**

În `server/app/routes.py`, linia 6, adaugă `Body`:

```python
from fastapi import APIRouter, Body, Depends, HTTPException, Header, Response, status, Request
```

În blocul `from .schemas import`:

```python
from .schemas import (
    AgentJobOut,
    DeviceCreateIn,
    DeviceCreateOut,
    DeviceOut,
    DeviceScanListItem,
    HeartbeatIn,
    JobFailureIn,
    JobProgressIn,
    JobResultIn,
    LoginIn,
    MeOut,
    RegisterIn,
    ScanCreateOut,
    ScanDetailOut,
    ScanIn,
    ScanJobCreateIn,
    ScanJobOut,
    TokenOut,
)
```

- [ ] **Step 4: Adaugă helper `_device_to_out`**

Imediat după `_utcnow()` (linia 74), adaugă:

```python
def _device_to_out(device: Device) -> DeviceOut:
    """Serializeaza un Device cu campurile de online + agent."""
    caps = device.capabilities if isinstance(device.capabilities, list) else []
    return DeviceOut(
        id=device.id,
        device_uid=device.device_uid,
        name=device.name,
        created_at=device.created_at.isoformat(),
        is_online=device.is_online,
        last_heartbeat=device.last_heartbeat.isoformat() if device.last_heartbeat else None,
        agent_version=device.agent_version,
        capabilities=caps,
    )
```

- [ ] **Step 5: Update `_scan_job_to_out` să includă `scan_type`, `progress`, `phase`**

Înlocuiește helper-ul existent:

```python
def _scan_job_to_out(job: ScanJob, device: Device) -> ScanJobOut:
    exposure_score = job.scan.exposure_score if (job.scan_id and getattr(job, "scan", None)) else None
    return ScanJobOut(
        job_id=job.id,
        device_uid=device.device_uid,
        device_name=device.name,
        status=job.status,
        created_at=job.created_at.isoformat(),
        started_at=job.started_at.isoformat() if job.started_at else None,
        finished_at=job.finished_at.isoformat() if job.finished_at else None,
        scan_id=job.scan_id,
        exposure_score=exposure_score,
        error_message=job.error_message,
        scan_type=job.scan_type,
        progress=job.progress,
        phase=job.phase,
    )
```

- [ ] **Step 6: Update `list_devices` + `get_device_by_uid` + `create_device` + `relink_device` să folosească `_device_to_out`**

Înlocuiește returnurile din cele 4 funcții:

- `create_device` → returnează `DeviceCreateOut` (păstrează cum era — `DeviceCreateOut` extinde `DeviceOut`, dar adaugă manual `is_online=False, capabilities=[]` și `device_token`). Refactorizează ca:

```python
    out = _device_to_out(device)
    return DeviceCreateOut(**out.model_dump(), device_token=plain_token)
```

- `list_devices` → `return [_device_to_out(d) for d in rows]`
- `get_device_by_uid` → `return _device_to_out(device)`
- `relink_device` → `return DeviceCreateOut(**_device_to_out(device).model_dump(), device_token=plain_token)`

- [ ] **Step 7: Adaugă endpoint `POST /agent/heartbeat`**

După `agent_get_next_job` (în jurul liniei 499), adaugă:

```python
@router.post("/agent/heartbeat", status_code=204)
def agent_heartbeat(
    payload: HeartbeatIn,
    db: Session = Depends(get_db),
    x_device_token: str | None = Header(default=None),
):
    """Agent semnaleaza ca este online. Update last_heartbeat + meta."""
    device = _device_for_token_or_401(db, x_device_token)
    device.last_heartbeat = _utcnow()
    device.agent_version = payload.agent_version[:32]
    device.capabilities = payload.capabilities
    db.commit()
```

- [ ] **Step 8: Adaugă endpoint `POST /agent/jobs/{job_id}/progress`**

După `agent_submit_failure`, adaugă:

```python
@router.post("/agent/jobs/{job_id}/progress", status_code=204)
def agent_update_progress(
    job_id: int,
    payload: JobProgressIn,
    db: Session = Depends(get_db),
    x_device_token: str | None = Header(default=None),
):
    """Agent raporteaza progresul intre colectori. UI polleaza /scan-jobs/{id}."""
    device = _device_for_token_or_401(db, x_device_token)
    job = db.get(ScanJob, job_id)
    if not job or job.device_id != device.id:
        raise HTTPException(status_code=404, detail="scan job not found")
    if job.status != ScanJobStatus.RUNNING:
        raise HTTPException(
            status_code=409,
            detail=f"job is '{job.status}', cannot update progress",
        )
    job.progress = max(0, min(100, payload.progress))
    job.phase = payload.phase[:128]
    db.commit()
```

- [ ] **Step 9: Update `create_scan_job` să accepte `ScanJobCreateIn`**

Înlocuiește funcția:

```python
@router.post("/devices/{device_uid}/scan-jobs", response_model=ScanJobOut)
def create_scan_job(
    device_uid: str,
    payload: ScanJobCreateIn = Body(default_factory=ScanJobCreateIn),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """User cere o scanare on-demand pentru un device al sau."""
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")

    existing = db.execute(
        select(ScanJob).where(
            ScanJob.device_id == device.id,
            ScanJob.status == ScanJobStatus.PENDING,
        ).order_by(ScanJob.id.desc())
    ).scalars().first()
    if existing:
        return _scan_job_to_out(existing, device)

    job = ScanJob(
        device_id=device.id,
        requested_by_user_id=user.id,
        status=ScanJobStatus.PENDING,
        scan_type=payload.scan_type,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return _scan_job_to_out(job, device)
```

- [ ] **Step 10: Update `agent_get_next_job` să returneze `scan_type`**

În corpul funcției, înlocuiește `return AgentJobOut(...)` cu:

```python
    return AgentJobOut(job_id=job.id, device_uid=device.device_uid, scan_type=job.scan_type)
```

- [ ] **Step 11: Update `agent_submit_result` să propage `scan_type` + colectorii extinși**

Înlocuiește construirea `scan_dict` din `agent_submit_result`:

```python
    scan_dict = {
        "device_uid": device.device_uid,
        "scan_type": job.scan_type,
        "os": payload.os,
        "system_info": payload.system_info,
        "network": payload.network,
        "processes": payload.processes,
        "software": payload.software,
        "persistence": payload.persistence,
        "forensics": payload.forensics,
    }
    score, findings = evaluate(scan_dict)
```

- [ ] **Step 12: Update `get_scan_detail` să expună `scan_type`**

Înlocuiește returnul din `get_scan_detail`:

```python
    payload = scan.payload or {}
    return ScanDetailOut(
        scan_id=scan.id,
        device_uid=device.device_uid,
        device_name=device.name,
        created_at=scan.created_at.isoformat(),
        exposure_score=scan.exposure_score,
        findings=[
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in scan.findings
        ],
        payload=payload,
        scan_type=payload.get("scan_type", "standard"),
    )
```

- [ ] **Step 13: Rulează testul heartbeat — trebuie să treacă**

Run: `cd server && python -m pytest tests/test_heartbeat.py -v`
Expected: PASS (3 teste)

- [ ] **Step 14: Rulează toate testele existente — niciunul nu trebuie să cadă**

Run: `cd server && python -m pytest`
Expected: PASS (29+ teste)

- [ ] **Step 15: Update `server/memory.md`** — adaugă `POST /agent/heartbeat`, `POST /agent/jobs/{id}/progress` și menționează că `create_scan_job` acceptă `scan_type`. Adaugă entry pentru `test_heartbeat.py`.

- [ ] **Step 16: Commit**

```bash
git add server/app/routes.py server/tests/test_heartbeat.py server/memory.md
git commit -m "routes: heartbeat + progress + scan_type pe create-job, is_online pe DeviceOut"
```

---

## Task 4 — Rules engine: decorator `@rule` + migrare 7 reguli existente

**Files:**
- Modify: `server/app/rules.py`
- Test: `server/tests/test_scan_types.py` (new)
- Modify: `server/memory.md`

- [ ] **Step 1: Scrie testul pentru filtrarea pe nivel (failing)**

Creează `server/tests/test_scan_types.py`:

```python
"""Filtrarea regulilor dupa scan_type + ordinea LEVEL_ORDER."""
from server.app.rules import evaluate, _RULES, LEVEL_ORDER


def _empty_scan(scan_type: str = "standard") -> dict:
    return {
        "scan_type": scan_type,
        "device_uid": "x",
        "os": {"system": "Windows", "release": "11", "version": "10.0.22000", "is_admin": False},
        "system_info": {},
        "network": {"open_ports": []},
        "processes": [],
        "software": [],
        "persistence": None,
        "forensics": None,
    }


def test_standard_runs_only_standard_rules():
    """Pentru scan_type='standard', nicio regula advanced/deep nu trebuie sa
    poata gasi findings (chiar daca am avea date — care nu exista oricum)."""
    score, findings = evaluate(_empty_scan("standard"))
    assert score == 0
    assert findings == []


def test_advanced_can_fire_advanced_rules():
    scan = _empty_scan("advanced")
    scan["network"]["shares"] = [{"name": "MyShare", "path": "C:\\Public"}]
    score, findings = evaluate(scan)
    assert any(f["rule_id"] == "NET-SHARE-1" for f in findings)


def test_standard_ignores_advanced_data():
    """Chiar daca trimitem date advanced intr-un scan standard, regulile
    advanced NU ruleaza."""
    scan = _empty_scan("standard")
    scan["network"]["shares"] = [{"name": "MyShare", "path": "C:\\Public"}]
    _, findings = evaluate(scan)
    assert not any(f["rule_id"] == "NET-SHARE-1" for f in findings)


def test_deep_can_fire_deep_rules():
    scan = _empty_scan("deep")
    scan["persistence"] = {"wmi_subscriptions": [{"name": "Evil", "command": "cmd.exe"}]}
    _, findings = evaluate(scan)
    assert any(f["rule_id"] == "WMI-PERSIST-1" for f in findings)


def test_level_order_constants():
    assert LEVEL_ORDER["standard"] == 0
    assert LEVEL_ORDER["advanced"] == 1
    assert LEVEL_ORDER["deep"] == 2


def test_rules_registered_have_min_level():
    """Toate regulile inregistrate prin @rule trebuie sa aiba _min_level."""
    for fn in _RULES:
        assert hasattr(fn, "_rule_id")
        assert hasattr(fn, "_min_level")
        assert fn._min_level in LEVEL_ORDER
```

- [ ] **Step 2: Rulează testul — toate cad (modulul nu există încă)**

Run: `cd server && python -m pytest tests/test_scan_types.py -v`
Expected: FAIL

- [ ] **Step 3: Refactor `server/app/rules.py` — decorator + evaluate() generic**

Înlocuiește **întreg conținutul** `server/app/rules.py` cu:

```python
"""
Rules engine cu auto-filtrare dupa scan_type.

Decorator @rule(id, min_level): inregistreaza o functie ca regula. La
evaluare, doar regulile cu min_level <= scan_type ruleaza.

Adaugare regula noua = decoreaza o functie. Zero modificari in alte parti.
"""
from __future__ import annotations

import math
from typing import Any, Callable

SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
    "info": 0,
}

LEVEL_ORDER: dict[str, int] = {"standard": 0, "advanced": 1, "deep": 2}

# Tip pentru o functie-regula: primeste scan dict, returneaza None / dict / list[dict].
RuleFn = Callable[[dict[str, Any]], "dict | list[dict] | None"]

# Lista globala de reguli inregistrate prin decorator. Ordinea = ordinea de
# definitie. Nu este expusa public — accesul se face prin evaluate().
_RULES: list[RuleFn] = []


def rule(rule_id: str, min_level: str = "standard") -> Callable[[RuleFn], RuleFn]:
    """Decorator: marcheaza o functie ca regula si o inregistreaza in _RULES."""
    if min_level not in LEVEL_ORDER:
        raise ValueError(f"min_level invalid: {min_level!r}")

    def decorator(fn: RuleFn) -> RuleFn:
        fn._rule_id = rule_id        # type: ignore[attr-defined]
        fn._min_level = min_level    # type: ignore[attr-defined]
        _RULES.append(fn)
        return fn

    return decorator


def evaluate(scan: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    """Ruleaza toate regulile aplicabile pentru `scan["scan_type"]`.
    Returneaza (exposure_score 0-100, lista de findings)."""
    scan_type = scan.get("scan_type", "standard")
    level = LEVEL_ORDER.get(scan_type, 0)

    findings: list[dict[str, Any]] = []
    for fn in _RULES:
        if LEVEL_ORDER.get(fn._min_level, 0) > level:
            continue
        result = fn(scan)
        if result is None:
            continue
        if isinstance(result, list):
            findings.extend(result)
        else:
            findings.append(result)

    raw = sum(SEVERITY_WEIGHT.get(f.get("severity", "info"), 0) for f in findings)
    exposure_score = min(100, round(100 * (1 - math.exp(-raw / 60))))
    return exposure_score, findings


# ─────────────────────────────────────────────────────────────────────────────
# REGULI EXISTENTE (7) — migrate la decorator
# ─────────────────────────────────────────────────────────────────────────────

@rule("NET-OPEN-PORTS-1", min_level="standard")
def check_risky_ports(scan: dict) -> dict | None:
    RISKY_PORTS: dict[int, str] = {
        21:   "FTP – transfer fisiere necriptat",
        23:   "Telnet – acces remote necriptat",
        25:   "SMTP – server de mail expus",
        139:  "NetBIOS – partajare fisiere Windows",
        445:  "SMB – partajare fisiere Windows (risc EternalBlue)",
        3389: "RDP – Remote Desktop Protocol",
        5900: "VNC – acces remote grafic",
        5985: "WinRM HTTP – management remote Windows",
        5986: "WinRM HTTPS – management remote Windows",
    }
    open_ports: list[int] = scan.get("network", {}).get("open_ports", []) or []
    risky_found = {p: RISKY_PORTS[p] for p in open_ports if p in RISKY_PORTS}
    if not risky_found:
        return None
    return {
        "rule_id": "NET-OPEN-PORTS-1",
        "title": "Porturi cu risc ridicat expuse",
        "severity": "high",
        "evidence": {"ports": [{"port": p, "service": d} for p, d in risky_found.items()]},
        "recommendation": (
            "Inchide porturile neutilizate din firewall. Daca sunt necesare, "
            "restrictioneaza accesul la IP-uri de incredere si utilizeaza VPN."
        ),
    }


@rule("NET-MANY-PORTS-2", min_level="standard")
def check_many_ports(scan: dict) -> dict | None:
    open_ports = scan.get("network", {}).get("open_ports", []) or []
    if len(open_ports) <= 20:
        return None
    return {
        "rule_id": "NET-MANY-PORTS-2",
        "title": "Suprafata de atac mare – multe porturi deschise",
        "severity": "medium",
        "evidence": {"total_open_ports": len(open_ports)},
        "recommendation": (
            f"Sistemul are {len(open_ports)} porturi deschise. "
            "Aplica least-privilege: deschide doar porturile strict necesare."
        ),
    }


@rule("OS-ADMIN-1", min_level="standard")
def check_admin_session(scan: dict) -> dict | None:
    os_info = scan.get("os", {}) or {}
    if os_info.get("is_admin") is not True:
        return None
    return {
        "rule_id": "OS-ADMIN-1",
        "title": "Sesiune activa cu privilegii de administrator",
        "severity": "medium",
        "evidence": {"is_admin": True, "hostname": os_info.get("hostname", "")},
        "recommendation": (
            "Foloseste un cont standard pentru activitatile zilnice. "
            "Administrator doar pentru operatii administrative punctuale."
        ),
    }


@rule("PROC-SUSPICIOUS-1", min_level="standard")
def check_suspicious_processes(scan: dict) -> dict | None:
    SUSPICIOUS: dict[str, str] = {
        "nc.exe":        "Netcat – tool de retea, frecvent abuzat",
        "netcat":        "Netcat – tool de retea, frecvent abuzat",
        "ncat.exe":      "Ncat (Nmap) – tool de retea",
        "nmap.exe":      "Nmap – scanner de retea",
        "mimikatz.exe":  "Mimikatz – extragere credentiale (malware)",
        "psexec.exe":    "PsExec – executie remote",
        "meterpreter":   "Meterpreter – payload Metasploit",
        "cobaltstrike":  "Cobalt Strike – framework ofensiv",
        "wireshark.exe": "Wireshark – sniffer de retea",
        "rawcap.exe":    "RawCap – captare pachete",
    }
    procs = scan.get("processes", []) or []
    names = {p.get("name", "").lower() for p in procs}
    found = {n: SUSPICIOUS[n] for n in names if n in SUSPICIOUS}
    if not found:
        return None
    return {
        "rule_id": "PROC-SUSPICIOUS-1",
        "title": "Procese suspecte detectate",
        "severity": "high",
        "evidence": {"processes": [{"name": n, "description": d} for n, d in found.items()]},
        "recommendation": (
            "Verifica daca aceste procese sunt legitime. Daca nu, opreste-le si "
            "investigheaza sursa."
        ),
    }


@rule("PROC-POWERSHELL-2", min_level="standard")
def check_powershell_running(scan: dict) -> dict | None:
    procs = scan.get("processes", []) or []
    ps = [p.get("name", "") for p in procs if "powershell" in p.get("name", "").lower()]
    if not ps:
        return None
    return {
        "rule_id": "PROC-POWERSHELL-2",
        "title": "PowerShell activ",
        "severity": "low",
        "evidence": {"processes": sorted(set(ps))},
        "recommendation": (
            "PowerShell este legitim dar frecvent abuzat. Activeaza Script Block "
            "Logging pentru audit."
        ),
    }


@rule("SW-VULNERABLE-1", min_level="standard")
def check_vulnerable_software(scan: dict) -> list[dict]:
    VULN: list[dict] = [
        {"name_contains": "Adobe Flash",       "severity": "critical", "cve": "multiple",       "note": "EOL din 2020, nu mai primeste patch-uri"},
        {"name_contains": "Internet Explorer", "severity": "high",     "cve": "multiple",       "note": "EOL din 2022, vulnerabilitati nepatched"},
        {"name_contains": "Java 6",            "severity": "high",     "cve": "multiple",       "note": "EOL, versiune nesupportata"},
        {"name_contains": "Java 7",            "severity": "high",     "cve": "multiple",       "note": "EOL, versiune nesupportata"},
        {"name_contains": "OpenSSL 1.0",       "severity": "high",     "cve": "CVE-2022-0778",  "note": "Versiune vulnerabila"},
        {"name_contains": "WinRAR 5",          "severity": "medium",   "cve": "CVE-2023-38831", "note": "Versiune vulnerabila la executie de cod"},
        {"name_contains": "7-Zip 2",           "severity": "low",      "cve": "CVE-2023-31102", "note": "Versiune mai veche"},
    ]
    software = scan.get("software", []) or []
    sw_names = [s.get("name", "") for s in software]
    out: list[dict] = []
    for r in VULN:
        for sw_name in sw_names:
            if r["name_contains"].lower() in sw_name.lower():
                out.append({
                    "rule_id": "SW-VULNERABLE-1",
                    "title": f"Software vulnerabil detectat: {sw_name[:60]}",
                    "severity": r["severity"],
                    "evidence": {"software": sw_name, "cve": r["cve"], "note": r["note"]},
                    "recommendation": (
                        "Dezinstaleaza sau actualizeaza la cea mai recenta versiune. "
                        "Software-ul EOL nu mai primeste patch-uri."
                    ),
                })
                break
    return out


@rule("OS-EOL-1", min_level="standard")
def check_eol_os(scan: dict) -> dict | None:
    OS_EOL = [
        {"system": "Windows", "rel": "XP",    "severity": "critical"},
        {"system": "Windows", "rel": "Vista", "severity": "critical"},
        {"system": "Windows", "rel": "7",     "severity": "high"},
        {"system": "Windows", "rel": "8.0",   "severity": "high"},
        {"system": "Linux",   "rel": "2.6",   "severity": "high"},
    ]
    os_info = scan.get("os", {}) or {}
    system = os_info.get("system", "")
    release = os_info.get("release", "")
    for r in OS_EOL:
        if r["system"] in system and r["rel"] in release:
            return {
                "rule_id": "OS-EOL-1",
                "title": f"Sistem de operare EOL: {system} {release}",
                "severity": r["severity"],
                "evidence": {"system": system, "release": release, "version": os_info.get("version", "")},
                "recommendation": (
                    "Acest OS nu mai primeste actualizari de securitate. Upgradeaza la o "
                    "versiune suportata cat mai curand."
                ),
            }
    return None
```

- [ ] **Step 4: Rulează testul scan_types — trebuie să treacă (regulile noi încă nu există, dar testul checke pe regulile existente + structura)**

Run: `cd server && python -m pytest tests/test_scan_types.py::test_standard_runs_only_standard_rules tests/test_scan_types.py::test_level_order_constants tests/test_scan_types.py::test_rules_registered_have_min_level -v`
Expected: PASS (3 teste). Restul cad — vor trece după Task 5.

- [ ] **Step 5: Rulează testele de reguli existente — toate trebuie să treacă**

Run: `cd server && python -m pytest tests/test_rules.py -v`
Expected: PASS (toate cele 7 reguli existente continuă să funcționeze).

- [ ] **Step 6: Rulează toate testele**

Run: `cd server && python -m pytest`
Expected: PASS pentru toate cele existente; 3 cad în `test_scan_types.py` (NET-SHARE-1, WMI-PERSIST-1 nu există încă) — vor trece în Task 5.

- [ ] **Step 7: Update `server/memory.md`** — descriere nouă pentru `rules.py`: decorator `@rule(id, min_level)`, `evaluate(scan)` filtrează după `scan_type`. Adaugă `test_scan_types.py`.

- [ ] **Step 8: Commit**

```bash
git add server/app/rules.py server/tests/test_scan_types.py server/memory.md
git commit -m "rules: decorator @rule cu min_level + migrare 7 reguli existente"
```

---

## Task 5 — Reguli noi (16): 2 standard + 6 advanced + 8 deep

**Files:**
- Modify: `server/app/rules.py`
- Test: `server/tests/test_new_rules.py` (new)
- Modify: `server/memory.md`

- [ ] **Step 1: Scrie testele pentru toate regulile noi (failing)**

Creează `server/tests/test_new_rules.py`:

```python
"""Cele 16 reguli noi: 2 standard + 6 advanced + 8 deep."""
from server.app.rules import evaluate


def _base(scan_type: str) -> dict:
    return {
        "scan_type": scan_type,
        "device_uid": "x",
        "os": {"system": "Windows", "release": "11", "version": "10.0.22000", "is_admin": False, "username": "alice"},
        "system_info": {},
        "network": {"open_ports": []},
        "processes": [],
        "software": [],
        "persistence": None,
        "forensics": None,
    }


def _ids(findings: list[dict]) -> set[str]:
    return {f["rule_id"] for f in findings}


# ── Standard ─────────────────────────────────────────────────────────────────

def test_fw_disabled_fires_on_public_off():
    scan = _base("standard")
    scan["system_info"] = {"firewall": {"profiles": {"domain": True, "private": True, "public": False}}}
    _, findings = evaluate(scan)
    assert "FW-DISABLED-1" in _ids(findings)


def test_fw_disabled_does_not_fire_when_all_on():
    scan = _base("standard")
    scan["system_info"] = {"firewall": {"profiles": {"domain": True, "private": True, "public": True}}}
    _, findings = evaluate(scan)
    assert "FW-DISABLED-1" not in _ids(findings)


def test_user_admin_fires_on_extra_admin():
    scan = _base("standard")
    scan["system_info"] = {"local_users": [
        {"name": "Administrator", "is_admin": True},
        {"name": "alice", "is_admin": True},
        {"name": "hacker", "is_admin": True},
    ]}
    _, findings = evaluate(scan)
    f = next(f for f in findings if f["rule_id"] == "USER-ADMIN-1")
    assert "hacker" in f["evidence"]["extra_admin_accounts"]
    assert "Administrator" not in f["evidence"]["extra_admin_accounts"]
    assert "alice" not in f["evidence"]["extra_admin_accounts"]


# ── Advanced ─────────────────────────────────────────────────────────────────

def test_startup_suspicious_fires_on_temp_path():
    scan = _base("advanced")
    scan["persistence"] = {"startup": [
        {"key": "Updater", "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe"},
    ]}
    _, findings = evaluate(scan)
    assert "STARTUP-SUSPICIOUS-1" in _ids(findings)


def test_task_suspicious_fires_on_encoded_command():
    scan = _base("advanced")
    scan["persistence"] = {"tasks": [
        {"name": "UpdateCheck", "action": "powershell.exe -EncodedCommand SGVsbG8="},
    ]}
    _, findings = evaluate(scan)
    assert "TASK-SUSPICIOUS-1" in _ids(findings)


def test_svc_suspicious_fires_on_nonstandard_path():
    scan = _base("advanced")
    scan["persistence"] = {"services": [
        {"name": "EvilSvc", "status": "running", "binary_path": "C:\\Users\\Public\\evil.exe"},
    ]}
    _, findings = evaluate(scan)
    assert "SVC-SUSPICIOUS-1" in _ids(findings)


def test_net_share_excludes_admin_default():
    scan = _base("advanced")
    scan["network"] = {"open_ports": [], "shares": [
        {"name": "ADMIN$", "path": "C:\\Windows"},  # default
        {"name": "MyShare", "path": "C:\\Public"},
    ]}
    _, findings = evaluate(scan)
    f = next(f for f in findings if f["rule_id"] == "NET-SHARE-1")
    names = [s["name"] for s in f["evidence"]["shares"]]
    assert "MyShare" in names
    assert "ADMIN$" not in names


def test_ps_policy_fires_on_bypass():
    scan = _base("advanced")
    scan["persistence"] = {"ps_policy": "Bypass"}
    _, findings = evaluate(scan)
    assert "PS-POLICY-1" in _ids(findings)


def test_ps_policy_does_not_fire_on_remote_signed():
    scan = _base("advanced")
    scan["persistence"] = {"ps_policy": "RemoteSigned"}
    _, findings = evaluate(scan)
    assert "PS-POLICY-1" not in _ids(findings)


def test_net_established_fires_on_external_nonstd_port():
    scan = _base("advanced")
    scan["network"] = {"open_ports": [], "connections": [
        {"remote_ip": "203.0.113.5", "remote_port": 4444, "local_port": 50000, "process": "x.exe"},
    ]}
    _, findings = evaluate(scan)
    assert "NET-ESTABLISHED-1" in _ids(findings)


def test_net_established_ignores_private_ips():
    scan = _base("advanced")
    scan["network"] = {"open_ports": [], "connections": [
        {"remote_ip": "192.168.1.1", "remote_port": 4444, "local_port": 50000, "process": "x.exe"},
    ]}
    _, findings = evaluate(scan)
    assert "NET-ESTABLISHED-1" not in _ids(findings)


# ── Deep ─────────────────────────────────────────────────────────────────────

def test_reg_hijack_fires_on_appinit_dlls():
    scan = _base("deep")
    scan["persistence"] = {"reg_persistence": {"AppInit_DLLs": "C:\\evil.dll"}}
    _, findings = evaluate(scan)
    assert "REG-HIJACK-1" in _ids(findings)


def test_wmi_persist_fires_on_any_subscription():
    scan = _base("deep")
    scan["persistence"] = {"wmi_subscriptions": [{"name": "Evil", "command": "cmd.exe"}]}
    _, findings = evaluate(scan)
    assert "WMI-PERSIST-1" in _ids(findings)


def test_cert_untrusted_fires_on_unknown_issuer():
    scan = _base("deep")
    scan["forensics"] = {"certificates": [
        {"subject": "Evil Root CA", "issuer": "Evil Root CA", "thumbprint": "abc"},
    ]}
    _, findings = evaluate(scan)
    assert "CERT-UNTRUSTED-1" in _ids(findings)


def test_cert_untrusted_skips_microsoft():
    scan = _base("deep")
    scan["forensics"] = {"certificates": [
        {"subject": "Microsoft Root", "issuer": "Microsoft Corp", "thumbprint": "abc"},
    ]}
    _, findings = evaluate(scan)
    assert "CERT-UNTRUSTED-1" not in _ids(findings)


def test_av_disabled_fires_when_off():
    scan = _base("deep")
    scan["system_info"] = {"defender": {"enabled": False, "signature_age_days": 1}}
    _, findings = evaluate(scan)
    assert "AV-DISABLED-1" in _ids(findings)


def test_av_disabled_fires_on_old_signatures():
    scan = _base("deep")
    scan["system_info"] = {"defender": {"enabled": True, "signature_age_days": 15}}
    _, findings = evaluate(scan)
    assert "AV-DISABLED-1" in _ids(findings)


def test_eventlog_bruteforce_fires_on_10_failures():
    scan = _base("deep")
    scan["forensics"] = {"event_log": [{"event_id": 4625, "account": "alice"} for _ in range(12)]}
    _, findings = evaluate(scan)
    assert "EVENTLOG-BRUTEFORCE-1" in _ids(findings)


def test_eventlog_bruteforce_does_not_fire_on_few():
    scan = _base("deep")
    scan["forensics"] = {"event_log": [{"event_id": 4625, "account": "alice"} for _ in range(3)]}
    _, findings = evaluate(scan)
    assert "EVENTLOG-BRUTEFORCE-1" not in _ids(findings)


def test_eventlog_privesc_fires_on_non_system_account():
    scan = _base("deep")
    scan["forensics"] = {"event_log": [{"event_id": 4672, "account": "alice"}]}
    _, findings = evaluate(scan)
    assert "EVENTLOG-PRIVESC-1" in _ids(findings)


def test_eventlog_privesc_ignores_system():
    scan = _base("deep")
    scan["forensics"] = {"event_log": [{"event_id": 4672, "account": "SYSTEM"}]}
    _, findings = evaluate(scan)
    assert "EVENTLOG-PRIVESC-1" not in _ids(findings)


def test_hosts_tampered_fires_on_non_default():
    scan = _base("deep")
    scan["forensics"] = {"hosts": [{"ip": "1.2.3.4", "hostname": "microsoft.com"}]}
    _, findings = evaluate(scan)
    assert "HOSTS-TAMPERED-1" in _ids(findings)


def test_hosts_tampered_ignores_localhost():
    scan = _base("deep")
    scan["forensics"] = {"hosts": [{"ip": "127.0.0.1", "hostname": "localhost"}]}
    _, findings = evaluate(scan)
    assert "HOSTS-TAMPERED-1" not in _ids(findings)


def test_bitlocker_off_fires_on_c_drive_unprotected():
    scan = _base("deep")
    scan["system_info"] = {"bitlocker": [{"volume": "C:", "protection_status": "off"}]}
    _, findings = evaluate(scan)
    assert "BITLOCKER-OFF-1" in _ids(findings)


def test_bitlocker_off_does_not_fire_when_on():
    scan = _base("deep")
    scan["system_info"] = {"bitlocker": [{"volume": "C:", "protection_status": "on"}]}
    _, findings = evaluate(scan)
    assert "BITLOCKER-OFF-1" not in _ids(findings)
```

- [ ] **Step 2: Rulează testele — toate cad (regulile nu există)**

Run: `cd server && python -m pytest tests/test_new_rules.py -v`
Expected: FAIL

- [ ] **Step 3: Adaugă cele 16 reguli noi la finalul `server/app/rules.py`**

Adaugă în continuarea fișierului:

```python
# ─────────────────────────────────────────────────────────────────────────────
# REGULI NOI (16): 2 standard + 6 advanced + 8 deep
# ─────────────────────────────────────────────────────────────────────────────


@rule("FW-DISABLED-1", min_level="standard")
def check_firewall_disabled(scan: dict) -> dict | None:
    profiles = (scan.get("system_info", {}) or {}).get("firewall", {}).get("profiles", {})
    disabled = [p for p in ("domain", "public") if profiles.get(p) is False]
    if not disabled:
        return None
    return {
        "rule_id": "FW-DISABLED-1",
        "title": "Windows Firewall dezactivat pe profil critic",
        "severity": "high",
        "evidence": {"disabled_profiles": disabled},
        "recommendation": (
            "Activeaza firewall: netsh advfirewall set allprofiles state on"
        ),
    }


@rule("USER-ADMIN-1", min_level="standard")
def check_extra_admins(scan: dict) -> dict | None:
    users = (scan.get("system_info", {}) or {}).get("local_users", []) or []
    current = (scan.get("os", {}) or {}).get("username", "").lower()
    extra = [
        u["name"] for u in users
        if u.get("is_admin")
        and u.get("name", "").lower() not in ("administrator",)
        and u.get("name", "").lower() != current
    ]
    if not extra:
        return None
    return {
        "rule_id": "USER-ADMIN-1",
        "title": "Conturi locale cu privilegii de administrator neasteptate",
        "severity": "medium",
        "evidence": {"extra_admin_accounts": extra},
        "recommendation": (
            "Revoca drepturile inutile: net localgroup administrators <user> /delete"
        ),
    }


@rule("STARTUP-SUSPICIOUS-1", min_level="advanced")
def check_suspicious_startup(scan: dict) -> dict | None:
    startup = (scan.get("persistence", {}) or {}).get("startup", []) or []
    SUSP = ("%temp%", "%appdata%", "\\temp\\", "\\appdata\\local\\temp",
            "\\users\\public\\", "\\programdata\\temp")
    suspicious = [
        s for s in startup
        if any(p in s.get("path", "").lower() for p in SUSP)
    ]
    if not suspicious:
        return None
    return {
        "rule_id": "STARTUP-SUSPICIOUS-1",
        "title": "Startup entry in director suspect",
        "severity": "high",
        "evidence": {"entries": [{"key": s.get("key"), "path": s.get("path")} for s in suspicious]},
        "recommendation": (
            "Sterge cheile suspecte din HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."
        ),
    }


@rule("TASK-SUSPICIOUS-1", min_level="advanced")
def check_suspicious_tasks(scan: dict) -> dict | None:
    tasks = (scan.get("persistence", {}) or {}).get("tasks", []) or []
    FLAGS = ("-enc ", "-encodedcommand", " -e ")
    suspicious = [
        t for t in tasks
        if "powershell" in t.get("action", "").lower()
        and any(f in t.get("action", "").lower() for f in FLAGS)
    ]
    if not suspicious:
        return None
    return {
        "rule_id": "TASK-SUSPICIOUS-1",
        "title": "Task Scheduler cu comanda PowerShell encodata",
        "severity": "high",
        "evidence": {"tasks": [{"name": t.get("name"), "action": t.get("action", "")[:200]} for t in suspicious]},
        "recommendation": (
            "Sterge task-urile cu: schtasks /delete /tn \"<TaskName>\" /f"
        ),
    }


@rule("SVC-SUSPICIOUS-1", min_level="advanced")
def check_suspicious_services(scan: dict) -> dict | None:
    services = (scan.get("persistence", {}) or {}).get("services", []) or []
    STD = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")
    suspicious = [
        s for s in services
        if s.get("status", "").lower() == "running"
        and s.get("binary_path", "")
        and not any(s.get("binary_path", "").lower().startswith(p) for p in STD)
    ]
    if not suspicious:
        return None
    return {
        "rule_id": "SVC-SUSPICIOUS-1",
        "title": "Servicii Windows cu executabil in path nestandard",
        "severity": "medium",
        "evidence": {"services": [{"name": s.get("name"), "path": s.get("binary_path")} for s in suspicious]},
        "recommendation": (
            "Verifica si opreste: sc stop <name> && sc delete <name>"
        ),
    }


@rule("NET-SHARE-1", min_level="advanced")
def check_network_shares(scan: dict) -> dict | None:
    shares = (scan.get("network", {}) or {}).get("shares", []) or []
    DEFAULT = {"admin$", "ipc$", "c$", "d$", "e$", "print$"}
    non_default = [s for s in shares if s.get("name", "").lower() not in DEFAULT]
    if not non_default:
        return None
    return {
        "rule_id": "NET-SHARE-1",
        "title": "Foldere partajate in retea detectate",
        "severity": "medium",
        "evidence": {"shares": [{"name": s.get("name"), "path": s.get("path")} for s in non_default]},
        "recommendation": (
            "Sterge share-urile inutile: net share <Name> /delete"
        ),
    }


@rule("PS-POLICY-1", min_level="advanced")
def check_ps_policy(scan: dict) -> dict | None:
    policy = (scan.get("persistence", {}) or {}).get("ps_policy", "")
    if not policy or policy.lower() not in ("bypass", "unrestricted"):
        return None
    return {
        "rule_id": "PS-POLICY-1",
        "title": f"PowerShell Execution Policy permisiva: {policy}",
        "severity": "medium",
        "evidence": {"policy": policy},
        "recommendation": (
            "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine"
        ),
    }


@rule("NET-ESTABLISHED-1", min_level="advanced")
def check_established_connections(scan: dict) -> dict | None:
    conns = (scan.get("network", {}) or {}).get("connections", []) or []
    PRIVATE = ("10.", "127.", "192.168.", "169.254.", "::1", "fe80:",
               "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
               "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
               "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")
    STD_PORTS = {80, 443, 53, 22, 25, 587, 465, 993, 995, 8080, 8443}
    suspicious = [
        c for c in conns
        if c.get("remote_ip")
        and not any(c["remote_ip"].startswith(p) for p in PRIVATE)
        and c.get("remote_port", 0) not in STD_PORTS
    ]
    if not suspicious:
        return None
    return {
        "rule_id": "NET-ESTABLISHED-1",
        "title": "Conexiuni active pe porturi nestandard catre IP-uri externe",
        "severity": "low",
        "evidence": {"connections": [
            {"ip": c.get("remote_ip"), "port": c.get("remote_port"), "process": c.get("process")}
            for c in suspicious[:20]
        ]},
        "recommendation": (
            "Verifica conexiunile cu netstat -b sau Resource Monitor."
        ),
    }


@rule("REG-HIJACK-1", min_level="deep")
def check_registry_hijack(scan: dict) -> dict | None:
    reg = (scan.get("persistence", {}) or {}).get("reg_persistence", {}) or {}
    suspicious = {k: v for k, v in reg.items() if v}
    if not suspicious:
        return None
    return {
        "rule_id": "REG-HIJACK-1",
        "title": "Persistenta prin registry (AppInit_DLLs / IFEO / Winlogon)",
        "severity": "critical",
        "evidence": {"registry_keys": suspicious},
        "recommendation": (
            "Investigheaza si sterge valorile suspecte din regedit.exe. "
            "AppInit_DLLs si IFEO sunt vectori clasici de persistenta malware."
        ),
    }


@rule("WMI-PERSIST-1", min_level="deep")
def check_wmi_persistence(scan: dict) -> dict | None:
    subs = (scan.get("persistence", {}) or {}).get("wmi_subscriptions", []) or []
    if not subs:
        return None
    return {
        "rule_id": "WMI-PERSIST-1",
        "title": "Subscriptii WMI active detectate",
        "severity": "critical",
        "evidence": {"subscriptions": [{"name": s.get("name"), "command": s.get("command")} for s in subs]},
        "recommendation": (
            "Sterge cu: Get-WMIObject -Namespace root\\subscription -Class __EventFilter | Remove-WMIObject"
        ),
    }


@rule("CERT-UNTRUSTED-1", min_level="deep")
def check_untrusted_certs(scan: dict) -> dict | None:
    certs = (scan.get("forensics", {}) or {}).get("certificates", []) or []
    KNOWN = ("microsoft", "digicert", "comodo", "sectigo", "verisign",
             "globalsign", "entrust", "thawte", "geotrust", "symantec",
             "let's encrypt", "lets encrypt", "amazon", "google trust services",
             "go daddy", "starfield", "identrust", "isrg")
    suspicious = [
        c for c in certs
        if not any(k in c.get("issuer", "").lower() for k in KNOWN)
        and not any(k in c.get("subject", "").lower() for k in ("microsoft", "windows"))
    ]
    if not suspicious:
        return None
    return {
        "rule_id": "CERT-UNTRUSTED-1",
        "title": "Certificate root necunoscute instalate",
        "severity": "high",
        "evidence": {"certificates": [
            {"subject": c.get("subject"), "issuer": c.get("issuer"), "thumbprint": (c.get("thumbprint") or "")[:40]}
            for c in suspicious[:20]
        ]},
        "recommendation": (
            "Certificatele root necunoscute permit interceptari HTTPS (MITM). "
            "Sterge din certmgr.msc → Trusted Root Certification Authorities."
        ),
    }


@rule("AV-DISABLED-1", min_level="deep")
def check_av_disabled(scan: dict) -> dict | None:
    defender = (scan.get("system_info", {}) or {}).get("defender", {})
    if not defender:
        return None
    issues = []
    if defender.get("enabled") is False:
        issues.append("Windows Defender dezactivat")
    age = defender.get("signature_age_days", 0)
    if isinstance(age, (int, float)) and age > 7:
        issues.append(f"Semnaturi vechi ({age} zile)")
    if not issues:
        return None
    return {
        "rule_id": "AV-DISABLED-1",
        "title": "Windows Defender dezactivat sau semnaturi expirate",
        "severity": "high",
        "evidence": {"issues": issues, "defender": defender},
        "recommendation": (
            "Activeaza: Set-MpPreference -DisableRealtimeMonitoring $false. "
            "Update: Update-MpSignature."
        ),
    }


@rule("EVENTLOG-BRUTEFORCE-1", min_level="deep")
def check_brute_force(scan: dict) -> dict | None:
    events = (scan.get("forensics", {}) or {}).get("event_log", []) or []
    failures = [e for e in events if e.get("event_id") == 4625]
    if len(failures) < 10:
        return None
    accounts = sorted({e.get("account", "") for e in failures})[:5]
    return {
        "rule_id": "EVENTLOG-BRUTEFORCE-1",
        "title": f"Posibil atac brute-force ({len(failures)} esecuri de autentificare)",
        "severity": "high",
        "evidence": {"failed_logon_count": len(failures), "sample_accounts": accounts},
        "recommendation": (
            "Restrictioneaza RDP/SMB la IP-uri de incredere. Configureaza Account "
            "Lockout Policy in Local Security Policy."
        ),
    }


@rule("EVENTLOG-PRIVESC-1", min_level="deep")
def check_privesc(scan: dict) -> dict | None:
    events = (scan.get("forensics", {}) or {}).get("event_log", []) or []
    SYS = {"system", "local service", "network service", "administrator", ""}
    suspicious = [
        e for e in events
        if e.get("event_id") == 4672
        and e.get("account", "").lower() not in SYS
        and not e.get("account", "").endswith("$")
    ]
    if not suspicious:
        return None
    accounts = sorted({e.get("account", "") for e in suspicious})
    return {
        "rule_id": "EVENTLOG-PRIVESC-1",
        "title": "Privilegii speciale acordate conturilor non-sistem",
        "severity": "high",
        "evidence": {"accounts": accounts, "event_count": len(suspicious)},
        "recommendation": (
            "Verifica daca aceste conturi necesita privilegii speciale. "
            "Revizuieste User Rights Assignment."
        ),
    }


@rule("HOSTS-TAMPERED-1", min_level="deep")
def check_hosts_tampered(scan: dict) -> dict | None:
    entries = (scan.get("forensics", {}) or {}).get("hosts", []) or []
    OK = {("127.0.0.1", "localhost"), ("::1", "localhost"),
          ("127.0.0.1", "localhost.localdomain")}
    suspicious = [
        h for h in entries
        if (h.get("ip", ""), h.get("hostname", "").lower()) not in OK
    ]
    if not suspicious:
        return None
    return {
        "rule_id": "HOSTS-TAMPERED-1",
        "title": "Fisierul hosts modificat cu intrari nestandard",
        "severity": "medium",
        "evidence": {"entries": [{"ip": h.get("ip"), "hostname": h.get("hostname")} for h in suspicious]},
        "recommendation": (
            "Hosts este modificat de malware pentru redirectionare trafic. "
            "Restaureaza: notepad C:\\Windows\\System32\\drivers\\etc\\hosts"
        ),
    }


@rule("BITLOCKER-OFF-1", min_level="deep")
def check_bitlocker_off(scan: dict) -> dict | None:
    volumes = (scan.get("system_info", {}) or {}).get("bitlocker", []) or []
    sys_vols = [
        v for v in volumes
        if v.get("volume", "").upper().startswith("C")
        and v.get("protection_status", "").lower() in ("off", "disabled", "unknown")
    ]
    if not sys_vols:
        return None
    return {
        "rule_id": "BITLOCKER-OFF-1",
        "title": "Volumul de sistem nu este protejat cu BitLocker",
        "severity": "medium",
        "evidence": {"volumes": [{"volume": v.get("volume"), "status": v.get("protection_status")} for v in sys_vols]},
        "recommendation": (
            "Activeaza: Enable-BitLocker -MountPoint 'C:' -EncryptionMethod "
            "XtsAes256 -UsedSpaceOnly -TpmProtector"
        ),
    }
```

- [ ] **Step 4: Rulează toate testele de reguli noi — toate trebuie să treacă**

Run: `cd server && python -m pytest tests/test_new_rules.py tests/test_scan_types.py -v`
Expected: PASS

- [ ] **Step 5: Rulează tot test suite-ul**

Run: `cd server && python -m pytest`
Expected: PASS

- [ ] **Step 6: Update `server/memory.md`** — `rules.py` are acum 23 reguli (7 existente + 16 noi). Adaugă `test_new_rules.py`.

- [ ] **Step 7: Commit**

```bash
git add server/app/rules.py server/tests/test_new_rules.py server/memory.md
git commit -m "rules: 16 reguli noi (FW, USER, STARTUP, TASK, SVC, NET-SHARE, PS, NET-EST, REG, WMI, CERT, AV, EVENTLOG x2, HOSTS, BITLOCKER)"
```

---

## Task 6 — Agent: `ScanProfile` + `SCAN_PROFILES` + modulul `collectors/`

**Files:**
- Create: `agent/collectors/__init__.py`
- Create: `agent/collectors/network.py`
- Create: `agent/collectors/processes.py`
- Create: `agent/collectors/software.py`
- Create: `agent/collectors/system_info.py`
- Create: `agent/collectors/persistence.py`
- Create: `agent/collectors/forensics.py`
- Modify: `agent/core.py` (adaugă `ScanProfile` + `SCAN_PROFILES` + rescrie `collect_system_data`)
- Create: `agent/collectors/memory.md`
- Modify: `agent/memory.md`

- [ ] **Step 1: Creează `agent/collectors/__init__.py`**

Conținut:

```python
"""Modul de colectori composabili. Fiecare colector primeste un ScanProfile
si returneaza datele relevante pentru nivelul curent."""
from .forensics import collect_forensics
from .network import collect_network
from .persistence import collect_persistence
from .processes import collect_processes
from .software import collect_software
from .system_info import collect_system

__all__ = [
    "collect_network",
    "collect_processes",
    "collect_software",
    "collect_system",
    "collect_persistence",
    "collect_forensics",
]
```

- [ ] **Step 2: Adaugă `ScanProfile` + `SCAN_PROFILES` în `agent/core.py`**

Imediat după import-uri (după linia 31), adaugă:

```python
import dataclasses


@dataclasses.dataclass(frozen=True)
class ScanProfile:
    """Strategie de colectare pentru un nivel de scanare. Flag-urile booleane
    activeaza/dezactiveaza sub-colectorii individual."""
    # Procese
    process_limit: int | None = 30
    include_cmdline: bool = False

    # Standard
    include_software: bool = True
    include_users: bool = True
    include_firewall: bool = True

    # Advanced
    include_connections: bool = False
    include_port_process: bool = False
    include_net_adapters: bool = False
    include_persistence: bool = False  # umbrella pentru collect_persistence
    include_services: bool = False
    include_startup: bool = False
    include_tasks: bool = False
    include_shares: bool = False
    include_ps_policy: bool = False

    # Deep
    include_wmi: bool = False
    include_reg_hijack: bool = False
    include_forensics: bool = False  # umbrella pentru collect_forensics
    include_defender: bool = False
    include_bitlocker: bool = False
    include_eventlog: bool = False
    include_hosts: bool = False
    include_certs: bool = False
    include_arp_dns: bool = False
    include_recent_files: bool = False


SCAN_PROFILES: dict[str, ScanProfile] = {
    "standard": ScanProfile(
        process_limit=30,
        include_cmdline=False,
        include_software=True,
        include_users=True,
        include_firewall=True,
    ),
    "advanced": ScanProfile(
        process_limit=None,
        include_cmdline=True,
        include_software=True,
        include_users=True,
        include_firewall=True,
        include_connections=True,
        include_port_process=True,
        include_net_adapters=True,
        include_persistence=True,
        include_services=True,
        include_startup=True,
        include_tasks=True,
        include_shares=True,
        include_ps_policy=True,
    ),
    "deep": ScanProfile(
        process_limit=None,
        include_cmdline=True,
        include_software=True,
        include_users=True,
        include_firewall=True,
        include_connections=True,
        include_port_process=True,
        include_net_adapters=True,
        include_persistence=True,
        include_services=True,
        include_startup=True,
        include_tasks=True,
        include_shares=True,
        include_ps_policy=True,
        include_wmi=True,
        include_reg_hijack=True,
        include_forensics=True,
        include_defender=True,
        include_bitlocker=True,
        include_eventlog=True,
        include_hosts=True,
        include_certs=True,
        include_arp_dns=True,
        include_recent_files=True,
    ),
}


AGENT_VERSION = "2.0.0"
```

- [ ] **Step 3: Creează `agent/collectors/network.py`**

```python
"""Colectare network: porturi LISTEN + (opt) port→proces, conexiuni ESTABLISHED, share-uri, adaptoare."""
from __future__ import annotations

import platform
import subprocess

import psutil

from ..core import ScanProfile


def collect_network(cfg: ScanProfile) -> dict:
    out: dict = {"open_ports": _listen_ports()}

    if cfg.include_port_process:
        out["port_processes"] = _port_processes()
    if cfg.include_connections:
        out["connections"] = _established_connections()
    if cfg.include_shares and platform.system() == "Windows":
        out["shares"] = _network_shares()
    if cfg.include_net_adapters:
        out["adapters"] = _adapters()

    return out


def _listen_ports() -> list[int]:
    ports: list[int] = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                p = conn.laddr.port
                if p not in ports:
                    ports.append(p)
    except (psutil.AccessDenied, PermissionError, Exception):
        pass
    return sorted(ports)


def _port_processes() -> list[dict]:
    out: list[dict] = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != psutil.CONN_LISTEN or not conn.laddr or not conn.pid:
                continue
            try:
                p = psutil.Process(conn.pid)
                out.append({"port": conn.laddr.port, "pid": conn.pid, "process": p.name()})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                out.append({"port": conn.laddr.port, "pid": conn.pid, "process": ""})
    except Exception:
        pass
    return out


def _established_connections() -> list[dict]:
    out: list[dict] = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                continue
            proc_name = ""
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            out.append({
                "local_port": conn.laddr.port if conn.laddr else None,
                "remote_ip": conn.raddr.ip,
                "remote_port": conn.raddr.port,
                "pid": conn.pid,
                "process": proc_name,
            })
    except Exception:
        pass
    return out[:500]


def _network_shares() -> list[dict]:
    shares: list[dict] = []
    try:
        r = subprocess.run(["net", "share"], capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("-") or line.lower().startswith("share name") or line.lower().startswith("the command"):
                continue
            parts = line.split(None, 2)
            if len(parts) >= 2:
                shares.append({"name": parts[0], "path": parts[1] if len(parts) > 1 else ""})
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return shares


def _adapters() -> list[dict]:
    out: list[dict] = []
    try:
        addrs = psutil.net_if_addrs()
        for name, infos in addrs.items():
            entry: dict = {"name": name, "ip": "", "mac": "", "gateway": ""}
            for info in infos:
                if info.family == 2:  # AF_INET
                    entry["ip"] = info.address
                elif hasattr(info, "family") and str(info.family).endswith("AF_LINK") or info.family == -1:
                    entry["mac"] = info.address
            out.append(entry)
    except Exception:
        pass
    return out
```

- [ ] **Step 4: Creează `agent/collectors/processes.py`**

```python
"""Colectare procese: top N dupa RAM (standard) sau toate cu cmdline (advanced/deep)."""
from __future__ import annotations

import psutil

from ..core import ScanProfile


def collect_processes(cfg: ScanProfile) -> list[dict]:
    procs: list[dict] = []
    attrs = ["pid", "name", "memory_percent", "username"]
    if cfg.include_cmdline:
        attrs += ["cmdline", "ppid"]

    for proc in psutil.process_iter(attrs):
        try:
            info = proc.info
            entry: dict = {
                "pid": info.get("pid", 0),
                "name": info.get("name") or "",
                "memory_percent": round(info.get("memory_percent") or 0, 2),
                "username": info.get("username") or "",
            }
            if cfg.include_cmdline:
                cmd = info.get("cmdline") or []
                entry["cmdline"] = " ".join(cmd)[:512]
                entry["ppid"] = info.get("ppid", 0)
            procs.append(entry)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs.sort(key=lambda x: x["memory_percent"], reverse=True)
    if cfg.process_limit is not None:
        procs = procs[:cfg.process_limit]
    return procs
```

- [ ] **Step 5: Creează `agent/collectors/software.py`**

```python
"""Colectare software instalat: registry Windows (Uninstall keys)."""
from __future__ import annotations

import platform

from ..core import ScanProfile


def collect_software(cfg: ScanProfile) -> list[dict]:
    if not cfg.include_software or platform.system() != "Windows":
        return []
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return []

    software: list[dict] = []
    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, path in keys:
        try:
            key = winreg.OpenKey(hive, path)
        except FileNotFoundError:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(key, i)
                i += 1
                try:
                    subkey = winreg.OpenKey(key, sub)
                    name = ""
                    version = ""
                    try:
                        name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                    except FileNotFoundError:
                        pass
                    try:
                        version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                    except FileNotFoundError:
                        pass
                    if name:
                        software.append({"name": name, "version": version or ""})
                    winreg.CloseKey(subkey)
                except OSError:
                    pass
            except OSError:
                break
        winreg.CloseKey(key)

    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for s in software:
        key = (s["name"], s["version"])
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    return deduped
```

- [ ] **Step 6: Creează `agent/collectors/system_info.py`**

```python
"""Colectare info sistem: OS, firewall, utilizatori, BitLocker, Defender."""
from __future__ import annotations

import ctypes
import json
import os
import platform
import socket
import subprocess
import time

import psutil

from ..core import ScanProfile


def collect_system(cfg: ScanProfile) -> dict:
    out: dict = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "hostname": socket.gethostname(),
        "username": _username(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "is_admin": _is_admin(),
    }
    if cfg.include_firewall and platform.system() == "Windows":
        out["firewall"] = _firewall_status()
    if cfg.include_users and platform.system() == "Windows":
        out["local_users"] = _local_users()
    if cfg.include_bitlocker and platform.system() == "Windows":
        out["bitlocker"] = _bitlocker_status()
    if cfg.include_defender and platform.system() == "Windows":
        out["defender"] = _defender_status()
    return out


def _username() -> str:
    return os.environ.get("USERNAME") or os.environ.get("USER") or ""


def _is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def _ps(script: str, timeout: int = 30) -> str | None:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return None


def _firewall_status() -> dict:
    """Citeste profilurile firewall din registry."""
    profiles = {"domain": None, "private": None, "public": None}
    try:
        import winreg  # type: ignore[import-not-found]
        base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        for name, sub in [("domain", "DomainProfile"), ("private", "StandardProfile"), ("public", "PublicProfile")]:
            try:
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{base}\\{sub}")
                val, _ = winreg.QueryValueEx(k, "EnableFirewall")
                profiles[name] = bool(val)
                winreg.CloseKey(k)
            except (FileNotFoundError, OSError):
                pass
    except ImportError:
        pass
    return {"profiles": profiles}


def _local_users() -> list[dict]:
    """Conturi locale + flag is_admin."""
    out = _ps("Get-LocalUser | Select-Object Name, Enabled | ConvertTo-Json -Compress")
    users: list[dict] = []
    if out:
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for u in data:
                users.append({"name": u.get("Name", ""), "enabled": bool(u.get("Enabled", True)), "is_admin": False})
        except json.JSONDecodeError:
            pass

    admin_names = _ps("Get-LocalGroupMember -Group Administrators | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress")
    if admin_names:
        try:
            members = json.loads(admin_names)
            if isinstance(members, str):
                members = [members]
            short = {m.split("\\")[-1].lower() for m in members}
            for u in users:
                if u["name"].lower() in short:
                    u["is_admin"] = True
        except json.JSONDecodeError:
            pass
    return users


def _bitlocker_status() -> list[dict]:
    out = _ps("Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus, EncryptionPercentage | ConvertTo-Json -Compress")
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [
            {
                "volume": v.get("MountPoint", ""),
                "protection_status": str(v.get("ProtectionStatus", "")).lower() if v.get("ProtectionStatus") != 1 else "on",
                "encryption_percent": v.get("EncryptionPercentage", 0),
            }
            for v in data
        ]
    except json.JSONDecodeError:
        return []


def _defender_status() -> dict:
    out = _ps("Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated | ConvertTo-Json -Compress")
    if not out:
        return {}
    try:
        data = json.loads(out)
        enabled = bool(data.get("RealTimeProtectionEnabled", False))
        # AntivirusSignatureLastUpdated vine ca string ISO sau /Date(...)/
        sig_age = 0
        sig_raw = str(data.get("AntivirusSignatureLastUpdated", ""))
        if "Date(" in sig_raw:
            try:
                ms = int(sig_raw.split("Date(")[1].split(")")[0])
                sig_age = int((time.time() - ms / 1000) / 86400)
            except (ValueError, IndexError):
                pass
        return {"enabled": enabled, "signature_age_days": max(0, sig_age), "mode": data.get("AMRunningMode", "")}
    except json.JSONDecodeError:
        return {}
```

- [ ] **Step 7: Creează `agent/collectors/persistence.py`**

```python
"""Colectare persistente: startup, tasks, services, shares-ps_policy, WMI, registry hijack."""
from __future__ import annotations

import json
import platform
import subprocess

from ..core import ScanProfile


def collect_persistence(cfg: ScanProfile) -> dict:
    if platform.system() != "Windows":
        return {}

    out: dict = {}
    if cfg.include_startup:
        out["startup"] = _startup()
    if cfg.include_tasks:
        out["tasks"] = _tasks()
    if cfg.include_services:
        out["services"] = _services()
    if cfg.include_ps_policy:
        out["ps_policy"] = _ps_policy()
    if cfg.include_reg_hijack:
        out["reg_persistence"] = _reg_hijack()
    if cfg.include_wmi:
        out["wmi_subscriptions"] = _wmi_subscriptions()
    return out


def _ps(script: str, timeout: int = 60) -> str | None:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return None


def _startup() -> list[dict]:
    entries: list[dict] = []
    try:
        import winreg  # type: ignore[import-not-found]
        for hive, base in [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]:
            try:
                k = winreg.OpenKey(hive, base)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                        entries.append({"key": name, "path": str(value), "source": base})
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(k)
            except FileNotFoundError:
                pass
    except ImportError:
        pass
    return entries


def _tasks() -> list[dict]:
    out = _ps(
        "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
        "ForEach-Object { $a = $_.Actions[0]; [PSCustomObject]@{ "
        "Name=$_.TaskName; "
        "Action=(if ($a.Execute) { \"$($a.Execute) $($a.Arguments)\" } else { '' }) } } | "
        "ConvertTo-Json -Compress"
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [{"name": t.get("Name", ""), "action": t.get("Action", "")} for t in data]
    except json.JSONDecodeError:
        return []


def _services() -> list[dict]:
    out = _ps(
        "Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName | "
        "ConvertTo-Json -Compress"
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [
            {
                "name": s.get("Name", ""),
                "display_name": s.get("DisplayName", ""),
                "status": str(s.get("State", "")).lower(),
                "start_type": str(s.get("StartMode", "")).lower(),
                "binary_path": (s.get("PathName") or "").strip('"'),
            }
            for s in data
        ]
    except json.JSONDecodeError:
        return []


def _ps_policy() -> str:
    out = _ps("Get-ExecutionPolicy")
    return out or ""


def _reg_hijack() -> dict:
    """Citeste AppInit_DLLs, IFEO, Winlogon (chei clasice de persistenta)."""
    result: dict = {"AppInit_DLLs": "", "IFEO": {}, "Winlogon": {}}
    try:
        import winreg  # type: ignore[import-not-found]

        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")
            val, _ = winreg.QueryValueEx(k, "AppInit_DLLs")
            result["AppInit_DLLs"] = str(val).strip()
            winreg.CloseKey(k)
        except (FileNotFoundError, OSError):
            pass

        # IFEO: cauta subchei cu Debugger
        try:
            base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
            i = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(k, i)
                    i += 1
                    try:
                        sk = winreg.OpenKey(k, sub_name)
                        try:
                            dbg, _ = winreg.QueryValueEx(sk, "Debugger")
                            result["IFEO"][sub_name] = str(dbg)
                        except FileNotFoundError:
                            pass
                        winreg.CloseKey(sk)
                    except OSError:
                        pass
                except OSError:
                    break
            winreg.CloseKey(k)
        except FileNotFoundError:
            pass

        # Winlogon
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
            for valname in ("Userinit", "Shell", "Notify"):
                try:
                    v, _ = winreg.QueryValueEx(k, valname)
                    s = str(v).strip()
                    DEFAULTS = {
                        "Userinit": "C:\\Windows\\system32\\userinit.exe,",
                        "Shell": "explorer.exe",
                    }
                    if s and s != DEFAULTS.get(valname, ""):
                        result["Winlogon"][valname] = s
                except FileNotFoundError:
                    pass
            winreg.CloseKey(k)
        except FileNotFoundError:
            pass
    except ImportError:
        pass
    return result


def _wmi_subscriptions() -> list[dict]:
    out = _ps(
        "Get-WmiObject -Namespace root\\subscription -Class __EventConsumer -ErrorAction SilentlyContinue | "
        "Select-Object Name, CommandLineTemplate, ExecutablePath | ConvertTo-Json -Compress"
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [
            {
                "name": s.get("Name", ""),
                "command": s.get("CommandLineTemplate") or s.get("ExecutablePath") or "",
            }
            for s in data
        ]
    except json.JSONDecodeError:
        return []
```

- [ ] **Step 8: Creează `agent/collectors/forensics.py`**

```python
"""Colectare forensics: event log, hosts, DNS/ARP, certificate, fisiere recent modificate."""
from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from pathlib import Path

from ..core import ScanProfile


def collect_forensics(cfg: ScanProfile) -> dict:
    if platform.system() != "Windows":
        return {}

    out: dict = {}
    if cfg.include_eventlog:
        out["event_log"] = _event_log()
    if cfg.include_hosts:
        out["hosts"] = _hosts_file()
    if cfg.include_arp_dns:
        out["dns_cache"] = _dns_cache()
        out["arp_table"] = _arp_table()
    if cfg.include_certs:
        out["certificates"] = _root_certs()
    if cfg.include_recent_files:
        out["recent_files"] = _recent_files()
    return out


def _ps(script: str, timeout: int = 60) -> str | None:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return None


def _event_log() -> list[dict]:
    """Last 500 eventuri Security: 4625 (logon failure), 4672 (special priv), 4720 (user created)."""
    out = _ps(
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4672,4720} "
        "-MaxEvents 500 -ErrorAction SilentlyContinue | "
        "ForEach-Object { [PSCustomObject]@{ Id=$_.Id; "
        "Account=(($_.Properties | Select-Object -Skip 1 -First 1).Value); "
        "Time=$_.TimeCreated.ToString('o') } } | ConvertTo-Json -Compress",
        timeout=120,
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [
            {"event_id": e.get("Id", 0), "account": str(e.get("Account") or ""), "timestamp": e.get("Time", "")}
            for e in data
        ]
    except json.JSONDecodeError:
        return []


def _hosts_file() -> list[dict]:
    path = Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    entries: list[dict] = []
    try:
        with path.open(encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    entries.append({"ip": parts[0], "hostname": parts[1].split()[0]})
    except OSError:
        pass
    return entries


def _dns_cache() -> list[dict]:
    out = _ps(
        "Get-DnsClientCache -ErrorAction SilentlyContinue | "
        "Select-Object Entry, Data | ConvertTo-Json -Compress"
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [{"name": e.get("Entry", ""), "ip": e.get("Data", "")} for e in data[:200]]
    except json.JSONDecodeError:
        return []


def _arp_table() -> list[dict]:
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        entries: list[dict] = []
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0][0].isdigit():
                entries.append({"ip": parts[0], "mac": parts[1]})
        return entries[:200]
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        return []


def _root_certs() -> list[dict]:
    out = _ps(
        "Get-ChildItem Cert:\\LocalMachine\\Root -ErrorAction SilentlyContinue | "
        "Select-Object Subject, Issuer, Thumbprint | ConvertTo-Json -Compress",
        timeout=60,
    )
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [
            {"subject": c.get("Subject", ""), "issuer": c.get("Issuer", ""), "thumbprint": c.get("Thumbprint", "")}
            for c in data
        ]
    except json.JSONDecodeError:
        return []


def _recent_files() -> list[dict]:
    cutoff = time.time() - 7 * 86400
    roots = [Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32",
             Path("C:\\Program Files")]
    out: list[dict] = []
    for root in roots:
        if not root.exists():
            continue
        try:
            for entry in root.iterdir():
                try:
                    if entry.is_file():
                        mtime = entry.stat().st_mtime
                        if mtime > cutoff:
                            out.append({"path": str(entry), "modified": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(mtime))})
                except OSError:
                    continue
        except OSError:
            continue
        if len(out) > 100:
            break
    return out[:100]
```

- [ ] **Step 9: Rescrie `collect_system_data` în `agent/core.py`**

Înlocuiește funcția existentă `collect_system_data` (linia ~219) și funcțiile vechi `get_open_ports`, `get_processes`, `get_installed_software`, `is_admin` (le păstrăm doar pe is_admin care e folosită în alte locuri — celelalte se mută în colectori).

**Șterge** definițiile `get_open_ports`, `get_processes`, `get_installed_software`, `collect_system_data` din `agent/core.py`. **Păstrează** `is_admin()` (poate fi folosită din afară — verifică cu Grep mai jos).

**Adaugă** noul `collect_system_data` la finalul fișierului (înainte de `is_frozen()`):

```python
def collect_system_data(device_uid: str, scan_type: str = "standard",
                        progress_cb: Callable[[int, str], None] | None = None) -> dict:
    """Orchestrator: ruleaza colectorii activi pentru `scan_type`.
    `progress_cb(percent, phase)` este apelat intre colectori — util pentru
    UI in cazul scanarilor Advanced/Deep care dureaza minute."""
    from . import collectors  # import tardiv ca sa evitam circular import

    cfg = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["standard"])

    def step(pct: int, phase: str) -> None:
        if progress_cb is not None:
            try:
                progress_cb(pct, phase)
            except Exception:
                pass

    step(5, "Sistem & OS")
    sys_data = collectors.collect_system(cfg)

    step(15, "Retea")
    net_data = collectors.collect_network(cfg)

    step(35, "Procese")
    procs = collectors.collect_processes(cfg)

    step(55, "Software")
    software = collectors.collect_software(cfg)

    persistence = None
    if cfg.include_persistence:
        step(70, "Persistente")
        persistence = collectors.collect_persistence(cfg)

    forensics = None
    if cfg.include_forensics:
        step(85, "Forensics")
        forensics = collectors.collect_forensics(cfg)

    step(95, "Finalizare")

    os_keys = ("system", "release", "version", "machine", "hostname", "uptime_seconds", "is_admin", "username")
    si_keys = ("local_users", "firewall", "bitlocker", "defender")

    return {
        "device_uid": device_uid,
        "scan_type": scan_type,
        "os": {k: sys_data.get(k) for k in os_keys if k in sys_data},
        "system_info": {k: sys_data[k] for k in si_keys if k in sys_data},
        "network": net_data,
        "processes": procs,
        "software": software,
        "persistence": persistence,
        "forensics": forensics,
    }
```

Verifică unde mai sunt referințe la funcțiile șterse:

Run: `cd agent && python -c "from agent.core import is_admin, collect_system_data, SCAN_PROFILES; print(list(SCAN_PROFILES))"`

Așteaptă: `['standard', 'advanced', 'deep']`

- [ ] **Step 10: Verifică că agent/scan.py și agent/gui.py nu folosesc funcțiile șterse**

Run: `grep -n "get_open_ports\|get_processes\|get_installed_software" agent/scan.py agent/gui.py`

Dacă există apeluri, ele trebuie înlocuite cu `collect_system_data(...)` direct. (Probabil nu există — funcțiile interne erau folosite doar din `collect_system_data`.)

- [ ] **Step 11: Creează `agent/collectors/memory.md`**

Conținut:

```markdown
# agent/collectors/

Modul de colectori composabili. Fiecare functie primeste un `ScanProfile` (din `agent/core.py`) si returneaza datele relevante.

- `network.py` — `collect_network(cfg)` → `{open_ports, port_processes?, connections?, shares?, adapters?}`
- `processes.py` — `collect_processes(cfg)` → `list[{pid, name, memory_percent, cmdline?, ppid?}]`
- `software.py` — `collect_software(cfg)` → `list[{name, version}]` (Windows registry Uninstall)
- `system_info.py` — `collect_system(cfg)` → `{system, release, version, machine, hostname, uptime_seconds, is_admin, username, firewall?, local_users?, bitlocker?, defender?}`
- `persistence.py` — `collect_persistence(cfg)` → `{startup?, tasks?, services?, ps_policy?, reg_persistence?, wmi_subscriptions?}`
- `forensics.py` — `collect_forensics(cfg)` → `{event_log?, hosts?, dns_cache?, arp_table?, certificates?, recent_files?}`

Toti colectorii sunt no-op (returneaza `{}` / `[]`) pe platforme non-Windows pentru sub-colectorii Windows-only.
```

- [ ] **Step 12: Update `agent/memory.md`** — adaugă referință la `collectors/`, menționează `ScanProfile` + `SCAN_PROFILES` + `AGENT_VERSION` în `core.py`, `collect_system_data` semnătură nouă cu `scan_type` și `progress_cb`.

- [ ] **Step 13: Commit**

```bash
git add agent/collectors/ agent/core.py agent/memory.md
git commit -m "agent: ScanProfile + SCAN_PROFILES + 6 colectori composabili"
```

---

## Task 7 — Agent: heartbeat + progress în daemon, scan_type în run_one_job

**Files:**
- Modify: `agent/core.py`
- Modify: `agent/memory.md`

- [ ] **Step 1: Adaugă funcțiile API noi în `agent/core.py`**

După `api_submit_job_failure` (linia ~380), adaugă:

```python
def api_heartbeat(api_base: str, device_token: str, agent_version: str,
                  capabilities: list[str], os_version: str) -> None:
    """Trimite heartbeat la backend. Best-effort: nu arunca daca esueaza."""
    try:
        _request(
            "POST", f"{api_base}/agent/heartbeat",
            json={"agent_version": agent_version, "capabilities": capabilities, "os_version": os_version},
            headers={"X-Device-Token": device_token},
            timeout=10,
        )
    except ApiError:
        pass  # heartbeat best-effort


def api_send_progress(api_base: str, device_token: str, job_id: int,
                       progress: int, phase: str) -> None:
    """Trimite update de progres pentru un job activ. Best-effort."""
    try:
        _request(
            "POST", f"{api_base}/agent/jobs/{job_id}/progress",
            json={"progress": int(progress), "phase": phase[:128]},
            headers={"X-Device-Token": device_token},
            timeout=5,
        )
    except ApiError:
        pass
```

- [ ] **Step 2: Update `api_submit_job_result` pentru noile câmpuri**

Înlocuiește funcția:

```python
def api_submit_job_result(api_base: str, device_token: str, job_id: int, payload: dict) -> dict:
    body = {
        "os": payload.get("os", {}),
        "system_info": payload.get("system_info", {}),
        "network": payload.get("network", {}),
        "processes": payload.get("processes", []),
        "software": payload.get("software", []),
        "persistence": payload.get("persistence"),
        "forensics": payload.get("forensics"),
    }
    return _request(
        "POST", f"{api_base}/agent/jobs/{job_id}/result",
        json=body,
        headers={"X-Device-Token": device_token},
    )
```

- [ ] **Step 3: Rescrie `run_one_job` să propage `scan_type` + progress**

Înlocuiește funcția:

```python
def run_one_job(api_base: str, device_uid: str, device_token: str,
                job: dict, log: LogFn = _noop_log) -> None:
    """Executa un job. Foloseste scan_type din job pentru a alege profilul de colectare."""
    job_id = job["job_id"]
    scan_type = job.get("scan_type", "standard")
    log(f"[{_ts()}] Job #{job_id} primit ({scan_type}). Colectez date...", "info")

    def progress_cb(pct: int, phase: str) -> None:
        log(f"[{_ts()}] Job #{job_id} {pct}% — {phase}", "info")
        api_send_progress(api_base, device_token, job_id, pct, phase)

    try:
        data = collect_system_data(device_uid, scan_type=scan_type, progress_cb=progress_cb)
        result = api_submit_job_result(api_base, device_token, job_id, data)
        score = result.get("exposure_score")
        scan_id = result.get("scan_id")
        log(f"[{_ts()}] Job #{job_id} done ({scan_type}). Scan #{scan_id}, score {score}/100.", "ok")
    except ApiError as e:
        log(f"[{_ts()}] Job #{job_id} failed: {e}", "error")
        try:
            api_submit_job_failure(api_base, device_token, job_id, str(e))
        except ApiError:
            pass
    except Exception as e:
        log(f"[{_ts()}] Job #{job_id} eroare interna: {e}", "error")
        try:
            api_submit_job_failure(api_base, device_token, job_id, f"agent error: {e}")
        except ApiError:
            pass
```

- [ ] **Step 4: Update `daemon_loop` să trimită heartbeat la fiecare 10s**

Înlocuiește funcția:

```python
def daemon_loop(
    api_base: str, device_uid: str, device_token: str,
    *,
    poll_interval: int = 3,
    heartbeat_interval: int = 10,
    auto_interval: int = 0,
    log: LogFn = _noop_log,
    should_stop: Callable[[], bool] = lambda: False,
    should_pause: Callable[[], bool] = lambda: False,
) -> None:
    """Bucla daemon: heartbeat la 10s + polling joburi + auto-scan optional."""
    last_auto_scan = time.monotonic()
    last_heartbeat = 0.0

    capabilities = list(SCAN_PROFILES.keys())
    os_version = f"{platform.system()} {platform.release()} {platform.version()}"

    while not should_stop():
        if should_pause():
            time.sleep(min(poll_interval, 1))
            continue

        now = time.monotonic()
        if now - last_heartbeat >= heartbeat_interval:
            api_heartbeat(api_base, device_token, AGENT_VERSION, capabilities, os_version)
            last_heartbeat = now

        try:
            job = api_get_next_job(api_base, device_token)
        except ApiError as e:
            log(f"[{_ts()}] Eroare polling: {e}", "warn")
            _interruptible_sleep(poll_interval, should_stop)
            continue

        if job is not None:
            run_one_job(api_base, device_uid, device_token, job, log=log)
            continue

        if auto_interval and (time.monotonic() - last_auto_scan) >= auto_interval:
            log(f"[{_ts()}] Auto-scan (interval {auto_interval}s)...", "info")
            try:
                data = collect_system_data(device_uid)
                result = api_send_scan(api_base, device_token, data)
                log(f"[{_ts()}] Auto-scan done. Scan #{result.get('scan_id')}, "
                    f"score {result.get('exposure_score')}/100.", "ok")
            except ApiError as e:
                log(f"[{_ts()}] Auto-scan failed: {e}", "warn")
            last_auto_scan = time.monotonic()

        _interruptible_sleep(poll_interval, should_stop)
```

- [ ] **Step 5: Verifică sintaxa și că importurile sunt corecte**

Run: `cd agent && python -c "from agent.core import api_heartbeat, api_send_progress, run_one_job, daemon_loop, AGENT_VERSION; print(AGENT_VERSION)"`
Expected: `2.0.0`

- [ ] **Step 6: Rulează testele agentului existente**

Run: `cd agent && python -m pytest`
Expected: PASS (sau ajustează test_core.py dacă referențiază funcții vechi — vezi Task 15)

- [ ] **Step 7: Update `agent/memory.md`** — `core.py` are funcții noi: `api_heartbeat`, `api_send_progress`; `daemon_loop` trimite heartbeat la 10s; `run_one_job` propagă `scan_type` și progress.

- [ ] **Step 8: Commit**

```bash
git add agent/core.py agent/memory.md
git commit -m "agent: api_heartbeat + api_send_progress + scan_type in run_one_job"
```

---

## Task 8 — Agent GUI: simplificare pagină Status (remove Scan now, add platform link)

**Files:**
- Modify: `agent/gui.py`
- Modify: `agent/memory.md`

- [ ] **Step 1: Citește pagina Status existentă în `agent/gui.py`**

Run: `grep -n "scan now\|Scan now\|_render_status\|def _do_scan_now" agent/gui.py`

Identifică:
- Metoda care randează pagina Status (probabil `_render_status_page` sau similar)
- Butonul „Scan now" și handler-ul lui (`_do_scan_now`)
- Butonul „Open dashboard" (deja există)

- [ ] **Step 2: Șterge butonul „Scan now" și handler-ul lui**

În metoda `_render_status_page` (sau echivalent), șterge widget-ul/butonul „Scan now". Șterge complet metoda `_do_scan_now` (nu mai e apelată din nicio parte).

- [ ] **Step 3: Adaugă badge pentru nivelul maxim suportat + buton „Deschide platforma"**

În pagina Status, sub email și nume device, adaugă:

```python
# Badge nivel maxim suportat
caps_label = ttk.Label(
    parent, text="Niveluri suportate: Standard / Advanced / Deep",
    style="Subtitle.TLabel"
)
caps_label.pack(anchor="w", pady=(4, 0))

# Link „Deschide platforma"
platform_url = self._api_base.replace("/api/v1", "").rstrip("/")
if not platform_url.startswith("http"):
    platform_url = "http://" + platform_url

open_btn = ttk.Button(
    parent, text="Deschide platforma în browser",
    style="Accent.TButton",
    command=lambda: webbrowser.open(platform_url),
)
open_btn.pack(fill="x", pady=(12, 0))
```

(Adaptează la layout-ul actual — folosește același `parent` și aceleași stiluri ca celelalte butoane.)

- [ ] **Step 4: Adaugă o linie clară de status: „Scanarea se inițiază din platformă"**

Sub badge-ul cu nivelele suportate, adaugă:

```python
hint = ttk.Label(
    parent,
    text="ⓘ Scanarea se initiaza din platforma web — agentul ruleaza in fundal.",
    style="Dim.TLabel",
)
hint.pack(anchor="w", pady=(8, 0))
```

- [ ] **Step 5: Testează GUI-ul manual**

Run: `cd agent && python scan.py gui`  (sau `python -m agent.scan gui` din radacina)

Verifică:
- Pagina Status NU mai are buton „Scan now"
- Apare badge-ul cu nivelele
- Apare butonul „Deschide platforma" care deschide browserul
- Daemon-ul rulează în fundal (vezi log-ul)

- [ ] **Step 6: Update `agent/memory.md`** — `gui.py` are pagina Status simplificată: fără Scan now, cu link către platformă.

- [ ] **Step 7: Commit**

```bash
git add agent/gui.py agent/memory.md
git commit -m "agent gui: simplificare pagina Status — remove Scan now, add platform link"
```

---

## Task 9 — Frontend: types + API client

**Files:**
- Modify: `web/src/api/types.ts`
- Modify: `web/src/api/exposure.ts`
- Modify: `web/src/api/memory.md`

- [ ] **Step 1: Update `web/src/api/types.ts`**

Înlocuiește tipurile relevante:

```typescript
export type ScanType = "standard" | "advanced" | "deep";

export type Finding = {
  rule_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info" | string;
  evidence?: unknown;
  recommendation: string;
};

export type DeviceScanListItem = {
  scan_id: number;
  created_at: string;
  exposure_score: number;
};

export type Device = {
  id: number;
  device_uid: string;
  name: string;
  created_at: string;
  is_online?: boolean;
  last_heartbeat?: string | null;
  agent_version?: string | null;
  capabilities?: string[];
};

export type ScanPayload = {
  scan_type?: ScanType;
  os?: {
    system?: string;
    release?: string;
    version?: string;
    machine?: string;
    hostname?: string;
    is_admin?: boolean;
    uptime_seconds?: number;
    username?: string;
  };
  system_info?: Record<string, unknown>;
  network?: {
    open_ports?: number[];
    connections?: unknown[];
    shares?: unknown[];
    adapters?: unknown[];
  };
  processes?: { pid: number; name: string; memory_percent: number; cmdline?: string }[];
  software?: { name: string; version?: string }[];
  persistence?: Record<string, unknown> | null;
  forensics?: Record<string, unknown> | null;
};

export type ScanDetailResponse = {
  scan_id: number;
  device_uid: string;
  device_name: string;
  created_at: string;
  exposure_score: number;
  findings: Finding[];
  payload?: ScanPayload;
  scan_type?: ScanType;
};

export type ScanJobStatus = "pending" | "running" | "done" | "failed" | "cancelled";

export type ScanJobResponse = {
  job_id: number;
  device_uid: string;
  device_name: string;
  status: ScanJobStatus;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  scan_id?: number | null;
  exposure_score?: number | null;
  error_message?: string | null;
  scan_type?: ScanType;
  progress?: number;
  phase?: string | null;
};
```

- [ ] **Step 2: Update `requestScan` în `web/src/api/exposure.ts`**

Înlocuiește funcția:

```typescript
import { apiGet, apiPost } from "./client";
import type {
  DeviceScanListItem,
  ScanDetailResponse,
  ScanJobResponse,
  ScanType,
} from "./types";

export function listDeviceScans(deviceId: string) {
  return apiGet<DeviceScanListItem[]>(
    `/devices/${encodeURIComponent(deviceId)}/scans`,
  );
}

export function getScan(scanId: number) {
  return apiGet<ScanDetailResponse>(`/scans/${scanId}`);
}

export function requestScan(deviceUid: string, scanType: ScanType = "standard") {
  return apiPost<{ scan_type: ScanType }, ScanJobResponse>(
    `/devices/${encodeURIComponent(deviceUid)}/scan-jobs`,
    { scan_type: scanType },
  );
}

export function getScanJob(jobId: number) {
  return apiGet<ScanJobResponse>(`/scan-jobs/${jobId}`);
}

export function listScanJobs(deviceUid: string) {
  return apiGet<ScanJobResponse[]>(
    `/devices/${encodeURIComponent(deviceUid)}/scan-jobs`,
  );
}

export function getAgentDownloadInfo() {
  return apiGet<{
    available: boolean;
    platform: string;
    size_bytes: number | null;
  }>("/agent/download/info");
}
```

- [ ] **Step 3: Verifică TypeScript**

Run: `cd web && npx tsc --noEmit`
Expected: 0 errors (sau doar din pagini care folosesc `Device` — vor fi rezolvate în Task 10).

- [ ] **Step 4: Update `web/src/api/memory.md`** — `types.ts` are `ScanType`, `Device` extins, `ScanJobResponse` cu `progress/phase/scan_type`. `exposure.ts` — `requestScan` ia parametrul `scanType`.

- [ ] **Step 5: Commit**

```bash
git add web/src/api/types.ts web/src/api/exposure.ts web/src/api/memory.md
git commit -m "web/api: tipuri pentru scan types + heartbeat + progress"
```

---

## Task 10 — Frontend Devices.tsx: online badge + scan type selector

**Files:**
- Modify: `web/src/pages/Devices.tsx`
- Modify: `web/src/pages/memory.md`
- Modify (opt): `web/src/App.css` sau `index.css` pentru clase noi

- [ ] **Step 1: Update tipul `Device` local să folosească tipul din api/types**

În top-of-file, înlocuiește:

```typescript
import type { ScanJobResponse, Device, ScanType } from "../api/types";
```

și **șterge** declarația locală `type Device = {...}` (linia 8-13). Folosește tipul importat.

`type DeviceCreateResponse = Device & { device_token: string };` rămâne.

- [ ] **Step 2: Adaugă state pentru tipul de scanare per device**

În componenta `Devices`, lângă `activeJob`:

```typescript
const [scanTypeByDevice, setScanTypeByDevice] = useState<Record<string, ScanType>>({});
```

- [ ] **Step 3: Update `loadDevices` să forțeze refresh la 15s pentru is_online**

Adaugă un interval în `useEffect`:

```typescript
useEffect(() => {
  loadDevices();
  getAgentDownloadInfo()
    .then(info => setAgentInfo({ available: info.available, size_bytes: info.size_bytes }))
    .catch(() => setAgentInfo({ available: false, size_bytes: null }));

  // Refresh online status la 15s (heartbeat = 10s, prag 30s).
  const refresh = setInterval(loadDevices, 15_000);

  return () => {
    Object.values(pollTimers.current).forEach(t => clearTimeout(t));
    clearInterval(refresh);
  };
}, []);
```

- [ ] **Step 4: Update handler-ul „Scan now" să trimită scan_type**

În handler-ul existent (probabil `handleScanNow` sau similar), schimbă apelul `requestScan(uid)` în:

```typescript
const scanType = scanTypeByDevice[uid] ?? "standard";
const job = await requestScan(uid, scanType);
```

- [ ] **Step 5: Adaugă render-ul pentru online badge + scan type selector în lista de device-uri**

În JSX-ul fiecărui device, adaugă lângă numele device-ului:

```jsx
<span className={`device-online-badge ${d.is_online ? "online" : "offline"}`}>
  {d.is_online ? "● Online" : "○ Offline"}
</span>
{d.is_online && d.agent_version && (
  <span className="device-meta">v{d.agent_version}</span>
)}
```

Și înlocuiește butonul „Scan now" simplu cu un selector + buton:

```jsx
<div className="scan-controls">
  <select
    className="scan-type-select"
    value={scanTypeByDevice[d.device_uid] ?? "standard"}
    onChange={e => setScanTypeByDevice(prev => ({
      ...prev,
      [d.device_uid]: e.target.value as ScanType,
    }))}
    disabled={!d.is_online}
  >
    <option value="standard">Standard (est. 45–90s)</option>
    <option value="advanced">Advanced (est. 3–8 min)</option>
    <option value="deep">Deep (est. 10–20 min)</option>
  </select>
  <button
    className="btn btn-primary"
    disabled={!d.is_online || activeJob[d.device_uid]?.status === "running"}
    title={!d.is_online ? "Agentul nu este conectat" : "Pornește scanare"}
    onClick={() => handleScanNow(d.device_uid)}
  >
    {activeJob[d.device_uid]?.status === "running" ? "Scanare în curs…" : "Scanează acum"}
  </button>
</div>
```

- [ ] **Step 6: Adaugă progress bar când există un job RUNNING**

Sub butonul de scan, când există job activ:

```jsx
{activeJob[d.device_uid]?.status === "running" && (
  <div className="job-progress">
    <div className="job-progress-bar">
      <div
        className="job-progress-fill"
        style={{ width: `${activeJob[d.device_uid]?.progress ?? 0}%` }}
      />
    </div>
    <span className="job-progress-label">
      {activeJob[d.device_uid]?.progress ?? 0}% — {activeJob[d.device_uid]?.phase ?? "Pornire…"}
    </span>
  </div>
)}
```

- [ ] **Step 7: Adaugă CSS pentru clasele noi**

În `web/src/index.css` (sau App.css — vezi unde sunt definite celelalte clase), adaugă:

```css
.device-online-badge { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; margin-left: 8px; }
.device-online-badge.online { background: rgba(74, 222, 128, 0.15); color: #4ade80; }
.device-online-badge.offline { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }
.device-meta { font-size: 11px; color: var(--text-muted); margin-left: 8px; font-family: 'JetBrains Mono', monospace; }

.scan-controls { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
.scan-type-select { background: var(--surface); color: var(--text); border: 1px solid var(--border); padding: 6px 10px; border-radius: 6px; font-size: 13px; }
.scan-type-select:disabled { opacity: 0.5; cursor: not-allowed; }

.job-progress { margin-top: 10px; }
.job-progress-bar { width: 100%; height: 6px; background: var(--surface); border-radius: 3px; overflow: hidden; }
.job-progress-fill { height: 100%; background: linear-gradient(90deg, #38bdf8, #4ade80); transition: width 0.5s ease; }
.job-progress-label { display: block; font-size: 11px; color: var(--text-secondary); margin-top: 4px; }
```

- [ ] **Step 8: Pornește dev server + verifică manual**

Run în 3 terminale:
1. `docker compose up -d`
2. `cd server && fastapi dev app/main.py`
3. `cd web && npm run dev`

Apoi:
- Login
- Verifică că device-urile arată "○ Offline" inițial
- Pornește agentul (`python -m agent.gui`)
- După ~10s, device-ul devine "● Online"
- Selectează "Standard" și click „Scanează acum" — vezi progress bar
- Repetă cu „Advanced" / „Deep"

- [ ] **Step 9: Update `web/src/pages/memory.md`** — `Devices.tsx` are online badge + scan type selector + progress bar.

- [ ] **Step 10: Commit**

```bash
git add web/src/pages/Devices.tsx web/src/index.css web/src/pages/memory.md
git commit -m "web/Devices: online badge + scan type selector + progress bar"
```

---

## Task 11 — Frontend ScanDetail.tsx: redesign cu categorii + finding panel

**Files:**
- Modify: `web/src/pages/ScanDetail.tsx`
- Modify: `web/src/index.css` (clase noi)
- Modify: `web/src/pages/memory.md`

- [ ] **Step 1: Mapare rule_id → categorie**

În top of `ScanDetail.tsx`, după imports:

```typescript
type Category = "persistence" | "network" | "system" | "software" | "processes" | "forensics";

const CATEGORY_META: Record<Category, { label: string; icon: string }> = {
  persistence: { label: "Persistență", icon: "🔒" },
  network:     { label: "Rețea", icon: "🌐" },
  system:      { label: "Sistem & OS", icon: "🖥️" },
  software:    { label: "Software", icon: "📦" },
  processes:   { label: "Procese & Servicii", icon: "⚙️" },
  forensics:   { label: "Event Log & Forensics", icon: "📋" },
};

const RULE_CATEGORY: Record<string, Category> = {
  "NET-OPEN-PORTS-1": "network",
  "NET-MANY-PORTS-2": "network",
  "NET-SHARE-1":      "network",
  "NET-ESTABLISHED-1":"network",
  "OS-ADMIN-1":       "system",
  "OS-EOL-1":         "system",
  "FW-DISABLED-1":    "system",
  "USER-ADMIN-1":     "system",
  "PS-POLICY-1":      "system",
  "AV-DISABLED-1":    "system",
  "BITLOCKER-OFF-1":  "system",
  "SW-VULNERABLE-1":  "software",
  "PROC-SUSPICIOUS-1":"processes",
  "PROC-POWERSHELL-2":"processes",
  "SVC-SUSPICIOUS-1": "processes",
  "STARTUP-SUSPICIOUS-1": "persistence",
  "TASK-SUSPICIOUS-1":    "persistence",
  "REG-HIJACK-1":         "persistence",
  "WMI-PERSIST-1":        "persistence",
  "EVENTLOG-BRUTEFORCE-1":"forensics",
  "EVENTLOG-PRIVESC-1":   "forensics",
  "HOSTS-TAMPERED-1":     "forensics",
  "CERT-UNTRUSTED-1":     "forensics",
};

function categoryOf(ruleId: string): Category {
  return RULE_CATEGORY[ruleId] ?? "system";
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
};
```

- [ ] **Step 2: Înlocuiește componenta `FindingCard` cu versiunea de detail panel**

Înlocuiește componenta existentă:

```typescript
function FindingDetailPanel({ finding }: { finding: Finding }) {
  return (
    <div className={`finding-detail ${finding.severity.toLowerCase()}`}>
      <div className="finding-detail-header">
        <span className={`severity-badge ${getSeverityClass(finding.severity)}`}>
          {finding.severity.toUpperCase()}
        </span>
        <h3 className="finding-detail-title">{finding.title}</h3>
        <span className="finding-detail-id">{finding.rule_id}</span>
      </div>

      <section className="finding-section">
        <h4>Recomandare</h4>
        <p>{finding.recommendation}</p>
      </section>

      {!!finding.evidence && Object.keys(finding.evidence as object).length > 0 && (
        <section className="finding-section">
          <h4>Dovezi</h4>
          <pre className="finding-evidence">
            {JSON.stringify(finding.evidence, null, 2)}
          </pre>
        </section>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Înlocuiește layout-ul principal al `ScanDetail`**

Înlocuiește JSX-ul de retur (sub `if (loading) ... if (error) ... if (!data) ...`):

```typescript
  const findingsByCategory = useMemo(() => {
    if (!data) return {} as Record<Category, Finding[]>;
    const out: Record<string, Finding[]> = {};
    for (const f of data.findings) {
      const cat = categoryOf(f.rule_id);
      (out[cat] ??= []).push(f);
    }
    // sortare descrescatoare dupa severitate in fiecare categorie
    for (const cat in out) {
      out[cat].sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0));
    }
    return out as Record<Category, Finding[]>;
  }, [data]);

  const categories = useMemo(() => {
    return (Object.keys(CATEGORY_META) as Category[])
      .filter(c => (findingsByCategory[c]?.length ?? 0) > 0);
  }, [findingsByCategory]);

  const [activeCategory, setActiveCategory] = useState<Category | null>(null);

  useEffect(() => {
    if (!activeCategory && categories.length > 0) {
      setActiveCategory(categories[0]);
    }
  }, [categories, activeCategory]);

  const [selectedFindingIdx, setSelectedFindingIdx] = useState(0);

  useEffect(() => {
    setSelectedFindingIdx(0);
  }, [activeCategory]);

  const activeFindings = activeCategory ? (findingsByCategory[activeCategory] ?? []) : [];
  const selectedFinding = activeFindings[selectedFindingIdx];
```

Și returnul:

```jsx
  return (
    <>
      <Navbar />
      <div className="scan-detail-page">
        <header className="scan-detail-topbar">
          <button onClick={() => navigate(-1)} className="btn btn-ghost">← Înapoi</button>
          <div className="scan-detail-meta">
            <h1>{data.device_name}</h1>
            <span className={`scan-type-badge ${data.scan_type ?? "standard"}`}>
              {(data.scan_type ?? "standard").toUpperCase()}
            </span>
            <span className="scan-date">{formatDate(data.created_at)}</span>
          </div>
        </header>

        <div className="scan-detail-grid">
          {/* Coloana stanga: score + sidebar categorii */}
          <aside className="scan-detail-sidebar">
            <div className={`score-gauge ${getScoreClass(data.exposure_score)}`}>
              <div className="score-value">{data.exposure_score}</div>
              <div className="score-label">/ 100</div>
            </div>
            <div className="score-summary">
              <strong>{data.findings.length}</strong> vulnerabilități găsite
            </div>

            <nav className="category-nav">
              {categories.map(cat => {
                const items = findingsByCategory[cat] ?? [];
                const topSev = items[0]?.severity ?? "info";
                return (
                  <button
                    key={cat}
                    className={`category-item ${activeCategory === cat ? "active" : ""}`}
                    onClick={() => setActiveCategory(cat)}
                  >
                    <span className="category-icon">{CATEGORY_META[cat].icon}</span>
                    <span className="category-label">{CATEGORY_META[cat].label}</span>
                    <span className={`category-count severity-${topSev}`}>{items.length}</span>
                  </button>
                );
              })}
              {categories.length === 0 && (
                <div className="no-findings">✓ Nicio vulnerabilitate detectată</div>
              )}
            </nav>
          </aside>

          {/* Coloana dreapta: lista findings + detail panel */}
          <main className="scan-detail-main">
            {activeCategory && activeFindings.length > 0 ? (
              <>
                <div className="finding-list">
                  {activeFindings.map((f, i) => (
                    <button
                      key={`${f.rule_id}-${i}`}
                      className={`finding-list-item ${i === selectedFindingIdx ? "active" : ""}`}
                      onClick={() => setSelectedFindingIdx(i)}
                    >
                      <span className={`severity-dot severity-${f.severity}`}></span>
                      <span className="finding-list-title">{f.title}</span>
                    </button>
                  ))}
                </div>
                {selectedFinding && <FindingDetailPanel finding={selectedFinding} />}
              </>
            ) : (
              <div className="empty-state">
                Selectează o categorie din stânga pentru a vedea detaliile.
              </div>
            )}
          </main>
        </div>
      </div>
    </>
  );
}
```

- [ ] **Step 4: Adaugă CSS pentru noul layout în `web/src/index.css`**

```css
.scan-detail-page { padding: 24px 32px; max-width: 1400px; margin: 0 auto; }
.scan-detail-topbar { display: flex; align-items: center; gap: 16px; margin-bottom: 24px; }
.scan-detail-meta { display: flex; align-items: center; gap: 12px; }
.scan-detail-meta h1 { margin: 0; font-size: 22px; }
.scan-type-badge { padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; letter-spacing: 0.05em; }
.scan-type-badge.standard { background: rgba(56, 189, 248, 0.15); color: #38bdf8; }
.scan-type-badge.advanced { background: rgba(251, 191, 36, 0.15); color: #fbbf24; }
.scan-type-badge.deep { background: rgba(248, 113, 113, 0.15); color: #f87171; }
.scan-date { color: var(--text-muted); font-size: 13px; }

.scan-detail-grid { display: grid; grid-template-columns: 260px 1fr; gap: 24px; }
.scan-detail-sidebar { display: flex; flex-direction: column; gap: 16px; }
.score-gauge { background: var(--surface); border-radius: 12px; padding: 24px; text-align: center; border: 1px solid var(--border); }
.score-value { font-size: 56px; font-weight: 700; line-height: 1; }
.score-gauge.score-high .score-value { color: #f87171; }
.score-gauge.score-medium .score-value { color: #fbbf24; }
.score-gauge.score-low .score-value { color: #38bdf8; }
.score-gauge.score-none .score-value { color: #4ade80; }
.score-label { font-size: 14px; color: var(--text-muted); }
.score-summary { font-size: 13px; color: var(--text-secondary); text-align: center; padding: 8px; }

.category-nav { display: flex; flex-direction: column; gap: 4px; }
.category-item { display: flex; align-items: center; gap: 10px; padding: 10px 12px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; color: var(--text); cursor: pointer; text-align: left; }
.category-item:hover { background: var(--surface-hover); }
.category-item.active { background: var(--accent-dim); border-color: var(--accent); }
.category-icon { font-size: 18px; }
.category-label { flex: 1; font-size: 13px; }
.category-count { padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; background: var(--surface-hover); }
.category-count.severity-critical { background: rgba(248,113,113,0.2); color: #f87171; }
.category-count.severity-high { background: rgba(251,146,60,0.2); color: #fb923c; }
.category-count.severity-medium { background: rgba(251,191,36,0.2); color: #fbbf24; }
.category-count.severity-low { background: rgba(148,163,184,0.2); color: #94a3b8; }
.no-findings { padding: 24px 12px; text-align: center; color: #4ade80; font-size: 13px; }

.scan-detail-main { display: grid; grid-template-columns: 280px 1fr; gap: 16px; }
.finding-list { display: flex; flex-direction: column; gap: 4px; max-height: 70vh; overflow-y: auto; padding-right: 4px; }
.finding-list-item { display: flex; align-items: flex-start; gap: 10px; padding: 10px 12px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; color: var(--text); cursor: pointer; text-align: left; }
.finding-list-item.active { background: var(--accent-dim); border-color: var(--accent); }
.finding-list-title { font-size: 13px; line-height: 1.4; }
.severity-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; margin-top: 6px; }
.severity-dot.severity-critical, .severity-dot.severity-high { background: #f87171; }
.severity-dot.severity-medium { background: #fbbf24; }
.severity-dot.severity-low { background: #94a3b8; }

.finding-detail { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px 24px; }
.finding-detail-header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
.finding-detail-title { margin: 0; font-size: 18px; flex: 1; }
.finding-detail-id { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-muted); }
.finding-section { margin-bottom: 16px; }
.finding-section h4 { margin: 0 0 6px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); }
.finding-evidence { background: var(--bg-base); padding: 12px; border-radius: 8px; font-size: 12px; color: var(--text-secondary); overflow-x: auto; max-height: 320px; }

.empty-state { padding: 48px; text-align: center; color: var(--text-muted); }
```

- [ ] **Step 5: Verifică TypeScript**

Run: `cd web && npx tsc --noEmit`
Expected: 0 errors

- [ ] **Step 6: Testare manuală**

Rulează scan Deep pe un device → deschide ScanDetail. Verifică:
- Top bar: nume device + badge `DEEP` + dată
- Score gauge afișează scorul cu culoarea corectă
- Sidebar: categoriile apar cu icoane și badge-uri de count
- Click pe categorie → lista de findings se actualizează în coloana din mijloc
- Click pe un finding → detail panel afișează severity, titlu, recomandare, evidence

- [ ] **Step 7: Update `web/src/pages/memory.md`** — `ScanDetail.tsx` redesign complet cu category sidebar + finding detail panel.

- [ ] **Step 8: Commit**

```bash
git add web/src/pages/ScanDetail.tsx web/src/index.css web/src/pages/memory.md
git commit -m "web/ScanDetail: redesign cu category sidebar + finding detail panel"
```

---

## Task 12 — Frontend Dashboard.tsx: progress bar + scan_type badge

**Files:**
- Modify: `web/src/pages/Dashboard.tsx`
- Modify: `web/src/pages/memory.md`

- [ ] **Step 1: Polling job activ pentru a afișa progress bar**

În `Dashboard`, când există un device selectat, polleaza `listScanJobs(deviceUid)` la 2s atâta timp cât există un job RUNNING. Adaugă state:

```typescript
const [activeJob, setActiveJob] = useState<ScanJobResponse | null>(null);
```

Și un useEffect care polleaza:

```typescript
useEffect(() => {
  if (!deviceId.trim()) return;
  let cancelled = false;
  let timer: ReturnType<typeof setTimeout> | null = null;

  async function tick() {
    try {
      const jobs = await listScanJobs(deviceId.trim());
      if (cancelled) return;
      const running = jobs.find(j => j.status === "running" || j.status === "pending");
      setActiveJob(running ?? null);
    } catch {
      setActiveJob(null);
    }
    if (!cancelled) timer = setTimeout(tick, 2000);
  }
  tick();
  return () => { cancelled = true; if (timer) clearTimeout(timer); };
}, [deviceId]);
```

Importă `listScanJobs` și `ScanJobResponse`:

```typescript
import { getScan, listDeviceScans, listScanJobs } from "../api/exposure";
import type { DeviceScanListItem, ScanDetailResponse, ScanJobResponse } from "../api/types";
```

- [ ] **Step 2: Adaugă progress bar deasupra listei de scanări**

În JSX, înainte de lista de scanări:

```jsx
{activeJob && (activeJob.status === "running" || activeJob.status === "pending") && (
  <div className="dashboard-active-job">
    <div className="active-job-header">
      <span className={`scan-type-badge ${activeJob.scan_type ?? "standard"}`}>
        {(activeJob.scan_type ?? "standard").toUpperCase()}
      </span>
      <span>Scanare în curs: {activeJob.phase ?? "Pornire…"}</span>
    </div>
    <div className="job-progress-bar">
      <div className="job-progress-fill" style={{ width: `${activeJob.progress ?? 0}%` }} />
    </div>
    <span className="job-progress-label">{activeJob.progress ?? 0}%</span>
  </div>
)}
```

- [ ] **Step 3: Adaugă scan_type badge pe fiecare scan din listă**

Pentru fiecare item din lista de scanări, dacă `detail.scan_type` e disponibil când e selectat — afișează-l. Pentru itemii din lista compact, scan_type nu vine în `DeviceScanListItem` — adaugă-l în Task 13 sau lasă-l doar pe ScanDetail.

(Pentru moment, lasă lista compact fără badge — adaugă-l doar când e încărcat `detail`.)

- [ ] **Step 4: Adaugă CSS**

În `web/src/index.css`:

```css
.dashboard-active-job { background: var(--surface); border: 1px solid var(--accent); border-radius: 10px; padding: 12px 16px; margin-bottom: 16px; }
.active-job-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; font-size: 13px; }
```

(`.job-progress-bar` și `.job-progress-fill` sunt deja definite în Task 10.)

- [ ] **Step 5: Verifică manual**

În browser, pornește o scanare Deep dintr-un device → mergi pe Dashboard cu acel device selectat → vezi progress bar-ul actualizându-se în timp real.

- [ ] **Step 6: Update `web/src/pages/memory.md`**

- [ ] **Step 7: Commit**

```bash
git add web/src/pages/Dashboard.tsx web/src/index.css web/src/pages/memory.md
git commit -m "web/Dashboard: progress bar pentru scanari active + scan_type badge"
```

---

## Task 13 — Backend tests: scan_types end-to-end + progress

**Files:**
- Create: `server/tests/test_progress.py`
- Modify: `server/tests/test_scan_jobs.py` (extindere)
- Modify: `server/memory.md`

- [ ] **Step 1: Test end-to-end scan_type**

Creează `server/tests/test_progress.py`:

```python
"""Progress + scan_type flow complet: create job -> agent picks -> progress -> result."""
import uuid


def _enroll(auth_client) -> tuple[str, str]:
    uid = f"dev-{uuid.uuid4().hex[:8]}"
    r = auth_client["client"].post(
        "/api/v1/devices",
        json={"device_uid": uid, "name": "Test"},
        headers=auth_client["headers"],
    )
    assert r.status_code == 200
    return uid, r.json()["device_token"]


def test_scan_type_propagated_to_agent(auth_client):
    uid, token = _enroll(auth_client)
    client = auth_client["client"]

    # UI creeaza job de tip deep
    r = client.post(
        f"/api/v1/devices/{uid}/scan-jobs",
        json={"scan_type": "deep"},
        headers=auth_client["headers"],
    )
    assert r.status_code == 200
    job = r.json()
    assert job["scan_type"] == "deep"
    assert job["progress"] == 0

    # Agent ridica jobul si primeste scan_type
    r = client.get("/api/v1/agent/jobs/next", headers={"X-Device-Token": token})
    assert r.status_code == 200
    agent_job = r.json()
    assert agent_job["scan_type"] == "deep"


def test_progress_update_flow(auth_client):
    uid, token = _enroll(auth_client)
    client = auth_client["client"]

    r = client.post(
        f"/api/v1/devices/{uid}/scan-jobs",
        json={"scan_type": "advanced"},
        headers=auth_client["headers"],
    )
    job_id = r.json()["job_id"]

    # Agent ridica jobul (pending -> running)
    client.get("/api/v1/agent/jobs/next", headers={"X-Device-Token": token})

    # Trimite update progres
    r = client.post(
        f"/api/v1/agent/jobs/{job_id}/progress",
        json={"progress": 45, "phase": "Procese"},
        headers={"X-Device-Token": token},
    )
    assert r.status_code == 204

    # UI polleaza
    r = client.get(f"/api/v1/scan-jobs/{job_id}", headers=auth_client["headers"])
    body = r.json()
    assert body["progress"] == 45
    assert body["phase"] == "Procese"
    assert body["status"] == "running"


def test_progress_rejected_on_done_job(auth_client):
    uid, token = _enroll(auth_client)
    client = auth_client["client"]

    r = client.post(
        f"/api/v1/devices/{uid}/scan-jobs",
        json={"scan_type": "standard"},
        headers=auth_client["headers"],
    )
    job_id = r.json()["job_id"]

    client.get("/api/v1/agent/jobs/next", headers={"X-Device-Token": token})

    # Submit result -> job devine done
    client.post(
        f"/api/v1/agent/jobs/{job_id}/result",
        json={
            "os": {"system": "Windows", "release": "11", "is_admin": False},
            "network": {"open_ports": []},
            "processes": [],
            "software": [],
            "system_info": {},
        },
        headers={"X-Device-Token": token},
    )

    # Progress update pe job done -> 409
    r = client.post(
        f"/api/v1/agent/jobs/{job_id}/progress",
        json={"progress": 100, "phase": "Finalizat"},
        headers={"X-Device-Token": token},
    )
    assert r.status_code == 409


def test_scan_result_evaluates_with_scan_type(auth_client):
    uid, token = _enroll(auth_client)
    client = auth_client["client"]

    r = client.post(
        f"/api/v1/devices/{uid}/scan-jobs",
        json={"scan_type": "deep"},
        headers=auth_client["headers"],
    )
    job_id = r.json()["job_id"]
    client.get("/api/v1/agent/jobs/next", headers={"X-Device-Token": token})

    # Trimite date care contin un WMI subscription (rezultat doar la deep)
    r = client.post(
        f"/api/v1/agent/jobs/{job_id}/result",
        json={
            "os": {"system": "Windows", "release": "11", "is_admin": False},
            "network": {"open_ports": []},
            "processes": [],
            "software": [],
            "system_info": {},
            "persistence": {"wmi_subscriptions": [{"name": "Evil", "command": "cmd.exe"}]},
            "forensics": {},
        },
        headers={"X-Device-Token": token},
    )
    assert r.status_code == 200
    body = r.json()
    # Verifica scan_type vine in detail
    scan_id = body["scan_id"]
    r = client.get(f"/api/v1/scans/{scan_id}", headers=auth_client["headers"])
    detail = r.json()
    assert detail["scan_type"] == "deep"
    assert any(f["rule_id"] == "WMI-PERSIST-1" for f in detail["findings"])
```

- [ ] **Step 2: Rulează testele**

Run: `cd server && python -m pytest tests/test_progress.py -v`
Expected: PASS (4 teste)

- [ ] **Step 3: Rulează tot test-suite-ul**

Run: `cd server && python -m pytest`
Expected: PASS pentru toate testele.

- [ ] **Step 4: Update `server/memory.md`** — adaugă `test_progress.py`.

- [ ] **Step 5: Commit**

```bash
git add server/tests/test_progress.py server/memory.md
git commit -m "tests: end-to-end scan_type + progress flow"
```

---

## Task 14 — Agent tests: collectors structure + SCAN_PROFILES valid

**Files:**
- Create: `agent/tests/test_collectors.py`
- Modify: `agent/tests/memory.md`

- [ ] **Step 1: Test pentru SCAN_PROFILES + structura colectori**

Creează `agent/tests/test_collectors.py`:

```python
"""SCAN_PROFILES valid + colectori returneaza structuri asteptate.
Note: tests run on Windows (dev machine); on non-Windows, Windows-only
sub-collectors return empty/default — verificat doar ce e cross-platform."""
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent.core import ScanProfile, SCAN_PROFILES, collect_system_data
from agent import collectors


def test_scan_profiles_have_three_levels():
    assert set(SCAN_PROFILES.keys()) == {"standard", "advanced", "deep"}


def test_standard_profile_minimal():
    p = SCAN_PROFILES["standard"]
    assert p.process_limit == 30
    assert p.include_cmdline is False
    assert p.include_software is True
    assert p.include_persistence is False
    assert p.include_forensics is False


def test_advanced_profile_includes_persistence():
    p = SCAN_PROFILES["advanced"]
    assert p.process_limit is None
    assert p.include_cmdline is True
    assert p.include_persistence is True
    assert p.include_services is True
    assert p.include_forensics is False


def test_deep_profile_includes_forensics():
    p = SCAN_PROFILES["deep"]
    assert p.include_forensics is True
    assert p.include_wmi is True
    assert p.include_bitlocker is True
    assert p.include_defender is True


def test_collect_network_returns_open_ports_list():
    cfg = SCAN_PROFILES["standard"]
    data = collectors.collect_network(cfg)
    assert "open_ports" in data
    assert isinstance(data["open_ports"], list)


def test_collect_network_advanced_includes_connections_key():
    cfg = SCAN_PROFILES["advanced"]
    data = collectors.collect_network(cfg)
    assert "connections" in data


def test_collect_processes_respects_limit():
    cfg = SCAN_PROFILES["standard"]
    procs = collectors.collect_processes(cfg)
    assert isinstance(procs, list)
    assert len(procs) <= 30
    if procs:
        assert "pid" in procs[0]
        assert "memory_percent" in procs[0]
        assert "cmdline" not in procs[0]


def test_collect_processes_advanced_has_cmdline():
    cfg = SCAN_PROFILES["advanced"]
    procs = collectors.collect_processes(cfg)
    if procs:
        assert "cmdline" in procs[0]


def test_collect_system_has_basic_fields():
    cfg = SCAN_PROFILES["standard"]
    data = collectors.collect_system(cfg)
    for k in ("system", "release", "hostname", "is_admin", "uptime_seconds"):
        assert k in data


def test_collect_system_data_standard_structure():
    data = collect_system_data("test-uid", scan_type="standard")
    assert data["scan_type"] == "standard"
    assert data["device_uid"] == "test-uid"
    assert "os" in data and "system" in data["os"]
    assert "network" in data
    assert isinstance(data["network"].get("open_ports"), list)
    assert data["persistence"] is None
    assert data["forensics"] is None


def test_collect_system_data_advanced_includes_persistence():
    data = collect_system_data("test-uid", scan_type="advanced")
    assert data["scan_type"] == "advanced"
    if platform.system() == "Windows":
        assert data["persistence"] is not None
    assert data["forensics"] is None


def test_collect_system_data_deep_includes_forensics():
    data = collect_system_data("test-uid", scan_type="deep")
    assert data["scan_type"] == "deep"
    if platform.system() == "Windows":
        assert data["persistence"] is not None
        assert data["forensics"] is not None


def test_collect_system_data_progress_callback_called():
    calls: list[tuple[int, str]] = []
    collect_system_data("x", scan_type="standard", progress_cb=lambda p, ph: calls.append((p, ph)))
    assert len(calls) > 0
    assert calls[0][0] >= 0
    assert all(0 <= p <= 100 for p, _ in calls)
```

- [ ] **Step 2: Rulează testele**

Run: `cd agent && python -m pytest tests/test_collectors.py -v`
Expected: PASS (toate testele). Pe Windows toate trec; pe alt OS, testele Windows-specific (`if platform.system() == "Windows"`) sunt skipped logic.

- [ ] **Step 3: Update `agent/tests/memory.md`** — adaugă `test_collectors.py`.

- [ ] **Step 4: Commit**

```bash
git add agent/tests/test_collectors.py agent/tests/memory.md
git commit -m "tests: agent collectors structure + SCAN_PROFILES valid"
```

---

## Task 15 — Smoke test final + actualizare CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`
- Modify: `memory.md` (root)

- [ ] **Step 1: Smoke test final manual**

Pornește toate componentele:

```powershell
# 1. DB
docker compose up -d
# 2. Backend
cd server; .\.venv\Scripts\Activate; fastapi dev app/main.py
# 3. Frontend (alt terminal)
cd web; npm run dev
# 4. Agent GUI (alt terminal)
cd agent; python scan.py gui
```

Pași de validare:
1. Login în browser (`http://localhost:5173`)
2. În agent GUI: enroll (vezi UID, salvează token)
3. Așteaptă 10s → device-ul apare „● Online" în pagina Devices
4. Selectează „Standard" → click Scanează → progress bar 0→100%, scor apare
5. Selectează „Advanced" → click Scanează → progress bar afișează faze (Sistem, Rețea, Procese, …) → durează 3-8 min
6. Selectează „Deep" → click Scanează → durează 10-20 min → la final, deschide ScanDetail → vezi categoriile cu icoane, click pe „Persistență" → vezi findings WMI/Registry dacă există
7. Oprește agent GUI → așteaptă 30s → device-ul devine „○ Offline" + butonul de scan e dezactivat

- [ ] **Step 2: Update root `memory.md`**

Adaugă/actualizează secțiunile principale: 3 tipuri scan, 23 reguli, arhitectură platform-centrică, heartbeat, progress real-time.

- [ ] **Step 3: Update `CLAUDE.md`**

În secțiunea „Rules engine" actualizează numărul (23 reguli) și menționează decorator `@rule(id, min_level)`. În secțiunea „Scan-on-demand flow" adaugă endpoint-urile noi: `POST /agent/heartbeat`, `POST /agent/jobs/{id}/progress`. Adaugă secțiune nouă „Scan types" cu cele 3 niveluri.

- [ ] **Step 4: Rulează tot test-suite-ul final**

Run: `cd server && python -m pytest && cd ..\agent && python -m pytest`
Expected: PASS pe ambele (toate testele backend + agent).

- [ ] **Step 5: Commit final**

```bash
git add CLAUDE.md memory.md
git commit -m "docs: actualizare CLAUDE.md + memory.md pentru scan types + arhitectura platform-centrica"
```

- [ ] **Step 6: Push (opțional, dacă vrei să creezi PR)**

```bash
git push origin main
```

---

## Self-Review

**Spec coverage:** Toate secțiunile spec-ului (3 niveluri scanare, 23 reguli, 6 colectori, heartbeat, progress, ScanDetail redesign, modificări DB, teste) au câte o task corespunzător.

**Placeholder scan:** Toate „TBD"-urile au fost eliminate. Codul din fiecare step este complet și executabil.

**Type consistency:**
- `ScanProfile` cu toate flag-urile (definit Task 6, folosit în Task 6/7).
- `SCAN_PROFILES["standard"|"advanced"|"deep"]` consistent peste tot.
- `evaluate(scan)` semnatura nu se schimbă — doar adaugă `scan_type` ca cheie opțională în input.
- `AgentJobOut.scan_type` (Task 2) propagat în `api_get_next_job` (Task 7) → folosit în `run_one_job` (Task 7).
- `JobResultIn.system_info|persistence|forensics` (Task 2) trimis de `api_submit_job_result` (Task 7).
- `_rule_id`, `_min_level` setate de decorator, citite de `evaluate()`.
- Frontend `ScanType` import consistent în Devices.tsx, ScanDetail.tsx, exposure.ts.

**Idempotență:** `docker compose down -v` rulat o dată după Task 1 — DB recreat. Apoi tabelele se completează prin `Base.metadata.create_all()` la pornirea backend-ului.

---

## Execution Handoff

**Plan complet, salvat la `docs/superpowers/plans/2026-05-11-scan-types-platform-centric.md`. Două opțiuni de execuție:**

**1. Subagent-Driven (recomandat)** — Dispatch fresh subagent pe fiecare task, review între task-uri, iterație rapidă.

**2. Inline Execution** — Execuție task cu task în sesiunea curentă (sau una nouă cu Opus), checkpoints pentru review.

**Care abordare?**
