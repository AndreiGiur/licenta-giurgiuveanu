# Agent Connectivity + Live Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix progresul nemonoton la scanare, afiseaza nmap in timp real, si adauga vizualizare live a conectivitatii Agent↔Backend↔Platforma + trafic de retea.

**Architecture:** Reutilizam canalul de progres existent (`/agent/jobs/{id}/progress`) pentru nmap real-time si heartbeat-ul (la 10s) pentru trafic. Backend tine traficul intr-un ring-buffer in-memory; frontend afiseaza diagrama de conexiune + grafic trafic. Agentul ramane pull-only.

**Tech Stack:** Python (psutil, subprocess), FastAPI, Pydantic 2, React + TypeScript, Recharts, Framer Motion, pytest, vitest.

---

## Comenzi de test

- Agent: `python -m pytest agent/tests/<file> -v` (din radacina repo)
- Server: `cd server; $env:DISABLE_SCHEDULER="true"; $env:DISABLE_RATELIMIT="true"; .\.venv\Scripts\python.exe -m pytest tests/<file> -v`
- Frontend: `cd web; npm test`

---

# FAZA 1 — Fix progres (#3) + Nmap real-time (#4)

### Task 1: Parser pentru liniile de progres nmap

**Files:**
- Modify: `agent/nmap_runner.py`
- Test: `agent/tests/test_nmap_runner.py`

- [ ] **Step 1: Write the failing test**

```python
# in agent/tests/test_nmap_runner.py
from agent.nmap_runner import parse_nmap_stats_line

def test_parse_nmap_stats_line_with_percent_and_eta():
    line = "Stats: 0:00:30 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan\nSYN Stealth Scan Timing: About 45.23% done; ETC: 16:32 (0:00:35 remaining)"
    res = parse_nmap_stats_line(line)
    assert res is not None
    pct, remaining = res
    assert abs(pct - 45.23) < 0.01
    assert remaining == "0:00:35"

def test_parse_nmap_stats_line_no_match_returns_none():
    assert parse_nmap_stats_line("Starting Nmap 7.99") is None
    assert parse_nmap_stats_line("") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest agent/tests/test_nmap_runner.py::test_parse_nmap_stats_line_with_percent_and_eta -v`
Expected: FAIL — `ImportError: cannot import name 'parse_nmap_stats_line'`

- [ ] **Step 3: Implement parser**

```python
# in agent/nmap_runner.py, dupa import-uri
import re

_STATS_RE = re.compile(r"About\s+([\d.]+)%\s+done", re.IGNORECASE)
_REMAINING_RE = re.compile(r"\(([\d:]+)\s+remaining\)", re.IGNORECASE)


def parse_nmap_stats_line(line: str) -> tuple[float, str] | None:
    """Extrage (percent, timp_ramas) dintr-o linie de progres nmap (--stats-every).
    Intoarce None daca linia nu contine progres."""
    m = _STATS_RE.search(line or "")
    if not m:
        return None
    pct = float(m.group(1))
    rem_m = _REMAINING_RE.search(line)
    remaining = rem_m.group(1) if rem_m else ""
    return pct, remaining
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest agent/tests/test_nmap_runner.py -k parse_nmap_stats -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add agent/nmap_runner.py agent/tests/test_nmap_runner.py
git commit -m "feat(nmap): parser pentru liniile de progres --stats-every"
```

---

### Task 2: run_nmap streaming cu progress_cb + --stats-every

**Files:**
- Modify: `agent/nmap_runner.py` (functia `run_nmap` + `NMAP_PROFILES`)
- Test: `agent/tests/test_nmap_runner.py`

- [ ] **Step 1: Write the failing test** (verifica ca `--stats-every` e in args + ca run_nmap accepta progress_cb fara nmap instalat returneaza eroare clara)

```python
# in agent/tests/test_nmap_runner.py
from agent.nmap_runner import build_nmap_args

def test_build_args_include_stats_every_for_profiles():
    args = build_nmap_args(targets=["127.0.0.1"], xml_out="x.xml", profile="deep")
    assert "--stats-every" in args
    joined = " ".join(args)
    assert "2s" in joined
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest agent/tests/test_nmap_runner.py::test_build_args_include_stats_every_for_profiles -v`
Expected: FAIL — `--stats-every` not in args

- [ ] **Step 3: Add --stats-every in build_nmap_args (ramura profile)**

In `build_nmap_args`, in ramura `if profile in NMAP_PROFILES:`, dupa adaugarea scripturilor:

```python
        args.extend(["--stats-every", "2s"])
```

- [ ] **Step 4: Refactor run_nmap la Popen cu streaming**

Inlocuieste corpul `run_nmap` (partea cu `subprocess.run`) cu:

```python
    cmd = [str(nmap)] + args
    if log:
        log(f"nmap: {' '.join(cmd)}", "info")
    import time as _time
    start = _time.time()
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except OSError as e:
        raise NmapRunnerError(f"nmap nu a putut porni: {e}") from e

    stderr_acc: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        stderr_acc.append(line)
        parsed = parse_nmap_stats_line(line)
        if parsed and progress_cb:
            pct, remaining = parsed
            try:
                progress_cb(pct, remaining)
            except Exception:
                pass
        if _time.time() - start > timeout_sec:
            proc.kill()
            raise NmapRunnerError(f"nmap timeout dupa {timeout_sec}s")
    proc.wait(timeout=30)
    return proc.returncode, "".join(stderr_acc)
```

Si extinde semnatura `run_nmap` cu `progress_cb=None`:

```python
def run_nmap(
    targets: list[str],
    xml_out: Path,
    top_ports: Optional[int] = 1000,
    all_ports: bool = False,
    timeout_sec: int = 1800,
    profile: str = "legacy",
    progress_cb=None,
    log=None,
) -> tuple[int, str]:
```

- [ ] **Step 5: Run tests**

Run: `python -m pytest agent/tests/test_nmap_runner.py -v`
Expected: PASS (toate, inclusiv cele vechi care nu trimit progress_cb)

- [ ] **Step 6: Commit**

```bash
git add agent/nmap_runner.py agent/tests/test_nmap_runner.py
git commit -m "feat(nmap): streaming Popen cu --stats-every + progress_cb"
```

---

### Task 3: collect_system_data cu max_progress (fix monoton)

**Files:**
- Modify: `agent/core.py` (`collect_system_data`)
- Test: `agent/tests/test_core.py`

- [ ] **Step 1: Write the failing test**

```python
# in agent/tests/test_core.py
def test_collect_system_data_scales_progress_to_max():
    from agent import core
    seen = []
    core.collect_system_data("uid", scan_type="standard",
                             progress_cb=lambda p, ph: seen.append(p),
                             max_progress=65)
    assert seen, "progress_cb trebuie apelat"
    assert max(seen) <= 65, f"progresul nu trebuie sa depaseasca 65, got {seen}"
    # monoton crescator
    assert seen == sorted(seen), f"progres nemonoton: {seen}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest agent/tests/test_core.py::test_collect_system_data_scales_progress_to_max -v`
Expected: FAIL — `collect_system_data() got an unexpected keyword argument 'max_progress'`

- [ ] **Step 3: Add max_progress param + scaling**

In `collect_system_data` signatura, adauga `max_progress: int = 100`. Inlocuieste functia `step`:

```python
    def step(pct: int, phase: str) -> None:
        if progress_cb is not None:
            try:
                scaled = round(pct / 100 * max_progress)
                progress_cb(scaled, phase)
            except Exception:
                pass
```

(Daca semnatura `collect_system_data` nu are inca `progress_cb`/`max_progress`, adauga-le ambele.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest agent/tests/test_core.py::test_collect_system_data_scales_progress_to_max -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent/core.py agent/tests/test_core.py
git commit -m "fix(progress): collect_system_data scaleaza la max_progress (monoton)"
```

---

### Task 4: Mapare progres nmap 65-95 + run_one_job

**Files:**
- Modify: `agent/core.py` (`_run_nmap_if_needed`, `run_one_job`)
- Test: `agent/tests/test_core.py`

- [ ] **Step 1: Write the failing test** (verifica ca run_one_job cere max_progress=65 pentru advanced/deep)

```python
# in agent/tests/test_core.py
def test_run_one_job_caps_collection_progress_for_deep(monkeypatch):
    from agent import core
    captured = {}
    def fake_collect(uid, scan_type="standard", progress_cb=None, max_progress=100):
        captured["max_progress"] = max_progress
        return {"os": {}, "network": {"open_ports": []}, "processes": [], "software": []}
    monkeypatch.setattr(core, "collect_system_data", fake_collect)
    monkeypatch.setattr(core, "_run_nmap_if_needed", lambda *a, **k: None)
    monkeypatch.setattr(core, "api_submit_job_result", lambda *a, **k: {"scan_id": 1, "exposure_score": 0})
    monkeypatch.setattr(core, "api_send_progress", lambda *a, **k: None)
    core.run_one_job("http://x", "uid", "tok", {"job_id": 1, "scan_type": "deep"})
    assert captured["max_progress"] == 65
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest agent/tests/test_core.py::test_run_one_job_caps_collection_progress_for_deep -v`
Expected: FAIL — `max_progress` ramane 100

- [ ] **Step 3: Update run_one_job + _run_nmap_if_needed**

In `run_one_job`, inlocuieste apelul `collect_system_data`:

```python
        nmap_will_run = scan_type in ("advanced", "deep")
        collect_max = 65 if nmap_will_run else 100
        data = collect_system_data(device_uid, scan_type=scan_type,
                                   progress_cb=progress_cb, max_progress=collect_max)
        nmap_result = _run_nmap_if_needed(job, log=log, progress_cb=progress_cb)
```

In `_run_nmap_if_needed`, inlocuieste blocul care apela `run_nmap` (fostul `progress_cb(80, ...)`):

```python
        def _nmap_progress(pct: float, remaining: str) -> None:
            # nmap 0-100 → global 65-95
            global_pct = 65 + round(pct / 100 * 30)
            eta = f" (ETC {remaining})" if remaining else ""
            if progress_cb:
                progress_cb(global_pct, f"Nmap: {pct:.0f}%{eta}")

        if progress_cb:
            progress_cb(65, "Nmap pornit...")
        ...
        exit_code, stderr = nmap_runner.run_nmap(
            targets=targets, xml_out=xml_out, profile=scan_type,
            progress_cb=_nmap_progress, log=log,
        )
```

(Sterge vechiul `progress_cb(80, phase)`.)

- [ ] **Step 4: Run tests**

Run: `python -m pytest agent/tests/test_core.py -v`
Expected: PASS (toate)

- [ ] **Step 5: Commit**

```bash
git add agent/core.py agent/tests/test_core.py
git commit -m "feat(nmap): progres real-time mapat 65-95% + colectare capata la 65%"
```

---

# FAZA 2 — Heartbeat extins + livestate + endpoint (#C)

### Task 5: HeartbeatIn extins cu campuri net

**Files:**
- Modify: `server/app/schemas.py` (`HeartbeatIn`)
- Test: `server/tests/test_heartbeat.py`

- [ ] **Step 1: Write the failing test**

```python
# in server/tests/test_heartbeat.py
def test_heartbeat_accepts_net_fields(auth_client):
    from conftest import make_token_pair
    c = auth_client["client"]; h = auth_client["headers"]
    tok, th = make_token_pair()
    c.post("/api/v1/devices", headers=h, json={"device_uid": "netdev", "name": "N", "token_hash": th})
    r = c.post("/api/v1/agent/heartbeat", headers={"X-Device-Token": tok}, json={
        "agent_version": "1.0", "capabilities": [], "os_version": "Win11",
        "net_bytes_sent": 1000, "net_bytes_recv": 2000, "net_conn_count": 5,
    })
    assert r.status_code == 204, r.text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd server; $env:DISABLE_SCHEDULER="true"; $env:DISABLE_RATELIMIT="true"; .\.venv\Scripts\python.exe -m pytest tests/test_heartbeat.py::test_heartbeat_accepts_net_fields -v`
Expected: FAIL (422 daca extra-forbidden) sau ignora campurile — verifica ca devin acceptate explicit.

- [ ] **Step 3: Add fields to HeartbeatIn**

```python
# in server/app/schemas.py, in clasa HeartbeatIn
    net_bytes_sent: int | None = None
    net_bytes_recv: int | None = None
    net_conn_count: int | None = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: ...`pytest tests/test_heartbeat.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server/app/schemas.py server/tests/test_heartbeat.py
git commit -m "feat(heartbeat): campuri net_bytes_sent/recv/conn_count"
```

---

### Task 6: Modul livestate (ring-buffer trafic)

**Files:**
- Create: `server/app/livestate.py`
- Test: `server/tests/test_livestate.py`

- [ ] **Step 1: Write the failing test**

```python
# server/tests/test_livestate.py
from server.app import livestate

def test_record_computes_rate_and_caps_buffer():
    livestate.reset()
    # primul sample: fara rata (baseline)
    livestate.record_sample(device_id=1, ts=1000.0, sent=0, recv=0, conn_count=2)
    # al doilea: 10s mai tarziu, +10000 bytes sent, +20000 recv
    livestate.record_sample(device_id=1, ts=1010.0, sent=10000, recv=20000, conn_count=3)
    series = livestate.get_series(1)
    assert len(series) >= 1
    last = series[-1]
    assert last["conn_count"] == 3
    # 10000 bytes / 10s = 1000 B/s ≈ 0.98 KB/s
    assert abs(last["sent_rate_kbps"] - (10000/10/1024)) < 0.01

def test_buffer_capped_at_60():
    livestate.reset()
    for i in range(80):
        livestate.record_sample(device_id=2, ts=float(i), sent=i*1000, recv=i*1000, conn_count=1)
    assert len(livestate.get_series(2)) <= 60

def test_series_isolated_per_device():
    livestate.reset()
    livestate.record_sample(device_id=1, ts=1.0, sent=0, recv=0, conn_count=1)
    livestate.record_sample(device_id=2, ts=1.0, sent=0, recv=0, conn_count=9)
    assert livestate.get_series(99) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: ...`pytest tests/test_livestate.py -v`
Expected: FAIL — `ModuleNotFoundError: server.app.livestate`

- [ ] **Step 3: Implement livestate**

```python
# server/app/livestate.py
"""Ring-buffer in-memory pentru traficul de retea live per device.

Date efemere de tip 'live monitor' — se pierd la restart backend (acceptabil).
Capat la 60 sample-uri/device (~10 min la 10s).
"""
from __future__ import annotations

from collections import deque
from threading import Lock

MAX_SAMPLES = 60

# device_id -> deque de sample-uri {ts, sent_rate_kbps, recv_rate_kbps, conn_count}
_buffers: dict[int, deque] = {}
# device_id -> ultimul (ts, sent, recv) cumulativ pentru calcul rata
_last_raw: dict[int, tuple[float, int, int]] = {}
_lock = Lock()


def reset() -> None:
    with _lock:
        _buffers.clear()
        _last_raw.clear()


def record_sample(device_id: int, ts: float, sent: int, recv: int, conn_count: int) -> None:
    """Inregistreaza un sample cumulativ; calculeaza rata fata de sample-ul anterior."""
    with _lock:
        prev = _last_raw.get(device_id)
        _last_raw[device_id] = (ts, sent, recv)
        if prev is None:
            return  # baseline, fara rata
        p_ts, p_sent, p_recv = prev
        dt = ts - p_ts
        if dt <= 0:
            return
        sent_rate = max(0, sent - p_sent) / dt / 1024.0
        recv_rate = max(0, recv - p_recv) / dt / 1024.0
        buf = _buffers.setdefault(device_id, deque(maxlen=MAX_SAMPLES))
        buf.append({
            "ts": ts,
            "sent_rate_kbps": round(sent_rate, 2),
            "recv_rate_kbps": round(recv_rate, 2),
            "conn_count": conn_count,
        })


def get_series(device_id: int) -> list[dict]:
    with _lock:
        return list(_buffers.get(device_id, []))
```

- [ ] **Step 4: Run tests**

Run: ...`pytest tests/test_livestate.py -v`
Expected: PASS (3)

- [ ] **Step 5: Commit**

```bash
git add server/app/livestate.py server/tests/test_livestate.py
git commit -m "feat(livestate): ring-buffer in-memory pentru trafic per device"
```

---

### Task 7: agent_heartbeat alimenteaza livestate

**Files:**
- Modify: `server/app/routes/agent.py` (`agent_heartbeat`)
- Test: `server/tests/test_livestate.py`

- [ ] **Step 1: Write the failing test**

```python
# in server/tests/test_livestate.py
def test_heartbeat_feeds_livestate(auth_client):
    from conftest import make_token_pair
    from server.app import livestate
    livestate.reset()
    c = auth_client["client"]; h = auth_client["headers"]
    tok, th = make_token_pair()
    c.post("/api/v1/devices", headers=h, json={"device_uid": "hbnet", "name": "H", "token_hash": th})
    dh = {"X-Device-Token": tok}
    base = {"agent_version": "1.0", "capabilities": [], "os_version": "Win11"}
    c.post("/api/v1/agent/heartbeat", headers=dh, json={**base, "net_bytes_sent": 0, "net_bytes_recv": 0, "net_conn_count": 1})
    c.post("/api/v1/agent/heartbeat", headers=dh, json={**base, "net_bytes_sent": 10240, "net_bytes_recv": 0, "net_conn_count": 2})
    # device id necunoscut direct; verificam ca exista cel putin o serie nenula
    import server.app.livestate as ls
    all_series = [s for d in ls._buffers for s in ls.get_series(d)]
    assert any(s["conn_count"] == 2 for s in all_series)
```

- [ ] **Step 2: Run test to verify it fails**

Run: ...`pytest tests/test_livestate.py::test_heartbeat_feeds_livestate -v`
Expected: FAIL — buffer gol

- [ ] **Step 3: Update agent_heartbeat**

In `server/app/routes/agent.py`, in `agent_heartbeat`, dupa `db.commit()`:

```python
    if payload.net_bytes_sent is not None and payload.net_bytes_recv is not None:
        from ..livestate import record_sample
        from ._helpers import _utcnow
        record_sample(
            device_id=device.id,
            ts=_utcnow().timestamp(),
            sent=payload.net_bytes_sent,
            recv=payload.net_bytes_recv,
            conn_count=payload.net_conn_count or 0,
        )
```

- [ ] **Step 4: Run tests**

Run: ...`pytest tests/test_livestate.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server/app/routes/agent.py server/tests/test_livestate.py
git commit -m "feat(heartbeat): alimenteaza livestate cu sample-uri de trafic"
```

---

### Task 8: Endpoint GET /devices/{uid}/net-traffic

**Files:**
- Modify: `server/app/routes/devices.py`
- Test: `server/tests/test_livestate.py`

- [ ] **Step 1: Write the failing test**

```python
# in server/tests/test_livestate.py
def test_net_traffic_endpoint_returns_series_and_isolates(auth_client):
    from conftest import make_token_pair
    from server.app import livestate
    livestate.reset()
    c = auth_client["client"]; h = auth_client["headers"]
    tok, th = make_token_pair()
    c.post("/api/v1/devices", headers=h, json={"device_uid": "trafdev", "name": "T", "token_hash": th})
    dh = {"X-Device-Token": tok}
    base = {"agent_version": "1.0", "capabilities": [], "os_version": "Win11"}
    c.post("/api/v1/agent/heartbeat", headers=dh, json={**base, "net_bytes_sent": 0, "net_bytes_recv": 0, "net_conn_count": 1})
    c.post("/api/v1/agent/heartbeat", headers=dh, json={**base, "net_bytes_sent": 10240, "net_bytes_recv": 5120, "net_conn_count": 2})
    r = c.get("/api/v1/devices/trafdev/net-traffic", headers=h)
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list) and len(data) >= 1
    assert "sent_rate_kbps" in data[-1] and "conn_count" in data[-1]
    # device inexistent → 404
    r2 = c.get("/api/v1/devices/nope/net-traffic", headers=h)
    assert r2.status_code == 404
```

- [ ] **Step 2: Run test to verify it fails**

Run: ...`pytest tests/test_livestate.py::test_net_traffic_endpoint_returns_series_and_isolates -v`
Expected: FAIL — 404 pe ruta inexistenta

- [ ] **Step 3: Add endpoint in devices.py**

```python
# in server/app/routes/devices.py
from ..livestate import get_series

@router.get("/devices/{device_uid}/net-traffic", tags=["devices"])
def device_net_traffic(device_uid: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Serie de trafic live (ultimele ~10 min) pentru graficul de retea."""
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")
    return get_series(device.id)
```

- [ ] **Step 4: Run tests**

Run: ...`pytest tests/test_livestate.py -v`
Expected: PASS (toate)

- [ ] **Step 5: Commit**

```bash
git add server/app/routes/devices.py server/tests/test_livestate.py
git commit -m "feat(api): GET /devices/{uid}/net-traffic din ring-buffer"
```

---

### Task 9: Agentul trimite net_io_counters in heartbeat

**Files:**
- Modify: `agent/core.py` (functia care construieste payload-ul heartbeat — `api_heartbeat` apelant / daemon loop)
- Test: `agent/tests/test_core.py`

- [ ] **Step 1: Write the failing test**

```python
# in agent/tests/test_core.py
def test_build_heartbeat_payload_includes_net():
    from agent import core
    p = core.build_heartbeat_payload(["standard"])
    assert "net_bytes_sent" in p and "net_bytes_recv" in p
    assert isinstance(p["net_bytes_sent"], int)
    assert "net_conn_count" in p
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest agent/tests/test_core.py::test_build_heartbeat_payload_includes_net -v`
Expected: FAIL — `build_heartbeat_payload` nu exista

- [ ] **Step 3: Implement build_heartbeat_payload + foloseste-l in daemon**

```python
# in agent/core.py
def build_heartbeat_payload(capabilities: list[str]) -> dict:
    """Construieste payload-ul heartbeat incl. contoare trafic net (psutil)."""
    import psutil
    try:
        io = psutil.net_io_counters()
        sent, recv = int(io.bytes_sent), int(io.bytes_recv)
    except Exception:
        sent, recv = 0, 0
    try:
        conn_count = len([c for c in psutil.net_connections(kind="inet")
                          if c.status == "ESTABLISHED"])
    except Exception:
        conn_count = 0
    return {
        "agent_version": AGENT_VERSION,
        "capabilities": capabilities,
        "os_version": f"{platform.system()} {platform.release()}",
        "net_bytes_sent": sent,
        "net_bytes_recv": recv,
        "net_conn_count": conn_count,
    }
```

Apoi in `daemon_loop`, inlocuieste construirea manuala a payload-ului heartbeat cu `build_heartbeat_payload(caps)` inainte de `api_heartbeat`. (Verifica `import platform` exista la nivel de modul; daca nu, adauga-l.)

- [ ] **Step 4: Run tests**

Run: `python -m pytest agent/tests/test_core.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent/core.py agent/tests/test_core.py
git commit -m "feat(agent): heartbeat trimite net_io_counters + nr conexiuni"
```

---

# FAZA 3 — Frontend UI (#1 diagrama + #2 grafic + #4 panou)

### Task 10: Tip + hook useNetworkTraffic

**Files:**
- Modify: `web/src/api/types.ts` (tip `NetTrafficPoint`)
- Modify: `web/src/api/exposure.ts` (`getNetTraffic`)
- Create: `web/src/hooks/useNetworkTraffic.ts`
- Test: `web/src/hooks/useNetworkTraffic.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// web/src/hooks/useNetworkTraffic.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { useNetworkTraffic } from "./useNetworkTraffic";

vi.mock("../api/exposure", () => ({ getNetTraffic: vi.fn() }));
import { getNetTraffic } from "../api/exposure";
const m = getNetTraffic as ReturnType<typeof vi.fn>;

describe("useNetworkTraffic", () => {
  beforeEach(() => vi.clearAllMocks());
  it("nu fetch-uieste cand uid gol", () => {
    const { result } = renderHook(() => useNetworkTraffic(""));
    expect(m).not.toHaveBeenCalled();
    expect(result.current).toEqual([]);
  });
  it("intoarce seria primita", async () => {
    m.mockResolvedValue([{ ts: 1, sent_rate_kbps: 5, recv_rate_kbps: 2, conn_count: 3 }]);
    const { result } = renderHook(() => useNetworkTraffic("dev1"));
    await waitFor(() => expect(result.current.length).toBe(1));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web; npm test -- useNetworkTraffic`
Expected: FAIL — module not found

- [ ] **Step 3: Implement type, api, hook**

```ts
// in web/src/api/types.ts
export type NetTrafficPoint = {
  ts: number;
  sent_rate_kbps: number;
  recv_rate_kbps: number;
  conn_count: number;
};
```

```ts
// in web/src/api/exposure.ts
import type { NetTrafficPoint } from "./types";
export function getNetTraffic(deviceUid: string) {
  return apiGet<NetTrafficPoint[]>(`/devices/${encodeURIComponent(deviceUid)}/net-traffic`);
}
```

```ts
// web/src/hooks/useNetworkTraffic.ts
import { useEffect, useState } from "react";
import { getNetTraffic } from "../api/exposure";
import type { NetTrafficPoint } from "../api/types";

const POLL_MS = 10000;

export function useNetworkTraffic(deviceUid: string): NetTrafficPoint[] {
  const [series, setSeries] = useState<NetTrafficPoint[]>([]);
  useEffect(() => {
    const uid = deviceUid.trim();
    if (!uid) { setSeries([]); return; }
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    async function tick() {
      try {
        const data = await getNetTraffic(uid);
        if (!cancelled) setSeries(data);
      } catch { /* offline / fara date */ }
      if (!cancelled) timer = setTimeout(tick, POLL_MS);
    }
    tick();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, [deviceUid]);
  return series;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web; npm test -- useNetworkTraffic`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add web/src/api/types.ts web/src/api/exposure.ts web/src/hooks/useNetworkTraffic.ts web/src/hooks/useNetworkTraffic.test.ts
git commit -m "feat(fe): hook useNetworkTraffic + API getNetTraffic"
```

---

### Task 11: Component ConnectionTopology (#1)

**Files:**
- Create: `web/src/components/ConnectionTopology.tsx`
- Test: `web/src/components/ConnectionTopology.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
// web/src/components/ConnectionTopology.test.tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ConnectionTopology } from "./ConnectionTopology";

describe("ConnectionTopology", () => {
  it("afiseaza cele 3 noduri", () => {
    render(<ConnectionTopology online={true} lastHeartbeat={new Date().toISOString()} scanActive={false} />);
    expect(screen.getByText(/Agent/i)).toBeInTheDocument();
    expect(screen.getByText(/Backend/i)).toBeInTheDocument();
    expect(screen.getByText(/Platform/i)).toBeInTheDocument();
  });
  it("marcheaza agentul offline", () => {
    render(<ConnectionTopology online={false} lastHeartbeat={null} scanActive={false} />);
    expect(screen.getByText(/Offline/i)).toBeInTheDocument();
  });
  it("marcheaza online cand online=true", () => {
    render(<ConnectionTopology online={true} lastHeartbeat={new Date().toISOString()} scanActive={false} />);
    expect(screen.getByText(/Online/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web; npm test -- ConnectionTopology`
Expected: FAIL — module not found

- [ ] **Step 3: Implement component**

```tsx
// web/src/components/ConnectionTopology.tsx
import { motion } from "framer-motion";

type Props = {
  online: boolean;
  lastHeartbeat: string | null;
  scanActive: boolean;
};

function Node({ label, sub, status }: { label: string; sub: string; status: "ok" | "off" }) {
  return (
    <div className="topo-node">
      <span className={`topo-dot ${status === "ok" ? "topo-dot-ok" : "topo-dot-off"}`} />
      <div className="topo-node-label">{label}</div>
      <div className="topo-node-sub">{sub}</div>
    </div>
  );
}

export function ConnectionTopology({ online, lastHeartbeat, scanActive }: Props) {
  const agentSub = online ? "Online" : "Offline";
  const flowing = online || scanActive;
  return (
    <div className="topo">
      <Node label="Agent (PC-ul tau)" sub={agentSub} status={online ? "ok" : "off"} />
      <div className={`topo-link ${flowing ? "topo-link-active" : ""}`}>
        {flowing && (
          <motion.span className="topo-packet"
            animate={{ x: ["0%", "100%"] }}
            transition={{ duration: 1.4, repeat: Infinity, ease: "linear" }} />
        )}
      </div>
      <Node label="Backend (API)" sub="FastAPI" status="ok" />
      <div className={`topo-link ${flowing ? "topo-link-active" : ""}`}>
        {flowing && (
          <motion.span className="topo-packet"
            animate={{ x: ["0%", "100%"] }}
            transition={{ duration: 1.4, repeat: Infinity, ease: "linear", delay: 0.7 }} />
        )}
      </div>
      <Node label="Platform (UI)" sub="React" status="ok" />
    </div>
  );
}
```

Adauga stilurile `.topo*` in `web/src/index.css` (flex row, dots colorate cu var(--green)/var(--text-muted), linie cu pozitie relativa pentru packet absolute). Respecta `prefers-reduced-motion` (ascunde packet-ul).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web; npm test -- ConnectionTopology`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add web/src/components/ConnectionTopology.tsx web/src/components/ConnectionTopology.test.tsx web/src/index.css
git commit -m "feat(fe): component ConnectionTopology (diagrama Agent-Backend-Platform)"
```

---

### Task 12: Component NetworkTrafficChart (#2)

**Files:**
- Create: `web/src/components/NetworkTrafficChart.tsx`
- Test: `web/src/components/NetworkTrafficChart.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
// web/src/components/NetworkTrafficChart.test.tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

vi.mock("../api/exposure", () => ({ getNetTraffic: vi.fn() }));
class RO { constructor(_: ResizeObserverCallback) {} observe() {} unobserve() {} disconnect() {} }
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).ResizeObserver = RO;
import { getNetTraffic } from "../api/exposure";
import { NetworkTrafficChart } from "./NetworkTrafficChart";
const m = getNetTraffic as ReturnType<typeof vi.fn>;

describe("NetworkTrafficChart", () => {
  it("afiseaza empty state cand nu sunt date", async () => {
    m.mockResolvedValue([]);
    render(<NetworkTrafficChart deviceUid="dev1" />);
    await waitFor(() => expect(screen.getByText(/Niciun trafic|offline|fara date/i)).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web; npm test -- NetworkTrafficChart`
Expected: FAIL — module not found

- [ ] **Step 3: Implement component** (Recharts AreaChart cu useNetworkTraffic)

```tsx
// web/src/components/NetworkTrafficChart.tsx
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useNetworkTraffic } from "../hooks/useNetworkTraffic";

export function NetworkTrafficChart({ deviceUid }: { deviceUid: string }) {
  const series = useNetworkTraffic(deviceUid);
  if (series.length === 0) {
    return <div className="empty-state">Niciun trafic inregistrat (agent offline sau fara activitate).</div>;
  }
  const data = series.map((p, i) => ({
    i, out: p.sent_rate_kbps, in: p.recv_rate_kbps, conn: p.conn_count,
  }));
  const last = series[series.length - 1];
  return (
    <div>
      <div style={{ display: "flex", gap: 16, marginBottom: 8, fontSize: 13 }}>
        <span>↑ {last.sent_rate_kbps.toFixed(1)} KB/s</span>
        <span>↓ {last.recv_rate_kbps.toFixed(1)} KB/s</span>
        <span>{last.conn_count} conexiuni active</span>
      </div>
      <ResponsiveContainer width="100%" height={160}>
        <AreaChart data={data}>
          <XAxis dataKey="i" hide />
          <YAxis width={40} tick={{ fontSize: 10 }} />
          <Tooltip />
          <Area type="monotone" dataKey="out" stroke="var(--accent)" fill="var(--accent-soft)" name="Iesit" />
          <Area type="monotone" dataKey="in" stroke="var(--plum)" fill="var(--lavender)" name="Intrat" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web; npm test -- NetworkTrafficChart`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add web/src/components/NetworkTrafficChart.tsx web/src/components/NetworkTrafficChart.test.tsx
git commit -m "feat(fe): component NetworkTrafficChart (trafic live in/out)"
```

---

### Task 13: Integrare in Dashboard + nmap live panel

**Files:**
- Modify: `web/src/pages/Dashboard.tsx`
- Modify: `web/src/pages/Dashboard.test.tsx` (mock getNetTraffic ca sa nu strice testele)

- [ ] **Step 1: Update Dashboard.test mock** (adauga getNetTraffic in mock-ul exposure)

In `vi.mock("../api/exposure", ...)` din Dashboard.test.tsx, adauga `getNetTraffic: vi.fn().mockResolvedValue([])`. Adauga `(globalThis as any).ResizeObserver = class { constructor(_:any){} observe(){} unobserve(){} disconnect(){} }`.

- [ ] **Step 2: Wire components in Dashboard**

Sub device picker, cand `deviceId` selectat, randeaza intr-un card:
```tsx
<ConnectionTopology
  online={!!selectedDevice?.is_online}
  lastHeartbeat={selectedDevice?.last_heartbeat ?? null}
  scanActive={!!activeJob && (activeJob.status === "running" || activeJob.status === "pending")}
/>
```
si un card "Trafic de retea" cu `<NetworkTrafficChart deviceUid={deviceId} />`.

(Adauga `is_online` + `last_heartbeat` in tipul `DeviceListItem` local din Dashboard si in `apiGet<DeviceListItem[]>("/devices")` — backend-ul deja le returneaza.)

- [ ] **Step 3: Run frontend tests + tsc**

Run: `cd web; npx tsc -b; npm test`
Expected: PASS (toate, inclusiv Dashboard)

- [ ] **Step 4: Commit**

```bash
git add web/src/pages/Dashboard.tsx web/src/pages/Dashboard.test.tsx
git commit -m "feat(fe): integrare ConnectionTopology + NetworkTrafficChart in Dashboard"
```

---

### Task 14: Update memory.md + suita completa + rebuild .exe

**Files:**
- Modify: `agent/memory.md`, `agent/tests/memory.md`, `server/app/memory.md`, `server/tests/memory.md`, `web/src/hooks/memory.md`, `web/src/components/memory.md`, `web/src/pages/memory.md`

- [ ] **Step 1: Update memory.md** pentru toate fisierele atinse (nmap streaming, max_progress, build_heartbeat_payload, livestate, net-traffic endpoint, ConnectionTopology, NetworkTrafficChart, useNetworkTraffic).

- [ ] **Step 2: Ruleaza suita completa**

Run agent: `python -m pytest agent/tests -q`
Run server: `cd server; $env:DISABLE_SCHEDULER="true"; $env:DISABLE_RATELIMIT="true"; .\.venv\Scripts\python.exe -m pytest -q`
Run frontend: `cd web; npx tsc -b; npm test`
Expected: toate verzi.

- [ ] **Step 3: Rebuild .exe** (agentul s-a schimbat — nmap streaming + heartbeat net)

Run: `& .\.venv-build\Scripts\python.exe -m PyInstaller --clean --noconfirm .\agent\VulnWatchAgent.spec`
Apoi copiaza in `server/app/static/agent/VulnWatchAgent.exe`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs: memory.md + rebuild agent .exe (nmap streaming + heartbeat net)"
```

---

## Self-Review

**Spec coverage:** A→Task 3,4 | B→Task 1,2,4 | C→Task 5,6,7,8,9 | D→Task 11,13 | E→Task 10,12,13. Toate sectiunile spec au taskuri. ✓
**Placeholders:** niciun TBD/TODO; cod real in fiecare step. ✓
**Type consistency:** `NetTrafficPoint` (ts/sent_rate_kbps/recv_rate_kbps/conn_count) folosit identic in livestate output, endpoint, type FE, hook, chart. `build_heartbeat_payload`, `parse_nmap_stats_line`, `record_sample`, `get_series` consistente intre taskuri. ✓
**Rebuild:** agentul s-a schimbat → Task 14 include rebuild .exe. ✓
