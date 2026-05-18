# nmap + NSE Lua Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrare nmap + NSE custom Lua în VulnWatch pentru scan-uri deep (localhost obligatoriu, LAN opt-in), cu agent refactorizat ca Windows Service.

**Architecture:** Single executable cu două moduri de rulare (`--service` flag pentru daemon LocalSystem, fără flag pentru GUI user-session). Comunicare GUI↔Service prin named pipe. nmap rulat ca prerequisit instalat separat; doar scriptul `vulnwatch-audit.nse` (3 sub-module Lua: agregator vuln + CVE mapper + topology) este bundle-uit și deployed în NSE scripts dir la startup.

**Tech Stack:** Python 3.10+ (pywin32 pentru Service + named pipe), Tkinter (GUI), nmap 7.x cu NSE Lua, FastAPI + SQLAlchemy backend, React + TypeScript frontend.

**Spec aprobat:** `docs/superpowers/specs/2026-05-18-nmap-nse-lua-design.md`

---

## Pre-flight: dependențe noi

Înainte de Task 1, verifică/instalează:

- [ ] **Step 0.1: Add pywin32 la requirements**

```bash
# Verifică daca există în requirements
grep -i pywin32 agent/requirements.txt || echo "MISSING"
```

Dacă lipsește, adaugă în `agent/requirements.txt`:

```
pywin32>=306; sys_platform == "win32"
```

Și instalează în venv dev:
```bash
pip install -r agent/requirements.txt
```

- [ ] **Step 0.2: Install nmap pe mașina dev** (manual, o singură dată)

Download installer Windows: https://nmap.org/download.html → Run → Default install (`C:\Program Files (x86)\Nmap`). Verifică:
```bash
nmap --version
```
Expected: `Nmap version 7.x` printed.

- [ ] **Step 0.3: Install lua + busted pentru NSE tests (optional)**

```bash
# Pe Windows folosim lua-portable din nmap install:
"C:\Program Files (x86)\Nmap\lua.exe" -v  # Lua 5.x
# Busted: instalează în venv Lua daca vrei să rulezi testele NSE local
luarocks install busted  # daca ai luarocks; altfel skip Task 10 sau rulează manual
```

---

## File Structure

**Files care vor fi create:**
- `agent/service.py` — Windows Service entry (pywin32) + IPC server (named pipe)
- `agent/ipc.py` — Protocol IPC GUI↔Service (JSON line-delimited)
- `agent/nmap_runner.py` — Construire CLI args + subprocess execution + timeout
- `agent/nmap_parser.py` — Parse XML nmap output → dict + extract vulnwatch-audit JSON
- `agent/nse/vulnwatch-audit.nse` — Scriptul NSE custom Lua (~400 LOC)
- `agent/tests/test_ipc.py` — Tests pentru protocol IPC
- `agent/tests/test_nmap_runner.py` — Tests pentru CLI args + CIDR validation
- `agent/tests/test_nmap_parser.py` — Tests pentru parsing XML
- `agent/tests/test_service_install.py` — Tests pentru install/uninstall Service
- `agent/tests/fixtures/nmap_localhost.xml` — Sample XML output pentru parser tests
- `agent/tests/fixtures/nmap_lan.xml` — Sample multi-host XML
- `server/tests/test_nmap_findings.py` — Tests pentru rule NMAP-LUA-1
- `web/src/components/NmapHostCard.tsx` — Component React per host
- `web/src/components/NmapSection.tsx` — Section în ScanDetail pentru nmap data

**Files care vor fi modificate:**
- `agent/core.py` — `_nmap_path()` helper, `_deploy_nse_script()`, capabilities reporter, integration în daemon_loop
- `agent/scan.py` — dispatch `--service`, `--install-service`, `--uninstall-service`
- `agent/gui.py` — IPC client (înlocuiește DaemonRunner cu pipe communication), modal install Service, UI dezactivat dacă nmap lipsește
- `agent/autostart.py` — Service-aware (înlocuiește/extinde HKCU Run cu Service registration)
- `agent/VulnWatchAgent.spec` — adaugă `agent/nse/vulnwatch-audit.nse` în `datas`
- `agent/requirements.txt` — adaugă `pywin32`
- `agent/memory.md` — documentează service.py, ipc.py, nmap_*.py
- `server/app/models.py` — `Scan.nmap_data`, `ScanJob.nmap_target`, `Device.local_subnet`, `Device.nmap_installed`
- `server/app/schemas.py` — extend `ScanIn`, `ScanJobCreate`, `HeartbeatIn`
- `server/app/routes.py` — validare CIDR pe `nmap_target`, endpoint nou `/scan-jobs/preview`, heartbeat salvează `local_subnet`
- `server/app/rules.py` — adaugă `@rule("NMAP-LUA-1")`
- `server/app/memory.md` — documentează rule și schema nouă
- `web/src/pages/Devices.tsx` — settings expander pentru deep + LAN checkbox + confirm modal
- `web/src/pages/ScanDetail.tsx` — render NmapSection dacă scan.nmap există
- `web/src/api/types.ts` — interface `NmapData`, `NmapHost`, `NmapFinding`

---

## Task 1: Schelet `service.py` + dispatch CLI

**Files:**
- Create: `agent/service.py`
- Modify: `agent/scan.py` — dispatch nou pentru `--service`, `--install-service`, `--uninstall-service`
- Modify: `agent/requirements.txt`

- [ ] **Step 1.1: Adaugă pywin32 în requirements.txt**

În `agent/requirements.txt`, după linia cu `google-auth>=2.30`, adaugă:
```
pywin32>=306; sys_platform == "win32"
```

- [ ] **Step 1.2: Creează `agent/service.py` cu schelet Service**

```python
"""Windows Service wrapper pentru agent VulnWatch (mode LocalSystem).

Service-ul invocă `core.daemon_loop` pe un thread, expune un named pipe pentru
control de la GUI (user session), și se înregistrează în Service Control
Manager. Activitate pre/post-stop tratată prin servicemanager events.
"""
from __future__ import annotations

import sys
import threading
import time
from typing import Optional

# pywin32 — disponibil doar pe Windows. Restul codului trebuie să degradeze
# gracefully când lipsește (dev pe non-Windows).
try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
    _PYWIN32_AVAILABLE = True
except ImportError:
    _PYWIN32_AVAILABLE = False

SERVICE_NAME = "VulnWatchSvc"
SERVICE_DISPLAY_NAME = "VulnWatch Agent Service"
SERVICE_DESCRIPTION = ("Background scanner service for VulnWatch platform. "
                       "Runs heartbeat, scan jobs, and nmap-based deep scans.")


if _PYWIN32_AVAILABLE:
    class VulnWatchService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._stop_flag = threading.Event()
            self._daemon_thread: Optional[threading.Thread] = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_flag.set()
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self._main()

        def _main(self) -> None:
            """Logica principală: pornește daemon_loop pe thread + așteaptă stop."""
            # Import lazy ca să nu crashăm pe non-Windows
            from . import core

            try:
                api_base, device_uid, device_token = core.get_enrollment()
            except RuntimeError:
                servicemanager.LogErrorMsg(
                    "VulnWatchSvc: agent neînrolat. Service se oprește."
                )
                return

            def daemon_target():
                core.daemon_loop(
                    api_base, device_uid, device_token,
                    poll_interval=3,
                    log=lambda msg, sev: servicemanager.LogInfoMsg(f"[{sev}] {msg}"),
                    should_stop=self._stop_flag.is_set,
                )

            self._daemon_thread = threading.Thread(
                target=daemon_target, daemon=True, name="vulnwatch-daemon",
            )
            self._daemon_thread.start()

            # Așteaptă stop event
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
            self._daemon_thread.join(timeout=5.0)
else:
    # Stub pentru dev pe non-Windows
    class VulnWatchService:
        pass


def install_service() -> int:
    """Înregistrează serviciul în SCM. Trebuie rulat sub UAC admin."""
    if not _PYWIN32_AVAILABLE:
        print("pywin32 indisponibil — Service mode necesită Windows.")
        return 1
    exe_path = sys.executable
    # Construim args: când SCM pornește serviciul, va apela exe-ul cu acești args
    win32serviceutil.InstallService(
        pythonClassString=None,  # folosim exe-ul direct, nu un .py
        serviceName=SERVICE_NAME,
        displayName=SERVICE_DISPLAY_NAME,
        description=SERVICE_DESCRIPTION,
        startType=win32service.SERVICE_AUTO_START,
        exeName=exe_path,
        exeArgs="--service",
    )
    # Start imediat
    win32serviceutil.StartService(SERVICE_NAME)
    return 0


def uninstall_service() -> int:
    """Oprește + dezinstalează serviciul. Trebuie rulat sub UAC admin."""
    if not _PYWIN32_AVAILABLE:
        return 1
    try:
        win32serviceutil.StopService(SERVICE_NAME)
    except Exception:
        pass  # poate nu rula
    win32serviceutil.RemoveService(SERVICE_NAME)
    return 0


def is_service_installed() -> bool:
    """Returnează True dacă serviciul e înregistrat în SCM."""
    if not _PYWIN32_AVAILABLE:
        return False
    try:
        win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        return True
    except Exception:
        return False


def is_service_running() -> bool:
    if not _PYWIN32_AVAILABLE:
        return False
    try:
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        return status[1] == win32service.SERVICE_RUNNING
    except Exception:
        return False


def run_as_service() -> int:
    """Entry point când exe-ul e lansat de SCM cu --service flag."""
    if not _PYWIN32_AVAILABLE:
        print("--service necesită Windows + pywin32")
        return 1
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(VulnWatchService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0
```

- [ ] **Step 1.3: Modifică `agent/scan.py` pentru dispatch nou**

Localizează în `agent/scan.py` funcția `main()` (dispatch CLI). Adaugă, înainte de dispatcherele existente:

```python
def main() -> int:
    if "--service" in sys.argv:
        from . import service
        return service.run_as_service()
    if "--install-service" in sys.argv:
        from . import service
        return service.install_service()
    if "--uninstall-service" in sys.argv:
        from . import service
        return service.uninstall_service()
    # ... restul codului existent (GUI dispatch, subcomenzi CLI)
```

- [ ] **Step 1.4: Verifică import**

```bash
python -c "import sys; sys.path.insert(0, '.'); from agent import service; print('import OK')"
```
Expected: `import OK` (pe Windows cu pywin32 instalat; pe Linux/Mac va printa și un warning, dar nu crash).

- [ ] **Step 1.5: Commit**

```bash
git add agent/service.py agent/scan.py agent/requirements.txt
git commit -m "feat(agent/service): schelet Windows Service + dispatch --service"
```

---

## Task 2: Named Pipe IPC — schelet protocol

**Files:**
- Create: `agent/ipc.py`
- Create: `agent/tests/test_ipc.py`

- [ ] **Step 2.1: Scrie testul pentru protocolul IPC (server + client roundtrip)**

În `agent/tests/test_ipc.py`:

```python
"""Tests pentru protocolul IPC GUI↔Service.
Folosim socket TCP localhost ca substitut pentru named pipe (portabilitate CI),
dar API-ul este abstractizat în ipc.py să folosească named pipe pe Windows.
"""
import json
import threading
import time
import socket
from contextlib import closing

import pytest

from agent.ipc import (
    IpcServer, IpcClient, IpcMessage,
    handle_message_default,
)


@pytest.fixture
def server_port():
    """Alege un port liber pentru fiecare test."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        yield s.getsockname()[1]


def test_status_cmd_returns_dict(server_port):
    """Client trimite {cmd:status}, Server răspunde cu starea."""
    handler_calls = []

    def handler(msg: IpcMessage) -> dict:
        handler_calls.append(msg)
        if msg.get("cmd") == "status":
            return {"running": True, "paused": False, "last_heartbeat": 1000}
        return {"error": "unknown"}

    server = IpcServer(host="127.0.0.1", port=server_port, handler=handler)
    server.start()
    time.sleep(0.1)

    try:
        client = IpcClient(host="127.0.0.1", port=server_port)
        response = client.request({"cmd": "status"})
        assert response["running"] is True
        assert response["last_heartbeat"] == 1000
        assert len(handler_calls) == 1
        assert handler_calls[0]["cmd"] == "status"
    finally:
        server.stop()


def test_push_event_to_client(server_port):
    """Server poate emite evenimente push (scan_done, token_invalid)."""
    received = []

    server = IpcServer(host="127.0.0.1", port=server_port,
                       handler=lambda msg: {"ok": True})
    server.start()
    time.sleep(0.1)

    client = IpcClient(host="127.0.0.1", port=server_port)
    client.subscribe_events(lambda evt: received.append(evt))
    time.sleep(0.1)

    server.broadcast_event({"event": "scan_done", "score": 42})
    time.sleep(0.2)

    server.stop()
    assert len(received) == 1
    assert received[0]["event"] == "scan_done"
    assert received[0]["score"] == 42


def test_unknown_cmd_returns_error(server_port):
    server = IpcServer(host="127.0.0.1", port=server_port,
                       handler=handle_message_default)
    server.start()
    time.sleep(0.1)
    try:
        client = IpcClient(host="127.0.0.1", port=server_port)
        response = client.request({"cmd": "bogus"})
        assert "error" in response
    finally:
        server.stop()
```

- [ ] **Step 2.2: Rulează testul (va eșua — modulul nu există)**

```bash
python -m pytest agent/tests/test_ipc.py -v
```
Expected: FAIL `ModuleNotFoundError: agent.ipc`

- [ ] **Step 2.3: Creează `agent/ipc.py` cu protocol abstract**

```python
"""Protocol IPC GUI↔Service.

Pe Windows folosim Named Pipe (`\\\\.\\pipe\\vulnwatch-status`) când serviciul
rulează ca LocalSystem. Pentru dev/testing și portabilitate folosim socket TCP
localhost. API-ul de mai jos abstractizează ambele cazuri.

Protocol: line-delimited JSON.
- Request: {"cmd": "status"} → Response: {"running": true, ...}
- Push event: {"event": "scan_done", "score": 42}
"""
from __future__ import annotations

import json
import socket
import threading
import time
from typing import Any, Callable, Optional

IpcMessage = dict[str, Any]


PIPE_NAME = r"\\.\pipe\vulnwatch-status"
DEFAULT_TCP_PORT = 47815  # fallback dev port


def handle_message_default(msg: IpcMessage) -> dict:
    """Default handler — răspunde cu error pentru cmd necunoscut."""
    cmd = msg.get("cmd", "")
    if cmd == "ping":
        return {"ok": True, "pong": True}
    return {"error": f"unknown cmd: {cmd}"}


class IpcServer:
    """Server IPC. Pe Windows folosim named pipe via pywin32 dacă disponibil;
    altfel TCP socket (dev mode)."""

    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_TCP_PORT,
                 handler: Callable[[IpcMessage], dict] = handle_message_default):
        self.host = host
        self.port = port
        self.handler = handler
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._subscribers: list[socket.socket] = []
        self._sub_lock = threading.Lock()

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn,),
                             daemon=True).start()

    def _handle_client(self, conn: socket.socket) -> None:
        conn.settimeout(2.0)
        buffer = b""
        try:
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
                    if msg.get("cmd") == "subscribe_events":
                        with self._sub_lock:
                            self._subscribers.append(conn)
                        self._send(conn, {"ok": True})
                        # Subscribers rămân conectați pentru push events
                        # Iese din buclă: noi monitorizăm pentru push, nu request
                        return
                    response = self.handler(msg)
                    self._send(conn, response)
        finally:
            try:
                conn.close()
            except Exception:
                pass
            with self._sub_lock:
                if conn in self._subscribers:
                    self._subscribers.remove(conn)

    def _send(self, conn: socket.socket, msg: dict) -> None:
        try:
            conn.sendall((json.dumps(msg) + "\n").encode("utf-8"))
        except OSError:
            pass

    def broadcast_event(self, event: dict) -> None:
        """Trimite event către toți subscribers."""
        with self._sub_lock:
            stale = []
            for conn in self._subscribers:
                try:
                    conn.sendall((json.dumps(event) + "\n").encode("utf-8"))
                except OSError:
                    stale.append(conn)
            for conn in stale:
                self._subscribers.remove(conn)

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)


class IpcClient:
    """Client IPC. Conectare on-demand per request."""

    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_TCP_PORT):
        self.host = host
        self.port = port
        self._sub_thread: Optional[threading.Thread] = None
        self._sub_stop = threading.Event()

    def request(self, msg: IpcMessage, timeout: float = 2.0) -> dict:
        with socket.create_connection((self.host, self.port), timeout=timeout) as s:
            s.sendall((json.dumps(msg) + "\n").encode("utf-8"))
            buffer = b""
            s.settimeout(timeout)
            while b"\n" not in buffer:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buffer += chunk
            line = buffer.split(b"\n", 1)[0]
            return json.loads(line.decode("utf-8"))

    def subscribe_events(self, callback: Callable[[dict], None]) -> None:
        """Pornește thread care primește evenimente push de la server."""
        def loop():
            try:
                with socket.create_connection((self.host, self.port),
                                              timeout=5.0) as s:
                    s.sendall(b'{"cmd":"subscribe_events"}\n')
                    s.settimeout(1.0)
                    buffer = b""
                    while not self._sub_stop.is_set():
                        try:
                            chunk = s.recv(4096)
                        except socket.timeout:
                            continue
                        if not chunk:
                            break
                        buffer += chunk
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            if not line.strip():
                                continue
                            try:
                                evt = json.loads(line.decode("utf-8"))
                                callback(evt)
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                continue
            except (OSError, socket.timeout):
                pass

        self._sub_thread = threading.Thread(target=loop, daemon=True)
        self._sub_thread.start()

    def unsubscribe(self) -> None:
        self._sub_stop.set()
```

- [ ] **Step 2.4: Rulează testele**

```bash
python -m pytest agent/tests/test_ipc.py -v
```
Expected: PASS — 3 tests.

- [ ] **Step 2.5: Commit**

```bash
git add agent/ipc.py agent/tests/test_ipc.py
git commit -m "feat(agent/ipc): protocol JSON line-delimited cu request/subscribe events"
```

---

## Task 3: Detecție nmap + deploy script NSE

**Files:**
- Modify: `agent/core.py` — adaugă `_nmap_path()`, `_deploy_nse_script()`, capabilities reporting

- [ ] **Step 3.1: Adaugă helper-ele în `agent/core.py`**

În `agent/core.py`, după secțiunea de imports, adaugă:

```python
import shutil
import sys

def _nmap_path() -> Path | None:
    """Returnează path către nmap.exe instalat de user, sau None dacă lipsește.

    Verifică în această ordine:
    1. nmap în PATH
    2. C:\\Program Files (x86)\\Nmap\\nmap.exe
    3. C:\\Program Files\\Nmap\\nmap.exe
    """
    found = shutil.which("nmap")
    if found:
        return Path(found)
    for candidate in [
        Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
        Path(r"C:\Program Files\Nmap\nmap.exe"),
    ]:
        if candidate.is_file():
            return candidate
    return None


def _bundled_nse_path() -> Path | None:
    """Returnează path către vulnwatch-audit.nse din bundle/dev tree."""
    if getattr(sys, "frozen", False):
        # PyInstaller bundle — script extras sub _MEIPASS/nse/
        return Path(sys._MEIPASS) / "nse" / "vulnwatch-audit.nse"
    # Dev mode — script trăiește în agent/nse/
    repo_root = Path(__file__).resolve().parent.parent
    candidate = repo_root / "agent" / "nse" / "vulnwatch-audit.nse"
    return candidate if candidate.is_file() else None


def deploy_nse_script(log: LogFn = _noop_log) -> bool:
    """Copiază vulnwatch-audit.nse din bundle în NSE scripts dir al instalării
    de nmap. Întoarce True dacă deploy a reușit, False dacă nmap lipsește.

    Trebuie rulat la startup-ul service-ului (idempotent — overwrite ok)."""
    nmap = _nmap_path()
    if not nmap:
        log("nmap lipsește — script vulnwatch-audit.nse nu poate fi deployed", "warn")
        return False
    bundled = _bundled_nse_path()
    if not bundled:
        log("vulnwatch-audit.nse lipsește din bundle/dev tree", "warn")
        return False
    # Scripts dir = `{nmap_dir}\scripts\`
    scripts_dir = nmap.parent / "scripts"
    if not scripts_dir.is_dir():
        log(f"NSE scripts dir lipsește la {scripts_dir}", "warn")
        return False
    target = scripts_dir / "vulnwatch-audit.nse"
    try:
        shutil.copy2(bundled, target)
        log(f"Deploy NSE script OK: {target}", "ok")
    except OSError as e:
        log(f"Deploy NSE script eșuat: {e}", "error")
        return False
    # Refresh script index
    try:
        subprocess.run([str(nmap), "--script-updatedb"],
                       capture_output=True, timeout=30)
    except subprocess.SubprocessError:
        pass  # not fatal
    return True


def agent_capabilities() -> list[str]:
    """Returnează lista de scan_type-uri suportate pe acest device.

    `standard` și `advanced` sunt mereu suportate (psutil).
    `deep` se adaugă DOAR dacă nmap e instalat.
    """
    caps = ["standard", "advanced"]
    if _nmap_path() is not None:
        caps.append("deep")
    return caps
```

- [ ] **Step 3.2: Update heartbeat să raporteze capabilities dinamic**

Localizează în `agent/core.py` funcția `daemon_loop` și secțiunea unde se construiește `capabilities` (~linia 694):

Înlocuiește:
```python
    capabilities = list(SCAN_PROFILES.keys())
```

Cu:
```python
    capabilities = agent_capabilities()  # dinamic: include "deep" doar dacă nmap e instalat
```

Și apelează `deploy_nse_script` la începutul daemon_loop, după `os_version = ...`:

```python
    deploy_nse_script(log=log)  # idempotent — copiază scriptul în nmap scripts dir
```

- [ ] **Step 3.3: Verifică (smoke) din REPL**

```bash
python -c "
import sys; sys.path.insert(0, '.')
from agent import core
print('nmap path:', core._nmap_path())
print('NSE bundled:', core._bundled_nse_path())
print('capabilities:', core.agent_capabilities())
"
```
Expected pe Windows cu nmap instalat: path real + capabilities cu "deep".

- [ ] **Step 3.4: Commit**

```bash
git add agent/core.py
git commit -m "feat(agent/core): detectie nmap + deploy NSE script + capabilities dinamice"
```

---

## Task 4: nmap runner — construire CLI args + execuție

**Files:**
- Create: `agent/nmap_runner.py`
- Create: `agent/tests/test_nmap_runner.py`

- [ ] **Step 4.1: Scrie testul pentru CLI args + CIDR validation**

În `agent/tests/test_nmap_runner.py`:

```python
"""Tests pentru construire CLI args nmap + validare target."""
import pytest
from agent.nmap_runner import (
    build_nmap_args, validate_cidr, NmapRunnerError,
)


def test_build_args_localhost_only():
    args = build_nmap_args(targets=["127.0.0.1"], top_ports=1000,
                           xml_out="result.xml")
    assert "-sV" in args
    assert "-O" in args
    assert "--top-ports" in args
    assert "1000" in args
    assert "--script" in args
    assert "vulnwatch-audit" in args
    assert "-oX" in args
    assert "result.xml" in args
    assert "127.0.0.1" in args


def test_build_args_with_lan():
    args = build_nmap_args(targets=["127.0.0.1", "192.168.1.0/24"],
                           top_ports=1000, xml_out="result.xml")
    assert "127.0.0.1" in args
    assert "192.168.1.0/24" in args


def test_build_args_all_ports():
    args = build_nmap_args(targets=["127.0.0.1"], top_ports=None,
                           all_ports=True, xml_out="result.xml")
    assert "-p-" in args
    assert "--top-ports" not in args


def test_validate_cidr_ok():
    validate_cidr("192.168.1.0/24")  # nu ridică
    validate_cidr("10.0.0.0/8")
    validate_cidr("127.0.0.1")  # single host = /32


def test_validate_cidr_rejects_public_ranges():
    """Refuzăm să scanăm IP-uri publice — fail-safe."""
    with pytest.raises(NmapRunnerError, match="public"):
        validate_cidr("8.8.8.0/24")


def test_validate_cidr_rejects_huge_range():
    """Refuzăm /16 sau mai mare (65k hosts)."""
    with pytest.raises(NmapRunnerError, match="prea mare"):
        validate_cidr("10.0.0.0/8")  # 16M hosts


def test_validate_cidr_rejects_invalid_syntax():
    with pytest.raises(NmapRunnerError, match="invalid"):
        validate_cidr("not.a.cidr")
```

Notă: testul pentru `/8` contrazice cel anterior care îl acceptă. Reformulez: `validate_cidr` acceptă orice CIDR valid din `ipaddress`, dar `validate_lan_target` (wrapper public-facing) refuză public + huge. Update testul:

```python
def test_validate_cidr_ok():
    validate_cidr("192.168.1.0/24")
    validate_cidr("10.0.0.0/24")  # /24, nu /8
    validate_cidr("127.0.0.1")


def test_validate_lan_target_rejects_public():
    from agent.nmap_runner import validate_lan_target
    with pytest.raises(NmapRunnerError, match="public"):
        validate_lan_target("8.8.8.0/24")


def test_validate_lan_target_rejects_huge():
    from agent.nmap_runner import validate_lan_target
    with pytest.raises(NmapRunnerError, match="prea mare"):
        validate_lan_target("10.0.0.0/8")
```

- [ ] **Step 4.2: Rulează testul (va eșua — modul lipsește)**

```bash
python -m pytest agent/tests/test_nmap_runner.py -v
```
Expected: FAIL `ModuleNotFoundError`.

- [ ] **Step 4.3: Creează `agent/nmap_runner.py`**

```python
"""Construirea CLI args + execuție nmap subprocess.

Nu importă pywin32 — funcționează atât în Service mode cât și în GUI mode
single-process fallback.
"""
from __future__ import annotations

import ipaddress
import subprocess
from pathlib import Path
from typing import Optional

from . import core


class NmapRunnerError(Exception):
    """Eroare în pregătire/execuție nmap."""


MAX_LAN_HOSTS = 4096  # /20 = 4096 hosts; refuzăm mai mult


def validate_cidr(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Validează sintactic un CIDR sau single IP. Ridică NmapRunnerError la fail."""
    try:
        return ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError) as e:
        raise NmapRunnerError(f"CIDR invalid: {value} ({e})")


def validate_lan_target(value: str) -> None:
    """Validare LAN: rejects public ranges + huge networks."""
    net = validate_cidr(value)
    if net.is_global:  # public IP
        raise NmapRunnerError(
            f"Target public refuzat (LAN scan permis doar pe rețele private): {value}"
        )
    if net.num_addresses > MAX_LAN_HOSTS:
        raise NmapRunnerError(
            f"Subnet prea mare ({net.num_addresses} host-uri); maxim {MAX_LAN_HOSTS}"
        )


def build_nmap_args(
    targets: list[str],
    xml_out: str,
    top_ports: Optional[int] = 1000,
    all_ports: bool = False,
    extra_script_args: Optional[str] = None,
) -> list[str]:
    """Construiește argumentele CLI pentru nmap (fără exe-ul în sine)."""
    args: list[str] = ["-sV", "-O"]
    if all_ports:
        args.append("-p-")
    elif top_ports:
        args.extend(["--top-ports", str(top_ports)])
    args.extend(["--script", "vulnwatch-audit"])
    if extra_script_args:
        args.extend(["--script-args", extra_script_args])
    args.extend(["-oX", xml_out])
    args.extend(targets)
    return args


def run_nmap(
    targets: list[str],
    xml_out: Path,
    top_ports: Optional[int] = 1000,
    all_ports: bool = False,
    timeout_sec: int = 1800,
    log = None,
) -> tuple[int, str]:
    """Rulează nmap. Întoarce (exit_code, stderr_text). XML va fi scris la xml_out.

    Ridică NmapRunnerError dacă nmap.exe lipsește.
    """
    nmap = core._nmap_path()
    if not nmap:
        raise NmapRunnerError("nmap.exe nu este instalat pe acest sistem")
    args = build_nmap_args(targets=targets, xml_out=str(xml_out),
                           top_ports=top_ports, all_ports=all_ports)
    cmd = [str(nmap)] + args
    if log:
        log(f"nmap: {' '.join(cmd)}", "info")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise NmapRunnerError(f"nmap timeout după {timeout_sec}s") from e
    return result.returncode, (result.stderr or "")
```

- [ ] **Step 4.4: Rulează testele**

```bash
python -m pytest agent/tests/test_nmap_runner.py -v
```
Expected: PASS — 7 tests.

- [ ] **Step 4.5: Commit**

```bash
git add agent/nmap_runner.py agent/tests/test_nmap_runner.py
git commit -m "feat(agent/nmap_runner): build CLI + CIDR/LAN target validation"
```

---

## Task 5: nmap XML parser

**Files:**
- Create: `agent/nmap_parser.py`
- Create: `agent/tests/test_nmap_parser.py`
- Create: `agent/tests/fixtures/nmap_localhost.xml`

- [ ] **Step 5.1: Creează fixture-ul `nmap_localhost.xml`**

În `agent/tests/fixtures/nmap_localhost.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -O 127.0.0.1" version="7.94" start="1684512345">
<host starttime="1684512345" endtime="1684512389">
<status state="up" reason="syn-ack" />
<address addr="127.0.0.1" addrtype="ipv4" />
<hostnames><hostname name="localhost" type="user" /></hostnames>
<ports>
<port protocol="tcp" portid="445">
<state state="open" reason="syn-ack" />
<service name="microsoft-ds" product="Windows" version="10" />
</port>
<port protocol="tcp" portid="139">
<state state="open" reason="syn-ack" />
<service name="netbios-ssn" product="Microsoft Windows" />
</port>
</ports>
<os>
<osmatch name="Microsoft Windows 11" accuracy="95" />
</os>
<hostscript>
<script id="vulnwatch-audit" output='{"host_ip":"127.0.0.1","findings":[{"rule_id":"NMAP-CVE-2017-0144","severity":"critical","title":"EternalBlue MS17-010","evidence":{"port":445,"cve":"CVE-2017-0144"}}],"topology":{"role":"workstation","risk_score":65,"reasons":["smb_open"]}}'/>
</hostscript>
</host>
</nmaprun>
```

- [ ] **Step 5.2: Scrie testul pentru parser**

În `agent/tests/test_nmap_parser.py`:

```python
"""Tests parsare XML nmap → dict + extract vulnwatch-audit JSON."""
import json
from pathlib import Path

import pytest

from agent.nmap_parser import parse_nmap_xml, NmapParseError

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_localhost():
    xml = (FIXTURES / "nmap_localhost.xml").read_text()
    result = parse_nmap_xml(xml)
    assert result["version"] == "7.94"
    assert len(result["hosts"]) == 1
    host = result["hosts"][0]
    assert host["ip"] == "127.0.0.1"
    assert host["hostname"] == "localhost"
    assert host["state"] == "up"
    assert "Microsoft Windows 11" in host["os_guess"]
    assert len(host["ports"]) == 2
    port_445 = next(p for p in host["ports"] if p["port"] == 445)
    assert port_445["service"] == "microsoft-ds"
    # vulnwatch-audit JSON deserialized
    findings = host["vulnwatch_findings"]
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "NMAP-CVE-2017-0144"
    assert findings[0]["severity"] == "critical"
    assert host["topology"]["role"] == "workstation"
    assert host["topology"]["risk_score"] == 65


def test_parse_invalid_xml_raises():
    with pytest.raises(NmapParseError):
        parse_nmap_xml("not xml at all")


def test_parse_missing_vulnwatch_script_returns_empty_findings():
    """Dacă scriptul nostru nu rulează (LSE missing), parser nu crash."""
    xml = """<?xml version="1.0"?><nmaprun version="7.94" start="1">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<ports></ports></host></nmaprun>"""
    result = parse_nmap_xml(xml)
    assert result["hosts"][0]["vulnwatch_findings"] == []
    assert result["hosts"][0]["topology"] == {}
```

- [ ] **Step 5.3: Creează `agent/nmap_parser.py`**

```python
"""Parse XML output de la nmap (-oX) într-un dict structurat VulnWatch."""
from __future__ import annotations

import json
from xml.etree import ElementTree as ET


class NmapParseError(Exception):
    """Eroare în parsarea XML nmap."""


def parse_nmap_xml(xml_text: str) -> dict:
    """Convertește XML nmap în dict cu schema:

    {
      "version": "7.94",
      "scan_time_sec": float | None,
      "hosts": [
        {
          "ip": "127.0.0.1",
          "hostname": "localhost",
          "state": "up",
          "os_guess": "Microsoft Windows 11 (95% confidence)",
          "ports": [{"port": 445, "proto": "tcp", "state": "open",
                     "service": "microsoft-ds", "version": "Windows 10",
                     "cpe": ""}],
          "vulnwatch_findings": [...],   # deserializat din script id="vulnwatch-audit"
          "topology": {...}
        }
      ]
    }
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise NmapParseError(f"XML invalid: {e}") from e

    if root.tag != "nmaprun":
        raise NmapParseError(f"Element root nu este nmaprun: {root.tag}")

    out: dict = {
        "version": root.get("version", ""),
        "scan_time_sec": None,
        "hosts": [],
    }
    start = root.get("start")
    if start:
        runstats = root.find("runstats/finished")
        if runstats is not None and runstats.get("time"):
            try:
                out["scan_time_sec"] = float(runstats.get("time")) - float(start)
            except ValueError:
                pass

    for host_el in root.findall("host"):
        out["hosts"].append(_parse_host(host_el))

    return out


def _parse_host(host_el: ET.Element) -> dict:
    host: dict = {
        "ip": "",
        "hostname": "",
        "state": "",
        "os_guess": "",
        "ports": [],
        "vulnwatch_findings": [],
        "topology": {},
    }
    # IP
    addr = host_el.find("address[@addrtype='ipv4']")
    if addr is None:
        addr = host_el.find("address[@addrtype='ipv6']")
    if addr is not None:
        host["ip"] = addr.get("addr", "")
    # State
    status = host_el.find("status")
    if status is not None:
        host["state"] = status.get("state", "")
    # Hostname
    hostname = host_el.find("hostnames/hostname")
    if hostname is not None:
        host["hostname"] = hostname.get("name", "")
    # OS
    osmatch = host_el.find("os/osmatch")
    if osmatch is not None:
        accuracy = osmatch.get("accuracy", "0")
        host["os_guess"] = f"{osmatch.get('name', 'Unknown')} ({accuracy}% confidence)"
    # Ports
    for port_el in host_el.findall("ports/port"):
        host["ports"].append(_parse_port(port_el))
    # vulnwatch-audit script output
    script = host_el.find("hostscript/script[@id='vulnwatch-audit']")
    if script is None:
        # Could be at port level for some scripts; check there too
        for port_el in host_el.findall("ports/port"):
            s = port_el.find("script[@id='vulnwatch-audit']")
            if s is not None:
                script = s
                break
    if script is not None:
        output = script.get("output", "")
        try:
            parsed = json.loads(output)
            host["vulnwatch_findings"] = parsed.get("findings", [])
            host["topology"] = parsed.get("topology", {})
        except (json.JSONDecodeError, ValueError):
            pass
    return host


def _parse_port(port_el: ET.Element) -> dict:
    port = {
        "port": int(port_el.get("portid", "0")),
        "proto": port_el.get("protocol", "tcp"),
        "state": "",
        "service": "",
        "version": "",
        "cpe": "",
    }
    state = port_el.find("state")
    if state is not None:
        port["state"] = state.get("state", "")
    svc = port_el.find("service")
    if svc is not None:
        port["service"] = svc.get("name", "")
        product = svc.get("product", "")
        version = svc.get("version", "")
        port["version"] = f"{product} {version}".strip()
        cpe = svc.find("cpe")
        if cpe is not None and cpe.text:
            port["cpe"] = cpe.text
    return port
```

- [ ] **Step 5.4: Rulează testele**

```bash
python -m pytest agent/tests/test_nmap_parser.py -v
```
Expected: PASS — 3 tests.

- [ ] **Step 5.5: Commit**

```bash
git add agent/nmap_parser.py agent/tests/test_nmap_parser.py agent/tests/fixtures/
git commit -m "feat(agent/nmap_parser): parser XML nmap cu extract vulnwatch-audit JSON"
```

---

## Task 6: Scriptul NSE custom `vulnwatch-audit.nse`

**Files:**
- Create: `agent/nse/vulnwatch-audit.nse`

- [ ] **Step 6.1: Creează scheletul scriptului cu cele 3 sub-module**

În `agent/nse/vulnwatch-audit.nse`:

```lua
description = [[
VulnWatch custom audit script.

Three sub-modules:
1. Aggregator — collects findings from built-in vuln NSE scripts
2. CVE mapper — correlates service+version against an embedded CVE database
3. Topology mapper — detects role (gateway/dns/fileserver/workstation) and risk score

Emits structured JSON per host for consumption by VulnWatch platform.
]]
author = "VulnWatch — A. Giurgiuveanu"
license = "Same as Nmap (NPSL)"
categories = {"safe", "discovery", "vuln"}

local stdnse = require "stdnse"
local nmap = require "nmap"
local json = require "json"
local string = require "string"
local table = require "table"

-- ================================================================
-- SUB-MODULE 1: AGGREGATOR
-- ================================================================
local aggregator = {}

-- Maparea service → list of NSE scripts care produc finding-uri utile
local SERVICE_TO_SCRIPTS = {
  ["microsoft-ds"] = {"smb-vuln-ms17-010", "smb-vuln-ms08-067"},
  ["netbios-ssn"]  = {"smb-vuln-ms17-010"},
  ["http"]         = {"http-vuln-cve2017-5638", "http-csrf"},
  ["https"]        = {"ssl-poodle", "ssl-heartbleed"},
  ["ssl"]          = {"ssl-poodle", "ssl-heartbleed"},
  ["ssh"]          = {"ssh-auth-methods"},
  ["ftp"]          = {"ftp-anon"},
  ["ms-wbt-server"] = {"rdp-vuln-ms12-020"},
}

-- Severitate per script (mapping known scripts to severity)
local SCRIPT_SEVERITY = {
  ["smb-vuln-ms17-010"]      = "critical",
  ["smb-vuln-ms08-067"]      = "critical",
  ["rdp-vuln-ms12-020"]      = "high",
  ["ssl-heartbleed"]         = "critical",
  ["ssl-poodle"]             = "high",
  ["http-vuln-cve2017-5638"] = "critical",
  ["ftp-anon"]               = "medium",
}

function aggregator.collect(host, port)
  -- Nmap rulează deja aceste scripts când includem categoria "vuln" sau le
  -- specificăm explicit. Aici doar inspectăm rezultatele existente pe port
  -- și le normalizăm.
  local findings = {}
  local scripts_for_service = SERVICE_TO_SCRIPTS[port.service or ""] or {}

  -- port.script_results e populat de nmap dacă scripts au rulat
  if port.script_results then
    for _, sr in ipairs(port.script_results) do
      local script_id = sr.id
      local output = sr.output or ""
      -- Detectăm „VULNERABLE" în output (convenția NSE pentru finding pozitiv)
      if string.match(output, "VULNERABLE") or string.match(output, "Vulnerable") then
        local severity = SCRIPT_SEVERITY[script_id] or "medium"
        table.insert(findings, {
          rule_id = "NMAP-" .. string.upper(script_id):gsub("-", "_"),
          severity = severity,
          title = "Detected by NSE: " .. script_id,
          evidence = {
            port = port.number,
            service = port.service,
            nse_script = script_id,
            nse_output = string.sub(output, 1, 500),  -- truncate
          },
        })
      end
    end
  end
  return findings
end

-- ================================================================
-- SUB-MODULE 2: CVE MAPPER
-- ================================================================
local cve_mapper = {}

-- DB embedded: service → list of {version_pattern, cve, severity, title}
local CVE_DB = {
  ["microsoft-ds"] = {
    {pattern = ".*",                cve = "CVE-2017-0144", severity = "critical",
     title = "EternalBlue (MS17-010) — verifica patch SMB"},
  },
  ["netbios-ssn"] = {
    {pattern = ".*",                cve = "CVE-2017-0144", severity = "high",
     title = "NetBIOS expus — risc EternalBlue dacă SMB neactualizat"},
  },
  ["http"] = {
    {pattern = "[Aa]pache 2%.4%.49", cve = "CVE-2021-41773", severity = "critical",
     title = "Apache 2.4.49 path traversal RCE"},
    {pattern = "[Aa]pache 2%.4%.50", cve = "CVE-2021-42013", severity = "critical",
     title = "Apache 2.4.50 path traversal (incomplete fix for CVE-2021-41773)"},
    {pattern = "[Nn]ginx 1%.1[0-7]%.", cve = "CVE-2021-23017", severity = "high",
     title = "nginx DNS resolver buffer overflow"},
  },
  ["https"] = {
    {pattern = ".*",                cve = "Heartbleed check needed", severity = "info",
     title = "Verifică versiunea OpenSSL pe acest host (Heartbleed CVE-2014-0160 dacă 1.0.1a-f)"},
  },
  ["ssh"] = {
    {pattern = "[Oo]pen[Ss][Ss][Hh] 7%.[0-6]", cve = "CVE-2018-15473", severity = "medium",
     title = "OpenSSH ≤7.7 username enumeration"},
    {pattern = "[Oo]pen[Ss][Ss][Hh] 7%.[0-3]", cve = "CVE-2016-10009", severity = "high",
     title = "OpenSSH ≤7.4 forwarded auth agent abuse"},
  },
  ["ftp"] = {
    {pattern = "vsftpd 2%.3%.4", cve = "CVE-2011-2523", severity = "critical",
     title = "vsftpd 2.3.4 backdoor — orice user:pass acceptat"},
    {pattern = "ProFTPD 1%.3%.5", cve = "CVE-2015-3306", severity = "high",
     title = "ProFTPD 1.3.5 mod_copy RCE"},
  },
  ["telnet"] = {
    {pattern = ".*",                cve = "Plaintext protocol", severity = "high",
     title = "Telnet — protocol necriptat; folosește SSH"},
  },
  ["ms-wbt-server"] = {
    {pattern = ".*",                cve = "CVE-2019-0708", severity = "critical",
     title = "BlueKeep — verifică patch RDP pe Windows 7/Server 2008"},
  },
  ["mysql"] = {
    {pattern = "5%.[0-6]%.", cve = "Multiple CVEs", severity = "high",
     title = "MySQL 5.0-5.6 — versiune end-of-life, multiple CVE-uri"},
  },
  ["postgresql"] = {
    {pattern = "10%.", cve = "CVE-2018-1058", severity = "medium",
     title = "PostgreSQL 10.x — verifică privilegii pe search_path (CVE-2018-1058)"},
  },
  ["redis"] = {
    {pattern = ".*",                cve = "Unauth access common", severity = "high",
     title = "Redis — verifică AUTH config (default e fără parolă)"},
  },
  ["mongodb"] = {
    {pattern = ".*",                cve = "Unauth access common", severity = "high",
     title = "MongoDB — verifică authentication (default e fără auth)"},
  },
}

function cve_mapper.correlate(host, port)
  local findings = {}
  local service = port.service or ""
  local version = port.version or ""
  local product = (port.product or "")
  local search_str = product .. " " .. version

  local entries = CVE_DB[service]
  if not entries then return findings end

  for _, entry in ipairs(entries) do
    if string.match(search_str, entry.pattern) then
      table.insert(findings, {
        rule_id = "NMAP-CVE-MAPPER-" .. entry.cve:gsub("[^%w]", "_"),
        severity = entry.severity,
        title = entry.title,
        evidence = {
          host_ip = host.ip,
          port = port.number,
          service = service,
          version_detected = search_str,
          cve = entry.cve,
          source = "vulnwatch-audit/cve_mapper",
        },
      })
    end
  end
  return findings
end

-- ================================================================
-- SUB-MODULE 3: TOPOLOGY MAPPER
-- ================================================================
local topology = {}

function topology.discover(host)
  local role = "workstation"
  local risk_score = 0
  local reasons = {}

  local open_ports = {}
  for _, p in ipairs(host.ports or {}) do
    if p.state == "open" then
      table.insert(open_ports, p.number)
    end
  end

  -- Determine role
  for _, port in ipairs(open_ports) do
    if port == 53 then
      role = "dns"
      table.insert(reasons, "dns_port_open")
      break
    end
    if port == 445 or port == 139 then
      if role == "workstation" then role = "fileserver" end
      table.insert(reasons, "smb_open")
    end
    if port == 22 or port == 80 or port == 443 then
      table.insert(reasons, "internet_facing_service")
    end
  end

  -- Risk score
  local n_ports = #open_ports
  risk_score = risk_score + math.min(30, n_ports * 2)  -- 0-30 din # ports

  -- OS confidence
  if host.os and host.os.osmatches and #host.os.osmatches > 0 then
    local best = host.os.osmatches[1]
    if best.accuracy and tonumber(best.accuracy) < 70 then
      risk_score = risk_score + 10
      table.insert(reasons, "os_unidentified")
    end
    if best.name and string.match(best.name:lower(), "windows xp") then
      risk_score = risk_score + 30
      table.insert(reasons, "outdated_os")
    end
    if best.name and string.match(best.name:lower(), "windows 7") then
      risk_score = risk_score + 20
      table.insert(reasons, "outdated_os")
    end
  end

  return {
    role = role,
    risk_score = math.min(100, risk_score),
    reasons = reasons,
  }
end

-- ================================================================
-- ENTRY POINT
-- ================================================================
hostrule = function(host)
  return host.state == "up" or host.state == nil
end

action = function(host)
  local output = {
    host_ip = host.ip or "",
    findings = {},
    topology = {},
  }

  for _, port in ipairs(host.ports or {}) do
    if port.state == "open" then
      for _, f in ipairs(aggregator.collect(host, port)) do
        table.insert(output.findings, f)
      end
      for _, f in ipairs(cve_mapper.correlate(host, port)) do
        table.insert(output.findings, f)
      end
    end
  end

  output.topology = topology.discover(host)

  -- Output JSON ca string (NSE convention: return a string from action)
  local ok, encoded = pcall(json.generate, output)
  if not ok then
    return "vulnwatch-audit: JSON encode error"
  end
  return encoded
end
```

- [ ] **Step 6.2: Validare sintactică (luac)**

Dacă ai Lua instalat:
```bash
"C:\Program Files (x86)\Nmap\lua.exe" -e "dofile('agent/nse/vulnwatch-audit.nse')" 2>&1 || echo "lua syntax check skipped (lua exe nu suportă direct .nse fără nmap context)"
```

Verificarea reală: scriptul va fi încărcat de nmap în Task 11 când rulează scan-ul end-to-end. Pentru sintaxă pură, nmap acceptă o încărcare dry:
```bash
nmap --script vulnwatch-audit --script-help 2>&1 | grep -i "error\|description" | head
```
Expected: descrierea scriptului apare (fără erori). Necesită scriptul deja deployat la nmap scripts dir (Task 3 step).

- [ ] **Step 6.3: Commit**

```bash
git add agent/nse/vulnwatch-audit.nse
git commit -m "feat(agent/nse): vulnwatch-audit.nse cu 3 sub-module Lua (aggregator + CVE + topology)"
```

---

## Task 7: Backend — coloane DB + schemas + endpoint preview

**Files:**
- Modify: `server/app/models.py`
- Modify: `server/app/schemas.py`
- Modify: `server/app/routes.py`

- [ ] **Step 7.1: Adaugă coloane noi în models.py**

În `server/app/models.py`, în clasa `Device` (după linia `capabilities`), adaugă:

```python
    local_subnet: Mapped[str | None] = mapped_column(String(64), nullable=True)
    nmap_installed: Mapped[bool] = mapped_column(Integer, default=0)  # SQLite-friendly bool
```

În clasa `Scan` (după `payload`), adaugă:

```python
    nmap_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
```

În clasa `ScanJob` (după proprietatea `scan_type`), adaugă:

```python
    nmap_target: Mapped[str | None] = mapped_column(String(64), nullable=True)
```

- [ ] **Step 7.2: Update schemas.py**

În `server/app/schemas.py`, găsește `class HeartbeatIn` și adaugă field:

```python
class HeartbeatIn(BaseModel):
    # ... câmpurile existente
    local_subnet: str | None = None
```

Găsește `class ScanJobCreate` (sau echivalent care e folosit la POST /scan-jobs); adaugă:

```python
class ScanJobCreate(BaseModel):
    scan_type: str = "standard"
    nmap_target: str | None = None  # CIDR sau null
```

Găsește `class ScanIn`; adaugă optional nmap field:

```python
class ScanIn(BaseModel):
    # ... câmpurile existente
    nmap: dict | None = None
```

- [ ] **Step 7.3: Update routes.py — heartbeat salvează local_subnet**

În `server/app/routes.py`, găsește endpoint-ul `POST /agent/heartbeat` (~linia 350-400). În body-ul handler-ului, după `device.last_heartbeat = utcnow()`, adaugă:

```python
    if body.local_subnet:
        device.local_subnet = body.local_subnet
    # Setează nmap_installed dacă agent raportează "deep" în capabilities
    if body.capabilities and "deep" in body.capabilities:
        device.nmap_installed = True
    else:
        device.nmap_installed = False
```

- [ ] **Step 7.4: Adaugă endpoint nou `/devices/{uid}/scan-jobs/preview`**

În `routes.py`, înainte de endpoint-ul `POST /devices/{uid}/scan-jobs`, adaugă:

```python
@router.get("/devices/{device_uid}/scan-jobs/preview")
def scan_jobs_preview(
    device_uid: str,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    """Returnează detected_subnet + estimări pentru UI înainte de scan deep."""
    device = _get_user_device_or_404(db, user, device_uid)
    import ipaddress
    estimated_hosts = 0
    if device.local_subnet:
        try:
            net = ipaddress.ip_network(device.local_subnet, strict=False)
            estimated_hosts = min(net.num_addresses, 256)
        except ValueError:
            pass
    return {
        "detected_subnet": device.local_subnet,
        "nmap_installed": bool(device.nmap_installed),
        "estimated_hosts": estimated_hosts,
        "estimated_duration_sec": 600 + estimated_hosts * 30,  # 10min base + 30s/host
    }
```

- [ ] **Step 7.5: Validare CIDR în POST /scan-jobs**

Localizează handler-ul `POST /devices/{uid}/scan-jobs`. Înainte de `db.add(scan_job)`, adaugă validarea:

```python
    if body.nmap_target:
        import ipaddress
        try:
            net = ipaddress.ip_network(body.nmap_target, strict=False)
            if net.is_global:
                raise HTTPException(400, "nmap_target nu poate fi IP public")
            if net.num_addresses > 4096:
                raise HTTPException(400, "nmap_target prea mare (max 4096 hosts)")
        except ValueError as e:
            raise HTTPException(400, f"nmap_target invalid: {e}")
```

Și asignează `scan_job.nmap_target = body.nmap_target` înainte de `db.add`.

- [ ] **Step 7.6: Resetează schema DB dev**

Coloanele noi necesită reset DB dev (proiectul folosește `Base.metadata.create_all` la startup, fără migrare):
```bash
docker compose down -v && docker compose up -d
# Restart backend ca să creeze schema cu coloanele noi
```

- [ ] **Step 7.7: Test rapid**

```bash
python -m pytest server/tests/ -v 2>&1 | tail -5
```
Expected: PASS pentru toate testele existente (modificările sunt aditive).

- [ ] **Step 7.8: Commit**

```bash
git add server/app/models.py server/app/schemas.py server/app/routes.py
git commit -m "feat(server): coloane DB + endpoint preview pentru nmap scan deep"
```

---

## Task 8: Backend — rule NMAP-LUA-1 pass-through

**Files:**
- Modify: `server/app/rules.py`
- Create: `server/tests/test_nmap_findings.py`

- [ ] **Step 8.1: Scrie testul pentru rule-ul nou**

În `server/tests/test_nmap_findings.py`:

```python
"""Tests pentru NMAP-LUA-1 rule — pass-through finding-uri din vulnwatch-audit.nse."""
from app.rules import evaluate


def test_nmap_lua_findings_passthrough():
    scan = {
        "scan_type": "deep",
        "nmap": {
            "hosts": [
                {
                    "ip": "127.0.0.1",
                    "vulnwatch_findings": [
                        {"rule_id": "NMAP-CVE-2017-0144", "severity": "critical",
                         "title": "EternalBlue", "evidence": {"port": 445}}
                    ]
                }
            ]
        },
        # adăugăm și un minim de date psutil ca scor-ul să nu fie 0 doar din nmap
        "network": {"open_ports": []},
        "system": {},
        "processes": [],
        "software": [],
    }
    score, findings = evaluate(scan)
    nmap_findings = [f for f in findings if f.get("source") == "nmap-lua"]
    assert len(nmap_findings) == 1
    assert nmap_findings[0]["rule_id"] == "NMAP-CVE-2017-0144"
    assert nmap_findings[0]["evidence"]["host_ip"] == "127.0.0.1"
    # Critical → scor mare
    assert score > 0


def test_nmap_lua_no_findings_when_no_nmap_data():
    scan = {
        "scan_type": "deep",
        "network": {"open_ports": []},
        "system": {},
        "processes": [],
        "software": [],
    }
    score, findings = evaluate(scan)
    nmap_findings = [f for f in findings if f.get("source") == "nmap-lua"]
    assert len(nmap_findings) == 0


def test_nmap_lua_skipped_for_standard_scan():
    scan = {
        "scan_type": "standard",  # NMAP-LUA-1 are min_level="deep"
        "nmap": {
            "hosts": [{"ip": "127.0.0.1",
                      "vulnwatch_findings": [
                          {"rule_id": "X", "severity": "high", "title": "Y",
                           "evidence": {}}
                      ]}]
        },
        "network": {"open_ports": []},
        "system": {},
        "processes": [],
        "software": [],
    }
    score, findings = evaluate(scan)
    nmap_findings = [f for f in findings if f.get("source") == "nmap-lua"]
    assert len(nmap_findings) == 0
```

- [ ] **Step 8.2: Rulează (va eșua)**

```bash
python -m pytest server/tests/test_nmap_findings.py -v
```
Expected: FAIL — `nmap-lua` source nu apare.

- [ ] **Step 8.3: Adaugă rule-ul în `server/app/rules.py`**

La sfârșitul fișierului `rules.py`, după ultima rule existentă (BITLOCKER-OFF-1), adaugă:

```python
@rule("NMAP-LUA-1", min_level="deep")
def collect_nmap_lua_findings(scan: dict) -> list[dict] | None:
    """Wrapper pass-through pentru finding-urile emise de scriptul NSE custom
    `vulnwatch-audit.nse`. Lua a decis deja severitatea; Python doar le mută
    în lista finală cu prefix source='nmap-lua' + host_ip în evidence."""
    nmap = scan.get("nmap")
    if not nmap or not nmap.get("hosts"):
        return None
    findings = []
    for host in nmap["hosts"]:
        host_ip = host.get("ip", "")
        for f in host.get("vulnwatch_findings", []):
            evidence = dict(f.get("evidence", {}))
            evidence["host_ip"] = host_ip
            findings.append({
                "rule_id": f.get("rule_id", "NMAP-UNKNOWN"),
                "title": f.get("title", "Finding from nmap NSE"),
                "severity": f.get("severity", "info"),
                "evidence": evidence,
                "recommendation": f.get("recommendation",
                    "Vezi detaliile în secțiunea Network scan din raport."),
                "source": "nmap-lua",
            })
    return findings or None
```

- [ ] **Step 8.4: Rulează testele**

```bash
python -m pytest server/tests/test_nmap_findings.py -v
```
Expected: PASS — 3 tests.

- [ ] **Step 8.5: Commit**

```bash
git add server/app/rules.py server/tests/test_nmap_findings.py
git commit -m "feat(server/rules): NMAP-LUA-1 wrapper pentru findings vulnwatch-audit.nse"
```

---

## Task 9: Integration — service-side run_one_job extins cu nmap

**Files:**
- Modify: `agent/core.py` — `run_one_job` extins pentru deep + nmap

- [ ] **Step 9.1: Adaugă helper `_run_nmap_if_deep` în core.py**

În `agent/core.py`, după funcțiile `_nmap_path` și `deploy_nse_script` adăugate în Task 3:

```python
def _run_nmap_if_deep(
    job: dict,
    log: LogFn = _noop_log,
    progress_cb=None,
) -> dict | None:
    """Rulează nmap pentru scan deep. Întoarce dict cu schema nmap pentru payload,
    sau None dacă scan_type != deep sau nmap lipsește."""
    if job.get("scan_type") != "deep":
        return None
    from . import nmap_runner, nmap_parser

    nmap = _nmap_path()
    if not nmap:
        log("nmap.exe nu e instalat — sărim faza nmap pentru deep scan", "warn")
        return {"error": "nmap_missing"}

    targets = ["127.0.0.1"]
    nmap_target = job.get("nmap_target")
    if nmap_target:
        try:
            nmap_runner.validate_lan_target(nmap_target)
            targets.append(nmap_target)
        except nmap_runner.NmapRunnerError as e:
            log(f"nmap_target invalid: {e}; continui cu localhost only", "warn")

    import tempfile
    import time
    with tempfile.TemporaryDirectory() as tmp:
        xml_out = Path(tmp) / "nmap_result.xml"
        if progress_cb:
            progress_cb(80, "Nmap rulează...")
        t0 = time.time()
        try:
            exit_code, stderr = nmap_runner.run_nmap(
                targets=targets,
                xml_out=xml_out,
                top_ports=1000,
                timeout_sec=1800,
                log=log,
            )
        except nmap_runner.NmapRunnerError as e:
            log(f"nmap eșuat: {e}", "error")
            return {"error": str(e)}
        elapsed = time.time() - t0
        if not xml_out.is_file():
            log("nmap: XML output lipsește", "error")
            return {"error": "no_output", "stderr": stderr[:500]}
        try:
            parsed = nmap_parser.parse_nmap_xml(xml_out.read_text(encoding="utf-8"))
        except nmap_parser.NmapParseError as e:
            log(f"nmap parser eșuat: {e}", "error")
            return {"error": str(e)}
        parsed["targets"] = targets
        parsed["scan_time_sec"] = round(elapsed, 1)
        parsed["lan_opt_in"] = bool(nmap_target)
        parsed["lua_errors"] = []
        if stderr:
            # Capturăm doar liniile script-err din stderr
            for line in stderr.splitlines():
                if "vulnwatch-audit" in line.lower():
                    parsed["lua_errors"].append(line.strip())
        log(f"nmap: {len(parsed['hosts'])} hosts în {elapsed:.0f}s", "ok")
        return parsed
```

- [ ] **Step 9.2: Integrează apelul în `run_one_job`**

Localizează `run_one_job` în `core.py`. Modifică body-ul try (după `collect_system_data`):

```python
    try:
        data = collect_system_data(device_uid, scan_type=scan_type, progress_cb=progress_cb)
        # Extensie: pentru deep, adaugă nmap data
        nmap_result = _run_nmap_if_deep(job, log=log, progress_cb=progress_cb)
        if nmap_result is not None:
            data["nmap"] = nmap_result
        result = api_submit_job_result(api_base, device_token, job_id, data)
        # ... restul codului existent
```

- [ ] **Step 9.3: Smoke test cu mock**

Adaugă în `agent/tests/test_core.py` (sau test nou) un test care:
- mock-uiește `_nmap_path` să returneze None
- apelează `_run_nmap_if_deep` cu job `{scan_type: "deep"}`
- verifică result `{"error": "nmap_missing"}`

```python
def test_run_nmap_if_deep_no_nmap(monkeypatch):
    from agent import core
    monkeypatch.setattr(core, "_nmap_path", lambda: None)
    result = core._run_nmap_if_deep({"scan_type": "deep"})
    assert result == {"error": "nmap_missing"}


def test_run_nmap_if_deep_skipped_for_standard(monkeypatch):
    from agent import core
    result = core._run_nmap_if_deep({"scan_type": "standard"})
    assert result is None
```

```bash
python -m pytest agent/tests/test_core.py -v -k nmap
```
Expected: PASS — 2 tests.

- [ ] **Step 9.4: Commit**

```bash
git add agent/core.py agent/tests/test_core.py
git commit -m "feat(agent/core): run_one_job integreaza nmap+NSE Lua pe scan deep"
```

---

## Task 10: Frontend — UI deep + LAN confirm

**Files:**
- Modify: `web/src/pages/Devices.tsx`
- Modify: `web/src/api/types.ts`

- [ ] **Step 10.1: Adaugă types pentru preview**

În `web/src/api/types.ts`:

```typescript
export interface ScanJobPreview {
  detected_subnet: string | null;
  nmap_installed: boolean;
  estimated_hosts: number;
  estimated_duration_sec: number;
}

export interface NmapFinding {
  rule_id: string;
  severity: string;
  title: string;
  evidence: Record<string, unknown>;
}

export interface NmapHost {
  ip: string;
  hostname: string;
  state: string;
  os_guess: string;
  ports: Array<{port: number; proto: string; state: string;
                 service: string; version: string; cpe: string}>;
  vulnwatch_findings: NmapFinding[];
  topology: {role: string; risk_score: number; reasons: string[]};
}

export interface NmapData {
  version: string;
  scan_time_sec: number | null;
  targets: string[];
  lan_opt_in: boolean;
  lua_errors: string[];
  hosts: NmapHost[];
  error?: string;
}
```

- [ ] **Step 10.2: Update Devices.tsx — adaugă state + fetch preview**

În `web/src/pages/Devices.tsx`, în component-ul principal, adaugă:

```typescript
const [previewByDevice, setPreviewByDevice] = useState<Record<string, ScanJobPreview | null>>({});
const [lanOptInByDevice, setLanOptInByDevice] = useState<Record<string, boolean>>({});

useEffect(() => {
  // Fetch preview pentru toate devices care au scan_type deep selectat
  for (const [uid, type] of Object.entries(scanTypeByDevice)) {
    if (type === "deep" && !previewByDevice[uid]) {
      http<ScanJobPreview>(`/api/v1/devices/${uid}/scan-jobs/preview`)
        .then(p => setPreviewByDevice(prev => ({...prev, [uid]: p})))
        .catch(() => setPreviewByDevice(prev => ({...prev, [uid]: null})));
    }
  }
}, [scanTypeByDevice]);
```

Și modifică `handleScanNow` să includă confirm + nmap_target:

```typescript
async function handleScanNow(uid: string) {
  const scan_type = scanTypeByDevice[uid] ?? "standard";
  let nmap_target: string | null = null;
  if (scan_type === "deep") {
    const preview = previewByDevice[uid];
    const lanOptIn = lanOptInByDevice[uid] ?? false;
    if (lanOptIn && preview?.detected_subnet) {
      const ok = confirm(
        `Vei scana ${preview.estimated_hosts} IP-uri din rețeaua ta locală ` +
        `(${preview.detected_subnet}). Asigură-te că ai autorizare să faci asta. Continui?`
      );
      if (!ok) return;
      nmap_target = preview.detected_subnet;
    }
  }
  // existing scan start logic + add nmap_target la body
  const body: Record<string, unknown> = {scan_type};
  if (nmap_target) body.nmap_target = nmap_target;
  await http(`/api/v1/devices/${uid}/scan-jobs`, {method: "POST", body});
  // ... existing poll logic
}
```

- [ ] **Step 10.3: Render expander pentru deep settings**

În JSX-ul Devices.tsx, după `<select className="scan-type-select">`, adaugă un wrapper conditional:

```tsx
{scanTypeByDevice[d.device_uid] === "deep" && (
  <div className="deep-settings">
    {(() => {
      const preview = previewByDevice[d.device_uid];
      if (!preview) return <div className="muted">Verificare nmap...</div>;
      if (!preview.nmap_installed) {
        return (
          <div className="warn-banner">
            ⚠ nmap nu e instalat pe acest device.
            <a href="https://nmap.org/download.html" target="_blank" rel="noreferrer">
              Instalează nmap
            </a> și restart agentul.
          </div>
        );
      }
      return (
        <label className="lan-toggle">
          <input
            type="checkbox"
            checked={lanOptInByDevice[d.device_uid] ?? false}
            onChange={e => setLanOptInByDevice(prev => ({
              ...prev, [d.device_uid]: e.target.checked,
            }))}
          />
          Include LAN: {preview.detected_subnet ?? "(subnet nedetectat)"} —
          {preview.estimated_hosts} hosts estimat,
          ~{Math.round(preview.estimated_duration_sec / 60)} min
        </label>
      );
    })()}
  </div>
)}
```

- [ ] **Step 10.4: Adaugă CSS minimal pentru .deep-settings + .warn-banner**

În `web/src/index.css`, după secțiunea `.scan-controls`:

```css
.deep-settings { margin-top: 8px; font-size: 12px; }
.deep-settings .warn-banner {
  background: rgba(244,201,93,0.10);
  border: 1px solid var(--accent);
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  color: var(--text-primary);
}
.deep-settings .warn-banner a { color: var(--accent); margin-left: 6px; }
.deep-settings .lan-toggle {
  display: flex;
  gap: 8px;
  align-items: center;
  color: var(--text-secondary);
}
.muted { color: var(--text-muted); font-size: 12px; }
```

- [ ] **Step 10.5: Verifică în browser**

Cu backend + frontend rulând, selectează "Deep" în dropdown → ar trebui să apară expander cu „Include LAN" sau bannerul de install nmap.

- [ ] **Step 10.6: Commit**

```bash
git add web/src/pages/Devices.tsx web/src/api/types.ts web/src/index.css
git commit -m "feat(web): UI deep scan cu LAN opt-in checkbox + preview nmap status"
```

---

## Task 11: Frontend — ScanDetail nmap section

**Files:**
- Create: `web/src/components/NmapHostCard.tsx`
- Create: `web/src/components/NmapSection.tsx`
- Modify: `web/src/pages/ScanDetail.tsx`

- [ ] **Step 11.1: Creează NmapHostCard.tsx**

```tsx
import type { NmapHost } from "../api/types";

interface Props { host: NmapHost; }

export default function NmapHostCard({ host }: Props) {
  const role = host.topology?.role ?? "unknown";
  const risk = host.topology?.risk_score ?? 0;
  return (
    <div className="nmap-host-card">
      <header className="nmap-host-header">
        <span className="nmap-host-ip">{host.ip}</span>
        {host.hostname && <span className="nmap-host-name">({host.hostname})</span>}
        <span className={`nmap-role nmap-role-${role}`}>{role}</span>
        <span className="nmap-risk">risc {risk}/100</span>
      </header>
      {host.os_guess && <div className="nmap-os">OS: {host.os_guess}</div>}
      <div className="nmap-ports">
        {host.ports.filter(p => p.state === "open").map(p => (
          <div key={`${p.proto}-${p.port}`} className="nmap-port">
            <code>{p.port}/{p.proto}</code> {p.service}
            {p.version && <span className="nmap-version"> {p.version}</span>}
          </div>
        ))}
      </div>
      {host.vulnwatch_findings.length > 0 && (
        <div className="nmap-findings">
          <h4>Findings ({host.vulnwatch_findings.length})</h4>
          {host.vulnwatch_findings.map((f, i) => (
            <div key={i} className={`nmap-finding sev-${f.severity}`}>
              <span className="finding-rule">{f.rule_id}</span>
              <span className="finding-title">{f.title}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 11.2: Creează NmapSection.tsx**

```tsx
import type { NmapData } from "../api/types";
import NmapHostCard from "./NmapHostCard";

interface Props { nmap: NmapData; }

export default function NmapSection({ nmap }: Props) {
  if (nmap.error) {
    return (
      <section className="nmap-section">
        <h2>Network scan (nmap)</h2>
        <div className="nmap-error">⚠ Faza nmap eșuată: {nmap.error}</div>
      </section>
    );
  }
  return (
    <section className="nmap-section">
      <h2>Network scan (nmap {nmap.version})</h2>
      <div className="nmap-meta">
        Scanat: {nmap.targets.join(", ")} ·
        Durată: {nmap.scan_time_sec}s ·
        {nmap.hosts.length} host-uri descoperite
      </div>
      <div className="nmap-hosts">
        {nmap.hosts.map(h => <NmapHostCard key={h.ip} host={h} />)}
      </div>
      {nmap.lua_errors.length > 0 && (
        <details className="nmap-lua-errors">
          <summary>Lua warnings ({nmap.lua_errors.length})</summary>
          <pre>{nmap.lua_errors.join("\n")}</pre>
        </details>
      )}
    </section>
  );
}
```

- [ ] **Step 11.3: Update ScanDetail.tsx**

În `web/src/pages/ScanDetail.tsx`, găsește unde se randează findings (sau payload). Adaugă, după secțiunea de findings standard:

```tsx
{scan.payload?.nmap && (
  <NmapSection nmap={scan.payload.nmap as NmapData} />
)}
```

Import:
```tsx
import NmapSection from "../components/NmapSection";
import type { NmapData } from "../api/types";
```

- [ ] **Step 11.4: CSS pentru nmap section**

În `web/src/index.css`:

```css
.nmap-section { margin-top: 32px; padding: 20px; background: var(--bg-elevated);
  border-radius: var(--radius-md); }
.nmap-section h2 { color: var(--accent); font-family: var(--font-display); }
.nmap-meta { font-size: 13px; color: var(--text-muted); margin-bottom: 14px; }
.nmap-host-card { padding: 14px; background: var(--bg);
  border: 1px solid var(--border); border-radius: var(--radius-sm);
  margin-bottom: 12px; }
.nmap-host-header { display: flex; gap: 10px; align-items: center;
  margin-bottom: 8px; }
.nmap-host-ip { font-family: var(--font-mono); font-weight: 700;
  color: var(--accent); }
.nmap-role { padding: 2px 8px; border-radius: var(--radius-full);
  background: var(--bg-elevated); font-size: 11px; }
.nmap-port { font-family: var(--font-mono); font-size: 12px; margin: 4px 0; }
.nmap-finding { padding: 6px 10px; margin: 4px 0; border-left: 3px solid;
  border-radius: var(--radius-sm); background: var(--bg-elevated); }
.nmap-finding.sev-critical { border-color: #d04060; }
.nmap-finding.sev-high     { border-color: #e07090; }
.nmap-finding.sev-medium   { border-color: var(--accent); }
.nmap-error { color: #e07090; padding: 12px; }
```

- [ ] **Step 11.5: Commit**

```bash
git add web/src/components/NmapHostCard.tsx web/src/components/NmapSection.tsx \
        web/src/pages/ScanDetail.tsx web/src/index.css
git commit -m "feat(web): NmapSection + NmapHostCard pentru afisare findings deep scan"
```

---

## Task 12: GUI install-service modal + IPC client

**Files:**
- Modify: `agent/gui.py`

- [ ] **Step 12.1: Adaugă check Service status la login reușit**

În `agent/gui.py`, în `_finalize_enrollment` (sau echivalent la trecerea spre Status page):

```python
def _finalize_enrollment(self):
    # ... cod existent
    # Check daca Service e installed; daca nu, prompt
    from . import service
    if service._PYWIN32_AVAILABLE and not service.is_service_installed():
        if messagebox.askyesno(
            "Instalare serviciu",
            "Pentru scan-uri deep cu network audit, agent-ul trebuie instalat "
            "ca serviciu Windows.\n\nVei vedea un prompt UAC pentru aprobare. "
            "Continui?",
        ):
            self._launch_install_service()
    self._render_status_page()


def _launch_install_service(self):
    """Relauncheaza exe-ul cu --install-service sub UAC."""
    import ctypes
    import sys
    exe = sys.executable
    try:
        # ShellExecute cu lpVerb='runas' → triggera UAC
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, "--install-service", None, 1
        )
        if ret <= 32:
            self._append_log("Install Service: UAC anulat sau eșuat", "warn")
    except Exception as e:
        self._append_log(f"Install Service: {e}", "error")
```

- [ ] **Step 12.2: Adaugă opțiunea „Re-instalează serviciu" în meniul ⚙**

În `_open_settings_menu` din gui.py, adaugă înainte de „Setări avansate API URL":

```python
        from . import service
        if service._PYWIN32_AVAILABLE:
            svc_label = "Re-instalează serviciu" if service.is_service_installed() else "Instalează serviciu"
            m.add_command(label=svc_label, command=self._launch_install_service)
            m.add_separator()
```

- [ ] **Step 12.3: Commit**

```bash
git add agent/gui.py
git commit -m "feat(agent/gui): prompt UAC install service + meniu re-instalare"
```

---

## Task 13: Update VulnWatchAgent.spec pentru bundling NSE

**Files:**
- Modify: `agent/VulnWatchAgent.spec`

- [ ] **Step 13.1: Adaugă scriptul NSE în datas**

În `agent/VulnWatchAgent.spec`, modifică Analysis:

```python
a = Analysis(
    [str(agent_dir / "scan.py")],
    pathex=[str(repo_root)],
    binaries=[],
    datas=[
        (str(agent_dir / "nse" / "vulnwatch-audit.nse"),
         "nse"),  # → sys._MEIPASS/nse/vulnwatch-audit.nse
    ],
    hiddenimports=[
        "agent",
        "agent.core",
        "agent.gui",
        "agent.autostart",
        "agent.tray",
        "agent.service",      # NOU
        "agent.ipc",          # NOU
        "agent.nmap_runner",  # NOU
        "agent.nmap_parser",  # NOU
        "pystray._win32",
        "pystray._gtk",
        "pystray._darwin",
        "pystray._dummy",
        "PIL.Image",
        "PIL.ImageDraw",
        "win32serviceutil",   # NOU pentru Service mode
        "win32service",
        "win32event",
        "servicemanager",
    ],
    # ... rest neschimbat
)
```

- [ ] **Step 13.2: Rebuild executabil**

```powershell
.\.venv-build\Scripts\python.exe -m pip install -r agent/requirements.txt
.\.venv-build\Scripts\python.exe -m PyInstaller --clean .\agent\VulnWatchAgent.spec
Copy-Item -Path .\dist\VulnWatchAgent.exe -Destination .\server\app\static\agent\VulnWatchAgent.exe -Force
```

Verifică mărime:
```powershell
(Get-Item .\dist\VulnWatchAgent.exe).Length / 1MB
```
Expected: ~28-30 MB (mic creștere față de 26 MB datorită pywin32 + module noi).

- [ ] **Step 13.3: Commit**

```bash
git add agent/VulnWatchAgent.spec
git commit -m "build: include vulnwatch-audit.nse + pywin32 hiddenimports in spec"
```

---

## Task 14: Memory.md updates + smoke checklist

**Files:**
- Modify: `agent/memory.md`
- Modify: `server/app/memory.md`
- Modify: `agent/tests/memory.md`

- [ ] **Step 14.1: Update agent/memory.md**

În tabelul `## Fisiere`, adaugă rânduri noi:
```markdown
| `service.py`               | **Windows Service wrapper (pywin32).** `VulnWatchService` class (subclasă `ServiceFramework`). Pornește `core.daemon_loop` pe thread, raportează la SCM. Funcții public: `install_service()`, `uninstall_service()`, `is_service_installed()`, `is_service_running()`, `run_as_service()` (entry point pentru `--service` flag). |
| `ipc.py`                   | **Protocol IPC GUI↔Service** prin TCP socket localhost (substituie named pipe pe Windows; cross-platform pentru dev). `IpcServer` cu handler + broadcast events; `IpcClient` cu request + subscribe_events. Mesaje JSON line-delimited. |
| `nmap_runner.py`           | **Construire CLI args nmap + execuție subprocess.** `validate_cidr`, `validate_lan_target` (refuză IP public + subnet > 4096 hosts), `build_nmap_args`, `run_nmap` (cu timeout 30 min). |
| `nmap_parser.py`           | **Parse XML output nmap → dict VulnWatch.** Extrage host info (IP, OS, ports) + deserializează JSON-ul emis de scriptul `vulnwatch-audit` din `<script id="vulnwatch-audit">`. |
| `nse/vulnwatch-audit.nse`  | **Scriptul NSE custom în Lua (~400 LOC).** 3 sub-module: aggregator (preia output din scripts vuln NSE built-in), CVE mapper (CVE_DB embedded ~30 entries, pattern matching pe service+version), topology mapper (determină rol gateway/dns/fileserver/workstation + risc 0-100). Output: JSON structurat per host. |
```

În tabel pentru `core.py`, extinde descrierea cu menționarea funcțiilor noi: `_nmap_path`, `_bundled_nse_path`, `deploy_nse_script`, `agent_capabilities`, `_run_nmap_if_deep`.

În tabel pentru `gui.py`, menționează `_launch_install_service` și prompt UAC.

În tabel pentru `VulnWatchAgent.spec`, menționează că include scriptul NSE + pywin32 hiddenimports.

- [ ] **Step 14.2: Update server/app/memory.md**

În tabelul `## Fisiere`:
- pentru `models.py`: menționează coloanele noi (`Device.local_subnet`, `Device.nmap_installed`, `Scan.nmap_data`, `ScanJob.nmap_target`)
- pentru `rules.py`: menționează rule nou `NMAP-LUA-1` în secțiunea regulilor + actualizează numărul total
- pentru `routes.py`: menționează endpoint nou `GET /devices/{uid}/scan-jobs/preview`

- [ ] **Step 14.3: Update agent/tests/memory.md**

Adaugă rânduri pentru testele noi:
```markdown
| `test_ipc.py`            | 3 teste pentru protocol IPC: request/response, push events, error pe cmd necunoscut. |
| `test_nmap_runner.py`    | 7 teste pentru CLI args + CIDR validation (refuz public + huge). |
| `test_nmap_parser.py`    | 3 teste parsing XML nmap (fixture localhost + multi-host + invalid). |
| `test_service_install.py`| (opt) tests pentru install/uninstall Service (mock pywin32). |
```

Update numărul total de teste în footer.

- [ ] **Step 14.4: Smoke testing checklist (manual)**

Adaugă într-o secțiune dedicată în `agent/memory.md` (sau document separat):

```
[ ] 1. Install nmap pe mașina test → restart agent → în UI capabilities arată "deep" disponibil
[ ] 2. Click Deep în dropdown → apare expander cu checkbox LAN
[ ] 3. Modal install service → UAC prompt → service instalat (verifică `sc.exe query VulnWatchSvc`)
[ ] 4. Service status: running, capabilities heartbeat include "deep"
[ ] 5. Trigger Deep scan FĂRĂ LAN → finalizat în 10-15 min → vezi nmap section în ScanDetail
[ ] 6. Findings nmap apar cu severity (critical/high/medium) și source=nmap-lua
[ ] 7. Trigger Deep scan CU LAN bifat → confirm modal → scan extins, vezi multi-host
[ ] 8. ScanDetail afișează NmapHostCard pentru fiecare host descoperit
[ ] 9. Uninstall nmap din sistem → restart service → capabilities NU mai include "deep" → UI dezactivează Deep
[ ] 10. Stop service manual (`sc.exe stop VulnWatchSvc`) → GUI status arată "offline"
```

- [ ] **Step 14.5: Commit final**

```bash
git add agent/memory.md server/app/memory.md agent/tests/memory.md
git commit -m "docs: memory.md reflecta integrare nmap + NSE Lua + Service mode"
```

---

## Self-Review Notes (after writing the plan)

**Spec coverage:**
- ✅ Process architecture (Service + GUI + IPC) → Tasks 1, 2, 12
- ✅ nmap detection + NSE deploy → Task 3
- ✅ NSE Lua custom (3 sub-module + CVE_DB) → Task 6
- ✅ nmap runner + parser → Tasks 4, 5
- ✅ Backend DB columns + endpoint preview → Task 7
- ✅ Backend rule NMAP-LUA-1 → Task 8
- ✅ Integration daemon_loop → Task 9
- ✅ Frontend Devices + ScanDetail → Tasks 10, 11
- ✅ Build spec update → Task 13
- ✅ Memory.md + smoke checklist → Task 14

**Gaps acceptate (out of scope conform spec):**
- Live nmap progress streaming per host (raportăm doar progress la trans psutil→nmap)
- CVE_DB online refresh
- Linux/macOS support pentru Service mode

**Known limitations / follow-ups:**
- Testele pentru `test_service_install.py` sunt opționale (mock pywin32 complicat) — planul nu le include în detaliu
- Testele NSE Lua (Busted) NU sunt incluse în plan ca task obligatoriu — pot fi adăugate ulterior dacă Lua testing infrastructure e configurată
- Named pipe Windows-specific NU e implementat — folosim TCP socket localhost peste tot pentru portabilitate. Pe Windows production se poate migra la `win32pipe` într-un task viitor dacă apare nevoie de securitate strictă DACL

---

**Plan complete. 14 task-uri executabile, fiecare cu cod complet + comenzi exacte + commit message. Estimat ~2050-2150 LOC + binary fixtures + script Lua.**
