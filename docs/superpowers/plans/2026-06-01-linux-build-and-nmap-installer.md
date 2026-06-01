# Linux Build + Nmap Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Build Linux pentru agent (binar PyInstaller + systemd, via CI) + buton de instalare nmap din executabil pe Windows si Linux, cu download per-OS in platforma.

**Architecture:** PyInstaller nu cross-compileaza → binarul Linux iese din CI (GitHub Actions pe Ubuntu). Installer-ul nmap e OS-aware (winget / apt|dnf|pacman|zypper + pkexec|sudo). Backend serveste artefactul potrivit; frontend detecteaza OS-ul.

**Tech Stack:** Python (PyInstaller, shutil, subprocess, psutil), bash, FastAPI, React/TS, GitHub Actions, pytest, vitest.

---

## Comenzi de test
- Agent: `python -m pytest agent/tests/<file> -v`
- Server: `cd server; $env:DISABLE_SCHEDULER="true"; $env:DISABLE_RATELIMIT="true"; .\.venv\Scripts\python.exe -m pytest tests/<file> -v`
- Frontend: `cd web; npm test`

---

# FAZA 1 — Installer nmap (Windows + Linux)

### Task 1: detect_package_manager + build_nmap_install_command

**Files:**
- Modify: `agent/core.py`
- Test: `agent/tests/test_nmap_install.py` (nou)

- [ ] **Step 1: Write the failing test**

```python
# agent/tests/test_nmap_install.py
from agent import core

def test_detect_package_manager_apt(monkeypatch):
    monkeypatch.setattr(core.shutil, "which", lambda x: "/usr/bin/apt-get" if x == "apt-get" else None)
    assert core.detect_package_manager() == "apt-get"

def test_detect_package_manager_none(monkeypatch):
    monkeypatch.setattr(core.shutil, "which", lambda x: None)
    assert core.detect_package_manager() is None

def test_build_nmap_install_command_windows(monkeypatch):
    monkeypatch.setattr(core.sys, "platform", "win32")
    cmd = core.build_nmap_install_command()
    assert cmd is not None and "winget" in cmd[0] and "Insecure.Nmap" in cmd

def test_build_nmap_install_command_linux_apt(monkeypatch):
    monkeypatch.setattr(core.sys, "platform", "linux")
    monkeypatch.setattr(core, "detect_package_manager", lambda: "apt-get")
    cmd = core.build_nmap_install_command()
    assert cmd == ["apt-get", "install", "-y", "nmap"]

def test_build_nmap_install_command_linux_pacman(monkeypatch):
    monkeypatch.setattr(core.sys, "platform", "linux")
    monkeypatch.setattr(core, "detect_package_manager", lambda: "pacman")
    cmd = core.build_nmap_install_command()
    assert cmd == ["pacman", "-S", "--noconfirm", "nmap"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest agent/tests/test_nmap_install.py -v`
Expected: FAIL — functii inexistente

- [ ] **Step 3: Implement (in agent/core.py)**

```python
def detect_package_manager() -> str | None:
    """Intoarce primul package manager Linux gasit, sau None."""
    for pm in ("apt-get", "dnf", "pacman", "zypper"):
        if shutil.which(pm):
            return pm
    return None


_PM_INSTALL = {
    "apt-get": ["apt-get", "install", "-y", "nmap"],
    "dnf": ["dnf", "install", "-y", "nmap"],
    "pacman": ["pacman", "-S", "--noconfirm", "nmap"],
    "zypper": ["zypper", "install", "-y", "nmap"],
}


def build_nmap_install_command() -> list[str] | None:
    """Comanda de instalare nmap pentru OS-ul curent (fara escaladare)."""
    if sys.platform == "win32":
        return ["winget", "install", "-e", "--id", "Insecure.Nmap", "--silent"]
    pm = detect_package_manager()
    if pm:
        return _PM_INSTALL[pm]
    return None
```

(Verifica `import shutil` si `import sys` exista in core.py — exista deja.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest agent/tests/test_nmap_install.py -v`
Expected: PASS (5)

- [ ] **Step 5: Commit**

```bash
git add agent/core.py agent/tests/test_nmap_install.py
git commit -m "feat(agent): detect package manager + build comanda install nmap (OS-aware)"
```

---

### Task 2: install_nmap cu escaladare + fallback

**Files:**
- Modify: `agent/core.py`
- Test: `agent/tests/test_nmap_install.py`

- [ ] **Step 1: Write the failing test**

```python
# in agent/tests/test_nmap_install.py
def test_install_nmap_linux_fallback_to_manual_command(monkeypatch):
    """Fara pkexec/sudo → intoarce (False, mesaj cu comanda manuala)."""
    monkeypatch.setattr(core.sys, "platform", "linux")
    monkeypatch.setattr(core, "build_nmap_install_command", lambda: ["apt-get", "install", "-y", "nmap"])
    monkeypatch.setattr(core.shutil, "which", lambda x: None)  # nici pkexec, nici sudo
    ok, msg = core.install_nmap(log=lambda m, s="info": None)
    assert ok is False
    assert "apt-get install -y nmap" in msg

def test_install_nmap_unknown_os(monkeypatch):
    monkeypatch.setattr(core, "build_nmap_install_command", lambda: None)
    ok, msg = core.install_nmap(log=lambda m, s="info": None)
    assert ok is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest agent/tests/test_nmap_install.py -k install_nmap -v`
Expected: FAIL — `install_nmap` inexistent

- [ ] **Step 3: Implement install_nmap**

```python
def install_nmap(log: LogFn = _noop_log) -> tuple[bool, str]:
    """Instaleaza nmap pe OS-ul curent. Intoarce (succes, mesaj).

    Windows: winget. Linux: prefixeaza cu pkexec (prompt grafic) sau sudo; daca
    niciunul nu exista, intoarce comanda manuala pentru user."""
    cmd = build_nmap_install_command()
    if cmd is None:
        return False, ("Nu pot detecta cum sa instalez nmap pe acest sistem. "
                       "Descarca-l manual de pe https://nmap.org/download.html")

    if sys.platform == "win32":
        full = cmd
    else:
        if shutil.which("pkexec"):
            full = ["pkexec"] + cmd
        elif shutil.which("sudo"):
            full = ["sudo"] + cmd
        else:
            manual = " ".join(["sudo"] + cmd)
            return False, f"Ruleaza manual (necesita root): {manual}"

    log(f"Instalez nmap: {' '.join(full)}", "info")
    try:
        result = subprocess.run(full, capture_output=True, text=True, timeout=300)
    except (subprocess.SubprocessError, OSError) as e:
        return False, f"Instalare esuata: {e}"
    if result.returncode != 0:
        return False, f"Instalare esuata (cod {result.returncode}): {(result.stderr or '')[:300]}"
    # Re-verifica
    if _nmap_path():
        return True, "nmap a fost instalat cu succes."
    return True, "Comanda de instalare a rulat. Reporneste agentul daca nmap nu e detectat inca."
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest agent/tests/test_nmap_install.py -v`
Expected: PASS (7)

- [ ] **Step 5: Commit**

```bash
git add agent/core.py agent/tests/test_nmap_install.py
git commit -m "feat(agent): install_nmap cu pkexec/sudo + fallback comanda manuala"
```

---

### Task 3: Buton "Instaleaza nmap" in GUI

**Files:**
- Modify: `agent/gui.py`

- [ ] **Step 1: Add button on Status page (cand nmap lipseste)**

In zona de Status, cand `core._nmap_path() is None`, afiseaza un buton "Instaleaza nmap". Handler:

```python
def _on_install_nmap(self):
    def worker():
        ok, msg = core.install_nmap(log=self._log)
        self._log(msg, "ok" if ok else "warn")
        if ok:
            # re-emite capabilities (deep devine disponibil)
            self._refresh_capabilities()
    threading.Thread(target=worker, daemon=True).start()
```

(Adapteaza la helper-ele de logging/threading existente in gui.py; `_refresh_capabilities` poate fi un no-op daca nu exista — minim: logheaza succesul.)

- [ ] **Step 2: Manual smoke (fara test automat pentru GUI)**

Verifica `python -c "from agent import gui"` nu arunca la import.
Run: `python -c "import agent.gui"`
Expected: fara eroare.

- [ ] **Step 3: Commit**

```bash
git add agent/gui.py
git commit -m "feat(gui): buton Instaleaza nmap cand lipseste (thread + log live)"
```

---

# FAZA 2 — Build Linux (spec platform-aware + build.sh + collectors + CI)

### Task 4: VulnWatchAgent.spec platform-aware

**Files:**
- Modify: `agent/VulnWatchAgent.spec`

- [ ] **Step 1: Make hiddenimports + name + icon conditional**

La inceput adauga `import sys`. Construieste `hiddenimports` de baza (agent.*, pystray._gtk/_dummy, PIL) si extinde cu pywin32 + pystray._win32 doar pe Windows:

```python
import sys
_win = sys.platform == "win32"
hidden = ["agent", "agent.core", "agent.gui", "agent.autostart", "agent.tray",
          "agent.service", "agent.ipc", "agent.nmap_runner", "agent.nmap_parser",
          "agent.single_instance", "PIL.Image", "PIL.ImageDraw",
          "pystray._gtk", "pystray._dummy"]
if _win:
    hidden += ["win32serviceutil", "win32service", "win32event", "win32api",
               "winerror", "servicemanager", "pywintypes", "pystray._win32"]
```

Foloseste `hidden` in `Analysis(hiddenimports=hidden, ...)`. In `EXE(...)`:
```python
    name="VulnWatchAgent" if _win else "vulnwatch-agent",
    icon=("agent/icon.ico" if _win else None),  # daca exista icon; altfel None pe ambele
```
(Daca specul nu seta icon, lasa fara icon — nu adauga.)

- [ ] **Step 2: Verify spec parses (Windows build inca merge)**

Run: `& .\.venv-build\Scripts\python.exe -m PyInstaller --clean --noconfirm .\agent\VulnWatchAgent.spec`
Expected: build OK, `dist\VulnWatchAgent.exe` produs.

- [ ] **Step 3: Commit**

```bash
git add agent/VulnWatchAgent.spec
git commit -m "build: spec PyInstaller platform-aware (pywin32 + nume doar pe Windows)"
```

---

### Task 5: agent/build.sh (build Linux)

**Files:**
- Create: `agent/build.sh`

- [ ] **Step 1: Write build.sh** (ASCII pur, set -e)

```bash
#!/usr/bin/env bash
# Build vulnwatch-agent (Linux). Ruleaza: bash agent/build.sh
set -e
cd "$(dirname "$0")/.."

echo "==> Verific Python..."
PY=$(command -v python3 || command -v python)
"$PY" --version

echo "==> venv build (.venv-build)..."
[ -d .venv-build ] || "$PY" -m venv .venv-build
VPY=.venv-build/bin/python

echo "==> Instalare dependente..."
"$VPY" -m pip install --quiet --upgrade pip
"$VPY" -m pip install --quiet pyinstaller psutil requests google-auth google-auth-oauthlib pillow pystray

echo "==> Build PyInstaller..."
"$VPY" -m PyInstaller --clean --noconfirm agent/VulnWatchAgent.spec

BIN=dist/vulnwatch-agent
if [ ! -f "$BIN" ]; then
  echo "Build esuat - nu s-a produs $BIN" >&2
  exit 2
fi
echo "==> SUCCES: $BIN ($(du -h "$BIN" | cut -f1))"

if [ -d server/app ]; then
  mkdir -p server/app/static/agent
  cp "$BIN" server/app/static/agent/vulnwatch-agent
  echo "    Copiat in server/app/static/agent/vulnwatch-agent"
fi
```

- [ ] **Step 2: Verify shell syntax**

Run: `bash -n agent/build.sh`
Expected: fara erori de sintaxa.

- [ ] **Step 3: Commit**

```bash
git add agent/build.sh
git commit -m "build: script build.sh pentru binarul Linux"
```

---

### Task 6: collect_system_data nu arunca pe Linux (smoke)

**Files:**
- Modify: `agent/core.py` (doar daca un colector arunca neprins)
- Test: `agent/tests/test_core.py`

- [ ] **Step 1: Write the test**

```python
# in agent/tests/test_core.py
import pytest
@pytest.mark.parametrize("st", ["standard", "advanced", "deep"])
def test_collect_system_data_never_raises(st):
    from agent import core
    data = core.collect_system_data("uid", scan_type=st)
    for key in ("os", "network", "processes", "software"):
        assert key in data
```

- [ ] **Step 2: Run test**

Run: `python -m pytest agent/tests/test_core.py::test_collect_system_data_never_raises -v`
Expected: PASS pe Windows. Daca esueaza pe Linux CI pentru un colector, adauga try/except in colectorul respectiv (intorc gol). (Pe Windows ar trebui sa treaca direct.)

- [ ] **Step 3: Commit**

```bash
git add agent/tests/test_core.py
git commit -m "test(agent): collect_system_data nu arunca pentru niciun scan_type"
```

---

### Task 7: scan.py --install-service pe Linux → systemd

**Files:**
- Modify: `agent/scan.py`

- [ ] **Step 1: Route service flags per-OS**

In `main()`, ramurile `--install-service` / `--uninstall-service`: pe Windows raman la `service`; pe non-Windows delegheaza la `autostart`:

```python
    if "--install-service" in sys.argv:
        if sys.platform == "win32":
            from . import service  # (cu fallback agent.service)
            return service.install_service()
        from . import autostart
        ok, msg = autostart.enable(); print(msg); return 0 if ok else 1
    if "--uninstall-service" in sys.argv:
        if sys.platform == "win32":
            from . import service
            return service.uninstall_service()
        from . import autostart
        ok, msg = autostart.disable(); print(msg); return 0 if ok else 1
```

(Pastreaza pattern-ul de import cu fallback `agent.X` existent.)

- [ ] **Step 2: Verify import**

Run: `python -c "import agent.scan"`
Expected: fara eroare.

- [ ] **Step 3: Commit**

```bash
git add agent/scan.py
git commit -m "feat(agent): --install-service pe Linux deleaga la systemd (autostart)"
```

---

### Task 8: CI job build-linux

**Files:**
- Modify: `.github/workflows/test.yml`

- [ ] **Step 1: Add job**

```yaml
  build-linux:
    name: Build agent Linux binary
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          pip install pyinstaller psutil requests google-auth google-auth-oauthlib pillow pystray
      - name: Build
        run: bash agent/build.sh
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: vulnwatch-agent-linux
          path: dist/vulnwatch-agent
```

- [ ] **Step 2: Verify YAML**

Run: `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/test.yml'))"`
Expected: fara eroare.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/test.yml
git commit -m "ci: job build-linux produce binarul agent pe Ubuntu"
```

---

# FAZA 3 — Download per-OS (backend + frontend)

### Task 9: Backend /agent/download/linux + info per-OS

**Files:**
- Modify: `server/app/routes/agent.py`
- Test: `server/tests/test_agent_download.py`

- [ ] **Step 1: Write the failing test**

```python
# in server/tests/test_agent_download.py
def test_download_linux_404_when_missing(tmp_path, monkeypatch):
    from server.app.routes import _helpers
    monkeypatch.setattr(_helpers, "_AGENT_BUILD_LOCATIONS", (tmp_path,))
    c = _make_user_client("linux-empty")
    r = c.get("/api/v1/agent/download/linux")
    assert r.status_code == 404

def test_download_linux_serves_when_present(tmp_path, monkeypatch):
    from server.app.routes import _helpers
    (tmp_path / "vulnwatch-agent").write_bytes(b"\x7fELF fake-binary")
    monkeypatch.setattr(_helpers, "_AGENT_BUILD_LOCATIONS", (tmp_path,))
    c = _make_user_client("linux-ok")
    r = c.get("/api/v1/agent/download/linux")
    assert r.status_code == 200
    assert r.content.startswith(b"\x7fELF")

def test_download_info_reports_per_os(tmp_path, monkeypatch):
    from server.app.routes import _helpers
    (tmp_path / "vulnwatch-agent").write_bytes(b"\x7fELF fake")
    monkeypatch.setattr(_helpers, "_AGENT_BUILD_LOCATIONS", (tmp_path,))
    c = _make_user_client("info-peros")
    body = c.get("/api/v1/agent/download/info").json()
    assert body["linux"]["available"] is True
    assert "windows" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: ...`pytest tests/test_agent_download.py -k "linux or per_os" -v`
Expected: FAIL — ruta /linux inexistenta

- [ ] **Step 3: Implement endpoint + extend info**

In `server/app/routes/agent.py`:

```python
@router.get("/agent/download/linux", tags=["agent"])
def download_agent_linux(_user: User = Depends(require_user)):
    artifact = _find_agent_artifact("vulnwatch-agent")
    if not artifact:
        raise HTTPException(status_code=404, detail=(
            "Binar Linux indisponibil. Build-eaza-l: bash agent/build.sh"))
    return FileResponse(path=str(artifact), media_type="application/octet-stream",
                        filename="vulnwatch-agent")
```

Inlocuieste `download_agent_info` ca sa raporteze per-OS (pastrand campurile top-level pentru compat):

```python
@router.get("/agent/download/info", tags=["agent"])
def download_agent_info(_user: User = Depends(require_user)):
    win = _find_agent_artifact("VulnWatchAgent.exe")
    lin = _find_agent_artifact("vulnwatch-agent")
    return {
        "available": win is not None,   # backward-compat (Windows)
        "platform": "windows",
        "size_bytes": win.stat().st_size if win else None,
        "windows": {"available": win is not None, "size_bytes": win.stat().st_size if win else None},
        "linux": {"available": lin is not None, "size_bytes": lin.stat().st_size if lin else None},
    }
```

- [ ] **Step 4: Run tests**

Run: ...`pytest tests/test_agent_download.py -v`
Expected: PASS (toate, inclusiv cele vechi).

- [ ] **Step 5: Commit**

```bash
git add server/app/routes/agent.py server/tests/test_agent_download.py
git commit -m "feat(api): GET /agent/download/linux + info disponibilitate per-OS"
```

---

### Task 10: Frontend detectOS + download OS-aware

**Files:**
- Create: `web/src/api/os.ts`
- Test: `web/src/api/os.test.ts`
- Modify: `web/src/pages/Devices.tsx` (banner download)

- [ ] **Step 1: Write the failing test**

```ts
// web/src/api/os.test.ts
import { describe, it, expect } from "vitest";
import { detectOS } from "./os";

describe("detectOS", () => {
  it("detecteaza Windows", () => {
    expect(detectOS("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")).toBe("windows");
  });
  it("detecteaza Linux", () => {
    expect(detectOS("Mozilla/5.0 (X11; Linux x86_64)")).toBe("linux");
  });
  it("alt OS -> other", () => {
    expect(detectOS("Mozilla/5.0 (Macintosh; Intel Mac OS X)")).toBe("other");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web; npm test -- os.test`
Expected: FAIL — module not found

- [ ] **Step 3: Implement detectOS**

```ts
// web/src/api/os.ts
export type ClientOS = "windows" | "linux" | "other";

export function detectOS(ua: string = navigator.userAgent): ClientOS {
  const s = ua.toLowerCase();
  if (s.includes("windows")) return "windows";
  if (s.includes("linux") || s.includes("x11")) return "linux";
  return "other";
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web; npm test -- os.test`
Expected: PASS (3)

- [ ] **Step 5: Wire into Devices banner**

In `Devices.tsx`, banner-ul de descarcare: `const os = detectOS();` → butonul principal deschide `/api/v1/agent/download/{os === "linux" ? "linux" : "windows"}` cu eticheta potrivita ("Descarca .exe (Windows)" / "Descarca binar (Linux)"), plus un link mic "alt OS?" care arata ambele. Foloseste `download/info` per-OS ca sa dezactivezi butonul cand artefactul lipseste.

- [ ] **Step 6: Run frontend tests + tsc**

Run: `cd web; npx tsc -b; npm test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add web/src/api/os.ts web/src/api/os.test.ts web/src/pages/Devices.tsx
git commit -m "feat(fe): detectOS + banner download agent per-OS"
```

---

### Task 11: Update memory.md + suita completa + rebuild Windows .exe

**Files:**
- Modify: memory.md afectate (`agent/`, `agent/tests/`, `server/app/routes/`, `server/tests/`, `web/src/api/`, `web/src/pages/`)

- [ ] **Step 1: Update memory.md** pentru: install_nmap/detect_package_manager (core), build.sh, spec platform-aware, --install-service Linux, /agent/download/linux + info per-OS, detectOS + banner.

- [ ] **Step 2: Ruleaza suita completa**

Agent: `python -m pytest agent/tests -q`
Server: `cd server; $env:DISABLE_SCHEDULER="true"; $env:DISABLE_RATELIMIT="true"; .\.venv\Scripts\python.exe -m pytest -q`
Frontend: `cd web; npx tsc -b; npm test`
Expected: toate verzi.

- [ ] **Step 3: Rebuild Windows .exe** (spec s-a schimbat)

Run: `& .\.venv-build\Scripts\python.exe -m PyInstaller --clean --noconfirm .\agent\VulnWatchAgent.spec`
Copiaza in `server/app/static/agent/VulnWatchAgent.exe`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs: memory.md + rebuild Windows .exe (spec platform-aware)"
```

---

## Self-Review

**Spec coverage:** A→Task 4,5 | B→Task 7 | C→Task 6 | D→Task 9 | E→Task 10 | F→Task 1,2,3 | G→Task 8. Toate sectiunile au taskuri. ✓
**Placeholders:** cod real in fiecare step; niciun TBD. ✓
**Type/nume consistency:** `detect_package_manager`, `build_nmap_install_command`, `install_nmap` (agent); `download_agent_linux`, info per-OS cu chei `windows`/`linux` (backend); `detectOS` → `ClientOS` (frontend). Artefact Linux numit `vulnwatch-agent` peste tot (spec, build.sh, endpoint, _find_agent_artifact). ✓
**Backward compat:** `/agent/download/info` pastreaza `available`/`platform`/`size_bytes` top-level → testele vechi nu se rup. ✓
**Rebuild:** spec-ul s-a schimbat → Task 11 reconstruieste .exe Windows; binarul Linux iese din CI (Task 8). ✓
