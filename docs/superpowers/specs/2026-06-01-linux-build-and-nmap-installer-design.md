# Design — Build Linux pentru agent + installer nmap (Windows + Linux)

Data: 2026-06-01
Status: aprobat (design), urmeaza plan de implementare

## Context

Agentul VulnWatch e momentan Windows-centric (build `.exe` PyInstaller, serviciu
Windows pywin32, autostart registry). Utilizatorul vrea:

1. O **versiune Linux** a agentului — binar PyInstaller standalone + serviciu
   systemd, distribuita prin platforma in functie de OS-ul userului.
2. Posibilitatea de a **instala nmap din executabil**, pe **Windows si Linux**
   (scanul deep are nevoie de nmap).

Scheletul cross-platform exista deja: `autostart.py` are suport systemd,
`single_instance.py` are fallback `fcntl`, colectorii ruleaza pe Ubuntu in CI.

## Principii

- PyInstaller NU cross-compileaza: binarul Linux se produce pe Linux (CI GitHub
  Actions). Tot codul + scripturile + testele se scriu acum; artefactul iese din CI.
- Degradare grațioasă: colectorii Windows-only intorc gol pe Linux, fara crash.
- Onestitate la privilegii: instalarea nmap cere root; pe Linux folosim pkexec/
  sudo, iar daca nu se poate escalada, afisam comanda exacta de copiat.

---

## A. Build Linux (agent)

**`agent/build.sh`** — oglinda lui `build.ps1` pentru Linux/POSIX:
- creeaza `.venv-build`, `pip install -r agent/requirements-dev.txt`
- `pyinstaller --clean --noconfirm agent/VulnWatchAgent.spec`
- output: `dist/vulnwatch-agent` (fara extensie)
- copiaza in `server/app/static/agent/vulnwatch-agent` daca `server/app` exista
- ASCII pur (fara diacritice), `set -e`.

**`agent/VulnWatchAgent.spec`** devine platform-aware:
- `import sys`
- `hiddenimports`: pywin32 (`win32serviceutil`, `win32service`, `win32event`,
  `win32api`, `winerror`, `servicemanager`, `pywintypes`) + `pystray._win32` doar
  cand `sys.platform == "win32"`.
- `icon=...` doar pe Windows.
- `name = "VulnWatchAgent" if sys.platform == "win32" else "vulnwatch-agent"`.

## B. Serviciu systemd (agent)

`autostart.py` are deja `enable()/disable()/status()` care scriu un user-service
systemd (`~/.config/systemd/user/vulnwatch-agent.service`). Verificam:
- `ExecStart` pointeaza la binarul/scriptul corect cu argument `daemon`.
- `--install-service` / `--uninstall-service` din `scan.py main()`: pe Linux
  delegheaza la `autostart.enable()/disable()` (pe Windows raman la pywin32).
  (Nu adaugam un al doilea mecanism — systemd user-service e suficient.)

## C. Colectori grațios pe Linux

Audit + teste de smoke ca apelurile Windows-only (reg, wmic, powershell, WMI,
Get-MpComputerStatus, manage-bde, Get-WinEvent) sunt prinse in `try/except` si
intorc gol pe Linux. `collect_system_data("uid", scan_type="deep")` trebuie sa
ruleze pe Linux fara exceptii (chiar daca multe campuri sunt goale).

Test nou (ruleaza pe orice OS, dar relevant pe Linux CI):
`collect_system_data` cu fiecare scan_type intoarce un dict cu cheile de baza
(`os`, `network`, `processes`, `software`) si nu arunca.

## D. Backend — download per-OS

- `GET /agent/download/linux` — serveste `vulnwatch-agent` (mirror al
  `/agent/download/windows`), media type `application/octet-stream`, 404 cu mesaj
  daca lipseste.
- `GET /agent/download/info` extins: intoarce disponibilitatea per-OS:
  `{ "windows": {available, size_bytes}, "linux": {available, size_bytes} }`.
  (Pastram compatibilitatea: pastram si `available`/`platform` la nivel top pentru
  Windows ca sa nu rupem UI-ul vechi — SAU actualizam UI-ul in E.)

Helper `_find_agent_artifact` ramane; adaugam constanta pentru numele Linux.

## E. Frontend — download OS-aware

`web/src/api` + pagina Devices:
- Util `detectOS()` din `navigator.userAgent`/`navigator.platform` → `"windows" |
  "linux" | "other"`.
- Banner-ul de descarcare ofera butonul potrivit OS-ului detectat, plus un link
  discret "alt sistem de operare?" care arata ambele.
- API: `getAgentDownloadInfo()` citeste noul format per-OS; `downloadAgent(os)`
  deschide `/agent/download/{os}`.

## F. Installer nmap — Windows + Linux

**`agent/core.py`:**
- `detect_package_manager() -> str | None` (Linux): `which` pe apt-get/dnf/pacman/
  zypper → intoarce numele sau None. **Pur, testabil** (monkeypatch pe `shutil.which`).
- `build_nmap_install_command() -> list[str] | None`: OS-aware, intoarce comanda:
  - Windows: `["winget", "install", "-e", "--id", "Insecure.Nmap", "--silent"]`
  - Linux apt: `["apt-get", "install", "-y", "nmap"]` (+ analog dnf/pacman/zypper)
  - None daca nu stim cum.
- `install_nmap(log) -> tuple[bool, str]`: executa instalarea.
  - Windows: ruleaza winget direct.
  - Linux: prefixeaza cu `pkexec` daca exista, altfel `sudo` daca exista; daca
    niciunul, intoarce `(False, "Ruleaza manual: sudo <cmd>")` cu comanda exacta.
  - Dupa instalare reusita, re-verifica `_nmap_path()`.

**GUI (`gui.py`):** cand `_nmap_path()` e None (deep indisponibil), afiseaza un
buton "Instaleaza nmap" pe pagina Status. La click ruleaza `install_nmap` pe un
thread, afiseaza log live; la succes re-emite capabilities (include "deep").

## G. CI — build Linux

`.github/workflows/` job nou `build-linux` (sau extindere workflow existent):
- `runs-on: ubuntu-latest`
- checkout, setup Python 3.12, `pip install pyinstaller -r agent/requirements.txt`
  (doar deps cross-platform; pywin32 e exclus pe Linux)
- `bash agent/build.sh`
- `actions/upload-artifact` cu `dist/vulnwatch-agent`.

Asa binarul Linux e produs automat la fiecare push, descarcabil din Actions.

---

## Componente (rezumat)

| Strat    | Fisier                                  | Modificare                              |
| -------- | --------------------------------------- | --------------------------------------- |
| Agent    | `build.sh` (nou)                        | build Linux                             |
| Agent    | `VulnWatchAgent.spec` (mod.)            | platform-aware                          |
| Agent    | `scan.py` (mod.)                        | --install-service pe Linux → systemd    |
| Agent    | `core.py` (mod.)                        | detect_package_manager, build_nmap_install_command, install_nmap |
| Agent    | `gui.py` (mod.)                         | buton "Instaleaza nmap"                 |
| Backend  | `routes/agent.py` (mod.)                | `/agent/download/linux` + info per-OS   |
| Backend  | `routes/_helpers.py` (mod.)             | nume artefact Linux                     |
| Frontend | `api/...` (mod.)                        | detectOS + download per-OS              |
| Frontend | `pages/Devices.tsx` (mod.)              | banner OS-aware                         |
| CI       | `.github/workflows/*.yml` (mod.)        | job build-linux                         |

## Testare

- **Agent:** `detect_package_manager` (monkeypatch which → apt/dnf/pacman/none);
  `build_nmap_install_command` per OS (monkeypatch platform); `install_nmap`
  fallback la comanda manuala cand nu exista pkexec/sudo; `collect_system_data`
  nu arunca pe niciun scan_type.
- **Backend:** `/agent/download/linux` (404 cand lipseste, serveste cand prezent,
  auth required); `/agent/download/info` format per-OS.
- **Frontend:** `detectOS` (windows/linux/other din userAgent); banner ofera
  butonul corect.

## Faze

1. **Faza 1:** installer nmap (F) — Windows + Linux, pur + testabil. Valoare imediata.
2. **Faza 2:** build Linux (A, B, C) + spec platform-aware + CI (G).
3. **Faza 3:** download per-OS backend (D) + frontend OS-aware (E).

## Non-obiective (YAGNI)

- Fara pachete .deb/.rpm/AppImage — doar binar PyInstaller (ca pe Windows).
- Fara serviciu systemd system-wide (root) — doar user-service (ca autostart-ul actual).
- Fara installer nmap din sursa/compilare — doar package manager / winget.
- Fara suport macOS in aceasta runda.
