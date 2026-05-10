# memory.md — server/app/static/agent/

Locatia in care `agent/build.ps1` copiaza `VulnWatchAgent.exe` dupa build.
Endpoint-ul `GET /api/v1/agent/download/windows` serveste fisierul de aici.

## Continut

| Fisier                  | Rol                                                            |
| ----------------------- | -------------------------------------------------------------- |
| `.gitkeep`              | Tine directorul in git (fisier text comentat). Nu intra in build. |
| `VulnWatchAgent.exe`    | **Generat de `agent/build.ps1`.** Aproximativ 22-30 MB. NU este in git (binary artifact, regenerat la fiecare release). |

## Workflow

1. Modifici cod in `agent/*.py` (sau `agent/VulnWatchAgent.spec`).
2. Rulezi `powershell -ExecutionPolicy Bypass -File agent\build.ps1`:
   - script-ul creeaza/refoloseste `.venv-build`
   - instaleaza `pyinstaller` si dep-urile in venv-ul izolat
   - genereaza `dist/VulnWatchAgent.exe`
   - copiaza .exe-ul aici, in `server/app/static/agent/`
3. Restart backend (sau hot-reload — backend-ul citeste fisierul la fiecare request).
4. Hard-refresh browser → bannerul din `/devices` afiseaza buton activ "Descarca .exe".

## De ce nu commit-uim .exe-ul?

- **Reproductibilitate**: oricine poate regenera .exe-ul cu `build.ps1`.
- **Marime repo**: fiecare release ar adauga ~30 MB → repo umflat.
- **Diff zgomot**: PR-urile ar avea binary diffs zilnice.
- **Securitate**: .exe-ul nu e semnat digital (nu avem certificate); cei care
  il descarca trebuie sa-l construiasca local sau sa aiba incredere in build-ul
  de pe backend-ul lor.

In `.gitignore` (la nivel de radacina) ar trebui sa fie excluse:
`server/app/static/agent/*.exe`
