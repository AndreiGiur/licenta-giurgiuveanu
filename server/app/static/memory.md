# memory.md — server/app/static/

Resurse statice servite de backend (binary artifacts, NU cod sursa).

## Continut

| Folder        | Rol                                                                  |
| ------------- | -------------------------------------------------------------------- |
| `agent/`      | Build-ul `VulnWatchAgent.exe` + placeholder. Vezi `agent/memory.md`. |

## De ce nu in `web/public/`?

`web/public/` este pentru asset-uri statice servite de Vite (frontend). Build-ul
agentului trebuie sa fie servit de **backend** pentru ca:
1. **Auth required** — endpoint-ul `/api/v1/agent/download/windows` cere user
   logat (returneaza 401 daca nu).
2. **Decuplare** — frontend-ul poate fi rebuild-uit / deployment-uit
   separat de .exe; nu vrem coupling intre ele.
3. **Path conventions** — backend-ul stie sa serveasca `FileResponse`-uri
   cu mime type corect.

Endpoint-ul `routes.py:download_agent_windows` cauta in:
1. `server/app/static/agent/VulnWatchAgent.exe` (locatia preferata, langa cod)
2. `server/static/agent/VulnWatchAgent.exe` (locatie alternativa, gitignore-ed by default)
