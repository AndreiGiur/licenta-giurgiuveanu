# memory.md — web/src/api/

Client HTTP unificat. Toate apelurile catre backend trec prin functiile de aici.
Cookie HttpOnly de sesiune este trimis automat (`credentials: "include"`).

## Fisiere

| Fisier         | Rol                                                                  |
| -------------- | -------------------------------------------------------------------- |
| `http.ts`      | **Modulul fundamental.** Defineste `API_BASE_URL` (default `/api/v1`, override prin `VITE_API_BASE_URL`), clasa `HttpError` cu `status` + `body`, functia `http<T>(path, opts)` cu timeout 8s default, AbortController, parse JSON safe. Helpere: `apiGet<T>(path)`, `apiPost<TReq, TRes>(path, body)`, `apiDelete<T>(path)`. Toate seteaza `credentials: "include"`. |
| `client.ts`    | Re-exporta tot din `http.ts` — pentru compatibilitate cu cod care importa din `client`. Nu adauga logica noua. |
| `auth.ts`      | Wrapper-i pentru endpoint-urile de auth: `registerUser`, `loginUser` (raspunsul contine `session_token` dar nu il folosim — cookie-ul e sursa de adevar), `fetchMe`, `logoutUser`. Frontend-ul **niciodata** nu citeste tokenul. |
| `exposure.ts`  | Wrapper-i pentru endpoint-urile de scan-uri si device-uri: `listDeviceScans`, `getScan`, `requestScan` (POST scan-job), `getScanJob` (polling status), `listScanJobs` (istoric), `getAgentDownloadInfo` (verifica daca .exe e build-uit). |
| `types.ts`     | **Tipuri TypeScript pentru raspunsurile API.** `Finding`, `DeviceScanListItem`, `ScanPayload` (struct de date colectate de agent), `ScanDetailResponse` (cu `device_uid` + `device_name`), `ScanJobStatus` (union type), `ScanJobResponse`. Reflectă schemas-urile Pydantic din backend (`server/app/schemas.py`). |

## Pattern de folosire

```typescript
import { apiGet, apiPost, apiDelete } from "../api/http";
import type { ScanDetailResponse } from "../api/types";

// GET cu tipare automata
const scan = await apiGet<ScanDetailResponse>("/scans/42");

// POST cu request si response tipate
const created = await apiPost<{ device_uid: string; name: string }, DeviceCreateResponse>(
  "/devices",
  { device_uid: "laptop-1", name: "Laptop Work" },
);

// Eroare → arunca cu HttpError, mesajul e detail-ul din backend
try { ... } catch (e) {
  setError(e instanceof Error ? e.message : "Eroare necunoscuta");
}
```

## Schimbari notabile in istoric

- **Inainte de PR #1**: aveam doua client-e duplicate (`client.ts` cu apiGet/apiPost si `http.ts` cu http()). Inconsistent. PR #1 a unificat in `http.ts`.
- **Inainte de PR #1**: tokenul era in `localStorage` → vulnerabil la XSS. PR #1 a mutat in cookie HttpOnly.
- **PR Plan A**: tipurile `ScanDetailResponse` si `ScanJobResponse` au acum si `device_name` in plus de `device_uid`. UI-ul afiseaza ambele.
