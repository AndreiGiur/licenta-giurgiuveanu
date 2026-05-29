# memory.md — web/src/hooks/

Hooks React custom, extrase din componentele-pagina pentru a slabi paginile si
a face logica testabila independent.

## Fisiere

| Fisier                    | Rol                                                                  |
| ------------------------- | -------------------------------------------------------------------- |
| `useScanJobPolling.ts`    | Polleaza `listScanJobs(deviceUid)` la 2s. Intoarce job-ul activ (running/pending) pentru progress bar, sau null. Cand un job tocmai s-a finalizat, apeleaza `onJobDone()` (callback tinut intr-un `ref` ca sa nu re-declanseze effect-ul). Cleanup la unmount/schimbare device. Extras din `Dashboard.tsx`. |
| `useScanDetail.ts`        | Incarca detaliul unui scan dupa `scanId` (sau null), cu anulare la schimbarea id-ului / unmount (fara setState pe componenta demontata). Intoarce `{ detail, error }`. Extras din `Dashboard.tsx`. |

## Teste

`useScanJobPolling.test.ts` (6 teste) + `useScanDetail.test.ts` (5 teste) —
`renderHook` + mock pe `../api/exposure`. Acopera: lipsa polling cand uid gol,
job activ returnat, null cand nu exista activ, callback la finalizare, fara crash
la eroare retea / unmount, reincarcare la schimbarea id-ului.
