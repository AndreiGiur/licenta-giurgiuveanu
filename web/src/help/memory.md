# memory.md — web/src/help/

Continut explicativ centralizat pentru butoanele de info (i) din UI.

## Fisiere

| Fisier            | Rol                                                                  |
| ----------------- | -------------------------------------------------------------------- |
| `helpContent.ts`  | **Dictionar central** `HELP: Record<string, { title; body }>`. O intrare per `topic`, in romana, format "ce este + de ce conteaza" (2-3 fraze). Folosit de `<InfoTip topic="..." />` (vezi `components/InfoTip.tsx`). Grupat pe sectiuni: scor expunere & sub-scoruri pe categorii (`cat-critical_risk`/`cat-network_exposure`/`cat-hygiene`/`cat-activity`), monitorizare live (`device-online`, `connection-topology`, `network-traffic`), tipuri scanare (`scan-type`, `scans-list`), findings (`findings`, `severity`, `recommendation`, `finding-evidence`, `rule-id`, `compliance`, `findings-count`, `category-nav`), nmap (`nmap`, `nmap-host`, `nmap-role`, `nmap-risk`, `nmap-os`, `nmap-ports`, `nmap-findings`, `nmap-lua-errors`), diff (`diff-delta`, `diff-added`, `diff-fixed`, `diff-unchanged`), trend (`score-trend`), profil (`stat-*`, `pref-scan-type`, `sessions`, `session-current`), platforma admin (`platform-*`), tabele admin (`admin-*`). |

## Conventie

Adaugarea unei explicatii noi = o singura intrare in `helpContent.ts` + un `<InfoTip topic="x" />` in componenta. In DEV, `InfoTip` avertizeaza in consola daca `topic` nu exista in dictionar.
