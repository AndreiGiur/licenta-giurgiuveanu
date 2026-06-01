# Design — Unificarea Dashboard + Dispozitive (Master-detail)

Data: 2026-06-01
Status: aprobat (design), urmeaza plan de implementare

## Context

Aplicatia are doua pagini separate cu responsabilitati care se suprapun:
- **Dashboard** (`/dashboard`): dropdown device + ConnectionTopology + NetworkTrafficChart
  + ScoreGauge/counts/breakdown + lista scanari + detaliu inline.
- **Dispozitive** (`/devices`): carduri device (status online, agent), Scaneaza-acum +
  selector tip scan, istoric scanari, planificare (schedules), delete, banner download.

Utilizatorul vrea o singura pagina, mai clean, de tip **master-detail**: lista de
dispozitive + workspace pentru dispozitivul selectat (monitorizare + actiuni + rezultate).
In plus: **typography responsiva** si un **explainer al tipului de scanare** (ce face
fiecare nivel cand e selectat).

Mockup-ul `/mockup` (varianta A confirmata) se sterge la finalul implementarii.

## Principii

- Refolosim componentele + hooks-urile existente; pagina unificata e un orchestrator
  subtire peste componente focalizate (`DeviceSidebar`, `DeviceWorkspace`, `ScanTypeExplainer`).
- Zero endpoint-uri noi de backend — datele exista deja (devices, scans, scan-jobs,
  net-traffic, schedules).
- Responsive: `clamp()` pentru titluri/scoruri, grid care colapseaza pe ecrane inguste.

---

## A. Rutare + navigatie

- `/dashboard` devine pagina unificata (`UnifiedDashboard`).
- `/devices` → `<Navigate to="/dashboard" replace />` (pastram ruta ca redirect ca sa
  nu rupem bookmark-uri / linkuri vechi).
- Navbar: un singur link "Dashboard" (scoatem "Dispozitive"). Restul (Profil, Admin,
  Logout) raman.
- `ScanDetail` (`/scans/:id`) ramane separat (detaliu complet + PDF + diff).
- Vechile fisiere `pages/Dashboard.tsx` si `pages/Devices.tsx` sunt inlocuite de
  `pages/UnifiedDashboard.tsx` + sub-componente; le stergem dupa migrare.

## B. Layout master-detail

`UnifiedDashboard.tsx` — grid 2 coloane (`260px 1fr`), colapseaza la 1 coloana sub 900px:

```
+-------------------+--------------------------------------+
| <DeviceSidebar>   | <DeviceWorkspace device={selected}>  |
| - lista devices   |  header: nume + status + scan ctrl   |
| - online + scor   |  <ScanTypeExplainer type=...>        |
| - + adauga        |  monitor: gauge + topology + traffic |
| - download (OS)   |  scanari + findings                  |
|                   |  planificare (schedules)             |
+-------------------+--------------------------------------+
```

State la nivel de pagina: `devices`, `selectedUid`, `scanType` (per selectie). La
prima incarcare se preselecteaza primul device online (sau primul din lista).

## C. Componente

### `DeviceSidebar.tsx`
- Props: `devices`, `selectedUid`, `onSelect`, `agentInfo` (per-OS).
- Lista de device-uri: dot online (verde/gri) + nume (ellipsis daca lung) + scor badge
  (ultimul scan) + nr scanari. Item activ evidentiat.
- Footer: buton "+ Adauga" (deschide instructiuni/inrolare) + buton download OS-aware
  (refoloseste `detectOS` + `getAgentDownloadInfo`).
- Pe mobil (<900px) devine un rand orizontal scrollabil de chips deasupra workspace-ului.

### `DeviceWorkspace.tsx`
- Props: `device`.
- Header: nume (titlu `clamp()`) + badge status online + selector `scanType`
  (standard/advanced/deep) + buton "Scaneaza acum" (`requestScan`) + buton "Sterge device".
- `<ScanTypeExplainer type={scanType} />` sub header.
- Bara de progres job activ (`useScanJobPolling`) — exista deja, mutata aici.
- Monitor row: `<ScoreGauge>` (din ultimul scan / scan selectat) + `<ConnectionTopology>` +
  `<NetworkTrafficChart>`.
- Scanari + Findings: lista scanari (`listDeviceScans`, click → `useScanDetail`) + findings
  ale scanului selectat; buton "Detalii complete →" spre `/scans/:id`.
- Planificare: sectiune `<details>` cu `ScheduleForm` + lista schedules (din Devices).

### `ScanTypeExplainer.tsx` (NOU)
- Props: `type: "standard" | "advanced" | "deep"`.
- Constanta `SCAN_TYPE_INFO` (in `api/types.ts` sau local) cu, per tip: `label`,
  `duration` (ex "~45-90s"), `summary`, `collects: string[]` (ce colecteaza), `rules`
  (nr aproximativ de reguli care ruleaza), `nmap` (descriere faza nmap unde e cazul).
- Randeaza un panou: titlu + durata + lista cu bullet-uri "ce se intampla in aceasta
  scanare" + (pentru advanced/deep) nota despre nmap. Se schimba live la schimbarea
  selectorului. Continut static (educativ); nu apeleaza backend-ul.
- Date (din SCAN_PROFILES / rules.py, nivel inalt):
  - **standard** (~45-90s, 9 reguli): porturi LISTEN, OS + versiune, firewall, useri
    locali, top 30 procese, software instalat.
  - **advanced** (~3-8 min, 15 reguli): toate procesele + cmdline, port→proces, conexiuni
    ESTABLISHED, servicii, chei startup, scheduled tasks, share-uri, politica PowerShell,
    adaptoare retea + **nmap moderat** (versiuni servicii, top 5000 porturi).
  - **deep** (~10-20 min, 23 reguli): WMI subscriptions, AppInit/IFEO/Winlogon, Security
    event log (4625/4672/4720), hosts, DNS+ARP, certificate root, BitLocker, Defender,
    fisiere recent modificate + **nmap agresiv** (detectie CVE prin NSE `vuln`, topologie).

## D. Typography responsiva

- Titluri pagina/workspace: `font-size: clamp(1.1rem, 2.5vw, 1.6rem)`.
- ScoreGauge: `size=150` fix (fara hook nou); responsiveness e data de colapsarea grid-ului
  + numarul intern se scaleaza cu marimea SVG-ului existenta. (YAGNI: fara `useElementWidth`.)
- Grid master-detail: media query <900px → o coloana; monitor row <700px → stivuit.
- Nume device / UID lungi: `text-overflow: ellipsis; overflow: hidden; white-space: nowrap`
  cu `title` attribut pentru tooltip.
- Clase noi in `index.css`: `.unified-grid`, `.workspace-header`, `.monitor-row`,
  `.scan-explainer`, cu media queries. Respecta `prefers-reduced-motion` (mostenit).

## E. Migrarea logicii existente

- Din `Dashboard.tsx`: device load, scan list/detail (hooks), monitor row, progress bar →
  in `DeviceWorkspace` + `UnifiedDashboard`.
- Din `Devices.tsx`: device cards → `DeviceSidebar`; Scaneaza-acum + scan type + delete +
  schedules + download banner → `DeviceWorkspace` / `DeviceSidebar`.
- Hooks refolosite: `useScanJobPolling`, `useScanDetail`, `useNetworkTraffic`.
- Componente refolosite: `ScoreGauge`, `ConnectionTopology`, `NetworkTrafficChart`,
  `ScheduleForm`, `ScoreBreakdownBars`.

## F. Testare

- `ScanTypeExplainer`: randeaza continutul corect per tip (standard/advanced/deep);
  comuta la schimbarea prop-ului `type`.
- `DeviceSidebar`: listeaza device-urile, marcheaza selectia, `onSelect` la click,
  status online/offline.
- `UnifiedDashboard` (smoke): mock api → randeaza sidebar + workspace; preselecteaza
  primul device; empty state cand nu exista device-uri.
- Pastram/adaptam testele utile din `Dashboard.test.tsx`; eliminam ce nu mai aplica.
- TSC curat; intreaga suita frontend verde.

## Faze

1. **Faza 1:** `ScanTypeExplainer` + constanta `SCAN_TYPE_INFO` (izolat, testabil).
2. **Faza 2:** `DeviceSidebar` + `DeviceWorkspace` (refolosesc componente/hooks).
3. **Faza 3:** `UnifiedDashboard` (orchestrator) + CSS responsiv + rutare/nav + redirect
   `/devices` + stergere `Dashboard.tsx`/`Devices.tsx` vechi + stergere mockup `/mockup`.
4. **Faza 4:** teste + memory.md + verificare vizuala.

## Non-obiective (YAGNI)

- Fara endpoint-uri noi de backend.
- Fara drag-and-drop / reordonare device-uri.
- Fara modificari la `ScanDetail` (ramane pagina separata).
- Fara persistarea device-ului selectat intre sesiuni (optional `?device=` in URL, ca acum).
