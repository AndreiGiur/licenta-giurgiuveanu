# Design — Conectivitate agent vizibila + monitorizare live

Data: 2026-06-01
Status: aprobat (design), urmeaza plan de implementare

## Context

VulnWatch are un agent (daemon pe masina monitorizata) care trimite heartbeat la
10s si executa joburi de scanare la cerere. UI-ul afiseaza scorul de expunere si
findings. Utilizatorul vrea sa **inteleaga si sa vada vizual** legatura
Agent↔Backend↔Platforma, sa **monitorizeze traficul de retea** care intra/iese
din calculator, sa vada **nmap in timp real** (nu un terminal negru), si a
raportat un **bug de progres** (procentajul da inapoi cand porneste nmap).

Patru livrabile, ordonate de la fundatie la varf:

1. **#3 Fix progres monoton** (bug) — fundatia pentru #4
2. **#4 Nmap in timp real** — prin canalul de progres existent
3. **#C Heartbeat extins** — infrastructura comuna pentru #1 + #2
4. **#1 Diagrama de conexiune** Agent↔Backend↔Platforma
5. **#2 Trafic live** (bytes in/out, near-real-time la 10s)

## Principii

- Reutilizam mecanismele existente (progress polling, heartbeat) in loc sa
  adaugam transport nou. Agentul ramane pull-only, fara port deschis.
- Onestitate asupra granularitatii: "live" = cadenta de 10s (heartbeat), nu ms.
- Fiecare componenta UI noua e un component React izolat, testabil.

---

## A. Fix progres monoton (#3)

**Problema:** in `agent/core.py`, `collect_system_data` ajunge la `step(95,
"Finalizare")`, apoi `_run_nmap_if_needed` apeleaza `progress_cb(80, ...)` →
bara scade de la 95% la 80%.

**Solutie:** `collect_system_data(..., max_progress: int = 100)`. Functia `step`
scaleaza fiecare procent: `scaled = round(pct / 100 * max_progress)`.
- `run_one_job`: cand `scan_type in ("advanced", "deep")` → `max_progress=65`
  (colectarea ocupa 5→65%). Altfel `max_progress=100`.
- `_run_nmap_if_needed`: raporteaza in intervalul **65→95%** (vezi B). Submit
  rezultat = 100% (UI marcheaza done).

Rezultat: progresul e monoton crescator in toate cazurile.

## B. Nmap in timp real (#4)

**Agent (`nmap_runner.run_nmap`):**
- Adauga `--stats-every 2s` la argumentele nmap (in `NMAP_PROFILES` base_args sau
  injectat in `run_nmap`).
- Trece de la `subprocess.run` (blocant) la `subprocess.Popen` + citire
  incrementala a stderr (nmap scrie statisticile pe stderr). Liniile de tip
  *"... Timing: About 45.23% done; ETC: 16:32 (0:00:35 remaining)"* sunt parsate
  cu un regex → `(percent, eta_remaining)`.
- `run_nmap` primeste un `progress_cb: Callable[[float, str|None], None]`
  opional. La fiecare linie de progres parsata, apeleaza
  `progress_cb(percent, "0:00:35")`.
- Helper pur `parse_nmap_stats_line(line) -> tuple[float, str] | None` —
  **testabil unitar** fara subprocess.

**Agent (`core._run_nmap_if_needed`):**
- Trece un progress_cb catre `run_nmap` care mapeaza percentul nmap (0-100) in
  intervalul global **65→95** si trimite prin `progress_cb` global cu
  `phase="Nmap: {pct}% (ETC {eta})"`.

**Backend:** zero schimbari — `/agent/jobs/{id}/progress` exista deja.

**UI (Dashboard):** panoul de job activ exista deja (bara + phase). Cand
`phase` incepe cu "Nmap", afisez un mic accent (icon + text ETA). Component
optional `<NmapLivePanel>` care formateaza faza nmap distinct.

## C. Heartbeat extins (infrastructura comuna)

**Agent:** in bucla heartbeat, sampleaza `psutil.net_io_counters()`. Adauga in
`HeartbeatIn`:
- `net_bytes_sent: int` (cumulativ de la boot)
- `net_bytes_recv: int`
- `net_conn_count: int` (numar conexiuni active, optional)

**Backend:** modul nou `app/livestate.py` cu un **ring-buffer in memorie** per
device (`dict[device_id, deque(maxlen=60)]`, ~10 min la 10s). La fiecare
heartbeat, backend calculeaza rata (delta bytes / delta timp fata de sample-ul
anterior) si adauga `{ts, sent_rate, recv_rate, conn_count}` in buffer.

**Decizie:** in-memory (nu tabel DB). E date de tip "live monitor", nu istoric de
pastrat; se pierde la restart backend — acceptabil. Capat la 60 sample-uri/device.

**Endpoint nou:** `GET /devices/{uid}/net-traffic` (auth owner) → lista de
sample-uri `{ts, sent_rate_kbps, recv_rate_kbps, conn_count}` din buffer.

## D. Diagrama de conexiune (#1)

Component nou `web/src/components/ConnectionTopology.tsx`:
- 3 noduri orizontale: **Agent (PC-ul tau)** → **Backend (API)** → **Platforma (UI)**.
- Status nod Agent din `device.is_online` + `last_heartbeat` (verde online /
  gri offline / galben degraded daca heartbeat > 30s). Backend + Platforma mereu
  active (esti in UI).
- Liniile Agent↔Backend si Backend↔Platforma. Cand agentul e online sau o
  scanare e activa, puncte animate curg pe linie (flux de date), cu
  `prefers-reduced-motion` respectat.
- Props: `device` (sau status derivat) + `scanActive: boolean`.
- Plasat sus pe Dashboard (si optional pe Devices per card).

## E. Trafic live (#2)

Component nou `web/src/components/NetworkTrafficChart.tsx`:
- Recharts area chart: **KB/s trimisi (out) vs primiti (in)** pe ultimele ~10 min.
- Polleaza `GET /devices/{uid}/net-traffic` la 10s (hook `useNetworkTraffic`).
- Afiseaza si numarul curent de conexiuni active + rata instantanee in/out.
- Empty state cand agentul e offline (fara sample-uri).
- Paleta Honey & Plum; respecta `prefers-reduced-motion`.

`psutil.net_io_counters()` = tot traficul pe toate interfetele = datele care
ies si intra din calculator (exact cererea utilizatorului).

---

## Componente noi (rezumat)

| Strat    | Fisier                                            | Rol                                  |
| -------- | ------------------------------------------------- | ------------------------------------ |
| Agent    | `nmap_runner.py` (mod.)                           | Popen + parse stats + progress_cb    |
| Agent    | `core.py` (mod.)                                  | max_progress + nmap progress mapping + net_io in heartbeat |
| Backend  | `app/livestate.py` (nou)                          | ring-buffer trafic per device        |
| Backend  | `routes/devices.py` (mod.)                        | `GET /devices/{uid}/net-traffic`     |
| Backend  | `routes/agent.py` + `schemas.py` (mod.)           | HeartbeatIn extins + update buffer   |
| Frontend | `components/ConnectionTopology.tsx` (nou)         | diagrama conexiune                   |
| Frontend | `components/NetworkTrafficChart.tsx` (nou)        | grafic trafic live                   |
| Frontend | `components/NmapLivePanel.tsx` (nou, optional)    | faza nmap live                       |
| Frontend | `hooks/useNetworkTraffic.ts` (nou)                | polling /net-traffic                 |

## Testare

- **Agent:** `parse_nmap_stats_line` (unit, fara subprocess); `collect_system_data`
  cu `max_progress` (progres monoton, scalat corect); heartbeat include campurile
  net.
- **Backend:** `livestate` ring-buffer (cap la 60, calcul rata, izolare per
  device); `GET /net-traffic` (auth + owner isolation + empty cand fara sample);
  HeartbeatIn accepta + stocheaza campurile net.
- **Frontend:** `ConnectionTopology` (status online/offline/degraded), 
  `NetworkTrafficChart` (loading/empty/data via mock), `useNetworkTraffic` hook.

## Faze de implementare

1. **Faza 1 (fundatie):** A (fix progres) + B (nmap real-time). Valoare imediata,
   risc mic, fara schimbari de schema.
2. **Faza 2 (infrastructura):** C (heartbeat extins + livestate + endpoint).
3. **Faza 3 (UI):** D (diagrama) + E (grafic trafic), peste infrastructura din F2.

## Non-obiective (YAGNI)

- Fara persistenta istorica a traficului (doar live in-memory).
- Fara WebSocket/SSE — pull la 10s e suficient si respecta modelul agentului.
- Fara terminal raw nmap (xterm.js) — afisam faze prietenoase, nu output brut.
- Fara captura pe pachete (npcap/scapy) — folosim contoarele psutil agregate.
