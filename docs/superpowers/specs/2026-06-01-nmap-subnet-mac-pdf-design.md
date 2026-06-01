# Nmap subnet scan + MAC + PDF imbogatit — Design

**Data:** 2026-06-01
**Goal:** Scanul nmap (advanced/deep) sa scaneze automat subnetul local /24 (nu doar localhost), sa descopere alte device-uri cu IP+MAC+vendor, sa dureze un timp realist, iar exportul PDF sa arate semnificativ mai multe date.

## Context / problema

- `core.py:346` hardcodeaza tinta nmap la `127.0.0.1` → scanul termina in ~30s, nu vede alte device-uri, MAC nu apare (loopback nu are MAC).
- `nmap_parser.py` extrage doar IPv4/IPv6, ignora `address[@addrtype='mac']` + `vendor`.
- `reports.py` afiseaza per host doar IP, hostname, os_guess, max 20 porturi (doar nume serviciu) si titlurile finding-urilor.
- "0 vulnerabilitati" pe Kali: cauza operationala (agent vechi fara colectorul `linux_audit` / server nerepornit fara `rules_linux.py` / nmap rulat fara root).

## Decizii (aprobate)

1. **Tinta implicita = auto subnet local /24.** Agentul detecteaza interfata activa, deriva CIDR plafonat la /24. Fallback: IP real host → localhost.
2. **Niveluri diferentiate:** advanced = usor pe subnet (discovery + `-sV --top-ports 1000` + `vulnwatch-audit`, fara `-O`/`-A`/vuln); deep = full pe subnet (`-A` + `vulnwatch-audit,vuln,default,auth,banner`, host-discovery intai cand tinta e subnet).
3. **MAC+vendor** parsate si propagate in schema host.
4. **PDF:** tabel retea (IP/MAC/vendor/hostname/OS/#porturi) + porturi complete (service+version+CPE) + findings nmap detaliate (evidence+recomandare) + sectiune audit Linux.

## Componente

### Agent
- `core._detect_local_subnet() -> str | None`: psutil `net_if_addrs`/`net_if_stats`, interfata up non-loopback cu IPv4+netmask, CIDR plafonat /24.
- `core._run_nmap_if_needed`: `targets` din subnet detectat (sau `nmap_target` explicit, sau fallback). Flag `subnet_scan` pasat la runner pentru a controla `-Pn`.

### nmap_runner.py
- `NMAP_PROFILES["advanced"]`: fara `-A`/`-O`, `--top-ports 1000`, scripts doar `vulnwatch-audit`.
- `NMAP_PROFILES["deep"]`: `-A` + scripturi vuln; `-Pn` aplicat DOAR pe tinta single-host (cand `subnet_scan=False`).
- `build_nmap_args(..., subnet_scan: bool=False)`: elimina `-Pn` cand `subnet_scan=True`.

### nmap_parser.py
- `_parse_host`: `host["mac"]` + `host["vendor"]` din `address[@addrtype='mac']`; `host["distance"]` din `distance/@value` daca exista.

### reports.py
- Tabel retea (ReportLab `Table`, paleta Ocean) la inceputul sectiunii nmap.
- Porturi complete per host (service+version+CPE), fara limita 20.
- Findings nmap cu evidence + recomandare.
- Sectiune audit Linux din `scan["linux"]` cand OS=Linux.

## Operational (Kali)
- rebuild agent dupa `git pull` (colector `linux_audit`);
- restart server (incarca `rules_linux.py`);
- rulare nmap cu root (`sudo`) pentru `-O`, MAC discovery, parte din `vuln`.

## Testare
- `nmap_parser`: fixture XML cu MAC+vendor → assert pe campuri.
- `nmap_runner`: deep+subnet fara `-Pn`; deep+single-host cu `-Pn`; advanced fara `-A`/`-O`.
- `core`: `_detect_local_subnet` mock psutil → /24 + fallback localhost.
- `reports`: PDF cu host cu MAC contine tabelul (`%PDF-` + dimensiune).
