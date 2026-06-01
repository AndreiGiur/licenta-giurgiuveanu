# PDF restructurat + identitate dispozitiv (IP/MAC) cu confidentialitate — Design

**Data:** 2026-06-02
**Goal:** Exportul PDF arata date relevante structurat, incluzand IP-ul si MAC-ul dispozitivului scanat, cu respectarea principiilor GDPR (minimizare, control acces, etichetare, retentie documentata).

## Decizii (aprobate)

1. **IP/MAC integral** in stocare + afisare (dispozitiv propriu, util pentru remediere). PDF etichetat `CONFIDENTIAL` + nota de retentie. Acces deja owner/admin-only.
2. **Doar interfata activa principala** (minimizare) — nu toate adaptoarele virtuale/VPN.
3. **Retentie**: doar nota documentata in footer, fara mecanism automat.

## Componente

### Agent — `agent/collectors/network.py`
- `collect_network_identity() -> dict`: alege interfata up, non-loopback, IPv4 privata (euristica din `core._detect_local_subnet`) si intoarce `{iface, local_ip, mac}` (MAC din `psutil.net_if_addrs` AF_LINK). `{}` daca nu gaseste.
- `collect_network(cfg)` adauga `out["identity"] = collect_network_identity()`.
- Payload: `scan["network"]["identity"]`. `network` e deja `Dict[str,Any]` in scheme → fara modificari de schema.

### Server — `server/app/reports.py`
Restructurare in sectiuni, in ordinea relevantei:
1. Header + linie clasificare `CONFIDENTIAL — contine identificatori de retea (IP/MAC)`.
2. **Identitate dispozitiv** (tabel meta imbogatit): Device, UID, Owner, OS, Hostname, **IP local**, **MAC**, Interfata, Scan type, Data, Scan ID.
3. Rezumat executiv (scor + severity breakdown).
4. Score breakdown 4 categorii.
5. Findings detaliate.
6. Coverage standarde CIS/NIST.
7. Network scan (nmap) + audit Linux (existente).
8. Footer + nota confidentialitate & retentie.

## Testare
- agent: `collect_network_identity` mock psutil → `local_ip`+`mac` ale interfetei active; `{}` cand nu gaseste.
- reports: PDF cu `network.identity` se genereaza, creste fata de unul fara, ramane `%PDF-`.

## Confidentialitate (norme demonstrate)
- Minimizare (o interfata), control acces (owner/admin), etichetare (header+footer), retentie documentata.
