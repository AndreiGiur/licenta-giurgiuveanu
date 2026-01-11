# Exposure Platform Agent

Agent local pentru colectarea și trimiterea de date către backend.

## Setup

```bash
cd agent
pip install -r requirements.txt
```

## Utilizare

1. **Înrolează un dispozitiv** în interfața web (`/devices`):
   - Creează un device nou
   - Copiază `device_token`-ul

2. **Configurează agent-ul**:
   - Deschide `scan.py`
   - Setează `DEVICE_UID` (ex: `laptop-work`)
   - Setează `DEVICE_TOKEN` (token-ul copiat mai sus)

3. **Rulează scan-ul**:

```bash
python scan.py
```

## Output Example

```
Exposure Platform Agent - Demo
==================================================
Device UID: laptop-work
Timestamp: 2026-01-11T22:15:30.123456

Collecting system data...
  - OS: Windows 10
  - Hostname: DESKTOP-ABC123
  - Processes collected: 10

Sending scan to backend...

✓ Scan submitted successfully!
  - Scan ID: 42
  - Exposure Score: 35/100
  - Findings: 2

Findings:
  🔴 [HIGH] Porturi cu risc expuse
     Inchide porturile sau limiteaza accesul prin firewall.
  🟡 [MEDIUM] Colectare efectuata cu privilegii ridicate
     Foloseste cont standard pentru utilizare zilnica; admin doar la nevoie.

View full results at: http://localhost:5173/scans/42
```

## Date Colectate

- **OS**: sistem, versiune, hostname
- **Procese**: top 10 după utilizare memorie
- **Network**: porturi deschise (simplified în demo)

## Limitări Demo

- Nu verifică permisiuni admin real
- Nu scanează porturi deschise (placeholder)
- Top 10 procese doar (nu toate)

Pentru producție, se pot adăuga:
- Scanning real de porturi (nmap/socket)
- Verificare privilegii native
- Aplicații instalate
- Configurări firewall
- Update status
