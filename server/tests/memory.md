# memory.md — server/tests/

Pytest end-to-end pentru backend. Foloseste `fastapi.testclient.TestClient`
care apeleaza ASGI direct (zero network, instant). DB temporara SQLite per
rulare.

Rulare: `python -m pytest server/tests` (din radacina repo-ului).

## Fisiere

| Fisier                          | Teste | Rol                                                            |
| ------------------------------- | ----- | -------------------------------------------------------------- |
| `conftest.py`                   | —     | Configurare pytest. Seteaza `DATABASE_URL=sqlite:///<tmp>` inainte de import-ul aplicatiei (esential — altfel se ataseaza la postgres dev). Fixtures: `client` (sesiune-scope, TestClient persistent), `auth_client` (creeaza user unic + login + headers). |
| `test_auth.py`                  | 6     | Register + login + logout flow happy path; login cu credentiale invalide; validare email format (`EmailStr`); validare lungime parola; logout idempotent (200 cu sau fara token); verifica setarea cookie-ului HttpOnly `vw_session`. |
| `test_devices_and_scans.py`     | 11    | Device enrollment + listare; constraint unique (owner_id, device_uid); auth required pe `/devices`; cascade delete; scan submission happy path; respingere token lipsa/invalid/mismatch UID; **3 teste izolare multi-tenant** (un user nu vede device-urile altuia, nu acceseaza scan-urile altuia, nu sterge device-urile altuia). |
| `test_rules.py`                 | 9     | Fiecare regula in parte: clean system fara findings, porturi riscante, multe porturi, sesiune admin, procese suspecte, PowerShell informativ, software vulnerabil, OS EOL. Scor saturare la 100 chiar cu multe findings critice. |
| `test_scan_jobs.py`             | 12    | Scan-on-demand flow complet: happy path UI→agent→rezultat, 204 cand nu sunt joburi, atomicitate pickup (doi agenti nu prind acelasi job), dedupe la PENDING (nu si la RUNNING), state machine respinge tranzitii invalide, idempotenta pe finalizare, agent raporteaza failure, **4 teste izolare multi-tenant** pentru job queue. |
| `test_agent_download.py`        | 4     | Endpoint download .exe: info available true/false, 404 cand artifactul lipseste, file serving cu mime corect, auth required (401 fara cookie/header). |
| `test_relink_and_names.py`      | 11    | Smart re-link + device_name: `GET /devices/by-uid/` returneaza 200/404, izoleaza pe owner; `POST /devices/{uid}/relink` re-emite token (vechiul invalidat) si pastreaza istoricul scan-urilor; `device_name` apare in toate cele 4 raspunsuri (`ScanCreateOut`, `ScanDetailOut`, `ScanJobOut`, lista joburi). |
| `test_heartbeat.py`             | 3     | `POST /agent/heartbeat` marcheaza device-ul online, returneaza 401 fara token, `is_online` apare pe `GET /devices` si `GET /devices/by-uid/{uid}`. |
| `test_scan_types.py`            | 6     | `evaluate(scan)` filtreaza regulile dupa `scan_type` (standard < advanced < deep); LEVEL_ORDER constants; toate regulile inregistrate prin `@rule` au `_rule_id` + `_min_level`. |
| `test_new_rules.py`             | 25    | Cele 16 reguli noi: cazuri pozitive + cazuri negative (skip pe LH/Microsoft/private IP/etc.). 2 standard (FW/USER), 6 advanced (STARTUP/TASK/SVC/SHARE/PS/CONN), 8 deep (REG/WMI/CERT/AV/BF/PRIV/HOSTS/BITLOCKER). |
| `test_progress.py`              | 4     | End-to-end scan_type: propagat in `AgentJobOut`; progress update flow + polling; rejected pe job done (409); deep scan declanseaza reguli min_level=deep, `ScanDetailOut.scan_type` propagat. |

## Total: 91 teste end-to-end + 17 unit tests in `agent/tests/` = **108 teste**.

## Pattern important

Pentru testele multi-tenant, folosim **clienti separati per user**, nu doar
headers diferite:

```python
def _new_client_for_user(suffix: str) -> TestClient:
    c = TestClient(app)
    c.post("/api/v1/auth/register", json={...})
    c.post("/api/v1/auth/login", json={...})  # → seteaza cookie pe c
    return c
```

`TestClient` persisteaza cookie-uri intre cereri. Daca am folosi un singur
client si am face logout/login intre teste, cookie-ul ar putea sa contamineze
testele urmatoare. Clienti separati = izolare reala.

Pentru testarea endpoint-urilor de agent (X-Device-Token), folosim un client
"agent" care nu are cookie de sesiune, doar header. Asta verifica explicit
ca endpoint-ul nu se bazeaza pe cookie-ul user-ului care s-a logat in
acelasi proces.
