# memory.md — server/tests/

Pytest end-to-end pentru backend. Foloseste `fastapi.testclient.TestClient`
care apeleaza ASGI direct (zero network, instant). DB temporara SQLite per
rulare.

Rulare: `python -m pytest server/tests` (din radacina repo-ului).

## Fisiere

| Fisier                          | Teste | Rol                                                            |
| ------------------------------- | ----- | -------------------------------------------------------------- |
| `conftest.py`                   | —     | Configurare pytest. Seteaza `DATABASE_URL=sqlite:///<tmp>` + env vars Google OAuth (`GOOGLE_CLIENT_ID_WEB`, `GOOGLE_CLIENT_SECRET_WEB`, `GOOGLE_CLIENT_ID_DESKTOP`, `FRONTEND_BASE_URL` via `setdefault`) inainte de import-ul aplicatiei. Fixtures: `client` (sesiune-scope, TestClient persistent), `auth_client` (creeaza user unic + login + headers). |
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
| `test_google_auth.py`           | 3     | Mock pentru modulul `server/app/google_auth.py`: `verify_id_token` returneaza payload-ul cand `id_token.verify_oauth2_token` da OK; arunca `GoogleAuthError` cand subjacent da `ValueError`; `exchange_code_for_token` (async) POST-eaza la token endpoint si returneaza dict cu `id_token`. Foloseste `pytest-asyncio` (auto-mode via `pytest.ini`). |
| `test_google_web_oauth.py`      | 4     | Flow web OAuth end-to-end cu mock pe `google_auth.exchange_code_for_token` + `verify_id_token`: `GET /auth/google/url` returneaza `auth_url` + `state`; `GET /auth/google/callback` cu state valid creeaza User nou (auth_provider=google), seteaza cookie `vw_session`, redirect 302 catre `/dashboard`; state invalid -> 400; user existent cu parola devine `auth_provider="both"` dupa login Google la acelasi email. |
| `test_google_agent_enroll.py`   | 3     | Endpoint `POST /api/v1/agent/google-enroll` cu mock pe `google_auth.verify_id_token`: creeaza User + Device la prima inrolare si returneaza `device_token` plain; re-emite token pentru acelasi `(owner, device_uid)` la a doua inrolare (relink, token1 != token2); 401 cand `verify_id_token` arunca `GoogleAuthError`. |
| `test_nmap_findings.py`         | 3     | Rule `NMAP-LUA-1` pass-through: finding-uri din `scan.nmap.hosts[].vulnwatch_findings` apar cu `source="nmap-lua"` + `host_ip` adaugat in evidence; lipsa `scan.nmap` -> zero findings nmap; scan_type=standard NU declanseaza regula (min_level=deep). |
| `test_admin_role.py`            | 2     | First user inregistrat in DB gol devine admin auto; al 2-lea user are `role="user"`. Foloseste fixture `fresh_db_client` (drop + create_all + TestClient nou). |
| `test_admin_endpoints.py`       | 9     | Endpoints `/admin/*`: list users / promote-demote / reset password (invalideaza sesiuni) / delete user. Self-protection: admin nu se poate demote sau sterge. Verifica 403 pentru user normal. Admin vede toate device-urile (cross-user) + scans paginat. |
| `test_reports.py`               | 4     | Endpoint `GET /scans/{id}/report.pdf`: PDF valid (`%PDF-` signature, > 1KB), 404 pentru non-owner, admin bypass, sectiunea nmap creste dimensiunea PDF. |
| `test_scheduler.py`             | 11    | `compute_next_run` pentru daily/weekly/monthly (cap la 28); CRUD endpoints `/devices/{uid}/schedules`; weekly fara `day_of_week` → 400; max 5 schedules/user; izolare multi-tenant (user B nu poate face schedule pe device-ul lui A). |
| `test_profile_endpoints.py`     | 8     | `/me/stats` (empty + with data), `/me/sessions` (current marker + revoke), `/me/password` (change ok + wrong old → 401), `/admin/stats` (platform metrics + 403 pentru user normal). |
| `test_scoring_breakdown.py`     | 12    | **Noul scoring multidimensional**: `evaluate()` returneaza 3-tuple, breakdown dict are exact 4 categorii (CATEGORIES), agregate weights insumate = 1.0, cap per categorie la 100, scor agregat foloseste ponderi 0.40/0.30/0.20/0.10, findings primesc metadata `category`+`rule_weight`+`rule_confidence`, confidence penalty aplicat la STARTUP-SUSPICIOUS, SEVERITY_WEIGHT actualizat (critical=40, high=20, medium=10, low=3), toate regulile au atribute valide, decorator rejecteaza category invalid + confidence invalid. |

## Total: 154 teste end-to-end + 63 unit tests in `agent/tests/` = **217 teste**.

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
