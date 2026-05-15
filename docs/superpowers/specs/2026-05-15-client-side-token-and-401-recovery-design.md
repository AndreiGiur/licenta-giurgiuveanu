# Client-side device tokens + auto-recovery la 401

**Data**: 2026-05-15
**Autor**: Giurgiuveanu Andrei
**Scope**: Refactor enrollment + lifecycle device în agent și backend

## Sumar

Două schimbări strâns legate, livrate împreună:

1. **Inversare flux token**: executabilul agent generează local `device_token` random și trimite doar hash-ul SHA-256 la backend. Tokenul plain nu mai trece niciodată prin rețea.
2. **Auto-recovery la 401**: când daemon-ul primește HTTP 401 de la backend (token invalidat: device șters din dashboard, DB reset, etc.), oprește daemon-ul și forțează UI-ul agent să revină la pagina Login cu mesaj clar, fără ca user-ul să fie nevoit să șteargă manual configul local.

## Motivație

**Pentru (1) — client-generated tokens:**
- Defense-in-depth: tokenul plain nu apare niciodată în răspunsuri HTTP, log-uri FastAPI, log-uri Postgres, proxy-uri intermediare sau heap-ul backend-ului în momentul creării
- Aliniere cu best-practices pentru API keys (același pattern folosit de Stripe, GitHub Personal Access Tokens, etc.: client generează / utilizator copiază; serverul stochează hash)
- Argument tehnic util pentru capitolul "Securitate" al lucrării de licență

**Pentru (2) — auto-recovery:**
- Astăzi, când token-ul devine invalid (cel mai frecvent: DB reset în dev, sau ștergere device din `/devices`), daemon-ul intră într-un loop infinit de erori 401 fără ca user-ul să vadă altceva decât log-ul. UI-ul rămâne pe pagina Status cu indicator verde înșelător.
- Recovery actual: user-ul trebuie să închidă agentul → să șteargă manual `~/.vulnwatch/config.ini` → să redeschidă. Inutil de complicat pentru un scenariu comun.

## Non-goals

- **Backward compatibility cu executabilele vechi**: schema body se schimbă incompatibil (`token_hash` obligatoriu). Executabilele compilate înainte de acest refactor vor primi 422 la enrollment și trebuie reconstruite. Nu introducem cod legacy.
- **Token rotation periodică**: tokenul, odată generat, rămâne valabil până la ștergere device sau relink explicit. Rotation automată e un feature separat.
- **Validare ping la pornire**: nu adăugăm un `GET /auth/me` profilactic la deschiderea executabilului. Detectarea 401 prin heartbeat (la 10s) e suficient de rapidă.
- **Modificări pe frontend web**: zero impact pe `web/`. Frontendul nu vede tokeni — interacționează doar cu metadata.

## Arhitectura propusă

### 1. Backend: schema + endpoint changes

**Fișier afectat**: `server/app/schemas.py`

```python
# DeviceCreateIn: adaugă token_hash obligatoriu, validat ca SHA-256 hex
class DeviceCreateIn(BaseModel):
    device_uid: str = Field(min_length=1, max_length=120)
    name: str = Field(min_length=1, max_length=120)
    token_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

# DeviceRelinkIn: nou tip dedicat (era folosit body gol înainte)
class DeviceRelinkIn(BaseModel):
    token_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

# AgentGoogleEnrollIn: extins cu token_hash
class AgentGoogleEnrollIn(BaseModel):
    id_token: str
    device_uid: str = Field(min_length=1, max_length=120)
    device_name: str = Field(min_length=1, max_length=120)
    token_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

# Output-urile NU mai conțin device_token:
class DeviceCreateOut(BaseModel):
    id: int
    device_uid: str
    name: str
    created_at: datetime

class DeviceRelinkOut(BaseModel):
    device_uid: str
    name: str

class AgentGoogleEnrollOut(BaseModel):
    device_uid: str
    device_name: str
    user_email: str
```

**Fișier afectat**: `server/app/routes.py`

Endpoint-uri modificate:

| Endpoint | Schimbare logică |
|---|---|
| `POST /api/v1/devices` | Primește `token_hash` din body, stochează direct ca atare. Nu mai apelează `secrets.token_urlsafe()`. Returnează `DeviceCreateOut` fără token. |
| `POST /api/v1/devices/{uid}/relink` | Body trebuie să fie `DeviceRelinkIn` (cu `token_hash`). Înlocuiește `token_hash` existent. Returnează `DeviceRelinkOut`. |
| `POST /api/v1/agent/google-enroll` | Primește `token_hash` în body. La creare/relink, stochează hash-ul direct. Returnează `AgentGoogleEnrollOut` fără token. |

**Validare implicită prin Pydantic**: orice request cu `token_hash` lipsă, lungime ≠ 64, sau care conține caractere non-hex → 422 Unprocessable Entity, fără logica suplimentară.

**Stocare**: coloana `token_hash` din `models.Device` rămâne neschimbată ca structură (VARCHAR(64)). Doar sursa se schimbă: în loc să fie populată din `sha256(plain_token)` calculat backend, e populată direct din valoarea trimisă de client.

### 2. Agent: generare token + erori specifice

**Fișier afectat**: `agent/core.py`

Funcție nouă:

```python
def generate_device_token() -> tuple[str, str]:
    """Genereaza un device_token random local + hash-ul SHA-256 hex.

    Returneaza (token_plain, token_hash_hex). Tokenul plain trebuie salvat
    in config-ul local IMEDIAT — nu va putea fi recuperat ulterior."""
    import hashlib, secrets
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, token_hash
```

Excepție nouă:

```python
class DeviceTokenInvalidError(Exception):
    """Backend a respins device_token-ul cu HTTP 401.

    Daemon-ul trebuie sa se opreasca si UI-ul trebuie sa intoarca la Login."""
```

Funcții `api_*` care folosesc `X-Device-Token` — modificate să arunce `DeviceTokenInvalidError` la 401 (în loc de `ApiError` generic):
- `api_heartbeat`
- `api_get_next_job`
- `api_send_scan`
- `api_submit_job_result`
- `api_submit_job_failure`
- `api_send_progress`

Funcții `api_*` care folosesc `X-Session-Token` (login/logout/me) — modificate să trimită `token_hash` în body:
- `api_create_device(api, session_token, device_uid, name, token_hash)` — semnătură extinsă
- `api_relink_device(api, session_token, device_uid, token_hash)` — semnătură extinsă
- `api_google_enroll(api, id_token, device_uid, device_name, token_hash)` — semnătură extinsă

Toate trei: nu mai primesc `device_token` din response — orchestratorul (ex. `enroll_device_with_session`) generează tokenul înainte de apel și-l păstrează local.

**`daemon_loop` modificat**:

```python
def daemon_loop(api_base, device_uid, device_token, ...,
                on_token_invalid: Optional[Callable[[], None]] = None):
    while not should_stop():
        try:
            # ... heartbeat, get_next_job, etc.
        except DeviceTokenInvalidError as e:
            log(f"Device token respins de backend (401): {e}", "error")
            if on_token_invalid:
                on_token_invalid()
            return  # iese imediat — nu mai retry
        except ApiError as e:
            log(f"Eroare temporara: {e}", "warn")
            time.sleep(poll_interval)
```

**`enroll_device_with_session` modificat**:

```python
def enroll_device_with_session(api, session_token, device_uid, name,
                               relink_if_exists=False, log=None):
    token_plain, token_hash = generate_device_token()

    if relink_if_exists and device_already_exists:
        api_relink_device(api, session_token, device_uid, token_hash=token_hash)
    else:
        api_create_device(api, session_token, device_uid, name, token_hash=token_hash)

    return {
        "device_uid": device_uid,
        "name": name,
        "device_token": token_plain,  # generat local, nu vine din response
    }
```

### 3. Agent GUI: eveniment "token invalid" propagat la UI

**Fișier afectat**: `agent/gui.py`

`DaemonRunner` primește un callback pentru evenimente speciale:

```python
class DaemonRunner:
    def _run(self, api_base, device_uid, device_token):
        core.daemon_loop(
            api_base, device_uid, device_token,
            ...,
            on_token_invalid=self._signal_token_invalid,
        )

    def _signal_token_invalid(self):
        try:
            self.log_queue.put_nowait(("__TOKEN_INVALID__", "error"))
        except queue.Full:
            pass
```

`_poll_log_queue` în `AgentApp` interceptează marker-ul `__TOKEN_INVALID__`:

```python
def _poll_log_queue(self):
    try:
        while True:
            msg, sev = self.log_queue.get_nowait()
            if msg == "__TOKEN_INVALID__":
                self._handle_token_invalid()
                return  # opreste polling, _handle_token_invalid il reia
            self._append_log(msg, sev)
    except queue.Empty:
        pass
    self.root.after(100, self._poll_log_queue)

def _handle_token_invalid(self):
    """Daemon a primit 401 — force re-login fara crash."""
    self.daemon.stop()
    self.daemon.join(timeout=2.0)
    self.daemon = DaemonRunner(self.log_queue)

    # Salveaza api_base pentru convenience inainte de clear
    try:
        saved_api, _, _ = core.get_enrollment()
    except RuntimeError:
        saved_api = core.DEFAULT_API_BASE
    core.clear_config()

    self._render_login_page()
    self._var_api.set(saved_api)
    self._login_msg.set(
        "Conexiunea cu platforma a expirat (device-ul a fost sters sau token "
        "invalidat). Reconecteaza-te pentru a continua sa primesti scanari."
    )

    # Reia polling-ul ca sa prinda evenimente viitoare
    self.root.after(100, self._poll_log_queue)
```

**Marker-ul** `__TOKEN_INVALID__` e prefixat cu underscore dublu deliberat — un mesaj de log normal nu va arăta vreodată așa, deci coliziunea e exclusă.

## Edge cases și comportamente

| Scenariu | Comportament |
|---|---|
| Server offline (ConnectionError) | `ApiError` generic → retry la 10s, daemon rămâne pornit, log warn |
| Server răspunde 500 / 503 | `ApiError` generic → retry, fără re-login |
| Server răspunde 401 la heartbeat | `DeviceTokenInvalidError` → daemon stop → UI Login |
| Server răspunde 401 doar la `/agent/jobs/next` dar heartbeat OK | Tot trigger → daemon stop → UI Login (orice 401 e suficient) |
| User apasă Logout manual din Status | Comportament identic cu cel actual |
| User închide fereastra | Tray rămâne disponibil, close → ascunde fereastra (identic cu acum) |
| Multiple 401-uri consecutive | Primul declanșează `on_token_invalid`, restul ignorate (daemon a ieșit deja din loop) |
| `enroll_device_with_session` eșuează după ce tokenul a fost generat | Tokenul plain rămâne în memoria executabilului dar nu se salvează — la următoarea tentativă se generează altul nou. Nu apare leak. |

## Migration

**Decizie: ruptură curată.**

- Schema veche și nouă sunt incompatibile la nivel de body request — nu există implementare rezonabilă care să suporte ambele
- DB curent e gol (zero device-uri după resetul de mai devreme) — nu există date de migrat
- Executabilele vechi (`dist/VulnWatchAgent.exe` compilat anterior) vor primi 422 la enrollment → trebuie reconstruite și redistribuite cu `agent/build.ps1`

Niciun feature flag, niciun cod compat shim. Refactorul e atomic.

## Testing

**Backend (`server/tests/`)**

| Fișier | Schimbări |
|---|---|
| `conftest.py` | Helper nou `make_token_pair() -> tuple[str, str]` care întoarce `(token_plain, token_hash)` — folosit de toate fixture-urile care creează device |
| `test_devices_and_scans.py` | Toate `client.post("/devices", json=...)` includ `token_hash`. Cazuri noi: payload fără `token_hash` → 422; `token_hash` cu 63 chars → 422; `token_hash` cu caractere non-hex → 422. Test: tokenul plain generat client funcționează în request ulterior cu `X-Device-Token`. |
| `test_scan_jobs.py` | Fixture-uri device-uri folosesc helper-ul nou |
| `test_auth.py` | Neschimbat |
| `test_rules.py` | Neschimbat |
| `test_agent_download.py` | Neschimbat |

**Test nou**: `test_token_lifecycle.py` (sau adăugat în `test_devices_and_scans.py`):

- ✓ POST /devices cu token_hash valid → 200, response fără `device_token`
- ✓ POST /devices fără token_hash → 422
- ✓ POST /devices cu token_hash invalid (lungime, charset) → 422
- ✓ Plain token generat client funcționează la request agent ulterior
- ✓ Token greșit → 401 din endpoint-uri agent
- ✓ Relink înlocuiește token_hash: tokenul vechi → 401, cel nou → 200

**Agent (`agent/tests/`)**

| Fișier | Schimbări |
|---|---|
| `test_core.py` | Teste noi: `generate_device_token()` întoarce tuplu, hash e SHA-256 hex 64 chars, hash-ul corespunde tokenului. Test: `DeviceTokenInvalidError` aruncat când mock HTTP returnează 401. |
| `test_core_relink.py` | Payload trimis include `token_hash`. |
| `test_collectors.py` | Neschimbat |

**Test nou**: `test_daemon_recovery.py` (sau adăugat în `test_core.py`):

- ✓ `daemon_loop` cu mock HTTP 401 → `on_token_invalid` apelat, loop iese
- ✓ `daemon_loop` cu mock HTTP 500 → loop continuă retry, `on_token_invalid` NU apelat
- ✓ `daemon_loop` cu `ConnectionError` → loop continuă retry, `on_token_invalid` NU apelat
- ✓ După `on_token_invalid`, daemon-ul nu mai face request-uri (verifică call count)

**Manual integration test (post-implementation)**

1. `docker compose down -v && docker compose up -d` (DB curat)
2. Pornește backend + frontend
3. Build `.exe` cu `agent/build.ps1`, rulează, login Google → enrollment OK, device apare în `/devices`
4. Pe platforma web, șterge device-ul din `/devices`
5. Așteaptă max 10s (next heartbeat) → UI-ul executabilului sare automat la Login cu mesajul "Conexiunea cu platforma a expirat..."
6. Reloghează-te → enrollment nou cu același UID → device reapare în UI

## Impact pe alte componente

**`web/`**: zero modificări — frontendul nu vede tokeni.

**Memory.md updates după implementare**:
- `agent/memory.md` — secțiunea "Auth flow" refăcută
- `agent/tests/memory.md` — adăugat noul test_daemon_recovery
- `server/app/memory.md` — semnătura schemas + endpoint-uri afectate
- `server/tests/memory.md` — adăugat noul test_token_lifecycle + helper
- `CLAUDE.md` — paragraful "Authentication" secțiunea Architecture, sub "Agent auth"

**Lucrare de licență (`docs/` thesis chapters)**: separat de acest spec. După implementare, ajustare la capitolul 4 (descriere arhitectură auth) cu noul model — argument util pentru secțiunea de Securitate.

## Riscuri și mitigări

| Risc | Mitigare |
|---|---|
| Tokenul generat client are entropie insuficientă | Folosim `secrets.token_urlsafe(48)` = 48 octeți random din CSPRNG OS → ~256 biți entropie. Securitate echivalentă cu generarea backend. |
| Hash format greșit ajunge prin user-modified executabil malițios | Backend validează format strict cu Pydantic regex. `token_hash` greșit → 422, niciodată nu ajunge în DB. |
| Race condition: două agenți cu același UID trimit simultan POST /devices | Backend are deja unique constraint pe `(owner_id, device_uid)`. Al doilea va primi 409 Conflict (sau IntegrityError mapat la 4xx). Comportament identic cu schema veche. |
| Daemon-ul s-a oprit pe 401 dar tray-ul rămâne agățat | `_handle_token_invalid` nu oprește tray-ul. Tray rămâne disponibil — utile dacă user-ul vrea să închidă din tray fără să mai deschidă fereastra. Behavior intenționat. |
| User reinstall pe alt PC cu același hostname | Sistem actual: oferă opțiunea de re-link. Nou: același flow, doar că noul `token_hash` e generat de noul executabil. Identic ca UX. |
