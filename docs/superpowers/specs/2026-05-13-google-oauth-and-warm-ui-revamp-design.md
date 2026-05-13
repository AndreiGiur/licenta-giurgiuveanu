# VulnWatch — Google OAuth + Warm UI Revamp

**Data:** 2026-05-13
**Autor:** Giurgiuveanu Andrei (lucrare de licență)
**Titlu lucrare:** Platformă web pentru detectarea vulnerabilităților pe dispozitivele personale

---

## 1. Context și obiective

VulnWatch are deja arhitectura platform-centric, 3 tipuri de scanare, heartbeat și 23 reguli. Această iterație extinde proiectul în trei direcții simultane:

1. **Google OAuth** — login simplificat în executabil și pe platformă, păstrând și email/parolă ca alternativă (hybrid).
2. **Crearea de dispozitive doar din executabil** — platforma web devine read-only pentru management dispozitive (listă + ștergere), enrollment-ul se face strict din agent.
3. **Revamp vizual complet** — abandonăm tema dark cyan/techy în favoarea unei estetici calde (paleta **Honey & Plum**) cu suport light/dark mode toggle și animații.

---

## 2. Arhitectura autentificării

### 2.1 Două flow-uri paralele

Utilizatorul are două opțiuni atât în agent cât și în platformă:

- **Google OAuth 2.0 cu PKCE** (Authorization Code Flow + Loopback Redirect pentru desktop, standard Authorization Code Flow pentru web)
- **Email + parolă** (sistemul existent, nemodificat)

Conturile pot fi legate: dacă un user cu email/parolă se loghează ulterior cu Google folosind același email, contul devine "hybrid" (`auth_provider = both`). Backend-ul găsește User-ul prin email, lipește `google_sub`.

### 2.2 Setup Google Cloud (one-time)

Înainte de implementare, utilizatorul (autorul lucrării) trebuie să creeze:

1. Proiect în [Google Cloud Console](https://console.cloud.google.com/)
2. **OAuth consent screen** — External, scopes: `openid email profile`
3. **OAuth 2.0 Client ID** de tip **Web application** pentru platformă:
   - Authorized redirect URI: `http://127.0.0.1:8000/api/v1/auth/google/callback`
4. **OAuth 2.0 Client ID** de tip **Desktop app** pentru agent:
   - Redirect URI: `http://127.0.0.1` (Google permite orice port pe loopback pentru desktop apps)

Variabile env noi în `server/.env`:
```
GOOGLE_CLIENT_ID_WEB=...apps.googleusercontent.com
GOOGLE_CLIENT_SECRET_WEB=GOCSPX-...
GOOGLE_CLIENT_ID_DESKTOP=...apps.googleusercontent.com
GOOGLE_CLIENT_SECRET_DESKTOP=GOCSPX-...
GOOGLE_REDIRECT_URI_WEB=http://127.0.0.1:8000/api/v1/auth/google/callback
FRONTEND_BASE_URL=http://localhost:5173
```

În build-ul agentului, `GOOGLE_CLIENT_ID_DESKTOP` se embed-uiește în executabil (nu și secretul — desktop apps nu pot ține secrete; Google permite asta când se folosește PKCE).

### 2.3 Flow web (platformă)

```
User → click "Continuă cu Google" pe /login
Frontend → GET /api/v1/auth/google/url
Backend → genereaza state aleator + URL Google (response_type=code, scope=openid email profile, redirect_uri, state)
         → salveaza state in sesiune temporara (in-memory dict cu TTL 5 min)
         → returneaza {auth_url, state}
Frontend → window.location = auth_url
Google → user se autentifica → redirect catre /api/v1/auth/google/callback?code=...&state=...
Backend → verifica state, exchange code → id_token + access_token
        → decode id_token (verifica iss, aud, exp prin google-auth)
        → User upsert by email (creeaza daca lipseste, lipeste google_sub daca exista pe email)
        → create_session() → cookie HttpOnly
        → redirect HTTP 302 catre {FRONTEND_BASE_URL}/dashboard
```

### 2.4 Flow desktop (agent) — Loopback Redirect cu PKCE

Agentul face exchange-ul direct cu Google (folosind `google-auth-oauthlib` care încapsulează toți pașii). Backend-ul primește doar `id_token` deja obținut, îl verifică, și emite `device_token`.

```
User → click "Continuă cu Google" in agent GUI
Agent → google-auth-oauthlib.InstalledAppFlow.run_local_server(port=0):
        - genereaza code_verifier + code_challenge (PKCE)
        - porneste mini-HTTP server pe 127.0.0.1:PORT (port=0 → OS alege random)
        - deschide browserul cu URL Google (client_id=DESKTOP_ID, redirect_uri=http://127.0.0.1:PORT, scope=openid email profile, PKCE)
Google → user se autentifica → redirect catre http://127.0.0.1:PORT/?code=...&state=...
Agent → mini-server prinde code → afiseaza pagina HTML "Te poti intoarce la VulnWatch Agent"
      → face EXCHANGE cu Google (POST oauth2.googleapis.com/token cu code + code_verifier, fara client_secret pentru ca e PKCE)
      → primeste id_token
      → POST /api/v1/agent/google-enroll {id_token, device_uid: hostname, device_name}
Backend → verifica id_token (issuer = accounts.google.com, audience = GOOGLE_CLIENT_ID_DESKTOP, exp valid)
        → extrage email, sub, name, picture
        → User upsert by email (creeaza daca lipseste, lipeste google_sub daca exista pe email)
        → Device upsert by (owner_id, device_uid) — daca exista, re-emite token (echivalent cu relink)
        → returneaza {device_token, device_name, user_email}
Agent → salveaza ~/.vulnwatch/config.ini + arata pagina Status
```

**Rationale**: agentul face exchange-ul ca să elimine un round-trip backend; backend-ul rămâne stateless pentru OAuth (verifică doar tokenul). Desktop apps cu PKCE nu au nevoie de `client_secret` la exchange (Google permite asta explicit).

### 2.5 Endpoint-uri backend noi

| Endpoint | Auth | Rol |
|---|---|---|
| `GET /api/v1/auth/google/url` | — | Returnează `{auth_url, state}` pentru web OAuth |
| `GET /api/v1/auth/google/callback` | — | Primește code+state din Google, exchange backend-side cu Google (Web Client Secret), creează sesiune, redirect spre frontend |
| `POST /api/v1/agent/google-enroll` | — | Primește `{id_token, device_uid, device_name}` (agentul a făcut deja exchange-ul cu Google folosind PKCE), returnează `{device_token, device_name, user_email}` |

### 2.6 Modificări modele

**`User`:**
```python
google_sub: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True, index=True)
google_picture_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
auth_provider: Mapped[str] = mapped_column(String(16), default="password")  # password | google | both
# password_salt + password_hash devin nullable (Google-only users nu au parola)
password_salt: Mapped[str | None]  # nullable=True
password_hash: Mapped[str | None]  # nullable=True
```

**Migrare**: drop & recreate Postgres în dev (`docker compose down -v && docker compose up -d`). Tabelele se creează la pornire backend.

### 2.7 Dependențe noi

**Backend** (`server/requirements.txt`):
- `google-auth>=2.30` — verificare ID tokens
- `httpx>=0.27` — exchange code → token (probabil deja există)

**Agent** (`agent/requirements.txt`):
- `google-auth-oauthlib>=1.2` — flow OAuth client (PKCE + local server helper)

**Frontend**: niciuna (folosim doar redirect-uri HTTP standard).

---

## 3. Schimbări enrollment + platform UI

### 3.1 Endpoint-uri device (backend)

| Endpoint | Status | Detalii |
|---|---|---|
| `POST /devices` | Rămâne | Folosit doar de agent în flow-ul email/parolă |
| `GET /devices/by-uid/{uid}` | Rămâne | Smart re-link check |
| `POST /devices/{uid}/relink` | Rămâne | Re-emite token |
| `POST /agent/google-enroll` | **Nou** | Flow Google complet (creează/upsert User+Device) |
| `GET /devices` | Rămâne | Listare (folosit de platform UI) |
| `DELETE /devices/{uid}` | Rămâne | Ștergere (singura acțiune din platform UI) |

### 3.2 Platform UI — `/devices`

**Elimin:**
- Form "Înregistrează dispozitiv nou" (coloana stânga)
- Banner-ul de afișare token după create
- Funcția `handleCreate` din `Devices.tsx`
- State-urile `newDeviceUid`, `newDeviceName`, `createdToken`, `createdUid`, `copied`

**Păstrez:**
- Banner "Descarcă agent .exe" sus
- Lista dispozitivelor (single column acum, layout mai larg)
- Badge online/offline cu pulse animat pe ● când online
- Selector tip scanare + buton "Scanează acum"
- Progress bar live
- Buton "Scanări" + "Șterge"

**Adaug:**
- Empty state mai prietenos când nu sunt device-uri: ilustrație + text "Conectează primul dispozitiv din agentul desktop ↓" + buton download agent

### 3.3 Pagini login/register

Login + Register devin aproape identice structural:

```
┌─────────────────────────────────────┐
│         [hero illustration]          │
│                                      │
│         Bine ai venit la             │
│           VulnWatch                  │
│                                      │
│   ┌──────────────────────────────┐  │
│   │ [G] Continuă cu Google       │  │  ← buton full-width
│   └──────────────────────────────┘  │
│                                      │
│   ──────── sau ────────             │
│                                      │
│   Email: [____________]              │
│   Parolă: [____________]            │
│                                      │
│   [    Autentifică-te     ]         │
│                                      │
│   Nu ai cont? Înregistrează-te      │
└─────────────────────────────────────┘
```

---

## 4. UI Revamp — Honey & Plum

### 4.1 Tipografie

```css
/* index.html <head> */
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,500;9..144,700&family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
```

```css
:root {
  --font-display: 'Fraunces', Georgia, serif;
  --font-body: 'Outfit', system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', Consolas, monospace;
}
```

### 4.2 Paletă light (default)

```css
:root,
[data-theme="light"] {
  /* Surface */
  --bg-base:       #fefaf2;
  --bg-elevated:   #fff8e6;
  --bg-hover:      #fdf4d8;
  --surface:       #ffffff;

  /* Borders */
  --border:        #f0e4cc;
  --border-strong: #e8d4a8;

  /* Text */
  --text-primary:  #2d1b3d;
  --text-secondary:#5a3a6e;
  --text-muted:    #8a7458;
  --text-inverse:  #fff8e6;

  /* Brand */
  --accent:        #f4c95d;
  --accent-strong: #d4a73d;
  --accent-soft:   #fff4d0;

  /* Severity */
  --severity-critical: #5a2d6e;
  --severity-high:     #b8456e;
  --severity-medium:   #d4a73d;
  --severity-low:      #a8639a;
  --severity-info:     #8a7458;

  /* Status */
  --success: #7a9a5a;
  --danger:  #c44b4b;
  --warning: #e8a23d;

  /* Shadows (warm plum-tinted, NOT black) */
  --shadow-sm: 0 1px 2px rgba(45,27,61,0.06), 0 2px 6px rgba(45,27,61,0.04);
  --shadow-md: 0 4px 12px rgba(45,27,61,0.08), 0 8px 24px rgba(45,27,61,0.04);
  --shadow-lg: 0 12px 32px rgba(45,27,61,0.12), 0 20px 60px rgba(45,27,61,0.08);
}
```

### 4.3 Paletă dark

```css
[data-theme="dark"] {
  --bg-base:       #1a0e22;
  --bg-elevated:   #2d1b3d;
  --bg-hover:      #3d2a4f;
  --surface:       #4a3458;

  --border:        #4a3458;
  --border-strong: #6a4a78;

  --text-primary:  #fff8e6;
  --text-secondary:#e8d8b8;
  --text-muted:    #a89880;
  --text-inverse:  #2d1b3d;

  --accent:        #f4c95d;
  --accent-strong: #ffd97a;
  --accent-soft:   #3d2a4f;

  --severity-critical: #ff7aa8;
  --severity-high:     #ff9a73;
  --severity-medium:   #ffd97a;
  --severity-low:      #c8a3d8;
  --severity-info:     #a89880;

  --success: #a8c285;
  --danger:  #e88a8a;
  --warning: #ffd97a;

  --shadow-sm: 0 1px 2px rgba(0,0,0,0.20), 0 2px 6px rgba(0,0,0,0.12);
  --shadow-md: 0 4px 12px rgba(0,0,0,0.30), 0 8px 24px rgba(0,0,0,0.20);
  --shadow-lg: 0 12px 32px rgba(0,0,0,0.40), 0 20px 60px rgba(0,0,0,0.30);
}
```

### 4.4 Border radius + spacing

```css
:root {
  --radius-xs: 6px;   /* small inputs */
  --radius-sm: 10px;  /* buttons, chips */
  --radius-md: 16px;  /* cards */
  --radius-lg: 24px;  /* modals */
  --radius-xl: 32px;  /* hero cards */
  --radius-full: 999px;

  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-6: 24px;
  --space-8: 32px;
  --space-12: 48px;
  --space-16: 64px;
}
```

### 4.5 Animații

**Dependență:** `framer-motion@^11` (~50KB gzipped).

**Animații page-load (Framer Motion):**

```tsx
// Pe orice pagina majora
<motion.div
  initial={{ opacity: 0, y: 12 }}
  animate={{ opacity: 1, y: 0 }}
  transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
>
  {/* page content */}
</motion.div>

// Liste cu stagger
<motion.div initial="hidden" animate="visible"
  variants={{ visible: { transition: { staggerChildren: 0.06 } } }}>
  {items.map(item => (
    <motion.div key={item.id} variants={{
      hidden: { opacity: 0, y: 8 },
      visible: { opacity: 1, y: 0 }
    }}>
      {/* item */}
    </motion.div>
  ))}
</motion.div>
```

**Score gauge animat (componentă nouă `<ScoreGauge>`):**

```tsx
import { motion, useMotionValue, useTransform, animate } from "framer-motion";

function ScoreGauge({ value }: { value: number }) {
  const count = useMotionValue(0);
  const rounded = useTransform(count, latest => Math.round(latest));
  const progress = useTransform(count, [0, 100], [0, 360]);

  useEffect(() => {
    const controls = animate(count, value, { duration: 1.2, ease: "easeOut" });
    return controls.stop;
  }, [value]);

  return (
    <div className="score-gauge">
      <svg viewBox="0 0 120 120">
        <circle cx="60" cy="60" r="50" stroke="var(--border)" strokeWidth="8" fill="none" />
        <motion.circle
          cx="60" cy="60" r="50" stroke="var(--accent)" strokeWidth="8"
          fill="none" strokeLinecap="round"
          style={{ pathLength: useTransform(count, [0, 100], [0, 1]) }}
          transform="rotate(-90 60 60)"
        />
      </svg>
      <motion.div className="score-value">{rounded}</motion.div>
    </div>
  );
}
```

**Theme toggle (CSS transitions pe variabile):**

```css
* {
  transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease;
}
```

**Reduced motion** (în `index.css`):
```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

**Card hover lift:**
```css
.card {
  transition: transform 0.2s ease, box-shadow 0.2s ease;
  box-shadow: var(--shadow-sm);
}
.card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}
```

**Progress bar shimmer (în timpul scanării):**
```css
.job-progress-fill.shimmer::after {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
  animation: shimmer 1.5s infinite;
}
@keyframes shimmer {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(100%); }
}
```

**Online badge pulse (când device e online):**
```css
.device-online-badge.online::before {
  content: "";
  display: inline-block;
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--success);
  animation: pulse 2s infinite;
}
@keyframes pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(122,154,90,0.4); }
  50%      { box-shadow: 0 0 0 6px rgba(122,154,90,0); }
}
```

### 4.6 Componente noi/refacute

| Componentă | Fișier | Rol |
|---|---|---|
| `<ThemeProvider>` | `web/src/components/ThemeProvider.tsx` | Context React, gestionează `data-theme` pe `<html>`, persistă în `localStorage` |
| `<ThemeToggle>` | `web/src/components/ThemeToggle.tsx` | Buton icon sun↔moon în Navbar |
| `<ScoreGauge>` | `web/src/components/ScoreGauge.tsx` | Cercul animat + număr tween (folosit în Dashboard + ScanDetail) |
| `<GoogleButton>` | `web/src/components/GoogleButton.tsx` | Buton "Continuă cu Google" cu logo SVG oficial |
| `<UserAvatar>` | `web/src/components/UserAvatar.tsx` | Avatar mic în Navbar — poza Google sau inițială |

### 4.7 Pagini — schimbări de detaliu

| Pagină | Schimbare |
|---|---|
| `Login.tsx` | Layout centrat (max-width 420px), Google btn sus, divider "sau", form jos. Animație page-enter. |
| `Register.tsx` | Identică structural cu Login. |
| `Dashboard.tsx` | `<ScoreGauge>` mare central. Device picker = pill cu icon Chevron. Stat row reorganizat cu numere serif Fraunces. Lista scanări = carduri cu hover lift. |
| `Devices.tsx` | Single column, fără form create. Empty state ilustrat. Carduri cu pulse pe online badge, scan controls în pill. |
| `ScanDetail.tsx` | Aplicare paletă nouă. Score gauge animat. Severity dots warm-tinted. Sidebar categorii cu indicator slide via `layoutId`. |
| `Navbar.tsx` | Background `var(--bg-elevated)`, border-bottom subtil. ThemeToggle + UserAvatar dreapta. Logo cu typography Fraunces. |

---

## 5. Componente noi în backend

### 5.1 `server/app/google_auth.py` (modul nou)

```python
"""Verificare ID tokens Google + exchange code → token."""
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import httpx
from typing import Literal

def verify_id_token(token: str, client_id: str) -> dict:
    """Returneaza payload-ul decodat sau arunca ValueError."""
    return id_token.verify_oauth2_token(token, google_requests.Request(), client_id)

async def exchange_code(code: str, client_id: str, client_secret: str,
                         redirect_uri: str, code_verifier: str | None = None) -> dict:
    """POST la token endpoint Google. PKCE daca code_verifier e dat."""
    data = {
        "code": code, "client_id": client_id, "client_secret": client_secret,
        "redirect_uri": redirect_uri, "grant_type": "authorization_code",
    }
    if code_verifier:
        data["code_verifier"] = code_verifier
    async with httpx.AsyncClient() as client:
        r = await client.post("https://oauth2.googleapis.com/token", data=data)
        r.raise_for_status()
        return r.json()
```

### 5.2 `server/app/routes.py` (extensii)

Endpoint-urile noi folosesc `google_auth.py` + un dict in-memory pentru state CSRF cu TTL 5 minute.

---

## 6. Componente noi în agent

### 6.1 `agent/google_oauth.py` (modul nou)

```python
"""Loopback OAuth flow pentru desktop folosind google-auth-oauthlib.

`InstalledAppFlow.run_local_server(port=0)` face toata coregrafia:
- genereaza PKCE code_verifier + challenge
- porneste local server pe port random
- deschide browserul
- prinde codul de pe redirect
- face exchange cu Google (token endpoint)
- returneaza Credentials cu id_token deja obtinut

Functia returneaza id_token-ul ca string; apelantul il trimite la backend."""
from google_auth_oauthlib.flow import InstalledAppFlow

# GOOGLE_CLIENT_ID_DESKTOP se embed-uieste in .exe la build (vezi agent/build.ps1)
# sau e citit din env la dezvoltare (AGENT_GOOGLE_CLIENT_ID).
GOOGLE_CLIENT_ID = "..."  # populat la build/runtime

SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email",
          "https://www.googleapis.com/auth/userinfo.profile"]

def login_with_google() -> str:
    """Deschide browserul, asteapta autentificare, returneaza id_token."""
    flow = InstalledAppFlow.from_client_config(
        {"installed": {
            "client_id": GOOGLE_CLIENT_ID,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["http://127.0.0.1"],
        }},
        scopes=SCOPES,
    )
    flow.run_local_server(
        port=0,                # OS alege port liber
        open_browser=True,
        success_message="Te poti intoarce la VulnWatch Agent.",
    )
    return flow.credentials.id_token
```

**Note de implementare:**
- `google-auth-oauthlib` foloseste PKCE automat când lipsește `client_secret` din config (Google permite asta pentru desktop apps de la 2022).
- `flow.credentials.id_token` e populat pentru că am cerut scope `openid`.
- Tot fluxul e sincron (blocant). În GUI îl rulăm într-un thread (vezi 6.2) ca să nu blocăm Tk.

### 6.2 `agent/gui.py` modificări

Pagina Login adaugă butonul "Continuă cu Google" deasupra formularului existent. Click → call `google_oauth.login_with_google()` într-un thread → la succes, chemare `api_google_enroll(id_token, device_uid, device_name)` → salvează config → status page.

---

## 7. Modificări bază de date

Schema nouă a tabelei `users` (creată automat prin `Base.metadata.create_all()` la pornirea backend-ului pe DB gol):

| Coloană | Tip | Nullable | Index | Notă |
|---|---|---|---|---|
| `id` | int PK | no | — | (existent) |
| `email` | varchar(255) | no | unique | (existent) |
| `password_salt` | varchar(64) | **YES** | — | Relaxat — Google-only users nu au parolă |
| `password_hash` | varchar(128) | **YES** | — | Relaxat — Google-only users nu au parolă |
| `google_sub` | varchar(64) | YES | unique | **Nou** — Google subject ID |
| `google_picture_url` | varchar(512) | YES | — | **Nou** — URL avatar Google |
| `auth_provider` | varchar(16) | no | — | **Nou** — `password` / `google` / `both` (default `password`) |
| `created_at` | timestamptz | no | — | (existent) |

**În dev**: `docker compose down -v && docker compose up -d` (recreează volumul). La următoarea pornire backend, `Base.metadata.create_all()` creează tabelele cu schema nouă. **Nu se rulează ALTER TABLE manual.**

**Pierdere de date**: utilizatorii existenți se șterg (ok pentru lucrare în dev).

---

## 8. Teste noi

| Fișier | Acoperă |
|---|---|
| `server/tests/test_google_auth.py` | Mock verificare id_token; flow `/auth/google/url` → callback; `/agent/google-enroll` cu mock; user upsert (creare cont nou + lipire pe email existent) |
| `server/tests/test_devices_create_disabled.py` | Verifică că platform UI nu mai are entrypoint de creare device (test integration cu frontend). De fapt: testez doar că ștergerea formului nu sparge alte teste. (Endpoint-ul `POST /devices` rămâne testat de testele existente.) |
| `web/src/__tests__/ThemeToggle.test.tsx` | Toggle schimbă `data-theme` pe `<html>` și persistă în localStorage |

Mock pentru Google: folosim `unittest.mock` pe `google_auth.verify_id_token` ca să returnăm un payload fake `{email: "test@x", sub: "12345", name: "Test"}`.

---

## 9. Ordine de implementare recomandată

Implementarea e împărțită în **3 faze** care pot fi commit-uite separat. Fiecare fază produce software funcțional.

**Faza A — Auth refactor (backend + agent):**
1. Backend: schema `User` updated + endpoint-uri `/auth/google/*` + `/agent/google-enroll` + teste cu mock Google
2. Agent: modul `google_oauth.py` + `api_google_enroll` în `core.py` + buton Google în GUI login page (deasupra formularului existent)

**Faza B — Platform UI cleanup:**
3. Elimin form create din `Devices.tsx` + empty state nou cu link agent download

**Faza C — UI revamp:**
4. Theme system: `ThemeProvider`, `ThemeToggle`, CSS variables noi, fonts Google
5. Componente noi: `<ScoreGauge>`, `<GoogleButton>`, `<UserAvatar>`
6. Refactor pagini cu noua paletă + animații: Login → Register → Navbar → Dashboard → Devices → ScanDetail
7. Teste UI: smoke pe ThemeToggle + verificare paletă aplicată corect

**Notă scope**: spec-ul acoperă două subsisteme (auth + UI). Sunt corelate (Login page conține și buton Google și design nou) — recomandarea: un singur plan de implementare. Dacă planul rezultat e prea mare (> 20 task-uri), pot decompune în două planuri separate la momentul scrierii planului.

---

## 10. Ce NU este în scope

- Account linking UI (user nu poate vedea/manage manual conexiunea Google ↔ parolă; conectarea se face automat dacă email-ul match-uiește)
- Sign in with Apple, GitHub, Microsoft (doar Google)
- Profile editing page (poza/numele user-ului)
- Sticky preference per-page (toggle e doar global, nu per pagină)
- Custom theme palettes (doar Honey light + Plum dark)
- Mobile responsive design (focus pe desktop pentru lucrare)
