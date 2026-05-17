# Redesign GUI executabil agent — Honey & Plum dark + funcționalități rafinate

**Data**: 2026-05-18
**Autor**: Giurgiuveanu Andrei
**Scope**: Rewrite complet `agent/gui.py` — paletă, tipografie, layout, comportamente butoane

## Sumar

Toate cele 3 pagini ale executabilului (Login, Enroll, Status) sunt refăcute pentru a folosi aceeași identitate vizuală cu platforma web (Honey & Plum dark mode) și pentru a curăța funcționalitățile confuze sau lipsă din UI-ul actual.

## Motivație

UI-ul curent are 3 probleme:

1. **Inconsistență vizuală** cu platforma web: executabilul folosește paletă dark cyan/blue în timp ce web-ul folosește Honey & Plum (cream + honey + plum). Pentru lucrarea de licență, identitatea trebuie să fie unitară.
2. **Funcționalități confuze**: butonul „Logout" face dual function (logout user + șterge config local) — user-ul nu poate distinge între „vreau să schimb cont" vs „vreau să elimin acest PC din contul meu".
3. **Info-uri irelevante** ocupă spațiu valoros: „Niveluri suportate: Standard / Advanced / Deep" e info dead (user nu face nimic cu asta), câmpul API URL e expus utilizatorilor non-tehnici, log-ul live ocupă jumătate de fereastră chiar și când nu e nevoie.

## Non-goals

- **Nu schimbăm Tkinter** la webview / Electron. Executabilul rămâne ~27 MB.
- **Nu schimbăm funcționalitățile core** (Google OAuth flow, daemon loop, scan-on-demand, auto-recovery 401). Doar UI.
- **Nu adăugăm „Forgot password"** — nu există flow în backend pentru asta și nu e în scope.
- **Nu schimbăm logica de enrollment / re-link** la nivel de API. Doar prezentarea în UI.

## Arhitectura vizuală

### Paletă (Honey & Plum dark, identică cu web)

```python
THEME_DARK = {
    "bg":            "#1a0e22",  # plum profund — fundal principal
    "surface":       "#2d1b3d",  # plum elevat — card-uri, input-uri
    "elevated":      "#3a2450",  # plum mai deschis — hover, btn secondary
    "border":        "#4a2d5f",  # border standard
    "accent":        "#f4c95d",  # honey — buton primary, brand, accent
    "accent_hover":  "#f7d572",  # honey hover
    "text":          "#fff8e6",  # cream — text principal
    "text_dim":      "#b8a8b8",  # text dim — labels, secondary
    "text_muted":    "#6b5b6e",  # text muted — footer, hint
    "green":         "#6fb96a",  # success / online
    "amber":         "#f4c95d",  # warning (reuse honey)
    "red":           "#e07090",  # error / offline (rose în loc de roșu strident)
}

THEME_LIGHT = {
    "bg":            "#fefaf2",  # cream — fundal principal
    "surface":       "#fff8e6",  # cream elevat
    "elevated":      "#f4e8c8",  # cream warm
    "border":        "#e8dccd",
    "accent":        "#f4c95d",  # honey rămâne (cross-mode)
    "accent_hover":  "#e8b840",
    "text":          "#2d1b3d",  # plum text
    "text_dim":      "#6b5b6e",
    "text_muted":    "#b8a8b8",
    "green":         "#3d8a3a",
    "amber":         "#c18a30",
    "red":           "#8a3a52",
}
```

Theme toggle persistă în `~/.vulnwatch/config.ini` sub cheia `theme = dark` sau `theme = light` (default: dark).

### Tipografie

| Rol | Font | Mărime | Greutate |
|---|---|---|---|
| Display (titluri pagină) | `Cambria` (fallback `Georgia`) | 22-28 px | 600 |
| Brand label | `Cambria` | 11 px | bold, letter-spacing 2px |
| Body sans | `Segoe UI` | 12-14 px | regular / 600 |
| Labels small | `Segoe UI` | 10-11 px | letter-spacing 1px, uppercase |
| Monospace (log, UID) | `Consolas` | 9 px | regular |

Toate fonturile sunt prezente în Windows by default; nu avem dependențe externe.

### Layout fereastră

- Dimensiune: 680×560 px (același ca acum)
- Min size: 560×460 px
- Padding container: 24-40 px lateral, 24 px top
- Toggle theme (☀/☾): colțul dreapta-sus, 28×28 px rotund
- Setări (⚙): la stânga lui toggle, doar pe pagina Status

## Detalii per pagină

### Pagina 1 — Login

**Layout:**

```
┌─────────────────────────────────────────────────────────────┐
│                                                  [⚙]  [☾]  │  ← settings icon doar dacă logat
│                                                              │
│  VULNWATCH AGENT                                             │  ← brand label (honey, mic, uppercase)
│                                                              │
│  Bun venit                                                   │  ← titlu (Cambria 26 px)
│  Conectează acest PC la contul tău VulnWatch.                │  ← subtitle (dim)
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  G   Continuă cu Google                             │    │  ← buton outlined cu logo G colorat
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ─────────────────  SAU  ─────────────────                  │
│                                                              │
│  EMAIL                                                       │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ andrei@example.com                                  │    │
│  └─────────────────────────────────────────────────────┘    │
│  PAROLĂ                                                      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ •••••••••                                           │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │             Autentificare                            │    │  ← buton honey primary
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│       Nu ai cont?  Înregistrează-te                          │  ← link honey underline
│                                                              │
│         VulnWatch Agent v1.0 · API: localhost:8000 ✎         │  ← footer mic, ✎ deschide popup
└─────────────────────────────────────────────────────────────┘
```

**Funcționalități:**

- **Buton Google**: identic cu actual — async `google_oauth.login_with_google()` → `api_google_enroll(...)`. La eroare, mesaj inline jos.
- **Email/parolă + toggle Register**: toggle inline (link „Înregistrează-te" / „Autentifică-te"). Acțiune submit: `api_login` (sau `api_register` + `api_login`).
- **API URL footer ✎**: click deschide o fereastră modală mică „Setări avansate API" cu un input + butoane „Salvează" / „Revino la default". Implicit `http://127.0.0.1:8000/api/v1`. Modificarea persistă imediat pentru următoarele tentative de login. Niciun user normal nu va deschide asta.
- **Toggle theme ☾/☀**: comută temele în fereastra curentă + persistă în config.
- **Validare client-side**: email regex simplu, parolă min 8 caractere. Mesaj afișat sub form, deasupra butonului primary.

**Lipsuri rezolvate față de UI actual:**

- ✘ Câmpul API URL editabil în form (confuz pentru non-tehnici) → ✓ ascuns în footer cu ✎
- ✘ Lipsă theme toggle → ✓ adăugat

### Pagina 2 — Enroll (consolidat)

**Două sub-stări vizuale (în aceeași pagină, decizia se face când agentul cere `GET /devices/by-uid/{hostname}`):**

**Sub-stare A — Device nou (UID nu există pe cont):**

```
VULNWATCH AGENT  ·  andrei@example.com                  [☾]

Conectează acest PC
Vom asocia acest calculator cu contul tău.

┌─────────────────────────────────────────────────────────┐
│  🖥  Windows · DESKTOP-ANDREI                            │
│       UID tehnic: desktop-andrei  [link „Schimbă"]      │
└─────────────────────────────────────────────────────────┘

CUM SĂ APARĂ ÎN DASHBOARD
┌─────────────────────────────────────────────────────────┐
│ PC Andrei                                                │  ← editable
└─────────────────────────────────────────────────────────┘

[✓] Pornește automat la pornirea Windows (recomandat)

┌──────────────────────┐  ┌─────────────┐
│       Conectează     │  │   Anulează  │  ← „Anulează" face logout → înapoi la Login
└──────────────────────┘  └─────────────┘
```

**Sub-stare B — Device deja înregistrat (re-link):**

```
VULNWATCH AGENT  ·  andrei@example.com                  [☾]

Reconectează acest PC
Vom refolosi înregistrarea existentă.

┌─────────────────────────────────────────────────────────┐
│  🖥  Windows · DESKTOP-ANDREI                            │
│       UID tehnic: desktop-andrei                        │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐  ← banner avertizare honey
│  ⚠  Acest PC e deja înregistrat ca „PC Andrei".          │
│     Probabil ai reinstalat OS-ul sau ai șters configul. │
│     Refolosim înregistrarea existentă — istoricul        │
│     scanărilor rămâne.                                   │
└─────────────────────────────────────────────────────────┘

[✓] Pornește automat la pornirea Windows (recomandat)

┌─────────────────────────┐  ┌─────────────┐
│  Refolosește „PC Andrei" │  │   Anulează  │
└─────────────────────────┘  └─────────────┘

[link mic dreapta-jos]  Vrei să-l înregistrezi ca PC nou? →
```

**Funcționalități:**

- **„Schimbă" UID în sub-stare A**: link mic deschide popup care permite editare manuală a UID (rar folosit; UID tehnic standard = `hostname.lower()`). Notă în popup: „Modifică doar dacă știi ce faci."
- **Banner re-link**: apare doar când `api_get_device_by_uid` returnează un device existent. Conține numele displayed actual al device-ului.
- **Link „Înregistrează ca PC nou" în sub-stare B**: trece la sub-stare A cu UID pre-completat cu o variantă (ex: `desktop-andrei-2`). Folosit dacă user-ul nu vrea să refolosească device-ul existent.
- **Buton Conectează / Refolosește**: trimite request POST `/devices` (cu token_hash generat local) sau POST `/devices/{uid}/relink`.
- **Buton Anulează**: face logout din session_token + revine la pagina Login.
- **Autostart checkbox**: invocă `autostart.enable()` / `autostart.disable()` la finalizare enrollment.

**Lipsuri rezolvate față de UI actual:**

- ✘ 2 pagini separate (New / Re-link) cu structuri diferite → ✓ 1 pagină consolidată cu sub-stare contextuală
- ✘ Câmp UID editabil mereu → ✓ Read-only by default + link „Schimbă" pentru cazuri rare
- ✘ Buton „Inrolează ca device nou" pe Re-link (prominent) → ✓ Înlocuit cu link discret „Înregistrează ca PC nou →"

### Pagina 3 — Status (regândit cu metrici)

```
VULNWATCH AGENT                                  [⚙]  [☾]

  ●  Activ și conectat                                          ← dot status colorat, h1 cambria
     PC Andrei · andrei@example.com · ultim heartbeat acum 3s   ← info-bar compact

  ┌──────────┐  ┌──────────────┐  ┌──────────────┐
  │   12     │  │    37/100    │  │    14:32     │
  │ SCANĂRI  │  │ULTIMA EXPUNERE│  │ULTIMA SCANARE│
  └──────────┘  └──────────────┘  └──────────────┘

  ┌────────────────────────────┐  ┌──────────┐
  │     Deschide dashboard      │  │  ⏸ Pauză  │
  └────────────────────────────┘  └──────────┘

  ▾ Detalii și log activitate                                   ← click pentru expand

  ──────────────────────────────────────────────────────────────
  Pornește automat la logon: activ ✓   ·   v1.0                ← footer status
```

**Funcționalități:**

**Status dot live** (top-left, 14px circle cu glow):

| Stare | Culoare | Etichetă | Condiție |
|---|---|---|---|
| online | verde `#6fb96a` cu glow | „Activ și conectat" | ultim heartbeat ≤ 15s |
| degraded | amber `#f4c95d` | „Conexiune intermitentă" | heartbeat între 15s și 60s |
| offline | rose `#e07090` | „Fără conexiune cu serverul" | heartbeat > 60s sau ConnectionError |
| paused | gri muted | „În pauză" | daemon pe pauză manual |
| starting | amber | „Pornesc daemon-ul..." | la inițializare |

Refresh automat la 2s (Tk `after`). Sursa: timestamp ultim heartbeat OK din daemon thread, propagat prin `queue.Queue` la UI.

**3 carduri metrici** (echivalent grid 3 coloane):

| Card | Sursă date | Format |
|---|---|---|
| SCANĂRI | counter intern session (incremented la fiecare submit_job_result OK) | număr întreg, font Cambria 22px honey |
| ULTIMA EXPUNERE | ultima valoare `exposure_score` din response submit_job_result | `XX/100` |
| ULTIMA SCANARE | timestamp ultima scanare finalizată | `HH:MM` (sau „—" dacă niciuna) |

Counterele sunt în-memoria (nu persistate între restart-uri). În viitor pot persista în config.

**Buton „Deschide dashboard"** (primary, honey):

- Click → `webbrowser.open(f"{frontend}/dashboard?device={uid}")` (identic cu acum).
- Frontend URL derivat din `api_base` (replace `/api/v1` → ``, `:8000` → `:5173`).

**Buton „⏸ Pauză" / „▶ Reia"** (secondary, plum elevat):

- Toggle pe `DaemonRunner.pause()`.
- Schimbă etichetă și culoare dot (paused → gri).

**„▾ Detalii și log activitate"** (expandable section):

- Click pe rândul „▾" → expandă o secțiune care conține:
  - **UID tehnic**: `desktop-andrei`
  - **API**: `http://127.0.0.1:8000/api/v1`
  - **Log live**: textarea cu mesaje (identic cu acum, dar ascuns default).
  - **Buton „Copiază în clipboard"** pentru log (util pentru debug).
- La click din nou → colapsă.
- State expansion persistă în config (`log_expanded = true/false`) pentru consistență la următoarea pornire.

**Meniu setări ⚙** (top-right, click → drop-down):

```
┌────────────────────────────────┐
│  ✓ Pornește la logon            │  ← toggle (autostart.enable/disable)
│                                 │
│  Schimbă cont                   │  ← logout user, păstrează device pe cont
│  Deconectează acest PC          │  ← logout + dezînrolează device (cu confirmare)
│                                 │
│  Setări avansate API URL...     │  ← deschide popup API URL editor
│  Despre VulnWatch Agent         │  ← popup cu versiunea + link GitHub (sau text simplu)
└────────────────────────────────┘
```

- **„Schimbă cont"**: șterge configul local (`core.clear_config()`) + revine la Login. **NU face nimic pe server** — device-ul rămâne pe contul vechi. Confirmare: „Vei fi delogat de pe acest PC. Device-ul rămâne pe contul tău (`andrei@example.com`) și-l poți reactiva oricând cu același cont. Continui?"
- **„Deconectează acest PC"**: confirmare cu avertisment mai serios. Apoi: dacă user-ul confirmă, agent încearcă `DELETE /api/v1/devices/{uid}` cu device_token (NOTĂ: backend-ul curent are doar `DELETE /devices/{uid}` cu cookie/X-Session — am 2 opțiuni: (a) cere user să-l șteargă din UI web, (b) adăugăm un endpoint nou agent-authorized). **Decizie pentru această iterație**: deconectarea șterge doar configul local (ca actualmente); afișează mesaj „Pentru a elimina și înregistrarea din cont, apasă ștergere device în dashboard web." Adăugarea endpoint-ului dedicat e backlog.
- **„Setări avansate API URL..."**: deschide modal cu editor API base URL (rar folosit, debug).
- **„Despre"**: modal simplu cu titlu, versiune, link spre repo / dashboard, mesaj scurt.

**Lipsuri rezolvate față de UI actual:**

- ✘ Card „Niveluri suportate" dead → ✓ 3 metrici concrete
- ✘ Câmpul „API" expus în info → ✓ Mutat în secțiunea Detalii expandabilă + meniu Setări
- ✘ Log mereu vizibil (ocupă jumătate de fereastră) → ✓ Colapsat default
- ✘ Buton „Logout" confuz → ✓ Înlocuit cu meniu ⚙ cu 2 acțiuni distincte
- ✘ Checkbox autostart în footer → ✓ Mutat în meniul ⚙; status afișat compact în footer
- ✘ Lipsă indicator status server (online/offline) → ✓ Dot cu 5 stări + glow

## Comportamente non-funcționale

- **Animații**: Tkinter nu suportă nativ animații complexe. Vom adăuga:
  - **Dot glow pulsing** pe stare online: alternare alpha (simulat prin alternare culoare verde light/dark la 800ms interval folosind `Canvas.itemconfig` + `root.after`).
  - **Fade-in la schimbarea paginii**: NU. Tkinter nu suportă opacity per-frame curat. Lăsăm tranziții instant.
  - **Hover lift pe butoane**: schimbare culoare background la `<Enter>` / `<Leave>` events.
- **Accessibility**: focus visible pe inputs și butoane (border honey 2px la `<FocusIn>`); tab order natural; Enter submite form pe Login.
- **Performance**: log live folosește `Text` widget cu max 5000 linii (auto-truncate ca acum); metricile actualizate doar la eveniment (nu poll).
- **Errors**: erorile API afișate inline ca toast jos pe form (nu modal); 401 → flow auto-recovery existent.

## Structura fișierului `agent/gui.py`

Fișierul actual are ~900 linii. După redesign va depăși probabil 1100-1200 linii dacă păstrăm totul într-un singur fișier. Decizie:

**Păstrăm într-un singur fișier** dar cu organizare clară prin secțiuni cu separatoare:

1. Imports + constants
2. `THEME_DARK` / `THEME_LIGHT` dict-uri
3. `ThemeManager` mic helper (carousel între dark/light + persist în config)
4. `DaemonRunner` (neschimbat funcțional)
5. `MetricsTracker` clasă mică nouă: counters pentru session metrics
6. `AgentApp.__init__` + setup styles ttk
7. `AgentApp._render_login_page` + `_login_*` handlers
8. `AgentApp._render_enroll_page` + `_enroll_*` handlers
9. `AgentApp._render_status_page` + `_status_*` handlers
10. `AgentApp._render_settings_menu` (popup ⚙)
11. `AgentApp._render_about_dialog` / `_render_api_url_dialog` (modale)
12. `AgentApp._poll_log_queue` + `_handle_token_invalid` (neschimbate)
13. Tray integration (neschimbată)
14. `run_gui` entry point

Dacă fișierul depășește 1500 de linii, în iterație viitoare extragem `theme.py`, `pages_login.py`, `pages_status.py`, etc. — dar nu acum.

## Persistență config

Cheile noi adăugate în `~/.vulnwatch/config.ini`:

```ini
[agent]
api_base = http://127.0.0.1:8000/api/v1
device_uid = desktop-andrei
device_token = ...
device_name = PC Andrei
user_email = andrei@example.com

[ui]
theme = dark              # nou: dark | light
log_expanded = false      # nou: state colapsare detalii
```

Configul existent rămâne neschimbat ca structură.

## Testing

**Manual tests** (nu există framework de unit test pentru Tkinter în acest repo; smoke tests sunt suficiente):

1. **Smoke test pornire**: `python scan.py gui` deschide GUI, fără crash, în <2 secunde.
2. **Login flow Google**: click „Continuă cu Google" → browser deschis → callback OK → trece la Status.
3. **Login flow email/parolă**: introdu credențiale → Autentificare → Enroll → Status.
4. **Toggle Register/Login**: pe Login, click „Înregistrează-te" → form schimbă titlu și buton; back la „Autentifică-te" reverte.
5. **Toggle theme**: click ☾/☀ → toate culorile se schimbă; restart aplicație → tema persistă.
6. **Re-link banner**: ștergere config local + re-deschidere → trebuie să vezi banner contextual cu numele device-ului existent.
7. **Status dot live**:
   - Cu daemon pornit normal: dot verde.
   - Oprește backend-ul (`docker compose stop db`): după 30s dot devine amber, apoi roșu.
   - Reia backend: dot revine verde în max 15s.
8. **Pauză**: click „⏸ Pauză" → buton schimbă la „▶ Reia" + dot devine gri. Click înapoi → reia.
9. **Detalii expandabile**: click „▾ Detalii" → log apare. Click din nou → ascunde. Restart → state persistat.
10. **Meniu ⚙**:
    - Toggle autostart → verifică în Registry Windows că cheia există / lipsește.
    - „Schimbă cont" → confirm dialog → revine la Login.
    - „Deconectează acest PC" → confirm cu avertisment → șterge config + mesaj informativ.
    - „Setări avansate API URL" → modal cu editor + butoane Save / Reset.
    - „Despre" → modal cu versiune + text.
11. **401 recovery**: șterge device din UI web → în max 10s GUI sare la Login cu mesajul existent + tema păstrată.
12. **Light mode parity**: după toggle la light, toate elementele rămân vizibile (contrast suficient) — în special: input borders, brand label, footer.

## Migration

Nicio migrare necesară. Configul vechi (fără cheia `[ui]`) e citit OK (default `theme = dark`, `log_expanded = false`). Executabilul rebuilt va folosi noul UI automat.

## Riscuri și mitigări

| Risc | Mitigare |
|---|---|
| Fonturi Cambria/Segoe UI inexistente pe Windows N edition (rar) | Fallback la `Georgia` și `Arial`. Tkinter face fallback automat când fontul lipsește. |
| Tkinter `Canvas` glow simulat consumă CPU dacă refresh prea des | Update la 800ms (nu 100ms) — neglijabil. |
| Theme toggle live cere reconstruirea tuturor widget-urilor | Acceptat — re-render pagina curentă la toggle. Singura latență vizibilă: ~50ms. |
| User vechi cu config existent fără `[ui]` | `configparser` returnează default-uri la cheie lipsă — niciun crash. |
| Dot status depinde de heartbeat — dacă daemon e oprit, nu mai e heartbeat → dot rămâne în stare ultimă | Acceptat: când daemon e oprit (pauză), dot devine gri „În pauză" — comportament corect. |
