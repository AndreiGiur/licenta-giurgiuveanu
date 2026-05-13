# memory.md — web/src/

Cod sursa React + TypeScript. Layout pe trei axe: API, componente reutilizabile,
si pagini.

## Layered architecture

```
   main.tsx          (ReactDOM.render, StrictMode)
       │
       └─► App.tsx   (BrowserRouter + Routes)
              │
              ├─► pages/Login.tsx          ─┐
              ├─► pages/Register.tsx       │  pagini publice
              │                            │
              ├─► pages/Dashboard.tsx      ─┤
              ├─► pages/Devices.tsx        │  pagini protejate
              ├─► pages/ScanDetail.tsx     │  (ProtectedRoute wrapper)
              │                            │
              ├─► components/Navbar.tsx    │  reutilizabil
              ├─► components/ProtectedRoute.tsx  (gateway de auth)
              │
              └─► api/    (HTTP client unificat)
```

## Continut

| Fisier / folder       | Rol                                                                  |
| --------------------- | -------------------------------------------------------------------- |
| `main.tsx`            | Entry point. `ReactDOM.createRoot(...).render(<StrictMode><ThemeProvider><App /></ThemeProvider></StrictMode>)`. Importa `index.css` si infasoara `<App />` cu `<ThemeProvider>` (din `components/ThemeProvider.tsx`) ca tema light/dark sa fie disponibila global. |
| `App.tsx`             | `BrowserRouter` + `Routes`. Rute: `/login`, `/register`, `/dashboard`, `/devices`, `/scans/:scanId`, `/` (redirect spre login). Cele 3 rute logate sunt invelite in `<ProtectedRoute>`. |
| `App.css`             | Stiluri specifice componentei `App` — minimale (cea mai mare parte a stilurilor sunt in `index.css`). |
| `index.css`           | **Design system VulnWatch — paleta Honey & Plum (light + dark).** Variabile CSS in doua scope-uri: `:root,[data-theme="light"]` (light: bg cremos #fefaf2, accent honey #f4c95d, text plum #2d1b3d) si `[data-theme="dark"]` (bg plum #1a0e22, accent honey, text cream #fff8e6). Tipografie: `--font-display` (Fraunces), `--font-body` (Outfit), `--font-mono` (JetBrains Mono). Severitati noi (`--severity-critical/high/medium/low/info`), shadows plum-tinted, radius scale (xs→xl→full). Variabilele vechi (`--bg-surface`, `--accent-dim`, `--red`, `--green`, `--amber`, `--purple`, `--border-subtle`, etc.) sunt pastrate ca aliasuri remappate la paleta noua, ca toate clasele existente (`.btn`, `.card`, `.device-card`, `.scan-detail-page`, `.severity-badge`, `.score-badge`, `.scan-type-badge`, `.token-block`, `.loading-dots`) sa continue sa functioneze. `@media (prefers-reduced-motion: reduce)` dezactiveaza tranzitii. Toggle-ul intre teme se face setand `data-theme` pe `<html>` (gestionat de `ThemeProvider`). |
| `api/`                | Client HTTP unificat. Vezi `api/memory.md`.                          |
| `components/`         | Componente reutilizabile. Vezi `components/memory.md`.               |
| `pages/`              | Pagini de aplicatie (mapate la rute). Vezi `pages/memory.md`.        |
| `assets/`             | Asset-uri importate in cod. Vezi `assets/memory.md`.                 |

## Auth model in frontend

**Niciun token in JS.** Sesiunea traieste exclusiv in cookie HttpOnly setat
de backend la `/auth/login`. `fetch(url, { credentials: "include" })` face
browser-ul sa trimita cookie-ul automat (in dev cu Vite proxy, prod cu CORS
configurat corect).

`fetchMe()` (`api/auth.ts`) e folosit ca **healthcheck**: daca returneaza
2xx, user-ul e logat; daca 401, nu. `ProtectedRoute` apeleaza `fetchMe()`
in `useEffect` si redirectioneaza la `/login` daca esueaza.
