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
| `main.tsx`            | Entry point. `ReactDOM.createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>)`. Importa `index.css`. |
| `App.tsx`             | `BrowserRouter` + `Routes`. Rute: `/login`, `/register`, `/dashboard`, `/devices`, `/scans/:scanId`, `/` (redirect spre login). Cele 3 rute logate sunt invelite in `<ProtectedRoute>`. |
| `App.css`             | Stiluri specifice componentei `App` — minimale (cea mai mare parte a stilurilor sunt in `index.css`). |
| `index.css`           | **Design system VulnWatch.** Variabile CSS pentru paleta dark cybersecurity (cyan accent, dark navy bg, severitati color-coded), tipografie Inter, tipuri de componente: `.btn`, `.btn-primary`, `.btn-accent`, `.btn-secondary`, `.btn-danger`, `.card`, `.severity-badge`, `.score-badge`, `.alert`, `.form-input`, `.scan-item`, `.device-card`, `.token-block`, `.loading-dots` (animatie). Tema este sincronizata cu paleta din `agent/gui.py` (`THEME` dict). |
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
