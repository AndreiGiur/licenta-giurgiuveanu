# memory.md — web/src/pages/

Pagini ale aplicatiei, mapate la rute in `App.tsx`. Fiecare pagina e o
componenta React standalone care isi gestioneaza propriul state (`useState`,
`useEffect`).

## Rute

| Ruta                   | Pagina            | Auth     |
| ---------------------- | ----------------- | -------- |
| `/login`               | `Login.tsx`       | publica  |
| `/register`            | `Register.tsx`    | publica  |
| `/dashboard`           | `UnifiedDashboard.tsx` | protejata |
| `/devices`             | → redirect la `/dashboard` | protejata |
| `/scans/:scanId`       | `ScanDetail.tsx`  | protejata |
| `/profile`             | `Profile.tsx`     | protejata |
| `/admin`               | `Admin.tsx`       | protejata + admin only |

## Fisiere

| Fisier              | Rol                                                                    |
| ------------------- | ---------------------------------------------------------------------- |
| `Login.tsx`         | **Revamp Honey & Plum.** Auth card centrat pe fundal cu gradient warm (radial accent-soft + bg-hover). Header centrat cu titlu serif Fraunces. **`<GoogleButton>` full-width sus** → click redirect catre `/api/v1/auth/google/url`. Divider "sau". Form email/parola cu submit handler. Auth redirect daca `fetchMe()` reuseste la mount. Animatie page-enter cu Framer Motion (fade + slide-up). Switch spre Register cu `<Link>`. |
| `Register.tsx`      | **Identical structural cu Login (revamp Honey & Plum).** GoogleButton sus + divider + form email/parola. Foloseste `registerUser` urmat de `loginUser` (auto-login dupa register). Validare suplimentara: parola minim 8 caractere (frontend; backend valida si el). Animatie page-enter cu Framer Motion. |
| `UnifiedDashboard.tsx` | **(2026-06-01) Pagina unificata master-detail** (a inlocuit fostele `Dashboard.tsx` + `Devices.tsx`). Orchestrator subtire: incarca `/devices`, preselecteaza primul device online, randeaza `<DeviceSidebar>` (lista selectabila) + `<DeviceWorkspace>` (workspace device selectat). Empty state cand nu exista device-uri. Grid responsiv `.unified-grid` (colapseaza <900px). Test: `UnifiedDashboard.test.tsx` (2). Logica per-device (monitorizare + scan-now + scanari/findings + explainer) sta in `DeviceWorkspace`; vezi `components/memory.md`. |
| `ScanDetail.tsx`    | Pagina detaliata pentru un scan — category sidebar (6 categorii cu indicator slide animat) + ScoreGauge + finding detail panel. **+ buton "↓ Export PDF"** in topbar care deschide `GET /scans/{id}/report.pdf` intr-un tab nou. Page-enter motion. |
| `Profile.tsx`       | **Pagina /profile** — 4 sectiuni standard (Cont cu avatar + email + provider + buton schimba parola; Statistici cu device_count / scan_count / avg_score / last_scan; Sesiuni active cu marker `is_current` + buton Revoca; pentru admin: sectiunea Platforma cu 4 metric cards: total_users / devices_online / scans_24h / avg_score). Foloseste `getUserStats`, `listMySessions`, `revokeSession`, `changePassword`, `getPlatformStats` din `api/profile.ts`. |
| `Admin.tsx`         | **Pagina /admin (require_admin)** — 3 tabs: **Users** (tabel cu select role, reset password via prompt, delete; search bar dupa email), **Devices** (tabel cu owner_email + status online), **Scans** (paginat 25/pagina, link catre `/scans/{id}`, scor + scan_type). Foloseste `listAdminUsers/Devices/Scans` etc. din `api/profile.ts`. |

## Pattern de loading + error

Toate paginile urmeaza acelasi pattern:
```tsx
const [loading, setLoading] = useState(true);
const [error, setError] = useState<string | null>(null);
const [data, setData] = useState<...>(null);

useEffect(() => {
  let cancelled = false;
  apiGet(...)
    .then(d => { if (!cancelled) setData(d); })
    .catch(e => { if (!cancelled) setError(e instanceof Error ? e.message : "Eroare"); })
    .finally(() => { if (!cancelled) setLoading(false); });
  return () => { cancelled = true; };
}, []);
```

`cancelled` e flag-ul pentru a evita `setState` pe componente unmount-uite.

## Stiluri inline vs CSS classes

Multe pagini folosesc **stiluri inline** in JSX (in special pe layout-uri grid).
Asta e o decizie pragmatica: stilurile sunt locale paginii si nu se reutilizeaza.
Pattern-urile reutilizabile (`.btn`, `.card`, `.alert`) sunt in `index.css`.

Cand vrei sa **adaugi un stil nou reutilizabil**, du-l in `index.css`. Cand
e specific paginii si nu poti gandi alt loc unde s-ar mai folosi, lasa-l inline.
