# memory.md — web/src/pages/

Pagini ale aplicatiei, mapate la rute in `App.tsx`. Fiecare pagina e o
componenta React standalone care isi gestioneaza propriul state (`useState`,
`useEffect`).

## Rute

| Ruta                   | Pagina            | Auth     |
| ---------------------- | ----------------- | -------- |
| `/login`               | `Login.tsx`       | publica  |
| `/register`            | `Register.tsx`    | publica  |
| `/dashboard`           | `Dashboard.tsx`   | protejata |
| `/devices`             | `Devices.tsx`     | protejata |
| `/scans/:scanId`       | `ScanDetail.tsx`  | protejata |

## Fisiere

| Fisier              | Rol                                                                    |
| ------------------- | ---------------------------------------------------------------------- |
| `Login.tsx`         | **Revamp Honey & Plum.** Auth card centrat pe fundal cu gradient warm (radial accent-soft + bg-hover). Header centrat cu titlu serif Fraunces. **`<GoogleButton>` full-width sus** → click redirect catre `/api/v1/auth/google/url`. Divider "sau". Form email/parola cu submit handler. Auth redirect daca `fetchMe()` reuseste la mount. Animatie page-enter cu Framer Motion (fade + slide-up). Switch spre Register cu `<Link>`. |
| `Register.tsx`      | **Identical structural cu Login (revamp Honey & Plum).** GoogleButton sus + divider + form email/parola. Foloseste `registerUser` urmat de `loginUser` (auto-login dupa register). Validare suplimentara: parola minim 8 caractere (frontend; backend valida si el). Animatie page-enter cu Framer Motion. |
| `Dashboard.tsx`     | **Pagina principala de vizualizare scanari.** Dropdown device + Reincarca. Polling `listScanJobs(uid)` la 2s → **progress bar live** (badge scan_type + faza curenta + %) pentru job activ. Cand un job finalizeaza, auto-reincarca lista de scanari pentru a vedea noul rezultat. **`<ScoreGauge>` animat (180px)** + 3 count cards (High/Critical + Medium + Low) cu fonturi serif Fraunces. Stat row in container `.dashboard-stat-row` cu page-enter motion. Click pe scan → detalii inline. Buton "Detalii complete →" duce la `ScanDetail`. |
| `Devices.tsx`       | Pagina device management — READ-ONLY pentru creare (eliminata in T9). Sus: banner descarcare agent. **Stagger entrance** pe lista de carduri (Framer Motion variants, 60ms intre carduri) + hover lift pe device card + **pulse animat** pe online badge (CSS keyframes) + **shimmer** alunecat pe progress fill in timpul scanarii. Selector tip scan + buton Scaneaza acum + Scanari + Delete. Empty state prietenos cu link spre download agent. **Crearea de device se face DOAR prin executabil** (Google flow → /agent/google-enroll sau email/parola → /devices). Polling status la 2s + auto-loadDevices la 15s. |
| `ScanDetail.tsx`    | **Pagina detaliata pentru un scan — redesign cu category sidebar.** Top bar: nume device + badge `scan_type` (STANDARD/ADVANCED/DEEP color-coded) + data scanarii. Layout 2 coloane: stanga (260px) — **`<ScoreGauge>` animat** + total findings + sidebar cu 6 categorii (🔒 Persistență, 🌐 Rețea, 🖥️ Sistem & OS, 📦 Software, ⚙️ Procese & Servicii, 📋 Event Log & Forensics), fiecare cu count si culoare = severitatea maxima; **indicator slide animat** intre categorii (Framer Motion `layoutId="category-indicator"` cu spring physics); dreapta — split in lista de findings (280px) cu severity dots + detail panel (titlu mare + severity badge + recomandare + JSON dovezi). Page-enter motion. Mapare `RULE_CATEGORY` pentru 23 reguli. Sortare findings descrescator dupa severitate in fiecare categorie. |

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
