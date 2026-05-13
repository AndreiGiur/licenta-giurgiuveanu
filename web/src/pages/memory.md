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
| `Login.tsx`         | Formular email + parola. La mount, daca user-ul are deja sesiune valida (verificat prin `fetchMe()`), redirect spre `/dashboard`. Validare email cu regex simplu (frontend) — backend-ul are `EmailStr` strict. La submit: `loginUser` → navigate `/dashboard`. Erori afisate in alert (mesaj generic — nu enumera daca exista emailul). |
| `Register.tsx`      | Aproape identic cu Login dar foloseste `registerUser` urmat de `loginUser` (auto-login dupa register). Validare suplimentara: parola minim 8 caractere (frontend; backend valida si el). |
| `Dashboard.tsx`     | **Pagina principala de vizualizare scanari.** Dropdown device + Reincarca. Polling `listScanJobs(uid)` la 2s → **progress bar live** (badge scan_type + faza curenta + %) pentru job activ. Cand un job finalizeaza, auto-reincarca lista de scanari pentru a vedea noul rezultat. Stat row: Exposure Score (color-coded), High/Medium/Low counts. Click pe scan → detalii inline. Buton "Detalii complete →" duce la `ScanDetail`. |
| `Devices.tsx`       | Pagina device management — READ-ONLY pentru creare (eliminata in T9). Sus: banner descarcare agent. Lista device-uri cu badge ●Online/○Offline + selector tip scan + progress bar live + buton Scaneaza acum + Scanari + Delete. Empty state prietenos cu link spre download agent. **Crearea de device se face DOAR prin executabil** (Google flow → /agent/google-enroll sau email/parola → /devices). Polling status la 2s + auto-loadDevices la 15s. |
| `ScanDetail.tsx`    | **Pagina detaliata pentru un scan — redesign cu category sidebar.** Top bar: nume device + badge `scan_type` (STANDARD/ADVANCED/DEEP color-coded) + data scanarii. Layout 2 coloane: stanga (260px) — score gauge mare + total findings + sidebar cu 6 categorii (🔒 Persistență, 🌐 Rețea, 🖥️ Sistem & OS, 📦 Software, ⚙️ Procese & Servicii, 📋 Event Log & Forensics), fiecare cu count si culoare = severitatea maxima; dreapta — split in lista de findings (280px) cu severity dots + detail panel (titlu mare + severity badge + recomandare + JSON dovezi). Mapare `RULE_CATEGORY` pentru 23 reguli. Sortare findings descrescator dupa severitate in fiecare categorie. |

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
