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
| `Dashboard.tsx`     | **Pagina principala de vizualizare scanari.** La mount: `apiGet("/devices")` pentru a popula dropdown-ul. Pre-selecteaza singurul device daca user-ul are unul; altfel asteapta selectia. Afiseaza scanarile device-ului selectat in panoul stanga (cu paginare implicita la 50). Click pe scan → carca detalii in panoul drept (findings cu severity badges, evidence collapsible, payload-ul colectat). Stat row: Exposure Score (color-coded), High/Medium/Low counts. Buton "Detalii complete →" duce la `ScanDetail`. |
| `Devices.tsx`       | **Pagina de management dispozitive.** Sus: banner cu **Descarca .exe** (citit prin `getAgentDownloadInfo`). Stanga: formular pentru inrolare device nou (UID + nume) — la creare, afiseaza tokenul plain o singura data + buton de copy. Dreapta: lista device-urilor cu butoane **Scan now** (cu polling status la 2s, mesaj inline color-coded), **Scanari** (navigate spre Dashboard cu `?device=`), **Sterge** (cu confirmare). Polling-urile sunt salvate in `useRef` pentru cleanup la unmount. |
| `ScanDetail.tsx`    | **Pagina detaliata pentru un scan.** Header cu numele device-ului + UID + timestamp. Stat row cu Exposure Score si countere High/Medium/Low. Lista findings cu severity badges si rule_id afisat in monospace; fiecare finding are un toggle "Dovezi" care arata `evidence` ca JSON pretty-printed. Sectiune "Date sistem colectate" (collapsible) care arata payload-ul: OS info ca grid, porturi cu evidentiere pentru cele riscante (cyan border pentru riscante), procese ca tabel sortat dupa memorie, software instalat cu paginare implicita la 300px height. |

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
