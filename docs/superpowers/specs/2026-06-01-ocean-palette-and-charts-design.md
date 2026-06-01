# Design — Paleta "Ocean" + wrapper grafice (spirit shadcn) + PDF coerent

Data: 2026-06-01
Status: aprobat (design), urmeaza plan de implementare

## Context

UI-ul foloseste paleta "Honey & Plum" (crem + galben miere + prun) definita ca
CSS variables in `web/src/index.css` (light + dark). Graficele (Recharts) au
fiecare propriul tooltip + culori hardcodate, inconsistent. PDF-ul (`reports.py`)
are constante de culoare proprii (PLUM/HONEY/CREAM...).

Utilizatorul vrea:
1. **Makeover paleta** → **"Ocean"**: albastru placut + teal care se imbina (analoge).
2. **Wrapper de grafice "spirit shadcn"** (plain CSS, fara Tailwind), peste Recharts
   (deja instalat), care unifica container + tooltip + theming + legenda.
3. **PDF-ul sa urmeze acelasi pattern de culori ca FE.**

## Principii

- O singura sursa de adevar pentru culori: CSS variables in `index.css`. Graficele
  consuma variabilele, nu hex-uri hardcodate. PDF-ul oglindeste aceleasi valori.
- Severitatile raman semantice (rosu = critic/high, ambra = medium, albastru deschis
  = low) ca sa nu pierzi citirea de securitate.
- Zero dependinte noi, zero Tailwind. Refactor, nu rescriere.
- Aliasurile legacy (`--purple`, `--amber`, `--green`, etc.) raman definite (remapate)
  ca sa nu se rupa clasele existente.

---

## A. Paleta "Ocean" — CSS variables (`web/src/index.css`)

### Light (`:root, [data-theme="light"]`)

| Variabila | Vechi | Nou (Ocean) |
|---|---|---|
| `--bg-base` | #fefaf2 | `#f6f9fc` |
| `--bg-elevated` | #fff8e6 | `#eef4fb` |
| `--bg-hover` | #fdf4d8 | `#e3edf8` |
| `--surface` | #ffffff | `#ffffff` |
| `--border` | #f0e4cc | `#d8e3f0` |
| `--border-strong` | #e8d4a8 | `#c2d4e8` |
| `--text-primary` | #2d1b3d | `#0f2942` |
| `--text-secondary` | #5a3a6e | `#3b5a78` |
| `--text-muted` | #8a7458 | `#6b8299` |
| `--text-inverse` | #fff8e6 | `#f6f9fc` |
| `--accent` | #f4c95d | `#2563eb` |
| `--accent-strong` | #d4a73d | `#1d4ed8` |
| `--accent-soft` | #fff4d0 | `#dbe9fe` |
| `--teal` (NOU) | — | `#0d9488` |
| `--teal-soft` (NOU) | — | `#ccfbf1` |
| `--severity-critical` | #5a2d6e | `#b91c1c` |
| `--severity-high` | #b8456e | `#ef4444` |
| `--severity-medium` | #d4a73d | `#f59e0b` |
| `--severity-low` | #a8639a | `#38bdf8` |
| `--severity-info` | #8a7458 | `#6b8299` |
| `--success` | #7a9a5a | `#16a34a` |
| `--danger` | #c44b4b | `#dc2626` |
| `--warning` | #e8a23d | `#f59e0b` |

Legacy aliases (light) remapate: `--bg-surface=#ffffff`, `--purple=#0d9488`,
`--amber=#f59e0b`, `--red=#dc2626`, `--green=#16a34a`, `--accent-dim=rgba(37,99,235,0.16)`,
`--accent-glow=rgba(37,99,235,0.30)`, + variantele `*-dim`/`*-border` recalculate din
culorile noi. `--plum-deep` (folosit ca fallback) → `#0f2942`. Shadows: tinta din
plum → navy: `rgba(15,41,66,0.08)` etc.

### Dark (`[data-theme="dark"]`)

| Variabila | Nou (Ocean dark) |
|---|---|
| `--bg-base` | `#0b1220` |
| `--bg-elevated` | `#131c2e` |
| `--bg-hover` | `#1c2942` |
| `--surface` | `#1c2942` |
| `--border` | `#243349` |
| `--border-strong` | `#35496a` |
| `--text-primary` | `#e8eef6` |
| `--text-secondary` | `#b8c6d8` |
| `--text-muted` | `#7e92aa` |
| `--text-inverse` | `#0f2942` |
| `--accent` | `#3b82f6` |
| `--accent-strong` | `#60a5fa` |
| `--accent-soft` | `#1c2942` |
| `--teal` | `#14b8a6` |
| `--teal-soft` | `#134e4a` |
| `--severity-critical` | `#f87171` |
| `--severity-high` | `#fb923c` |
| `--severity-medium` | `#fbbf24` |
| `--severity-low` | `#38bdf8` |
| `--severity-info` | `#7e92aa` |
| `--success` | `#34d399` |
| `--danger` | `#f87171` |
| `--warning` | `#fbbf24` |

Legacy dark: `--purple=#14b8a6`, `--amber=#fbbf24`, `--red=#f87171`, `--green=#34d399`,
`--accent-dim/glow` din `#3b82f6`. Shadows raman pe negru (ca acum).

**Nota:** comentariul-titlu din `index.css` ("Honey & Plum") devine "Ocean".
Restul claselor folosesc deja variabilele → se actualizeaza automat.

## B. Wrapper grafice — pachet `web/src/components/chart/`

### `chart.ts`
- Tip `ChartConfig = Record<string, { label: string; color: string }>`.
- `axisDefaults` — obiect cu props comune pentru `XAxis`/`YAxis`/`CartesianGrid`
  (culoare `var(--border)`, tick `var(--text-muted)`, fontSize 11, fara tickLine).

### `ChartContainer.tsx`
- `<ChartContainer config height={260} className?>{children}</ChartContainer>`.
- Randeaza un `<div>` care injecteaza, ca inline style, `--color-<key>: <color>`
  pentru fiecare cheie din config (exact ca shadcn) → seriile folosesc
  `stroke="var(--color-out)"` etc. Apoi `<ResponsiveContainer width="100%" height>`.

### `ChartTooltip.tsx`
- `<ChartTooltip />` folosit ca `content={<ChartTooltip config={...} labelFormatter? valueFormatter? />}`.
- Box tematizat (bg `--bg-elevated`, border `--border`, shadow, radius) cu:
  titlu (label-ul punctului, via `labelFormatter`) + un rand per serie:
  `pastila culoare (var(--color-<key>)) + config[key].label + valoare (valueFormatter)`.

### `ChartLegend.tsx`
- `<ChartLegend config={...} />` — rand de `pastila + label` per cheie. Folosit DOAR
  unde ajuta (trafic in/out). Scor-trend (o singura serie) NU primeste legenda.

### Teste
- `ChartTooltip`: cu `active+payload`, randeaza label + randuri din config (label +
  valoare formatata); inactiv → null.
- `ChartContainer`: randeaza copiii + seteaza `--color-<key>` pe container.

## C. Refactor consumatori

### `ScoreTrendChart.tsx`
- Scoate `CustomTooltip` propriu → foloseste `<ChartContainer config>` +
  `<ChartTooltip config labelFormatter valueFormatter>`.
- Gradient linie: din hex hardcodate (#b8456e/#f4c95d/#a8639a) → **albastru→teal**
  (`#2563eb` → `#0d9488`). `ReferenceArea`-urile de severitate folosesc
  `var(--severity-*)` cu opacitate mica. Dot/activeDot pe `var(--accent)`.
- Config: `{ exposure_score: { label: "Scor expunere", color: "var(--accent)" } }`.

### `NetworkTrafficChart.tsx`
- Foloseste `<ChartContainer config>` + `<ChartTooltip>` + `<ChartLegend>`.
- Config: `{ out: { label: "Iesit", color: "var(--accent)" }, in: { label: "Intrat",
  color: "var(--teal)" } }`. Ariile folosesc `var(--color-out)`/`var(--color-in)`.
- **Fix bug latent:** versiunea actuala foloseste `var(--plum)` (nedefinit) pentru
  aria "in" → acum `var(--color-in)` (teal). Header-ul (↑/↓ KB/s) ia culorile din config.

`ScoreBreakdownBars.tsx` NU se atinge (bare CSS custom; preia automat noile variabile).

## D. PDF — `server/app/reports.py` (oglindeste FE)

Remap constante (PDF ruleaza pe alb → folosim valorile light din Ocean):

| Constanta | Vechi | Nou (Ocean light) | Rol |
|---|---|---|---|
| `PLUM` → `NAVY` | #2d1b3d | `#0f2942` | text/headere principale |
| `HONEY` → `BLUE` | #f4c95d | `#2563eb` | accent primar |
| `CREAM` → `BG` | #fefaf2 | `#f6f9fc` | fundal deschis |
| `CREAM_ALT` → `BG_ALT` | #fff8e6 | `#eef4fb` | fundal coloana |
| `RASPBERRY` | #b8456e | `#ef4444` | severity high |
| `LAVENDER` → `SKY` | #a8639a | `#38bdf8` | severity low |
| `MUTED` | #8a7458 | `#6b8299` | text secundar |
| `BORDER` | #f0e4cc | `#d8e3f0` | linii tabel |
| `PLUM_DEEP` → `CRIT` | #5a2d6e | `#b91c1c` | severity critical |
| `TEAL` (NOU) | — | `#0d9488` | accent secundar |

`SEVERITY_COLORS` (PDF) = exact ca FE light: critical `#b91c1c`, high `#ef4444`,
medium `#f59e0b`, low `#38bdf8`. Pastram numele vechi de constante ca alias DACA
e mai putin invaziv, SAU redenumim si actualizam referintele — decizie de
implementare: **pastram numele existente (PLUM/HONEY/CREAM...) dar cu valori Ocean**,
ca sa nu atingem ~20 de referinte; un comentariu explica remap-ul. (Test-ul de PDF
verifica doar ca PDF-ul e valid + dimensiune, nu culori exacte → nu se rupe.)

## E. Testare

- Frontend: teste noi `ChartTooltip` + `ChartContainer`; testele existente
  (`ScoreTrendChart`, `NetworkTrafficChart`) raman verzi dupa refactor (adaptate
  daca verifica stringuri de culoare — nu o fac). `tsc` curat; suita verde.
- Backend: `test_reports.py` ramane verde (verifica PDF valid + marime, nu culori).
- Verificare vizuala live: dashboard + un export PDF dupa makeover.

## Faze

1. **Faza 1:** Paleta Ocean in `index.css` (light + dark + legacy aliases). Verificare
   vizuala — toata aplicatia trece pe albastru/teal automat (clasele folosesc variabile).
2. **Faza 2:** Pachet `components/chart/` (chart.ts, ChartContainer, ChartTooltip,
   ChartLegend) + teste.
3. **Faza 3:** Refactor `ScoreTrendChart` + `NetworkTrafficChart` pe wrapper + culori Ocean.
4. **Faza 4:** PDF `reports.py` remap la valorile Ocean.
5. **Faza 5:** suita completa + memory.md + verificare vizuala (UI + PDF).

## Non-obiective (YAGNI)

- Fara Tailwind / shadcn CLI / components.json.
- Fara refactor la `ScoreBreakdownBars` (preia variabilele automat).
- Fara legenda pe scor-trend (o singura serie).
- Fara teme suplimentare (raman doar light + dark).
