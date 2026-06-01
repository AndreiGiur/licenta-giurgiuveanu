# Ocean Palette + Chart Wrapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Inlocuieste paleta Honey&Plum cu "Ocean" (albastru + teal) in FE, adauga un wrapper de grafice spirit-shadcn (plain CSS peste Recharts), refactorizeaza cele 2 grafice si aliniaza culorile PDF-ului la FE.

**Architecture:** O singura sursa de adevar pentru culori — CSS variables in `index.css`; graficele consuma variabilele prin `ChartContainer` (injecteaza `--color-<key>`); PDF-ul oglindeste aceleasi valori hex. Zero Tailwind, zero dependinte noi.

**Tech Stack:** React 19 + TS, Vite, Recharts 3, plain CSS variables, reportlab (PDF), vitest, pytest.

---

## Comenzi
- FE: `cd web; npm test -- <pattern>` · `npx tsc -b` · `npm test`
- BE: `cd server; $env:DISABLE_SCHEDULER="true"; $env:DISABLE_RATELIMIT="true"; .\.venv\Scripts\python.exe -m pytest tests/test_reports.py -q`

---

# FAZA 1 — Paleta Ocean (`web/src/index.css`)

### Task 1: Variabile light Ocean

**Files:** Modify `web/src/index.css` (blocul `:root, [data-theme="light"]`)

- [ ] **Step 1: Inlocuieste valorile** in blocul light (pastreaza numele variabilelor):

```css
  /* Surface */
  --bg-base:       #f6f9fc;
  --bg-elevated:   #eef4fb;
  --bg-hover:      #e3edf8;
  --surface:       #ffffff;
  /* Borders */
  --border:        #d8e3f0;
  --border-strong: #c2d4e8;
  /* Text */
  --text-primary:   #0f2942;
  --text-secondary: #3b5a78;
  --text-muted:     #6b8299;
  --text-inverse:   #f6f9fc;
  /* Brand */
  --accent:        #2563eb;
  --accent-strong: #1d4ed8;
  --accent-soft:   #dbe9fe;
  --teal:          #0d9488;
  --teal-soft:     #ccfbf1;
  /* Severity */
  --severity-critical: #b91c1c;
  --severity-high:     #ef4444;
  --severity-medium:   #f59e0b;
  --severity-low:      #38bdf8;
  --severity-info:     #6b8299;
  /* Status */
  --success: #16a34a;
  --danger:  #dc2626;
  --warning: #f59e0b;
```

Inlocuieste si shadows (tinta navy) + aliasurile legacy din acelasi bloc:

```css
  --shadow-sm: 0 1px 2px rgba(15,41,66,0.06), 0 2px 6px rgba(15,41,66,0.04);
  --shadow-md: 0 4px 12px rgba(15,41,66,0.08), 0 8px 24px rgba(15,41,66,0.04);
  --shadow-lg: 0 12px 32px rgba(15,41,66,0.12), 0 20px 60px rgba(15,41,66,0.08);

  --bg-surface:    #ffffff;
  --border-subtle: rgba(15, 41, 66, 0.06);
  --accent-dim:    rgba(37, 99, 235, 0.16);
  --accent-glow:   rgba(37, 99, 235, 0.30);
  --purple:        #0d9488;
  --purple-dim:    rgba(13, 148, 136, 0.14);
  --red:           #dc2626;
  --red-dim:       rgba(220, 38, 38, 0.10);
  --red-border:    rgba(220, 38, 38, 0.28);
  --amber:         #f59e0b;
  --amber-dim:     rgba(245, 158, 11, 0.12);
  --amber-border:  rgba(245, 158, 11, 0.32);
  --green:         #16a34a;
  --green-dim:     rgba(22, 163, 74, 0.12);
  --green-border:  rgba(22, 163, 74, 0.32);
  --plum-deep:     #0f2942;
```

(`--plum-deep` poate sa nu fi existat ca variabila separata — adaug-o explicit pt. fallback-ul din `.theme-toggle:hover`.)

- [ ] **Step 2: Update titlu comentariu** linia 1-3: "Honey & Plum Theme" → "Ocean Theme (blue + teal)".

- [ ] **Step 3: Verify build**

Run: `cd web; npx tsc -b`
Expected: PASS (CSS nu afecteaza tsc, dar confirmam ca nimic nu s-a stricat in fisier).

- [ ] **Step 4: Commit**

```bash
git add web/src/index.css
git commit -m "feat(ui): paleta Ocean light (albastru + teal)"
```

---

### Task 2: Variabile dark Ocean

**Files:** Modify `web/src/index.css` (blocul `[data-theme="dark"]`)

- [ ] **Step 1: Inlocuieste valorile** in blocul dark:

```css
  --bg-base:       #0b1220;
  --bg-elevated:   #131c2e;
  --bg-hover:      #1c2942;
  --surface:       #1c2942;
  --border:        #243349;
  --border-strong: #35496a;
  --text-primary:   #e8eef6;
  --text-secondary: #b8c6d8;
  --text-muted:     #7e92aa;
  --text-inverse:   #0f2942;
  --accent:        #3b82f6;
  --accent-strong: #60a5fa;
  --accent-soft:   #1c2942;
  --teal:          #14b8a6;
  --teal-soft:     #134e4a;
  --severity-critical: #f87171;
  --severity-high:     #fb923c;
  --severity-medium:   #fbbf24;
  --severity-low:      #38bdf8;
  --severity-info:     #7e92aa;
  --success: #34d399;
  --danger:  #f87171;
  --warning: #fbbf24;
```

Aliasuri legacy (dark):

```css
  --bg-surface:    #1c2942;
  --border-subtle: rgba(232, 238, 246, 0.06);
  --accent-dim:    rgba(59, 130, 246, 0.16);
  --accent-glow:   rgba(59, 130, 246, 0.28);
  --purple:        #14b8a6;
  --purple-dim:    rgba(20, 184, 166, 0.14);
  --red:           #f87171;
  --red-dim:       rgba(248, 113, 113, 0.14);
  --red-border:    rgba(248, 113, 113, 0.32);
  --amber:         #fbbf24;
  --amber-dim:     rgba(251, 191, 36, 0.14);
  --amber-border:  rgba(251, 191, 36, 0.32);
  --green:         #34d399;
  --green-dim:     rgba(52, 211, 153, 0.14);
  --green-border:  rgba(52, 211, 153, 0.32);
  --plum-deep:     #0f2942;
```

(Pastreaza shadow-urile dark existente pe negru — nu se schimba.)

- [ ] **Step 2: Verify no leftover Honey&Plum hex**

Run: `cd web; grep -niE "#f4c95d|#2d1b3d|#fefaf2|#fff8e6|#b8456e|#a8639a|#5a2d6e" src/index.css`
Expected: ZERO rezultate (toate hex-urile vechi inlocuite). Daca apar, inlocuieste-le.

- [ ] **Step 3: Commit**

```bash
git add web/src/index.css
git commit -m "feat(ui): paleta Ocean dark + verificare zero hex vechi"
```

---

# FAZA 2 — Wrapper grafice (`web/src/components/chart/`)

### Task 3: chart.ts (ChartConfig + axisDefaults)

**Files:** Create `web/src/components/chart/chart.ts`

- [ ] **Step 1: Implement**

```ts
// web/src/components/chart/chart.ts
export type ChartSeries = { label: string; color: string };
export type ChartConfig = Record<string, ChartSeries>;

/** Props comune pentru axe + grid (Honey&Plum-agnostic, foloseste variabilele temei). */
export const axisDefaults = {
  tick: { fontSize: 11, fill: "var(--text-muted)" },
  axisLine: { stroke: "var(--border)" },
  tickLine: false as const,
};

/** CSS variables `--color-<key>` din config, pentru containerul de chart. */
export function chartColorVars(config: ChartConfig): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, s] of Object.entries(config)) {
    out[`--color-${key}`] = s.color;
  }
  return out;
}
```

- [ ] **Step 2: Commit**

```bash
git add web/src/components/chart/chart.ts
git commit -m "feat(fe): chart.ts — ChartConfig + axisDefaults + chartColorVars"
```

---

### Task 4: ChartContainer

**Files:** Create `web/src/components/chart/ChartContainer.tsx` + test

- [ ] **Step 1: Write the failing test**

```tsx
// web/src/components/chart/ChartContainer.test.tsx
import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import { ChartContainer } from "./ChartContainer";

class RO { constructor(_: ResizeObserverCallback) {} observe() {} unobserve() {} disconnect() {} }
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).ResizeObserver = RO;

describe("ChartContainer", () => {
  it("randeaza copiii si seteaza --color-<key> din config", () => {
    const { container } = render(
      <ChartContainer config={{ out: { label: "Iesit", color: "#2563eb" } }} height={100}>
        <div data-testid="child" />
      </ChartContainer>,
    );
    const root = container.querySelector(".chart-container") as HTMLElement;
    expect(root).toBeTruthy();
    expect(root.style.getPropertyValue("--color-out")).toBe("#2563eb");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web; npm test -- ChartContainer`
Expected: FAIL — module not found

- [ ] **Step 3: Implement**

```tsx
// web/src/components/chart/ChartContainer.tsx
import type { ReactElement } from "react";
import { ResponsiveContainer } from "recharts";
import type { ChartConfig } from "./chart";
import { chartColorVars } from "./chart";

type Props = {
  config: ChartConfig;
  height?: number;
  className?: string;
  children: ReactElement;
};

export function ChartContainer({ config, height = 240, className = "", children }: Props) {
  return (
    <div className={`chart-container ${className}`}
      style={{ width: "100%", height, ...chartColorVars(config) } as React.CSSProperties}>
      <ResponsiveContainer width="100%" height="100%">
        {children}
      </ResponsiveContainer>
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web; npm test -- ChartContainer`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add web/src/components/chart/ChartContainer.tsx web/src/components/chart/ChartContainer.test.tsx
git commit -m "feat(fe): ChartContainer (ResponsiveContainer + injecteaza --color-<key>)"
```

---

### Task 5: ChartTooltip + ChartLegend

**Files:** Create `web/src/components/chart/ChartTooltip.tsx`, `ChartLegend.tsx` + test; CSS in `index.css`

- [ ] **Step 1: Write the failing test**

```tsx
// web/src/components/chart/ChartTooltip.test.tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ChartTooltip } from "./ChartTooltip";

const config = { out: { label: "Iesit", color: "#2563eb" }, in: { label: "Intrat", color: "#0d9488" } };

describe("ChartTooltip", () => {
  it("inactiv → null", () => {
    const { container } = render(<ChartTooltip config={config} active={false} payload={[]} />);
    expect(container.firstChild).toBeNull();
  });
  it("activ → label + randuri din config cu valoare formatata", () => {
    render(<ChartTooltip config={config} active
      payload={[{ dataKey: "out", value: 12.5 }, { dataKey: "in", value: 3 }]}
      labelFormatter={() => "14:20"} valueFormatter={(v) => `${v} KB/s`} />);
    expect(screen.getByText("14:20")).toBeInTheDocument();
    expect(screen.getByText("Iesit")).toBeInTheDocument();
    expect(screen.getByText("12.5 KB/s")).toBeInTheDocument();
    expect(screen.getByText("Intrat")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web; npm test -- ChartTooltip`
Expected: FAIL — module not found

- [ ] **Step 3: Implement ChartTooltip**

```tsx
// web/src/components/chart/ChartTooltip.tsx
import type { ChartConfig } from "./chart";

type Item = { dataKey?: string | number; value?: number | string; payload?: unknown };
type Props = {
  config: ChartConfig;
  active?: boolean;
  payload?: Item[];
  label?: unknown;
  labelFormatter?: (label: unknown, payload: Item[]) => string;
  valueFormatter?: (value: number | string, key: string) => string;
};

export function ChartTooltip({ config, active, payload = [], label,
                              labelFormatter, valueFormatter }: Props) {
  if (!active || payload.length === 0) return null;
  const title = labelFormatter ? labelFormatter(label, payload) : null;
  return (
    <div className="chart-tooltip">
      {title && <div className="chart-tooltip-title">{title}</div>}
      {payload.map((item) => {
        const key = String(item.dataKey ?? "");
        const series = config[key];
        if (!series) return null;
        const val = valueFormatter ? valueFormatter(item.value as number, key) : String(item.value);
        return (
          <div key={key} className="chart-tooltip-row">
            <span className="chart-tooltip-dot" style={{ background: `var(--color-${key}, ${series.color})` }} />
            <span className="chart-tooltip-label">{series.label}</span>
            <span className="chart-tooltip-value">{val}</span>
          </div>
        );
      })}
    </div>
  );
}
```

- [ ] **Step 4: Implement ChartLegend**

```tsx
// web/src/components/chart/ChartLegend.tsx
import type { ChartConfig } from "./chart";

export function ChartLegend({ config }: { config: ChartConfig }) {
  return (
    <div className="chart-legend">
      {Object.entries(config).map(([key, s]) => (
        <span key={key} className="chart-legend-item">
          <span className="chart-legend-dot" style={{ background: `var(--color-${key}, ${s.color})` }} />
          {s.label}
        </span>
      ))}
    </div>
  );
}
```

- [ ] **Step 5: Add CSS** in `web/src/index.css`:

```css
/* ============================================================
   CHART (wrapper spirit-shadcn)
   ============================================================ */
.chart-tooltip {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 12px;
  box-shadow: var(--shadow-md);
  font-size: 12px;
}
.chart-tooltip-title { font-weight: 600; color: var(--text-primary); margin-bottom: 6px; }
.chart-tooltip-row { display: flex; align-items: center; gap: 8px; margin-top: 3px; }
.chart-tooltip-dot { width: 10px; height: 10px; border-radius: 3px; flex-shrink: 0; }
.chart-tooltip-label { color: var(--text-secondary); }
.chart-tooltip-value { margin-left: auto; font-weight: 700; color: var(--text-primary); font-variant-numeric: tabular-nums; }
.chart-legend { display: flex; gap: 16px; flex-wrap: wrap; font-size: 12px; color: var(--text-secondary); margin-bottom: 6px; }
.chart-legend-item { display: inline-flex; align-items: center; gap: 6px; }
.chart-legend-dot { width: 10px; height: 10px; border-radius: 3px; }
```

- [ ] **Step 6: Run tests**

Run: `cd web; npm test -- ChartTooltip`
Expected: PASS (2)

- [ ] **Step 7: Commit**

```bash
git add web/src/components/chart/ChartTooltip.tsx web/src/components/chart/ChartTooltip.test.tsx web/src/components/chart/ChartLegend.tsx web/src/index.css
git commit -m "feat(fe): ChartTooltip + ChartLegend tematizate (Ocean)"
```

---

# FAZA 3 — Refactor consumatori

### Task 6: Refactor NetworkTrafficChart

**Files:** Modify `web/src/components/NetworkTrafficChart.tsx`

- [ ] **Step 1: Rescrie corpul** (pastreaza hook + empty state):

```tsx
import { Area, AreaChart, Tooltip, XAxis, YAxis } from "recharts";
import { useNetworkTraffic } from "../hooks/useNetworkTraffic";
import { ChartContainer } from "./chart/ChartContainer";
import { ChartTooltip } from "./chart/ChartTooltip";
import { ChartLegend } from "./chart/ChartLegend";
import { axisDefaults, type ChartConfig } from "./chart/chart";

const CONFIG: ChartConfig = {
  out: { label: "Iesit", color: "var(--accent)" },
  in: { label: "Intrat", color: "var(--teal)" },
};

export function NetworkTrafficChart({ deviceUid }: { deviceUid: string }) {
  const series = useNetworkTraffic(deviceUid);
  if (series.length === 0) {
    return <div className="empty-state">Niciun trafic inregistrat (agent offline sau fara activitate recenta).</div>;
  }
  const data = series.map((p, i) => ({ i, out: p.sent_rate_kbps, in: p.recv_rate_kbps }));
  const last = series[series.length - 1];
  return (
    <div>
      <ChartLegend config={CONFIG} />
      <div style={{ display: "flex", gap: 18, marginBottom: 8, fontSize: 13, flexWrap: "wrap" }}>
        <span style={{ color: "var(--color-out, var(--accent))" }}>↑ {last.sent_rate_kbps.toFixed(1)} KB/s</span>
        <span style={{ color: "var(--color-in, var(--teal))" }}>↓ {last.recv_rate_kbps.toFixed(1)} KB/s</span>
        <span style={{ color: "var(--text-secondary)" }}>{last.conn_count} conexiuni active</span>
      </div>
      <ChartContainer config={CONFIG} height={160}>
        <AreaChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
          <XAxis dataKey="i" hide />
          <YAxis width={42} {...axisDefaults} />
          <Tooltip content={<ChartTooltip config={CONFIG}
            valueFormatter={(v) => `${Number(v).toFixed(1)} KB/s`} labelFormatter={() => "Trafic"} />} />
          <Area type="monotone" dataKey="out" stroke="var(--color-out)" fill="var(--color-out)" fillOpacity={0.25} isAnimationActive={false} />
          <Area type="monotone" dataKey="in" stroke="var(--color-in)" fill="var(--color-in)" fillOpacity={0.18} isAnimationActive={false} />
        </AreaChart>
      </ChartContainer>
    </div>
  );
}
```

- [ ] **Step 2: Run test + tsc**

Run: `cd web; npx tsc -b; npm test -- NetworkTrafficChart`
Expected: PASS (testul existent — empty state + ratele curente).

- [ ] **Step 3: Commit**

```bash
git add web/src/components/NetworkTrafficChart.tsx
git commit -m "refactor(fe): NetworkTrafficChart pe wrapper chart + culori Ocean (fix --plum)"
```

---

### Task 7: Refactor ScoreTrendChart

**Files:** Modify `web/src/components/ScoreTrendChart.tsx`

- [ ] **Step 1: Inlocuieste CustomTooltip + ResponsiveContainer** cu wrapper-ul. Pastreaza fetch + loading/error/empty. Inlocuieste blocul de la `<div className="score-trend-chart"...>` pana la final cu:

```tsx
  const CONFIG = { exposure_score: { label: "Scor expunere", color: "var(--accent)" } };
  const chartData = data.map(p => ({ ...p, dateLabel: formatDateShort(p.created_at) }));

  return (
    <ChartContainer config={CONFIG} height={height} className="score-trend-chart">
      <LineChart data={chartData} margin={{ top: 12, right: 16, left: 0, bottom: 4 }}>
        <defs>
          <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#2563eb" stopOpacity={0.95} />
            <stop offset="100%" stopColor="#0d9488" stopOpacity={0.8} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
        <XAxis dataKey="dateLabel" {...axisDefaults} />
        <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} {...axisDefaults} />
        <ReferenceArea y1={0} y2={25} fill="var(--severity-low)" fillOpacity={0.06} />
        <ReferenceArea y1={25} y2={50} fill="var(--severity-medium)" fillOpacity={0.08} />
        <ReferenceArea y1={50} y2={75} fill="var(--severity-high)" fillOpacity={0.08} />
        <ReferenceArea y1={75} y2={100} fill="var(--severity-critical)" fillOpacity={0.10} />
        <ReferenceLine y={50} stroke="var(--text-muted)" strokeDasharray="2 4" strokeOpacity={0.4} />
        <Tooltip content={<ChartTooltip config={CONFIG}
          labelFormatter={(_l, p) => {
            const pt = (p[0]?.payload ?? {}) as TrendPoint;
            return new Date(pt.created_at).toLocaleString("ro-RO");
          }}
          valueFormatter={(v) => `${v}/100`} />} />
        <Line type="monotone" dataKey="exposure_score" stroke="url(#scoreGradient)" strokeWidth={3}
          dot={{ r: 4, fill: "var(--accent)", strokeWidth: 0 }}
          activeDot={{ r: 6, fill: "var(--accent)" }} isAnimationActive animationDuration={900} />
      </LineChart>
    </ChartContainer>
  );
```

Adauga importurile: `import { ChartContainer } from "./chart/ChartContainer";`,
`import { ChartTooltip } from "./chart/ChartTooltip";`, `import { axisDefaults } from "./chart/chart";`.
Sterge functia `CustomTooltip` si importul `ResponsiveContainer` daca nu mai e folosit
(ChartContainer il aduce).

- [ ] **Step 2: Run test + tsc**

Run: `cd web; npx tsc -b; npm test -- ScoreTrendChart`
Expected: PASS (testele existente — loading/empty/error/params).

- [ ] **Step 3: Commit**

```bash
git add web/src/components/ScoreTrendChart.tsx
git commit -m "refactor(fe): ScoreTrendChart pe wrapper chart + gradient albastru-teal"
```

---

# FAZA 4 — PDF coerent (`server/app/reports.py`)

### Task 8: Remap culori PDF la Ocean

**Files:** Modify `server/app/reports.py` (liniile 23-37 — constantele de culoare)

- [ ] **Step 1: Inlocuieste valorile hex** (pastreaza numele constantelor ca sa nu atingi ~20 referinte):

```python
# Paleta Ocean (oglindeste FE — vezi web/src/index.css, valorile light).
# Numele istorice (PLUM/HONEY/CREAM...) sunt pastrate ca alias, valorile sunt Ocean.
PLUM = colors.HexColor("#0f2942")        # navy — text/headere
HONEY = colors.HexColor("#2563eb")       # albastru — accent primar
CREAM = colors.HexColor("#f6f9fc")       # fundal deschis
CREAM_ALT = colors.HexColor("#eef4fb")   # fundal coloana
RASPBERRY = colors.HexColor("#ef4444")   # severity high
LAVENDER = colors.HexColor("#38bdf8")    # severity low (sky)
MUTED = colors.HexColor("#6b8299")
BORDER = colors.HexColor("#d8e3f0")
PLUM_DEEP = colors.HexColor("#b91c1c")   # severity critical (deep red)
TEAL = colors.HexColor("#0d9488")        # accent secundar
```

`SEVERITY_COLORS` ramane mapat pe aceste constante:
```python
SEVERITY_COLORS = {
    "critical": PLUM_DEEP,   # #b91c1c
    "high": RASPBERRY,       # #ef4444
    "medium": HONEY if False else colors.HexColor("#f59e0b"),  # amber
    "low": LAVENDER,         # #38bdf8
}
```
(Atentie: `medium` era `HONEY` (galben) — acum HONEY e albastru, deci pune explicit
amber `#f59e0b` pentru medium, ca sa ramana semantic galben/portocaliu.)

- [ ] **Step 2: Run PDF test**

Run: `cd server; $env:DISABLE_SCHEDULER="true"; $env:DISABLE_RATELIMIT="true"; .\.venv\Scripts\python.exe -m pytest tests/test_reports.py -q`
Expected: PASS (4 — PDF valid + marime; culorile nu sunt verificate exact).

- [ ] **Step 3: Commit**

```bash
git add server/app/reports.py
git commit -m "feat(pdf): paleta Ocean in reports.py (oglindeste FE), medium=amber"
```

---

# FAZA 5 — Verificare + docs

### Task 9: Suita completa + memory.md + verificare vizuala

**Files:** Modify memory.md: `web/src/components/memory.md`, `server/app/memory.md`

- [ ] **Step 1: Ruleaza tot**

Run FE: `cd web; npx tsc -b; npm test`
Run BE: `cd server; $env:DISABLE_SCHEDULER="true"; $env:DISABLE_RATELIMIT="true"; .\.venv\Scripts\python.exe -m pytest -q`
Expected: toate verzi.

- [ ] **Step 2: Update memory.md**

`web/src/components/memory.md`: adauga pachetul `chart/` (ChartContainer, ChartTooltip,
ChartLegend, chart.ts) + noteaza ca ScoreTrend/NetworkTraffic il folosesc; mentioneaza
paleta Ocean. `server/app/memory.md`: noteaza ca `reports.py` foloseste paleta Ocean
(oglindeste FE). Nota paleta in `index.css` (Honey&Plum → Ocean).

- [ ] **Step 3: Verificare vizuala live** (reporneste BE+FE, deschide dashboard +
exporta un PDF; confirma albastru/teal coerent).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs+test: memory.md paleta Ocean + wrapper grafice; suita verde"
```

---

## Self-Review

**Spec coverage:** A (paleta light/dark + legacy)→Task 1,2 | B (wrapper: chart.ts→T3,
Container→T4, Tooltip+Legend→T5)→Task 3-5 | C (refactor NetworkTraffic→T6, ScoreTrend→T7)
→Task 6,7 | D (PDF)→Task 8 | E (testare)→fiecare task + Task 9. Toate acoperite. ✓
**Placeholders:** cod real in fiecare step; verificarea hex-urilor vechi e o comanda grep
concreta. ✓
**Type consistency:** `ChartConfig`/`ChartSeries`, `chartColorVars`, `axisDefaults`,
`ChartContainer(config,height,className,children)`, `ChartTooltip(config,active,payload,
labelFormatter,valueFormatter)`, `ChartLegend(config)` — folosite consistent in T3-T7. ✓
**Capcana medium=HONEY:** semnalata explicit in Task 8 (HONEY devine albastru → medium
trebuie pus pe amber). ✓
