# memory.md — web/src/components/chart/

Wrapper de grafice "spirit shadcn" peste **Recharts** (zero Tailwind, zero
dependinte noi). Unifica container + tooltip + legenda + theming pentru toate
graficele, folosind variabilele paletei **Ocean** din `index.css`.

## Fisiere

| Fisier                | Rol                                                                  |
| --------------------- | -------------------------------------------------------------------- |
| `chart.ts`            | Tipuri + helpere: `ChartConfig = Record<key, {label, color}>`, `ChartSeries`, `axisDefaults` (props comune axe/grid pe variabile temei), `chartColorVars(config)` → `{ "--color-<key>": color }`. |
| `ChartContainer.tsx`  | `<ChartContainer config height className>{copil Recharts}</ChartContainer>` — `ResponsiveContainer` + injecteaza `--color-<key>` ca CSS variables pe container (ca shadcn). Seriile folosesc `stroke="var(--color-<key>)"`. |
| `ChartTooltip.tsx`    | Tooltip tematizat (Ocean), folosit prin `content={<ChartTooltip config labelFormatter valueFormatter />}`. Randeaza titlu + rand `pastila + label + valoare` per serie din config. Inactiv → null. |
| `ChartLegend.tsx`     | `<ChartLegend config />` — rand de `pastila + label` per serie. Folosit doar unde ajuta (trafic in/out), NU pe scor-trend (o singura serie). |

## Consumatori

- `NetworkTrafficChart.tsx` — config `{out: accent, in: teal}`; legenda + tooltip + arii cu `var(--color-*)`.
- `ScoreTrendChart.tsx` — config `{exposure_score: accent}`; gradient linie albastru→teal, benzi de severitate cu `var(--severity-*)`, tooltip cu data + scor.

## Teste

`ChartContainer.test.tsx` (1): randeaza copiii + seteaza `--color-<key>`.
`ChartTooltip.test.tsx` (2): inactiv → null; activ → titlu + randuri din config cu valoare formatata.

## Stilizare

Clase `.chart-tooltip*` + `.chart-legend*` in `index.css`, toate pe variabilele
temei → urmeaza automat light/dark si paleta Ocean.
