export type ChartSeries = { label: string; color: string };
export type ChartConfig = Record<string, ChartSeries>;

/** Props comune pentru axe + grid — folosesc variabilele temei (Ocean). */
export const axisDefaults = {
  tick: { fontSize: 11, fill: "var(--text-muted)" },
  axisLine: { stroke: "var(--border)" },
  tickLine: false as const,
};

/** CSS variables `--color-<key>` derivate din config, pentru containerul de chart. */
export function chartColorVars(config: ChartConfig): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, s] of Object.entries(config)) {
    out[`--color-${key}`] = s.color;
  }
  return out;
}
