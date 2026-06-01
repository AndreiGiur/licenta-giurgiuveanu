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

/** Tooltip tematizat (Ocean), folosit prin `content={<ChartTooltip config=... />}`.
 *  Randeaza un titlu + un rand `pastila + label + valoare` per serie din config. */
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
        const val = valueFormatter
          ? valueFormatter(item.value as number, key)
          : String(item.value);
        return (
          <div key={key} className="chart-tooltip-row">
            <span className="chart-tooltip-dot"
                  style={{ background: `var(--color-${key}, ${series.color})` }} />
            <span className="chart-tooltip-label">{series.label}</span>
            <span className="chart-tooltip-value">{val}</span>
          </div>
        );
      })}
    </div>
  );
}
