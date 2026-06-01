import type { ChartConfig } from "./chart";

/** Legenda tematizata (pastila + label per serie). Folosita doar unde ajuta. */
export function ChartLegend({ config }: { config: ChartConfig }) {
  return (
    <div className="chart-legend">
      {Object.entries(config).map(([key, s]) => (
        <span key={key} className="chart-legend-item">
          <span className="chart-legend-dot"
                style={{ background: `var(--color-${key}, ${s.color})` }} />
          {s.label}
        </span>
      ))}
    </div>
  );
}
