import type { CSSProperties, ReactElement } from "react";
import { ResponsiveContainer } from "recharts";
import type { ChartConfig } from "./chart";
import { chartColorVars } from "./chart";

type Props = {
  config: ChartConfig;
  height?: number;
  className?: string;
  children: ReactElement;
};

/** Wrapper responsiv peste Recharts care injecteaza culorile config-ului ca
 *  CSS variables `--color-<key>` pe container (spirit shadcn, fara Tailwind). */
export function ChartContainer({ config, height = 240, className = "", children }: Props) {
  return (
    <div
      className={`chart-container ${className}`.trim()}
      style={{ width: "100%", height, ...chartColorVars(config) } as CSSProperties}
    >
      <ResponsiveContainer width="100%" height="100%">
        {children}
      </ResponsiveContainer>
    </div>
  );
}
