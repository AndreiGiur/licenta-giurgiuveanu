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

/** Grafic live al traficului de retea (KB/s iesit vs intrat) pe ultimele ~10 min.
 *  Polleaza la 10s. Datele = psutil.net_io_counters() = tot traficul masinii. */
export function NetworkTrafficChart({ deviceUid }: { deviceUid: string }) {
  const series = useNetworkTraffic(deviceUid);

  if (series.length === 0) {
    return (
      <div className="empty-state">
        Niciun trafic inregistrat (agent offline sau fara activitate recenta).
      </div>
    );
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
            valueFormatter={(v) => `${Number(v).toFixed(1)} KB/s`}
            labelFormatter={() => "Trafic"} />} />
          <Area type="monotone" dataKey="out" stroke="var(--color-out)"
                fill="var(--color-out)" fillOpacity={0.25} isAnimationActive={false} />
          <Area type="monotone" dataKey="in" stroke="var(--color-in)"
                fill="var(--color-in)" fillOpacity={0.18} isAnimationActive={false} />
        </AreaChart>
      </ChartContainer>
    </div>
  );
}
