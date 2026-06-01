import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useNetworkTraffic } from "../hooks/useNetworkTraffic";

/** Grafic live al traficului de retea (KB/s iesit vs intrat) pe ultimele ~10 min.
 *  Polleaza la 10s (cadenta heartbeat). Datele vin din psutil.net_io_counters()
 *  = tot traficul care iese si intra din calculator. */
export function NetworkTrafficChart({ deviceUid }: { deviceUid: string }) {
  const series = useNetworkTraffic(deviceUid);

  if (series.length === 0) {
    return (
      <div className="empty-state">
        Niciun trafic inregistrat (agent offline sau fara activitate recenta).
      </div>
    );
  }

  const data = series.map((p, i) => ({
    i,
    out: p.sent_rate_kbps,
    in: p.recv_rate_kbps,
  }));
  const last = series[series.length - 1];

  return (
    <div>
      <div style={{ display: "flex", gap: 18, marginBottom: 8, fontSize: 13, flexWrap: "wrap" }}>
        <span style={{ color: "var(--accent)" }}>↑ {last.sent_rate_kbps.toFixed(1)} KB/s iesit</span>
        <span style={{ color: "var(--plum)" }}>↓ {last.recv_rate_kbps.toFixed(1)} KB/s intrat</span>
        <span style={{ color: "var(--text-secondary)" }}>{last.conn_count} conexiuni active</span>
      </div>
      <ResponsiveContainer width="100%" height={160}>
        <AreaChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
          <XAxis dataKey="i" hide />
          <YAxis width={42} tick={{ fontSize: 10 }} unit=" KB/s" />
          <Tooltip
            formatter={(value, name) =>
              [`${Number(value).toFixed(1)} KB/s`, name === "out" ? "Iesit" : "Intrat"]}
            labelFormatter={() => ""}
          />
          <Area type="monotone" dataKey="out" stroke="var(--accent)"
                fill="var(--accent)" fillOpacity={0.25} name="out" isAnimationActive={false} />
          <Area type="monotone" dataKey="in" stroke="var(--plum)"
                fill="var(--plum)" fillOpacity={0.15} name="in" isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
