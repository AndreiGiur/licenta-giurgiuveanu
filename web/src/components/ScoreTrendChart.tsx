import { useEffect, useState } from "react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ReferenceArea, ReferenceLine,
} from "recharts";
import { apiGet } from "../api/http";
import { ChartContainer } from "./chart/ChartContainer";
import { ChartTooltip } from "./chart/ChartTooltip";
import { axisDefaults, type ChartConfig } from "./chart/chart";

interface TrendPoint {
  scan_id: number;
  created_at: string;
  exposure_score: number;
  scan_type: string;
}

interface Props {
  deviceUid: string;
  days?: number;
  height?: number;
}

const CONFIG: ChartConfig = {
  exposure_score: { label: "Scor expunere", color: "var(--accent)" },
};

function formatDateShort(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("ro-RO", { day: "2-digit", month: "short" });
  } catch { return iso; }
}

export function ScoreTrendChart({ deviceUid, days = 30, height = 260 }: Props) {
  const [data, setData] = useState<TrendPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    apiGet<TrendPoint[]>(`/devices/${encodeURIComponent(deviceUid)}/score-trend?days=${days}`)
      .then(d => { if (!cancelled) setData(d); })
      .catch(e => { if (!cancelled) setError(e instanceof Error ? e.message : "Eroare"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [deviceUid, days]);

  if (loading) {
    return <div className="score-trend-empty">Se incarca graficul...</div>;
  }
  if (error) {
    return <div className="score-trend-empty score-trend-error">Eroare: {error}</div>;
  }
  if (data.length === 0) {
    return (
      <div className="score-trend-empty">
        Nu exista scanari in ultimele {days} zile.
      </div>
    );
  }

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
        {/* Benzi colorate de fundal pentru zonele de severitate. */}
        <ReferenceArea y1={0} y2={25} fill="var(--severity-low)" fillOpacity={0.06} />
        <ReferenceArea y1={25} y2={50} fill="var(--severity-medium)" fillOpacity={0.08} />
        <ReferenceArea y1={50} y2={75} fill="var(--severity-high)" fillOpacity={0.08} />
        <ReferenceArea y1={75} y2={100} fill="var(--severity-critical)" fillOpacity={0.10} />
        <ReferenceLine y={50} stroke="var(--text-muted)" strokeDasharray="2 4" strokeOpacity={0.4} />
        <Tooltip content={<ChartTooltip config={CONFIG}
          labelFormatter={(_label, p) => {
            const pt = (p[0]?.payload ?? {}) as TrendPoint;
            return new Date(pt.created_at).toLocaleString("ro-RO");
          }}
          valueFormatter={(v) => `${v}/100`} />} />
        <Line
          type="monotone"
          dataKey="exposure_score"
          stroke="url(#scoreGradient)"
          strokeWidth={3}
          dot={{ r: 4, fill: "var(--accent)", strokeWidth: 0 }}
          activeDot={{ r: 6, fill: "var(--accent)" }}
          isAnimationActive={true}
          animationDuration={900}
        />
      </LineChart>
    </ChartContainer>
  );
}
