import { useEffect, useState } from "react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  ReferenceArea, ReferenceLine,
} from "recharts";
import { apiGet } from "../api/http";

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

function formatDateShort(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("ro-RO", { day: "2-digit", month: "short" });
  } catch { return iso; }
}

function CustomTooltip({ active, payload }: { active?: boolean; payload?: { payload: TrendPoint }[] }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div style={{
      background: "var(--bg-elevated)",
      border: "1px solid var(--border)",
      borderRadius: 8,
      padding: "10px 14px",
      boxShadow: "0 4px 12px rgba(45, 27, 61, 0.15)",
      fontSize: 13,
    }}>
      <div style={{ fontWeight: 600, color: "var(--text-primary)" }}>
        {new Date(p.created_at).toLocaleString("ro-RO")}
      </div>
      <div style={{ marginTop: 4 }}>
        <span style={{ color: "var(--text-muted)" }}>Scor: </span>
        <span style={{ fontWeight: 700, color: "var(--accent-strong)" }}>{p.exposure_score}/100</span>
      </div>
      <div>
        <span style={{ color: "var(--text-muted)" }}>Tip: </span>
        <span style={{ fontFamily: "var(--font-mono)" }}>{p.scan_type}</span>
      </div>
    </div>
  );
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
    <div className="score-trend-chart" style={{ width: "100%", height }}>
      <ResponsiveContainer>
        <LineChart data={chartData} margin={{ top: 12, right: 16, left: 0, bottom: 4 }}>
          <defs>
            <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#b8456e" stopOpacity={0.95} />
              <stop offset="50%" stopColor="#f4c95d" stopOpacity={0.85} />
              <stop offset="100%" stopColor="#a8639a" stopOpacity={0.7} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
          <XAxis
            dataKey="dateLabel"
            tick={{ fontSize: 11, fill: "var(--text-muted)" }}
            axisLine={{ stroke: "var(--border)" }}
            tickLine={false}
          />
          <YAxis
            domain={[0, 100]}
            ticks={[0, 25, 50, 75, 100]}
            tick={{ fontSize: 11, fill: "var(--text-muted)" }}
            axisLine={{ stroke: "var(--border)" }}
            tickLine={false}
          />
          {/* Benzi colorate fundal pentru zone de severitate. */}
          <ReferenceArea y1={0} y2={25} fill="#a8639a" fillOpacity={0.06} />
          <ReferenceArea y1={25} y2={50} fill="#f4c95d" fillOpacity={0.08} />
          <ReferenceArea y1={50} y2={75} fill="#b8456e" fillOpacity={0.08} />
          <ReferenceArea y1={75} y2={100} fill="#5a2d6e" fillOpacity={0.12} />
          <ReferenceLine y={50} stroke="var(--text-muted)" strokeDasharray="2 4" strokeOpacity={0.4} />
          <Tooltip content={<CustomTooltip />} />
          <Line
            type="monotone"
            dataKey="exposure_score"
            stroke="url(#scoreGradient)"
            strokeWidth={3}
            dot={{ r: 4, fill: "var(--accent-strong)", strokeWidth: 0 }}
            activeDot={{ r: 6, fill: "var(--accent-strong)" }}
            isAnimationActive={true}
            animationDuration={900}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
