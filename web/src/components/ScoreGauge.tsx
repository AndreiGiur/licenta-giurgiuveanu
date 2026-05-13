import { useEffect, useState } from "react";
import { animate, motion, useMotionValue, useTransform } from "framer-motion";

type Props = {
  value: number;
  size?: number;
  strokeWidth?: number;
  label?: string;
};

export function ScoreGauge({ value, size = 160, strokeWidth = 12, label }: Props) {
  const count = useMotionValue(0);
  const [display, setDisplay] = useState(0);
  const dashLength = useTransform(count, [0, 100], [0, 1]);

  const radius = (size - strokeWidth) / 2;
  const cx = size / 2;
  const cy = size / 2;

  useEffect(() => {
    const controls = animate(count, value, {
      duration: 1.2,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (latest) => setDisplay(Math.round(latest)),
    });
    return controls.stop;
  }, [value, count]);

  const severity = value >= 70 ? "high" : value >= 40 ? "medium" : value > 0 ? "low" : "none";

  return (
    <div className={`score-gauge score-${severity}`} style={{ width: size, height: size, position: "relative" }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={cx} cy={cy} r={radius}
          fill="none"
          stroke="var(--border)"
          strokeWidth={strokeWidth}
        />
        <motion.circle
          cx={cx} cy={cy} r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          style={{ pathLength: dashLength }}
          transform={`rotate(-90 ${cx} ${cy})`}
        />
      </svg>
      <div className="score-gauge-center">
        <div className="score-gauge-value">{display}</div>
        <div className="score-gauge-label">{label ?? "/ 100"}</div>
      </div>
    </div>
  );
}
