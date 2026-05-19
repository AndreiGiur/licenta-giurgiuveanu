import { motion } from "framer-motion";
import type { ScoreBreakdown } from "../api/types";
import { SCORE_CATEGORIES } from "../api/types";

interface Props {
  breakdown: ScoreBreakdown;
  compact?: boolean;
}

function severityColor(score: number): string {
  if (score >= 75) return "var(--score-critical, #5a2d6e)";
  if (score >= 50) return "var(--score-high, #b8456e)";
  if (score >= 25) return "var(--score-medium, #f4c95d)";
  if (score > 0)   return "var(--score-low, #a8639a)";
  return "var(--border, #f0e4cc)";
}

export function ScoreBreakdownBars({ breakdown, compact = false }: Props) {
  return (
    <div className={`score-breakdown ${compact ? "score-breakdown-compact" : ""}`}>
      {SCORE_CATEGORIES.map(({ key, label, weight }) => {
        const value = breakdown[key];
        return (
          <div key={key} className="score-breakdown-row">
            <div className="score-breakdown-label">
              <span className="score-breakdown-name">{label}</span>
              <span className="score-breakdown-weight">{Math.round(weight * 100)}%</span>
            </div>
            <div className="score-breakdown-track">
              <motion.div
                className="score-breakdown-fill"
                initial={{ width: 0 }}
                animate={{ width: `${value}%` }}
                transition={{ duration: 0.9, ease: "easeOut" }}
                style={{ background: severityColor(value) }}
              />
            </div>
            <div className="score-breakdown-value">{value}</div>
          </div>
        );
      })}
    </div>
  );
}
