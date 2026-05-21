import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { getScanDiff } from "../api/exposure";
import type { ScanDiff as ScanDiffData, ScanDiffFinding } from "../api/types";


function sevClass(s: string): string {
  switch (s.toLowerCase()) {
    case "critical": return "diff-sev-critical";
    case "high":     return "diff-sev-high";
    case "medium":   return "diff-sev-medium";
    case "low":      return "diff-sev-low";
    default:         return "diff-sev-info";
  }
}


function FindingRow({ f, kind }: { f: ScanDiffFinding; kind: "added" | "fixed" | "unchanged" }) {
  return (
    <div className={`diff-row diff-row-${kind}`}>
      <span className={`diff-sev-dot ${sevClass(f.severity)}`} />
      <span className="diff-rule-id">{f.rule_id}</span>
      <span className="diff-title">{f.title}</span>
    </div>
  );
}


interface Props {
  scanId: number;
  previousId?: number;
}

export function ScanDiff({ scanId, previousId }: Props) {
  const [data, setData] = useState<ScanDiffData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    getScanDiff(scanId, previousId)
      .then(d => { if (!cancelled) setData(d); })
      .catch(e => {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Eroare");
        }
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [scanId, previousId]);

  if (loading) return <div className="diff-empty">Se calculeaza diferentele...</div>;
  if (error) return <div className="diff-empty diff-error">{error}</div>;
  if (!data) return null;

  const deltaClass = data.delta < 0 ? "diff-delta-improved" : data.delta > 0 ? "diff-delta-regressed" : "diff-delta-same";
  const deltaIcon = data.delta < 0 ? "↓" : data.delta > 0 ? "↑" : "=";
  const deltaText = data.delta < 0
    ? `Scor scazut cu ${Math.abs(data.delta)} puncte (imbunatatire)`
    : data.delta > 0
      ? `Scor crescut cu ${data.delta} puncte (regresie)`
      : "Scor neschimbat";

  return (
    <motion.div
      className="scan-diff"
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div className="diff-header">
        <div>
          <div className="diff-comparison">
            Scan #{data.from_scan_id} ({data.from_score}/100) → Scan #{data.to_scan_id} ({data.to_score}/100)
          </div>
          <div className={`diff-delta ${deltaClass}`}>
            <span className="diff-delta-icon">{deltaIcon}</span>
            <span>{deltaText}</span>
          </div>
        </div>
      </div>

      <div className="diff-columns">
        <div className="diff-column">
          <div className="diff-column-title diff-added-title">
            <span>Adaugate</span>
            <span className="diff-count">{data.added.length}</span>
          </div>
          {data.added.length === 0
            ? <div className="diff-empty-col">Nicio vulnerabilitate noua.</div>
            : data.added.map(f => <FindingRow key={`a-${f.rule_id}`} f={f} kind="added" />)
          }
        </div>

        <div className="diff-column">
          <div className="diff-column-title diff-fixed-title">
            <span>Rezolvate</span>
            <span className="diff-count">{data.fixed.length}</span>
          </div>
          {data.fixed.length === 0
            ? <div className="diff-empty-col">Nicio rezolvare.</div>
            : data.fixed.map(f => <FindingRow key={`f-${f.rule_id}`} f={f} kind="fixed" />)
          }
        </div>

        <div className="diff-column">
          <div className="diff-column-title diff-unchanged-title">
            <span>Nemodificate</span>
            <span className="diff-count">{data.unchanged.length}</span>
          </div>
          {data.unchanged.length === 0
            ? <div className="diff-empty-col">—</div>
            : data.unchanged.map(f => <FindingRow key={`u-${f.rule_id}`} f={f} kind="unchanged" />)
          }
        </div>
      </div>
    </motion.div>
  );
}
