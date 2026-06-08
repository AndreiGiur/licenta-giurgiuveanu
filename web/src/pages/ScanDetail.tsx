import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { motion } from "framer-motion";
import { getScan, getScanPdfUrl } from "../api/exposure";
import type { ScanDetailResponse, Finding } from "../api/types";
import Navbar from "../components/Navbar";
import { ScoreGauge } from "../components/ScoreGauge";
import { ScoreBreakdownBars } from "../components/ScoreBreakdownBars";
import { ScanDiff } from "../components/ScanDiff";
import NmapSection from "../components/NmapSection";
import { InfoTip } from "../components/InfoTip";

type Category = "persistence" | "network" | "system" | "software" | "processes" | "forensics";

const CATEGORY_META: Record<Category, { label: string; icon: string }> = {
  persistence: { label: "Persistență", icon: "🔒" },
  network:     { label: "Rețea", icon: "🌐" },
  system:      { label: "Sistem & OS", icon: "🖥️" },
  software:    { label: "Software", icon: "📦" },
  processes:   { label: "Procese & Servicii", icon: "⚙️" },
  forensics:   { label: "Event Log & Forensics", icon: "📋" },
};

const RULE_CATEGORY: Record<string, Category> = {
  "NET-OPEN-PORTS-1":   "network",
  "NET-MANY-PORTS-2":   "network",
  "NET-SHARE-1":        "network",
  "NET-ESTABLISHED-1":  "network",
  "OS-ADMIN-1":         "system",
  "OS-EOL-1":           "system",
  "FW-DISABLED-1":      "system",
  "USER-ADMIN-1":       "system",
  "PS-POLICY-1":        "system",
  "AV-DISABLED-1":      "system",
  "BITLOCKER-OFF-1":    "system",
  "SW-VULNERABLE-1":    "software",
  "PROC-SUSPICIOUS-1":  "processes",
  "PROC-POWERSHELL-2":  "processes",
  "SVC-SUSPICIOUS-1":   "processes",
  "STARTUP-SUSPICIOUS-1": "persistence",
  "TASK-SUSPICIOUS-1":    "persistence",
  "REG-HIJACK-1":         "persistence",
  "WMI-PERSIST-1":        "persistence",
  "EVENTLOG-BRUTEFORCE-1": "forensics",
  "EVENTLOG-PRIVESC-1":    "forensics",
  "HOSTS-TAMPERED-1":      "forensics",
  "CERT-UNTRUSTED-1":      "forensics",
};

function categoryOf(ruleId: string): Category {
  return RULE_CATEGORY[ruleId] ?? "system";
}


function ScanDiffSection({ scanId }: { scanId: number }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ marginTop: 12 }}>
      <button
        className="btn btn-ghost btn-sm"
        onClick={() => setOpen(o => !o)}
        style={{ border: "1px solid var(--border)" }}
      >
        {open ? "▾ Ascunde comparatie" : "▸ Compara cu scanarea anterioara"}
      </button>
      {open && <ScanDiff scanId={scanId} />}
    </div>
  );
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
};

function getSeverityClass(sev: string): string {
  switch (sev.toLowerCase()) {
    case "critical": return "severity-critical";
    case "high":     return "severity-high";
    case "medium":   return "severity-medium";
    case "low":      return "severity-low";
    default:         return "severity-info";
  }
}

function formatDate(raw: string): string {
  try {
    return new Date(raw).toLocaleString("ro-RO", {
      day: "2-digit", month: "long", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch { return raw; }
}

function formatLabel(key: string): string {
  // Capitalize si inlocuieste _ cu spatii pentru o cheie tehnica.
  if (!key) return "";
  const cleaned = key.replace(/_/g, " ");
  return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
}

function renderEvidenceValue(value: unknown): ReactNode {
  // Primitive (string, number, bool) → afisate direct.
  if (value === null || value === undefined) {
    return <span className="ev-null">—</span>;
  }
  if (typeof value === "string") return <span className="ev-string">{value}</span>;
  if (typeof value === "number") return <span className="ev-number">{value}</span>;
  if (typeof value === "boolean") {
    return <span className={value ? "ev-true" : "ev-false"}>{value ? "da" : "nu"}</span>;
  }
  // Arrays → lista cu chips daca primitive, sau lista de carduri daca obiecte.
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="ev-null">—</span>;
    if (value.every(v => typeof v === "string" || typeof v === "number")) {
      return (
        <div className="ev-chips">
          {value.map((v, i) => <span key={i} className="ev-chip">{String(v)}</span>)}
        </div>
      );
    }
    return (
      <div className="ev-list">
        {value.map((v, i) => (
          <div key={i} className="ev-list-item">{renderEvidenceValue(v)}</div>
        ))}
      </div>
    );
  }
  // Obiect → grid key-value recursiv.
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return <span className="ev-null">—</span>;
    return (
      <div className="ev-object">
        {entries.map(([k, v]) => (
          <div key={k} className="ev-kv">
            <span className="ev-key">{formatLabel(k)}</span>
            <span className="ev-val">{renderEvidenceValue(v)}</span>
          </div>
        ))}
      </div>
    );
  }
  return <span className="ev-string">{String(value)}</span>;
}


function EvidenceView({ evidence }: { evidence: unknown }) {
  if (evidence === null || evidence === undefined) return null;
  if (typeof evidence !== "object") return <div>{String(evidence)}</div>;
  return <div className="finding-evidence-tree">{renderEvidenceValue(evidence)}</div>;
}


function FindingDetailPanel({ finding }: { finding: Finding }) {
  const compliance = finding.compliance ?? [];
  const cisRefs = compliance.filter(c => c.startsWith("CIS-"));
  const nistRefs = compliance.filter(c => c.startsWith("NIST-"));

  return (
    <div className={`finding-detail ${finding.severity.toLowerCase()}`}>
      <div className="finding-detail-header">
        <span className={`severity-badge ${getSeverityClass(finding.severity)}`}>
          {finding.severity.toUpperCase()}
        </span>
        <InfoTip topic="severity" />
        <h3 className="finding-detail-title">{finding.title}</h3>
        <span className="finding-detail-id">{finding.rule_id}</span>
        <InfoTip topic="rule-id" size={14} />
      </div>

      {compliance.length > 0 && (
        <div className="finding-compliance">
          <InfoTip topic="compliance" size={14} />
          {cisRefs.map(ref => (
            <span key={ref} className="compliance-chip compliance-cis" title="CIS Controls v8">
              {ref}
            </span>
          ))}
          {nistRefs.map(ref => (
            <span key={ref} className="compliance-chip compliance-nist" title="NIST CSF 2.0">
              {ref}
            </span>
          ))}
        </div>
      )}

      <section className="finding-section">
        <h4>Recomandare<InfoTip topic="recommendation" size={14} /></h4>
        <p>{finding.recommendation}</p>
      </section>

      {!!finding.evidence && typeof finding.evidence === "object" &&
        Object.keys(finding.evidence as object).length > 0 && (
        <section className="finding-section">
          <h4>Dovezi<InfoTip topic="finding-evidence" size={14} /></h4>
          <EvidenceView evidence={finding.evidence} />
        </section>
      )}
    </div>
  );
}

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

  const [data, setData] = useState<ScanDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeCategory, setActiveCategory] = useState<Category | null>(null);
  const [selectedFindingIdx, setSelectedFindingIdx] = useState(0);

  useEffect(() => {
    const id = Number(scanId);
    if (!Number.isInteger(id)) {
      setError("ID scan invalid");
      setLoading(false);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await getScan(id);
        if (!cancelled) setData(res);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Eroare la încărcare");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [scanId]);

  const findingsByCategory = useMemo(() => {
    if (!data) return {} as Record<Category, Finding[]>;
    const out: Partial<Record<Category, Finding[]>> = {};
    for (const f of data.findings) {
      const cat = categoryOf(f.rule_id);
      (out[cat] ??= []).push(f);
    }
    for (const cat of Object.keys(out) as Category[]) {
      out[cat]!.sort((a, b) =>
        (SEVERITY_RANK[b.severity.toLowerCase()] ?? 0) -
        (SEVERITY_RANK[a.severity.toLowerCase()] ?? 0)
      );
    }
    return out as Record<Category, Finding[]>;
  }, [data]);

  const categories = useMemo(() => {
    return (Object.keys(CATEGORY_META) as Category[])
      .filter(c => (findingsByCategory[c]?.length ?? 0) > 0);
  }, [findingsByCategory]);

  useEffect(() => {
    if (!activeCategory && categories.length > 0) {
      setActiveCategory(categories[0]);
    }
  }, [categories, activeCategory]);

  useEffect(() => {
    setSelectedFindingIdx(0);
  }, [activeCategory]);

  const activeFindings = activeCategory ? (findingsByCategory[activeCategory] ?? []) : [];
  const selectedFinding = activeFindings[selectedFindingIdx];

  const scanType = data?.scan_type ?? "standard";

  return (
    <div className="page">
      <Navbar />

      <div className="container scan-detail-page">
        <header className="scan-detail-topbar">
          <button onClick={() => navigate(-1)} className="btn btn-ghost"
                  style={{ border: "1px solid var(--border)" }}>← Înapoi</button>
          {data && (
            <div className="scan-detail-meta">
              <h1>{data.device_name}</h1>
              <span className={`scan-type-badge ${scanType}`}>{scanType.toUpperCase()}</span>
              <span className="scan-date">{formatDate(data.created_at)}</span>
            </div>
          )}
          {data && (
            <a
              href={getScanPdfUrl(data.scan_id)}
              target="_blank"
              rel="noreferrer"
              className="btn btn-accent btn-sm"
              style={{ textDecoration: "none", marginLeft: "auto" }}
              title="Descarca raport PDF"
            >
              ↓ Export PDF
            </a>
          )}
        </header>

        {loading && (
          <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
            <span className="loading-dots"><span /><span /><span /></span>
          </div>
        )}

        {error && (
          <div className="alert alert-error">
            <div className="alert-title">Eroare</div>
            <div style={{ fontSize: 12, marginTop: 2 }}>{error}</div>
          </div>
        )}

        {data && (
          <ScanDiffSection scanId={data.scan_id} />
        )}

        {data && (
          <motion.div
            className="scan-detail-grid"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
          >
            <aside className="scan-detail-sidebar">
              <ScoreGauge value={data.exposure_score} size={160} />
              <div className="score-summary">
                <span>Scor de expunere</span><InfoTip topic="exposure-score" size={14} />
              </div>
              <div className="score-summary">
                <strong>{data.findings.length}</strong> vulnerabilități găsite
                <InfoTip topic="findings-count" size={14} />
              </div>
              {data.score_breakdown && (
                <ScoreBreakdownBars breakdown={data.score_breakdown} compact />
              )}

              {categories.length > 0 && (
                <div className="score-summary" style={{ marginTop: 4 }}>
                  <span>Categorii</span><InfoTip topic="category-nav" size={14} />
                </div>
              )}
              <nav className="category-nav">
                {categories.map(cat => {
                  const items = findingsByCategory[cat] ?? [];
                  const topSev = items[0]?.severity?.toLowerCase() ?? "info";
                  const isActive = activeCategory === cat;
                  return (
                    <button
                      key={cat}
                      className={`category-item ${isActive ? "active" : ""}`}
                      onClick={() => setActiveCategory(cat)}
                      style={{ position: "relative" }}
                    >
                      {isActive && (
                        <motion.div
                          layoutId="category-indicator"
                          className="category-indicator"
                          transition={{ type: "spring", stiffness: 350, damping: 30 }}
                        />
                      )}
                      <span className="category-icon" style={{ position: "relative" }}>{CATEGORY_META[cat].icon}</span>
                      <span className="category-label" style={{ position: "relative" }}>{CATEGORY_META[cat].label}</span>
                      <span className={`category-count severity-${topSev}`} style={{ position: "relative" }}>{items.length}</span>
                    </button>
                  );
                })}
                {categories.length === 0 && (
                  <div className="no-findings">✓ Nicio vulnerabilitate detectată</div>
                )}
              </nav>
            </aside>

            <main className="scan-detail-main">
              {activeCategory && activeFindings.length > 0 ? (
                <>
                  <div className="finding-list">
                    {activeFindings.map((f, i) => (
                      <button
                        key={`${f.rule_id}-${i}`}
                        className={`finding-list-item ${i === selectedFindingIdx ? "active" : ""}`}
                        onClick={() => setSelectedFindingIdx(i)}
                      >
                        <span className={`severity-dot severity-${f.severity.toLowerCase()}`}></span>
                        <span className="finding-list-title">{f.title}</span>
                      </button>
                    ))}
                  </div>
                  {selectedFinding && <FindingDetailPanel finding={selectedFinding} />}
                </>
              ) : (
                <div className="empty-state" style={{ padding: 48, textAlign: "center", color: "var(--text-muted)" }}>
                  {categories.length === 0
                    ? "Scanare curată — nicio vulnerabilitate detectată."
                    : "Selectează o categorie din stânga pentru a vedea detaliile."}
                </div>
              )}
            </main>
          </motion.div>
        )}

        {data?.payload?.nmap && (
          <NmapSection nmap={data.payload.nmap} />
        )}
      </div>
    </div>
  );
}
