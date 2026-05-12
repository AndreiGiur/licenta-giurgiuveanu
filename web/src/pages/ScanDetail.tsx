import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { getScan } from "../api/exposure";
import type { ScanDetailResponse, Finding } from "../api/types";
import Navbar from "../components/Navbar";

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

function getScoreClass(score: number): string {
  if (score >= 70) return "score-high";
  if (score >= 40) return "score-medium";
  if (score > 0)  return "score-low";
  return "score-none";
}

function formatDate(raw: string): string {
  try {
    return new Date(raw).toLocaleString("ro-RO", {
      day: "2-digit", month: "long", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch { return raw; }
}

function FindingDetailPanel({ finding }: { finding: Finding }) {
  return (
    <div className={`finding-detail ${finding.severity.toLowerCase()}`}>
      <div className="finding-detail-header">
        <span className={`severity-badge ${getSeverityClass(finding.severity)}`}>
          {finding.severity.toUpperCase()}
        </span>
        <h3 className="finding-detail-title">{finding.title}</h3>
        <span className="finding-detail-id">{finding.rule_id}</span>
      </div>

      <section className="finding-section">
        <h4>Recomandare</h4>
        <p>{finding.recommendation}</p>
      </section>

      {!!finding.evidence && typeof finding.evidence === "object" &&
        Object.keys(finding.evidence as object).length > 0 && (
        <section className="finding-section">
          <h4>Dovezi</h4>
          <pre className="finding-evidence">
            {JSON.stringify(finding.evidence, null, 2)}
          </pre>
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
          <div className="scan-detail-grid">
            <aside className="scan-detail-sidebar">
              <div className={`score-gauge ${getScoreClass(data.exposure_score)}`}>
                <div className="score-value">{data.exposure_score}</div>
                <div className="score-label">/ 100</div>
              </div>
              <div className="score-summary">
                <strong>{data.findings.length}</strong> vulnerabilități găsite
              </div>

              <nav className="category-nav">
                {categories.map(cat => {
                  const items = findingsByCategory[cat] ?? [];
                  const topSev = items[0]?.severity?.toLowerCase() ?? "info";
                  return (
                    <button
                      key={cat}
                      className={`category-item ${activeCategory === cat ? "active" : ""}`}
                      onClick={() => setActiveCategory(cat)}
                    >
                      <span className="category-icon">{CATEGORY_META[cat].icon}</span>
                      <span className="category-label">{CATEGORY_META[cat].label}</span>
                      <span className={`category-count severity-${topSev}`}>{items.length}</span>
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
          </div>
        )}
      </div>
    </div>
  );
}
