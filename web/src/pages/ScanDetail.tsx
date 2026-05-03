import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { getScan } from "../api/exposure";
import type { ScanDetailResponse, Finding } from "../api/types";
import Navbar from "../components/Navbar";

function getSeverityClass(sev: string): string {
  switch (sev.toLowerCase()) {
    case "critical": return "severity-high";
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

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`finding-card ${finding.severity.toLowerCase()}`}>
      <div className="finding-header">
        <span className="finding-title">{finding.title}</span>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
          <span className={`severity-badge ${getSeverityClass(finding.severity)}`}>
            {finding.severity}
          </span>
          <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
            {finding.rule_id}
          </span>
        </div>
      </div>
      <div className="finding-rec">{finding.recommendation}</div>
      {!!finding.evidence && Object.keys(finding.evidence as object).length > 0 && (
        <div style={{ marginTop: 8 }}>
          <button
            onClick={() => setOpen(o => !o)}
            className="btn btn-ghost btn-sm"
            style={{ fontSize: 11, padding: "2px 8px", border: "1px solid var(--border)" }}
          >
            {open ? "▲ Ascunde dovezi" : "▼ Dovezi"}
          </button>
          {open && (
            <pre style={{
              marginTop: 8, padding: "10px 12px",
              background: "var(--bg-base)", borderRadius: 8,
              fontSize: 11, color: "var(--text-secondary)",
              overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word",
            }}>
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>
          )}
        </div>
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
  const [rawOpen, setRawOpen] = useState(false);

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

  const highCount     = data?.findings.filter(f => ["high","critical"].includes(f.severity.toLowerCase())).length ?? 0;
  const medCount      = data?.findings.filter(f => f.severity.toLowerCase() === "medium").length ?? 0;
  const lowCount      = data?.findings.filter(f => f.severity.toLowerCase() === "low").length    ?? 0;
  const payload       = data?.payload;

  return (
    <div className="page">
      <Navbar />

      <div className="container" style={{ paddingTop: 32, paddingBottom: 48 }}>
        {/* ── Header ── */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
          <div>
            <h1 className="page-title">Scan #{scanId}</h1>
            {data && (
              <p className="page-subtitle">
                Device: <span style={{ fontFamily: "'JetBrains Mono', monospace", color: "var(--accent)" }}>{data.device_uid}</span>
                {" · "}{formatDate(data.created_at)}
              </p>
            )}
          </div>
          <button
            onClick={() => navigate(data ? `/dashboard?device=${data.device_uid}` : "/dashboard")}
            className="btn btn-ghost"
            style={{ border: "1px solid var(--border)" }}
          >
            ← Înapoi
          </button>
        </div>

        {/* ── Loading ── */}
        {loading && (
          <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
            <span className="loading-dots"><span /><span /><span /></span>
          </div>
        )}

        {/* ── Error ── */}
        {error && (
          <div className="alert alert-error">
            <div className="alert-title">Eroare</div>
            <div style={{ fontSize: 12, marginTop: 2 }}>{error}</div>
          </div>
        )}

        {/* ── Content ── */}
        {data && (
          <>
            {/* Stats */}
            <div className="stat-grid">
              <div className="stat-card">
                <div className={`stat-value ${getScoreClass(data.exposure_score)}`}
                  style={{ background: "transparent", border: "none", padding: 0 }}>
                  {data.exposure_score}
                </div>
                <div className="stat-label">Exposure Score</div>
              </div>
              <div className="stat-card">
                <div className="stat-value" style={{ color: "var(--red)" }}>{highCount}</div>
                <div className="stat-label">High / Critical</div>
              </div>
              <div className="stat-card">
                <div className="stat-value" style={{ color: "var(--amber)" }}>{medCount}</div>
                <div className="stat-label">Medium</div>
              </div>
              <div className="stat-card">
                <div className="stat-value" style={{ color: "var(--green)" }}>{lowCount}</div>
                <div className="stat-label">Low</div>
              </div>
            </div>

            {/* Findings */}
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-header">
                <span className="card-title">Vulnerabilități detectate</span>
                <span className="card-badge">{data.findings.length} findings</span>
              </div>
              <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {data.findings.length === 0 && (
                  <div style={{ padding: "30px 0", textAlign: "center", color: "var(--green)", fontSize: 13 }}>
                    ✓ Nicio vulnerabilitate detectată
                  </div>
                )}
                {data.findings.map((f) => (
                  <FindingCard key={`${data.scan_id}-${f.rule_id}-${f.title}`} finding={f} />
                ))}
              </div>
            </div>

            {/* Date sistem colectate */}
            {payload && (
              <div className="card">
                <div className="card-header" style={{ cursor: "pointer" }} onClick={() => setRawOpen(o => !o)}>
                  <span className="card-title">Date sistem colectate</span>
                  <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{rawOpen ? "▲ Ascunde" : "▼ Afișează"}</span>
                </div>
                {rawOpen && (
                  <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 16 }}>

                    {/* OS Info */}
                    {payload.os && (
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>
                          Sistem de operare
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 8 }}>
                          {Object.entries(payload.os).map(([k, v]) => (
                            <div key={k} style={{ background: "var(--bg-elevated)", padding: "8px 12px", borderRadius: 8 }}>
                              <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 2 }}>{k}</div>
                              <div style={{ fontSize: 13, fontFamily: "'JetBrains Mono', monospace", color: String(v) === "true" ? "var(--red)" : "var(--text-primary)" }}>
                                {String(v)}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Porturi */}
                    {payload.network?.open_ports && payload.network.open_ports.length > 0 && (
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>
                          Porturi deschise ({payload.network.open_ports.length})
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                          {payload.network.open_ports.map(p => (
                            <span key={p} style={{
                              background: "var(--bg-elevated)", padding: "4px 10px",
                              borderRadius: 6, fontSize: 12,
                              fontFamily: "'JetBrains Mono', monospace",
                              color: [21,23,25,139,445,3389,5900,5985,5986].includes(p) ? "var(--red)" : "var(--text-primary)",
                              border: [21,23,25,139,445,3389,5900,5985,5986].includes(p) ? "1px solid var(--red)" : "1px solid var(--border)",
                            }}>
                              {p}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Procese */}
                    {payload.processes && payload.processes.length > 0 && (
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>
                          Procese active (top {payload.processes.length} după memorie)
                        </div>
                        <div style={{ overflowX: "auto" }}>
                          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                            <thead>
                              <tr style={{ color: "var(--text-muted)", borderBottom: "1px solid var(--border)" }}>
                                <th style={{ textAlign: "left", padding: "6px 8px" }}>PID</th>
                                <th style={{ textAlign: "left", padding: "6px 8px" }}>Nume</th>
                                <th style={{ textAlign: "right", padding: "6px 8px" }}>Memorie (MB)</th>
                                <th style={{ textAlign: "left", padding: "6px 8px" }}>Utilizator</th>
                              </tr>
                            </thead>
                            <tbody>
                              {payload.processes.map((p, i) => (
                                <tr key={i} style={{ borderBottom: "1px solid var(--border-subtle, #222)" }}>
                                  <td style={{ padding: "5px 8px", fontFamily: "'JetBrains Mono', monospace", color: "var(--text-muted)" }}>{p.pid}</td>
                                  <td style={{ padding: "5px 8px", fontFamily: "'JetBrains Mono', monospace" }}>{p.name}</td>
                                  <td style={{ padding: "5px 8px", textAlign: "right", color: "var(--text-secondary)" }}>{p.memory_mb}</td>
                                  <td style={{ padding: "5px 8px", color: "var(--text-muted)", fontSize: 11 }}>{p.username ?? ""}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {/* Software instalat */}
                    {payload.software && payload.software.length > 0 && (
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>
                          Software instalat ({payload.software.length} programe)
                        </div>
                        <div style={{ overflowX: "auto", maxHeight: 300, overflowY: "auto" }}>
                          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                            <thead>
                              <tr style={{ color: "var(--text-muted)", borderBottom: "1px solid var(--border)" }}>
                                <th style={{ textAlign: "left", padding: "6px 8px" }}>Aplicație</th>
                                <th style={{ textAlign: "left", padding: "6px 8px" }}>Versiune</th>
                              </tr>
                            </thead>
                            <tbody>
                              {payload.software.map((s, i) => (
                                <tr key={i} style={{ borderBottom: "1px solid var(--border-subtle, #222)" }}>
                                  <td style={{ padding: "5px 8px" }}>{s.name}</td>
                                  <td style={{ padding: "5px 8px", fontFamily: "'JetBrains Mono', monospace", color: "var(--text-muted)" }}>{s.version ?? "—"}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
