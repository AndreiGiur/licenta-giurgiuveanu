import { useEffect, useMemo, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { getScan, listDeviceScans } from "../api/exposure";
import type { DeviceScanListItem, ScanDetailResponse } from "../api/types";
import Navbar from "../components/Navbar";

/* ── helpers ── */
function getScoreClass(score: number): string {
  if (score >= 70) return "score-high";
  if (score >= 40) return "score-medium";
  if (score > 0)  return "score-low";
  return "score-none";
}

function getSeverityClass(sev: string): string {
  switch (sev.toLowerCase()) {
    case "high":   return "severity-high";
    case "medium": return "severity-medium";
    case "low":    return "severity-low";
    default:       return "severity-info";
  }
}

function formatDate(raw: string): string {
  try {
    return new Date(raw).toLocaleString("ro-RO", {
      day: "2-digit", month: "short", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return raw;
  }
}

const SearchIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
  </svg>
);

export default function Dashboard() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [deviceId, setDeviceId] = useState(() => searchParams.get("device") ?? "");
  const [loading, setLoading] = useState(false);
  const [scans, setScans] = useState<DeviceScanListItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [detail, setDetail] = useState<ScanDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canLoad = useMemo(() => deviceId.trim().length > 0, [deviceId]);

  // Auto-load cand se vine cu ?device= din pagina Devices
  useEffect(() => {
    const fromUrl = searchParams.get("device");
    if (fromUrl) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function load() {
    setError(null);
    setLoading(true);
    setDetail(null);
    setSelectedScanId(null);
    try {
      const items = await listDeviceScans(deviceId.trim());
      setScans(items);
      if (items.length > 0) setSelectedScanId(items[0].scan_id);
    } catch (e) {
      setScans([]);
      setError(e instanceof Error ? e.message : "Eroare necunoscută");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!selectedScanId) return;
    let cancel = false;
    (async () => {
      try {
        const d = await getScan(selectedScanId);
        if (!cancel) setDetail(d);
      } catch (e) {
        if (!cancel) setError(e instanceof Error ? e.message : "Eroare necunoscută");
      }
    })();
    return () => { cancel = true; };
  }, [selectedScanId]);

  const highCount   = detail?.findings.filter(f => f.severity.toLowerCase() === "high").length   ?? 0;
  const medCount    = detail?.findings.filter(f => f.severity.toLowerCase() === "medium").length ?? 0;
  const lowCount    = detail?.findings.filter(f => f.severity.toLowerCase() === "low").length    ?? 0;

  return (
    <div className="page">
      <Navbar />

      <div className="container" style={{ paddingTop: 32, paddingBottom: 48 }}>
        {/* ── Page header ── */}
        <div className="page-header">
          <h1 className="page-title">Security Dashboard</h1>
          <p className="page-subtitle">Monitorizează expunerile de securitate ale dispozitivelor tale</p>
        </div>

        {/* ── Search bar ── */}
        <div style={{ display: "flex", gap: 10, marginBottom: 24 }}>
          <div style={{ position: "relative", flex: 1 }}>
            <span style={{
              position: "absolute", left: 13, top: "50%",
              transform: "translateY(-50%)", color: "var(--text-muted)",
              display: "flex", pointerEvents: "none",
            }}>
              <SearchIcon />
            </span>
            <input
              className="form-input"
              value={deviceId}
              onChange={(e) => setDeviceId(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && canLoad && !loading && load()}
              placeholder="ID dispozitiv (ex: Utilizator 1)"
              style={{ paddingLeft: 36 }}
            />
          </div>
          <button
            disabled={!canLoad || loading}
            onClick={load}
            className="btn btn-accent"
            style={{ flexShrink: 0 }}
          >
            {loading
              ? <span className="loading-dots"><span /><span /><span /></span>
              : "Caută scanări"}
          </button>
        </div>

        {/* ── Error ── */}
        {error && (
          <div className="alert alert-error" style={{ marginBottom: 20 }}>
            <div className="alert-title">Eroare</div>
            <div style={{ fontSize: 12, marginTop: 2, whiteSpace: "pre-wrap" }}>{error}</div>
          </div>
        )}

        {/* ── Stats row ── */}
        {detail && (
          <div className="stat-grid">
            <div className="stat-card">
              <div className={`stat-value ${getScoreClass(detail.exposure_score)}`}
                style={{ background: "transparent", border: "none", padding: 0 }}>
                {detail.exposure_score}
              </div>
              <div className="stat-label">Exposure Score</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: "var(--red)" }}>{highCount}</div>
              <div className="stat-label">High</div>
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
        )}

        {/* ── Main grid ── */}
        <div style={{ display: "grid", gridTemplateColumns: "280px 1fr", gap: 16, alignItems: "start" }}
          className="dashboard-grid">

          {/* Scan list */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Scanări</span>
              <span className="card-badge">{scans.length}</span>
            </div>
            <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {scans.length === 0 && (
                <div className="empty-state">
                  Nicio scanare găsită.<br />
                  <span style={{ fontSize: 12 }}>Caută un dispozitiv mai sus.</span>
                </div>
              )}
              {scans.map((s) => (
                <div
                  key={s.scan_id}
                  onClick={() => setSelectedScanId(s.scan_id)}
                  className={`scan-item ${selectedScanId === s.scan_id ? "active" : ""}`}
                >
                  <div className="scan-item-row">
                    <span className="scan-id">#{s.scan_id}</span>
                    <span className={`score-badge ${getScoreClass(s.exposure_score)}`}>
                      {s.exposure_score}
                    </span>
                  </div>
                  <div className="scan-date">{formatDate(s.created_at)}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Findings detail */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Detalii Scanare</span>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                {detail && (
                  <span className="card-badge">{detail.findings.length} findings</span>
                )}
                {detail && (
                  <button
                    onClick={() => navigate(`/scans/${detail.scan_id}`)}
                    className="btn btn-ghost btn-sm"
                    style={{ fontSize: 11, border: "1px solid var(--border)" }}
                  >
                    Detalii complete →
                  </button>
                )}
              </div>
            </div>
            <div className="card-body">
              {!detail && (
                <div className="empty-state">
                  Selectează o scanare din lista din stânga.
                </div>
              )}

              {detail && (
                <>
                  {/* Meta */}
                  <div style={{
                    padding: "10px 12px",
                    background: "var(--bg-elevated)",
                    borderRadius: 10,
                    fontSize: 12,
                    color: "var(--text-secondary)",
                    display: "flex",
                    flexWrap: "wrap",
                    gap: "6px 20px",
                    marginBottom: 16,
                  }}>
                    <span>
                      <span style={{ color: "var(--text-muted)", marginRight: 4 }}>Device</span>
                      <strong style={{ color: "var(--text-primary)", fontFamily: "'JetBrains Mono', monospace" }}>
                        {detail.device_uid}
                      </strong>
                    </span>
                    <span>
                      <span style={{ color: "var(--text-muted)", marginRight: 4 }}>Data</span>
                      <strong style={{ color: "var(--text-primary)" }}>{formatDate(detail.created_at)}</strong>
                    </span>
                  </div>

                  {/* Findings */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {detail.findings.length === 0 && (
                      <div style={{
                        padding: "30px 0", textAlign: "center",
                        color: "var(--green)", fontSize: 13,
                      }}>
                        ✓ Nicio vulnerabilitate detectată
                      </div>
                    )}
                    {detail.findings.map((f) => (
                      <div
                        key={`${detail.scan_id}:${f.rule_id}:${f.title}`}
                        className={`finding-card ${f.severity.toLowerCase()}`}
                      >
                        <div className="finding-header">
                          <span className="finding-title">{f.title}</span>
                          <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
                            <span className={`severity-badge ${getSeverityClass(f.severity)}`}>
                              {f.severity}
                            </span>
                            <span style={{
                              fontSize: 10, color: "var(--text-muted)",
                              fontFamily: "'JetBrains Mono', monospace",
                            }}>
                              {f.rule_id}
                            </span>
                          </div>
                        </div>
                        <div className="finding-rec">{f.recommendation}</div>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

