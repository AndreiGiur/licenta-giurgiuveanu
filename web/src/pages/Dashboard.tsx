import { useEffect, useMemo, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { apiGet } from "../api/http";
import { getScan, listDeviceScans, listScanJobs } from "../api/exposure";
import type { DeviceScanListItem, ScanDetailResponse, ScanJobResponse } from "../api/types";
import Navbar from "../components/Navbar";
import { ScoreGauge } from "../components/ScoreGauge";
import { ScoreBreakdownBars } from "../components/ScoreBreakdownBars";

type DeviceListItem = {
  id: number;
  device_uid: string;
  name: string;
  created_at: string;
};

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

export default function Dashboard() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [deviceId, setDeviceId] = useState(() => searchParams.get("device") ?? "");
  const [devices, setDevices] = useState<DeviceListItem[]>([]);
  const [devicesLoading, setDevicesLoading] = useState(true);
  const [loading, setLoading] = useState(false);
  const [scans, setScans] = useState<DeviceScanListItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [detail, setDetail] = useState<ScanDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Job activ (pending/running) pentru device-ul selectat — pentru progress bar.
  const [activeJob, setActiveJob] = useState<ScanJobResponse | null>(null);

  const canLoad = useMemo(() => deviceId.trim().length > 0, [deviceId]);

  // Lookup rapid pentru afisarea numelui linga UID
  const selectedDevice = useMemo(
    () => devices.find(d => d.device_uid === deviceId.trim()),
    [devices, deviceId],
  );

  // Incarca lista de device-uri pentru dropdown
  useEffect(() => {
    apiGet<DeviceListItem[]>("/devices")
      .then((items) => {
        setDevices(items);
        // Daca nu avem ?device= in URL si user-ul are doar un device, il pre-selectam.
        const fromUrl = searchParams.get("device");
        if (!fromUrl && items.length === 1) {
          setDeviceId(items[0].device_uid);
        }
      })
      .catch((e) => {
        setError(e instanceof Error ? e.message : "Eroare la incarcarea device-urilor");
      })
      .finally(() => setDevicesLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-load cand avem device selectat (din URL sau din pre-select)
  useEffect(() => {
    if (deviceId.trim() && !devicesLoading) {
      load();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deviceId, devicesLoading]);

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

  // Polling job activ — afisat ca progress bar live (Advanced/Deep dureaza minute).
  useEffect(() => {
    const uid = deviceId.trim();
    if (!uid) {
      setActiveJob(null);
      return;
    }
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const lastDoneId = { current: null as number | null };

    async function tick() {
      try {
        const jobs = await listScanJobs(uid);
        if (cancelled) return;
        const active = jobs.find(j => j.status === "running" || j.status === "pending");
        setActiveJob(active ?? null);
        // Daca tocmai a terminat un job, reincarca lista de scanari pentru a vedea noul rezultat.
        const newest = jobs.find(j => j.status === "done");
        if (!active && newest && newest.scan_id && newest.scan_id !== lastDoneId.current) {
          lastDoneId.current = newest.scan_id;
          load();
        }
      } catch {
        if (!cancelled) setActiveJob(null);
      }
      if (!cancelled) timer = setTimeout(tick, 2000);
    }
    tick();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deviceId]);

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

        {/* ── Device picker ── */}
        <div style={{ display: "flex", gap: 10, marginBottom: 24, alignItems: "stretch" }}>
          <div style={{ position: "relative", flex: 1 }}>
            <select
              className="form-input"
              value={deviceId}
              onChange={(e) => setDeviceId(e.target.value)}
              disabled={devicesLoading}
              style={{ width: "100%", cursor: devicesLoading ? "wait" : "pointer" }}
            >
              {devicesLoading && <option value="">Se incarca dispozitivele...</option>}
              {!devicesLoading && devices.length === 0 && (
                <option value="">Niciun dispozitiv inrolat — du-te la /devices ca sa adaugi unul</option>
              )}
              {!devicesLoading && devices.length > 0 && (
                <>
                  <option value="">— alege dispozitivul —</option>
                  {devices.map((d) => (
                    <option key={d.id} value={d.device_uid}>
                      {d.name} ({d.device_uid})
                    </option>
                  ))}
                </>
              )}
            </select>
          </div>
          <button
            disabled={!canLoad || loading}
            onClick={load}
            className="btn btn-accent"
            style={{ flexShrink: 0 }}
          >
            {loading
              ? <span className="loading-dots"><span /><span /><span /></span>
              : "Reincarca"}
          </button>
        </div>

        {selectedDevice && (
          <div style={{
            marginBottom: 16, padding: "8px 12px",
            background: "var(--bg-elevated)", borderRadius: 8,
            fontSize: 12, color: "var(--text-secondary)",
          }}>
            Vizualizezi scanarile pentru <strong style={{ color: "var(--text-primary)" }}>
              {selectedDevice.name}
            </strong>
            <span style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
              {" "}({selectedDevice.device_uid})
            </span>
          </div>
        )}

        {/* ── Job activ ── */}
        {activeJob && (activeJob.status === "running" || activeJob.status === "pending") && (
          <div className="dashboard-active-job">
            <div className="active-job-header">
              <span className={`scan-type-badge ${activeJob.scan_type ?? "standard"}`}>
                {(activeJob.scan_type ?? "standard").toUpperCase()}
              </span>
              <span>
                {activeJob.status === "pending"
                  ? "Se asteapta agentul…"
                  : `Scanare in curs: ${activeJob.phase ?? "Pornire…"}`}
              </span>
            </div>
            <div className="job-progress-bar">
              <div className="job-progress-fill" style={{ width: `${activeJob.progress ?? 0}%` }} />
            </div>
            <span className="job-progress-label">{activeJob.progress ?? 0}%</span>
          </div>
        )}

        {/* ── Error ── */}
        {error && (
          <div className="alert alert-error" style={{ marginBottom: 20 }}>
            <div className="alert-title">Eroare</div>
            <div style={{ fontSize: 12, marginTop: 2, whiteSpace: "pre-wrap" }}>{error}</div>
          </div>
        )}

        {/* ── Stats row ── */}
        {detail && (
          <motion.div
            className="dashboard-stat-row"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
          >
            <div className="dashboard-score">
              <ScoreGauge value={detail.exposure_score} size={180} />
            </div>
            <div className="dashboard-counts">
              <div className="count-card">
                <div className="count-value" style={{ color: "var(--severity-high)" }}>{highCount}</div>
                <div className="count-label">High / Critical</div>
              </div>
              <div className="count-card">
                <div className="count-value" style={{ color: "var(--severity-medium)" }}>{medCount}</div>
                <div className="count-label">Medium</div>
              </div>
              <div className="count-card">
                <div className="count-value" style={{ color: "var(--severity-low)" }}>{lowCount}</div>
                <div className="count-label">Low</div>
              </div>
            </div>
          </motion.div>
        )}

        {/* ── Score breakdown 4 categorii ── */}
        {detail?.score_breakdown && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.1 }}
            style={{ marginTop: 16 }}
          >
            <ScoreBreakdownBars breakdown={detail.score_breakdown} />
          </motion.div>
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
                      <strong style={{ color: "var(--text-primary)" }}>
                        {detail.device_name}
                      </strong>
                      <span style={{ color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace", marginLeft: 6 }}>
                        ({detail.device_uid})
                      </span>
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

