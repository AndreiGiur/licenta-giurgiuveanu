import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import Navbar from "../components/Navbar";
import { apiDelete, apiGet, API_BASE_URL } from "../api/http";
import {
  requestScan, getScanJob, getAgentDownloadInfo, getScanJobPreview,
  listSchedules, deleteSchedule,
} from "../api/exposure";
import type {
  Device, ScanJobPreview, ScanJobResponse, ScanType, Schedule,
} from "../api/types";
import ScheduleForm from "../components/ScheduleForm";

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.06 } },
};
const itemVariants = {
  hidden: { opacity: 0, y: 8 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.3 } },
};

const SCAN_TYPE_LABEL: Record<ScanType, string> = {
  standard: "Standard (est. 45–90 s)",
  advanced: "Advanced (est. 3–8 min)",
  deep: "Deep (est. 10–20 min)",
};

// Cat asteapta UI-ul ca daemon-ul sa preia jobul inainte sa avertizeze user-ul.
const PICKUP_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS  = 2_000;

function formatDate(raw: string): string {
  try {
    return new Date(raw).toLocaleString("ro-RO", {
      day: "2-digit", month: "short", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch { return raw; }
}

export default function Devices() {
  const navigate = useNavigate();
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Map device_uid -> ultimul status job afisat in UI. Folosit pentru
  // butonul "Scan now" si pentru avertismente cand daemon-ul nu raspunde.
  const [activeJob, setActiveJob] = useState<Record<string, ScanJobResponse>>({});
  // Map device_uid -> mesaj de notificare ("pornit", "finalizat", "esuat")
  const [jobNotice, setJobNotice] = useState<Record<string, string>>({});
  // Map device_uid -> tipul de scanare ales pentru urmatoarea cerere.
  const [scanTypeByDevice, setScanTypeByDevice] = useState<Record<string, ScanType>>({});
  // Map device_uid -> preview info pentru scan deep (nmap installed, subnet detectat).
  const [previewByDevice, setPreviewByDevice] = useState<Record<string, ScanJobPreview | null>>({});
  // Map device_uid -> opt-in pentru scanarea LAN (doar pentru scan deep).
  const [lanOptInByDevice, setLanOptInByDevice] = useState<Record<string, boolean>>({});
  // Map device_uid -> lista de scheduluri pentru device.
  const [schedules, setSchedules] = useState<Record<string, Schedule[]>>({});
  // Tinem ref-uri ca sa anulam polling-urile la unmount.
  const pollTimers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

  // Disponibilitatea agent-ului pentru download (depinde daca a fost build-uit pe server).
  const [agentInfo, setAgentInfo] = useState<{ available: boolean; size_bytes: number | null } | null>(null);

  useEffect(() => {
    loadDevices();
    getAgentDownloadInfo()
      .then(info => setAgentInfo({ available: info.available, size_bytes: info.size_bytes }))
      .catch(() => setAgentInfo({ available: false, size_bytes: null }));

    // Refresh online status la 15s (heartbeat = 10s, prag offline = 30s).
    const refresh = setInterval(loadDevices, 15_000);

    return () => {
      Object.values(pollTimers.current).forEach(t => clearTimeout(t));
      clearInterval(refresh);
    };
  }, []);

  async function reloadSchedules(uid: string) {
    try {
      const list = await listSchedules(uid);
      setSchedules(p => ({ ...p, [uid]: list }));
    } catch {
      // silent — endpoint poate da 404 daca device a fost sters
    }
  }

  async function handleDeleteSchedule(sid: number, uid: string) {
    if (!window.confirm("Stergi acest schedule?")) return;
    await deleteSchedule(sid);
    reloadSchedules(uid);
  }

  // Load schedules pentru fiecare device la prima incarcare a listei
  useEffect(() => {
    devices.forEach(d => reloadSchedules(d.device_uid));
  }, [devices.length]);

  // Fetch preview pentru orice device cu scan_type deep selectat (cache local).
  useEffect(() => {
    for (const [uid, type] of Object.entries(scanTypeByDevice)) {
      if (type === "deep" && !(uid in previewByDevice)) {
        getScanJobPreview(uid)
          .then(p => setPreviewByDevice(prev => ({ ...prev, [uid]: p })))
          .catch(() => setPreviewByDevice(prev => ({ ...prev, [uid]: null })));
      }
    }
  }, [scanTypeByDevice, previewByDevice]);

  async function loadDevices() {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGet<Device[]>("/devices");
      setDevices(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Eroare necunoscută");
    } finally {
      setLoading(false);
    }
  }

  async function handleDelete(device_uid: string, name: string) {
    if (!window.confirm(`Stergi dispozitivul "${name}"?\nToate scanarile asociate vor fi sterse.`)) return;
    setError(null);
    try {
      await apiDelete(`/devices/${encodeURIComponent(device_uid)}`);
      await loadDevices();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Eroare la stergere");
    }
  }

  // ── Scan-on-demand ────────────────────────────────────────────────────────
  //
  // Click "Scan now" → POST /devices/{uid}/scan-jobs → primim un job pending.
  // Polling la POLL_INTERVAL_MS pana cand status devine done/failed/cancelled.
  // Daca jobul ramane "pending" mai mult de PICKUP_TIMEOUT_MS, avertizam ca
  // daemon-ul nu raspunde (probabil agentul nu ruleaza pe masina respectiva).

  const stopPolling = useCallback((deviceUid: string) => {
    const t = pollTimers.current[deviceUid];
    if (t) {
      clearTimeout(t);
      delete pollTimers.current[deviceUid];
    }
  }, []);

  const pollJob = useCallback((deviceUid: string, jobId: number, startedAt: number) => {
    const tick = async () => {
      try {
        const job = await getScanJob(jobId);
        setActiveJob(prev => ({ ...prev, [deviceUid]: job }));

        if (job.status === "done") {
          stopPolling(deviceUid);
          setJobNotice(prev => ({
            ...prev,
            [deviceUid]: `Scanare finalizata (score ${job.exposure_score ?? "?"}/100).`,
          }));
          return;
        }
        if (job.status === "failed") {
          stopPolling(deviceUid);
          setJobNotice(prev => ({
            ...prev,
            [deviceUid]: `Scanare esuata: ${job.error_message ?? "necunoscut"}`,
          }));
          return;
        }
        if (job.status === "cancelled") {
          stopPolling(deviceUid);
          setJobNotice(prev => ({ ...prev, [deviceUid]: "Scanare anulata." }));
          return;
        }

        // Inca pending/running. Daca pending dureaza prea mult → avertisment.
        if (job.status === "pending" && Date.now() - startedAt > PICKUP_TIMEOUT_MS) {
          setJobNotice(prev => ({
            ...prev,
            [deviceUid]:
              "Agentul nu raspunde. Asigura-te ca ai pornit `python scan.py daemon` pe masina respectiva.",
          }));
        }

        pollTimers.current[deviceUid] = setTimeout(tick, POLL_INTERVAL_MS);
      } catch (e) {
        stopPolling(deviceUid);
        setJobNotice(prev => ({
          ...prev,
          [deviceUid]: e instanceof Error ? e.message : "Eroare la polling status",
        }));
      }
    };
    pollTimers.current[deviceUid] = setTimeout(tick, POLL_INTERVAL_MS);
  }, [stopPolling]);

  async function handleScanNow(deviceUid: string) {
    const scanType = scanTypeByDevice[deviceUid] ?? "standard";
    let nmapTarget: string | null = null;
    if (scanType === "deep") {
      const preview = previewByDevice[deviceUid];
      const lanOptIn = lanOptInByDevice[deviceUid] ?? false;
      if (lanOptIn && preview?.detected_subnet) {
        const ok = window.confirm(
          `Vei scana ~${preview.estimated_hosts} IP-uri din reteaua ta locala ` +
          `(${preview.detected_subnet}). Asigura-te ca ai autorizare sa faci asta. Continui?`
        );
        if (!ok) return;
        nmapTarget = preview.detected_subnet;
      }
    }
    setJobNotice(prev => ({ ...prev, [deviceUid]: `Se cere scanare ${scanType}...` }));
    stopPolling(deviceUid);
    try {
      const job = await requestScan(deviceUid, scanType, nmapTarget);
      setActiveJob(prev => ({ ...prev, [deviceUid]: job }));
      setJobNotice(prev => ({
        ...prev,
        [deviceUid]: job.status === "running" ? "Scanare in curs..." : "In asteptare...",
      }));
      // Daca era deja done (caz teoretic improbabil), nu mai polleaza
      if (job.status === "done" || job.status === "failed" || job.status === "cancelled") {
        return;
      }
      pollJob(deviceUid, job.job_id, Date.now());
    } catch (e) {
      setJobNotice(prev => ({
        ...prev,
        [deviceUid]: e instanceof Error ? e.message : "Eroare la cererea scanarii",
      }));
    }
  }

  return (
    <div className="page">
      <Navbar />

      <div className="container" style={{ paddingTop: 32, paddingBottom: 48 }}>
        <div className="page-header">
          <h1 className="page-title">Dispozitive</h1>
          <p className="page-subtitle">Gestionează dispozitivele înregistrate în platformă</p>
        </div>

        {/* ── Agent download banner ── */}
        <div style={{
          padding: "14px 16px",
          marginBottom: 20,
          background: "var(--bg-elevated)",
          border: "1px solid var(--border)",
          borderRadius: 10,
          display: "flex",
          alignItems: "center",
          gap: 14,
          flexWrap: "wrap",
        }}>
          <div style={{ flex: 1, minWidth: 240 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 2 }}>
              Instaleaza VulnWatch Agent (Windows)
            </div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
              Descarca, dublu-click, completeaza email-ul si parola in fereastra. Zero terminal.
            </div>
          </div>
          {agentInfo?.available ? (
            <a
              href={`${API_BASE_URL}/agent/download/windows`}
              className="btn btn-accent"
              style={{ textDecoration: "none" }}
            >
              ↓ Descarca .exe {agentInfo.size_bytes ? `(${(agentInfo.size_bytes / (1024 * 1024)).toFixed(1)} MB)` : ""}
            </a>
          ) : (
            <span style={{ fontSize: 12, color: "var(--text-muted)", fontStyle: "italic" }}>
              Build indisponibil — ruleaza <code>agent/build.ps1</code> pe serverul backend.
            </span>
          )}
        </div>

        {error && (
          <div className="alert alert-error" style={{ marginBottom: 20 }}>
            <div className="alert-title">Eroare</div>
            <div style={{ fontSize: 12, marginTop: 2 }}>{error}</div>
          </div>
        )}

        {/* ── Device list ── */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Dispozitivele tale</span>
            <span className="card-badge">{devices.length}</span>
          </div>
          <motion.div
            className="card-body"
            style={{ display: "flex", flexDirection: "column", gap: 10 }}
            initial="hidden"
            animate="visible"
            variants={containerVariants}
          >
            {loading && (
              <div className="empty-state">
                <span className="loading-dots"><span /><span /><span /></span>
              </div>
            )}

            {!loading && devices.length === 0 && (
              <div className="empty-state" style={{ padding: 48, textAlign: "center" }}>
                <div style={{ fontSize: 48, marginBottom: 16 }}>📡</div>
                <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>
                  Niciun dispozitiv conectat încă
                </div>
                <div style={{ fontSize: 13, color: "var(--text-muted)", maxWidth: 420, margin: "0 auto 20px" }}>
                  Pentru a conecta primul dispozitiv, descarcă agentul VulnWatch și
                  autentifică-te din aplicație.
                </div>
                {agentInfo?.available && (
                  <a
                    href={`${API_BASE_URL}/agent/download/windows`}
                    className="btn btn-accent"
                    style={{ textDecoration: "none" }}
                  >
                    ↓ Descarcă VulnWatch Agent
                  </a>
                )}
              </div>
            )}

            {!loading && devices.map((d) => {
              const job = activeJob[d.device_uid];
              const notice = jobNotice[d.device_uid];
              const inFlight = job && (job.status === "pending" || job.status === "running");
              const isOnline = d.is_online === true;
              const selectedType = scanTypeByDevice[d.device_uid] ?? "standard";
              const noticeColor =
                job?.status === "done" ? "var(--green)" :
                job?.status === "failed" ? "var(--red)" :
                inFlight ? "var(--accent)" : "var(--text-muted)";
              return (
              <motion.div key={d.id} className="device-card" variants={itemVariants}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <div className="device-uid">{d.device_uid}</div>
                      <span className={`device-online-badge ${isOnline ? "online" : "offline"}`}>
                        {isOnline ? "● Online" : "○ Offline"}
                      </span>
                      {isOnline && d.agent_version && (
                        <span className="device-meta-inline">v{d.agent_version}</span>
                      )}
                    </div>
                    <div className="device-name">{d.name}</div>
                    <div className="device-meta">înregistrat: {formatDate(d.created_at)}</div>
                  </div>
                  <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                    <button
                      onClick={() => navigate(`/dashboard?device=${encodeURIComponent(d.device_uid)}`)}
                      className="btn btn-accent btn-sm"
                    >
                      Scanări
                    </button>
                    <button
                      onClick={() => handleDelete(d.device_uid, d.name)}
                      className="btn btn-sm"
                      style={{ color: "var(--red)", border: "1px solid var(--red)", background: "transparent" }}
                    >
                      Șterge
                    </button>
                  </div>
                </div>

                <div className="scan-controls">
                  <select
                    className="scan-type-select"
                    value={selectedType}
                    onChange={e => setScanTypeByDevice(prev => ({
                      ...prev,
                      [d.device_uid]: e.target.value as ScanType,
                    }))}
                    disabled={!isOnline || !!inFlight}
                  >
                    {(["standard", "advanced", "deep"] as ScanType[]).map(t => (
                      <option key={t} value={t}>{SCAN_TYPE_LABEL[t]}</option>
                    ))}
                  </select>
                  <button
                    onClick={() => handleScanNow(d.device_uid)}
                    disabled={!isOnline || !!inFlight}
                    className="btn btn-primary btn-sm"
                    title={!isOnline ? "Agentul nu este conectat" : "Porneşte scanare"}
                  >
                    {inFlight
                      ? <span className="loading-dots"><span /><span /><span /></span>
                      : "Scanează acum"}
                  </button>
                </div>

                {selectedType === "deep" && (
                  <div className="deep-settings">
                    {(() => {
                      const preview = previewByDevice[d.device_uid];
                      if (preview === undefined) return <div className="muted">Verificare nmap…</div>;
                      if (preview === null) return <div className="muted">Preview indisponibil.</div>;
                      if (!preview.nmap_installed) {
                        return (
                          <div className="warn-banner">
                            ⚠ nmap nu este instalat pe acest device.{" "}
                            <a href="https://nmap.org/download.html" target="_blank" rel="noreferrer">
                              Instalează nmap
                            </a> şi reporneşte agentul.
                          </div>
                        );
                      }
                      return (
                        <label className="lan-toggle">
                          <input
                            type="checkbox"
                            checked={lanOptInByDevice[d.device_uid] ?? false}
                            onChange={e => setLanOptInByDevice(prev => ({
                              ...prev, [d.device_uid]: e.target.checked,
                            }))}
                          />
                          Include LAN: {preview.detected_subnet ?? "(subnet nedetectat)"}{" — "}
                          ~{preview.estimated_hosts} hosts,
                          ~{Math.max(1, Math.round(preview.estimated_duration_sec / 60))} min
                        </label>
                      );
                    })()}
                  </div>
                )}

                <details className="schedule-section">
                  <summary>
                    📅 Planificare ({schedules[d.device_uid]?.length ?? 0})
                  </summary>
                  {(schedules[d.device_uid] ?? []).map(s => (
                    <div key={s.id} className="schedule-row">
                      <span className="schedule-tag">{s.scan_type}</span>
                      <span>{s.frequency === "daily" ? "zilnic"
                        : s.frequency === "weekly" ? "săptămânal"
                        : "lunar"}</span>
                      <span>{String(s.hour).padStart(2, "0")}:00 UTC</span>
                      <span className="schedule-next">
                        următorul: {new Date(s.next_run_at).toLocaleString("ro-RO", {
                          dateStyle: "short", timeStyle: "short",
                        })}
                      </span>
                      <button
                        onClick={() => handleDeleteSchedule(s.id, d.device_uid)}
                        className="btn btn-ghost btn-sm"
                        title="Sterge"
                        style={{ marginLeft: "auto", padding: "0 8px" }}
                      >×</button>
                    </div>
                  ))}
                  <ScheduleForm
                    deviceUid={d.device_uid}
                    onCreated={() => reloadSchedules(d.device_uid)}
                  />
                </details>

                {inFlight && (
                  <div className="job-progress">
                    <div className="job-progress-bar">
                      <div
                        className="job-progress-fill"
                        style={{ width: `${job?.progress ?? 0}%` }}
                      />
                    </div>
                    <span className="job-progress-label">
                      {job?.progress ?? 0}% — {job?.phase ?? "Pornire…"}
                    </span>
                  </div>
                )}

                {notice && !inFlight && (
                  <div style={{
                    marginTop: 10,
                    padding: "6px 10px",
                    fontSize: 12,
                    borderRadius: 6,
                    background: "var(--bg-elevated)",
                    color: noticeColor,
                    borderLeft: `2px solid ${noticeColor}`,
                  }}>
                    {notice}
                    {job?.status === "done" && job.scan_id && (
                      <>
                        {" "}
                        <button
                          onClick={() => navigate(`/scans/${job.scan_id}`)}
                          className="btn btn-ghost btn-sm"
                          style={{ fontSize: 11, padding: "1px 8px", marginLeft: 4 }}
                        >
                          Vezi detalii →
                        </button>
                      </>
                    )}
                  </div>
                )}
              </motion.div>
              );
            })}
          </motion.div>
        </div>
      </div>
    </div>
  );
}
