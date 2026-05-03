import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar";
import { apiDelete, apiGet, apiPost } from "../api/http";
import { requestScan, getScanJob } from "../api/exposure";
import type { ScanJobResponse } from "../api/types";

type Device = {
  id: number;
  device_uid: string;
  name: string;
  created_at: string;
};

type DeviceCreateResponse = Device & { device_token: string };

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

const CopyIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  </svg>
);

export default function Devices() {
  const navigate = useNavigate();
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newDeviceUid, setNewDeviceUid] = useState("");
  const [newDeviceName, setNewDeviceName] = useState("");
  const [createdToken, setCreatedToken] = useState<string | null>(null);
  const [createdUid, setCreatedUid] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Map device_uid -> ultimul status job afisat in UI. Folosit pentru
  // butonul "Scan now" si pentru avertismente cand daemon-ul nu raspunde.
  const [activeJob, setActiveJob] = useState<Record<string, ScanJobResponse>>({});
  // Map device_uid -> mesaj de notificare ("pornit", "finalizat", "esuat")
  const [jobNotice, setJobNotice] = useState<Record<string, string>>({});
  // Tinem ref-uri ca sa anulam polling-urile la unmount.
  const pollTimers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

  useEffect(() => {
    loadDevices();
    return () => {
      // cleanup la unmount
      Object.values(pollTimers.current).forEach(t => clearTimeout(t));
    };
  }, []);

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

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setCreating(true);
    setCreatedToken(null);
    setCreatedUid(null);
    try {
      const created = await apiPost<{ device_uid: string; name: string }, DeviceCreateResponse>(
        "/devices",
        { device_uid: newDeviceUid.trim(), name: newDeviceName.trim() },
      );
      setCreatedToken(created.device_token);
      setCreatedUid(created.device_uid);
      setNewDeviceUid("");
      setNewDeviceName("");
      await loadDevices();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Eroare la creare");
    } finally {
      setCreating(false);
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

  async function copyToken() {
    if (!createdToken) return;
    try {
      await navigator.clipboard.writeText(createdToken);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* ignore */ }
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
    setJobNotice(prev => ({ ...prev, [deviceUid]: "Se cere scanare..." }));
    stopPolling(deviceUid);
    try {
      const job = await requestScan(deviceUid);
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

        {error && (
          <div className="alert alert-error" style={{ marginBottom: 20 }}>
            <div className="alert-title">Eroare</div>
            <div style={{ fontSize: 12, marginTop: 2 }}>{error}</div>
          </div>
        )}

        {/* ── Token success banner ── */}
        {createdToken && (
          <div className="alert alert-success" style={{ marginBottom: 20 }}>
            <div className="alert-title">✓ Dispozitiv înregistrat cu succes!</div>
            <p style={{ fontSize: 12, margin: "6px 0 10px", color: "var(--text-secondary)" }}>
              Copiază acest token pentru agentul tău. Nu va mai fi afişat după închiderea acestui mesaj.
            </p>
            <p style={{ fontSize: 11, margin: "0 0 10px", color: "var(--text-muted)" }}>
              Sau, mai simplu: rulează <code style={{ background: "var(--bg-elevated)", padding: "1px 6px", borderRadius: 4 }}>
                python scan.py enroll
              </code> in agent — credenţialele tale vor crea automat dispozitivul şi vor salva tokenul local.
            </p>
            <div style={{ position: "relative" }}>
              <div className="token-block">{createdToken}</div>
              <button
                onClick={copyToken}
                className="btn btn-sm"
                style={{
                  position: "absolute", top: 8, right: 8,
                  background: copied ? "var(--green-dim)" : "var(--bg-elevated)",
                  color: copied ? "var(--green)" : "var(--text-secondary)",
                  border: "1px solid var(--border)",
                  display: "flex", alignItems: "center", gap: 5,
                }}
              >
                <CopyIcon /> {copied ? "Copiat!" : "Copiază"}
              </button>
            </div>
            {createdUid && (
              <p style={{ fontSize: 11, marginTop: 8, color: "var(--text-muted)" }}>
                Device UID: <code>{createdUid}</code>
              </p>
            )}
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "340px 1fr", gap: 16, alignItems: "start" }}
          className="dashboard-grid">

          {/* ── Enroll form ── */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Înregistrează dispozitiv nou</span>
            </div>
            <div className="card-body">
              <form onSubmit={handleCreate}>
                <div className="form-group">
                  <label className="form-label">Device UID</label>
                  <input
                    className="form-input"
                    value={newDeviceUid}
                    onChange={(e) => setNewDeviceUid(e.target.value)}
                    placeholder="ex: laptop-work"
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Nume</label>
                  <input
                    className="form-input"
                    value={newDeviceName}
                    onChange={(e) => setNewDeviceName(e.target.value)}
                    placeholder="ex: My Work Laptop"
                    required
                  />
                </div>
                <button
                  type="submit"
                  disabled={creating}
                  className="btn btn-primary"
                  style={{ marginTop: 4 }}
                >
                  {creating
                    ? <span className="loading-dots"><span /><span /><span /></span>
                    : "Înregistrează"}
                </button>
              </form>
            </div>
          </div>

          {/* ── Device list ── */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Dispozitivele tale</span>
              <span className="card-badge">{devices.length}</span>
            </div>
            <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {loading && (
                <div className="empty-state">
                  <span className="loading-dots"><span /><span /><span /></span>
                </div>
              )}

              {!loading && devices.length === 0 && (
                <div className="empty-state">
                  Niciun dispozitiv înregistrat.<br />
                  <span style={{ fontSize: 12 }}>Foloseşte formularul din stânga.</span>
                </div>
              )}

              {!loading && devices.map((d) => {
                const job = activeJob[d.device_uid];
                const notice = jobNotice[d.device_uid];
                const inFlight = job && (job.status === "pending" || job.status === "running");
                const noticeColor =
                  job?.status === "done" ? "var(--green)" :
                  job?.status === "failed" ? "var(--red)" :
                  inFlight ? "var(--accent)" : "var(--text-muted)";
                return (
                <div key={d.id} className="device-card">
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="device-uid">{d.device_uid}</div>
                      <div className="device-name">{d.name}</div>
                      <div className="device-meta">înregistrat: {formatDate(d.created_at)}</div>
                    </div>
                    <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                      <button
                        onClick={() => handleScanNow(d.device_uid)}
                        disabled={!!inFlight}
                        className="btn btn-primary btn-sm"
                        title="Cere o scanare on-demand de la agent"
                      >
                        {inFlight
                          ? <span className="loading-dots"><span /><span /><span /></span>
                          : "Scan now"}
                      </button>
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
                  {notice && (
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
                </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
