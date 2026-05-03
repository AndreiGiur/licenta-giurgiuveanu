import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar";
import { apiDelete, apiGet, apiPost } from "../api/http";

type Device = {
  id: number;
  device_uid: string;
  name: string;
  created_at: string;
};

type DeviceCreateResponse = Device & { device_token: string };

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

  useEffect(() => { loadDevices(); }, []);

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

              {!loading && devices.map((d) => (
                <div key={d.id} className="device-card">
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="device-uid">{d.device_uid}</div>
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
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
