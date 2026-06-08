import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { DeviceScanListItem, ScanType } from "../api/types";
import { listDeviceScans, requestScan } from "../api/exposure";
import { apiDelete } from "../api/http";
import { ScoreGauge } from "./ScoreGauge";
import { ConnectionTopology } from "./ConnectionTopology";
import { NetworkTrafficChart } from "./NetworkTrafficChart";
import { ScanTypeExplainer } from "./ScanTypeExplainer";
import { InfoTip } from "./InfoTip";
import { useScanJobPolling } from "../hooks/useScanJobPolling";
import { useScanDetail } from "../hooks/useScanDetail";

type WorkspaceDevice = {
  id: number;
  device_uid: string;
  name: string;
  is_online?: boolean;
  last_heartbeat?: string | null;
};

export function DeviceWorkspace({ device, onDeleted }:
  { device: WorkspaceDevice; onDeleted: () => void }) {
  const navigate = useNavigate();
  const [scanType, setScanType] = useState<ScanType>("standard");
  const [scans, setScans] = useState<DeviceScanListItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);

  const uid = device.device_uid;

  async function loadScans() {
    try {
      const items = await listDeviceScans(uid);
      setScans(items);
      setSelectedScanId(items.length ? items[0].scan_id : null);
    } catch {
      setScans([]);
    }
  }
  useEffect(() => { loadScans(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [uid]);

  const activeJob = useScanJobPolling(uid, loadScans);
  const { detail } = useScanDetail(selectedScanId);

  async function onScanNow() {
    setBusy(true);
    try { await requestScan(uid, scanType); } finally { setBusy(false); }
  }

  async function onDelete() {
    if (!confirm(`Stergi dispozitivul ${device.name}?`)) return;
    await apiDelete(`/devices/${encodeURIComponent(uid)}`);
    onDeleted();
  }

  return (
    <div className="workspace">
      <div className="workspace-header">
        <h2 className="workspace-title" title={device.name}>
          {device.name}
          <span className="score-badge" style={{ marginLeft: 10, fontSize: 12 }}>
            {device.is_online ? "online" : "offline"}
          </span>
          <InfoTip topic="device-online" />
        </h2>
        <div className="workspace-actions">
          <label className="sr-only" htmlFor="scan-type">Tip scanare</label>
          <InfoTip topic="scan-type" />
          <select id="scan-type" aria-label="Tip scanare" className="form-input"
            value={scanType} onChange={(e) => setScanType(e.target.value as ScanType)}
            style={{ width: 140 }}>
            <option value="standard">standard</option>
            <option value="advanced">advanced</option>
            <option value="deep">deep</option>
          </select>
          <button className="btn btn-accent" disabled={busy} onClick={onScanNow}>
            {busy ? "..." : "Scaneaza acum"}
          </button>
          <button className="btn btn-ghost btn-sm" onClick={onDelete}>Sterge</button>
        </div>
      </div>

      <ScanTypeExplainer type={scanType} />

      {activeJob && (activeJob.status === "running" || activeJob.status === "pending") && (
        <div className="job-progress">
          <div className="job-progress-bar">
            <div className="job-progress-fill" style={{ width: `${activeJob.progress ?? 0}%` }} />
          </div>
          <span className="job-progress-label">{activeJob.phase ?? "Pornire"} · {activeJob.progress ?? 0}%</span>
        </div>
      )}

      <div className="monitor-row">
        <div className="card">
          <div className="card-header"><span className="card-title">Scor expunere</span><InfoTip topic="exposure-score" /></div>
          <div className="card-body monitor-gauge">
            {detail ? <ScoreGauge value={detail.exposure_score} size={160} />
                    : <div className="empty-state">Nicio scanare inca.</div>}
          </div>
        </div>
        <div className="card">
          <div className="card-header"><span className="card-title">Conexiune</span><InfoTip topic="connection-topology" /></div>
          <div className="card-body">
            <ConnectionTopology online={!!device.is_online}
              lastHeartbeat={device.last_heartbeat ?? null}
              scanActive={!!activeJob && activeJob.status === "running"} />
          </div>
        </div>
        <div className="card">
          <div className="card-header"><span className="card-title">Trafic de retea (live)</span><InfoTip topic="network-traffic" /></div>
          <div className="card-body"><NetworkTrafficChart deviceUid={uid} /></div>
        </div>
      </div>

      <div className="workspace-scans">
        <div className="card">
          <div className="card-header"><span className="card-title">Scanari</span><InfoTip topic="scans-list" />
            <span className="card-badge">{scans.length}</span></div>
          <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {scans.length === 0 && <div className="empty-state">Nicio scanare.</div>}
            {scans.map((s) => (
              <div key={s.scan_id} onClick={() => setSelectedScanId(s.scan_id)}
                className={`scan-item ${selectedScanId === s.scan_id ? "active" : ""}`}
                style={{ cursor: "pointer" }}>
                <div className="scan-item-row">
                  <span className="scan-id">#{s.scan_id}</span>
                  <span className="score-badge">{s.exposure_score}</span>
                </div>
                <div className="scan-date">{new Date(s.created_at).toLocaleString("ro-RO")}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="card">
          <div className="card-header"><span className="card-title">Findings</span><InfoTip topic="findings" />
            {detail && <button className="btn btn-ghost btn-sm"
              onClick={() => navigate(`/scans/${detail.scan_id}`)}>Detalii complete →</button>}</div>
          <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {!detail && <div className="empty-state">Selecteaza o scanare.</div>}
            {detail && detail.findings.length === 0 &&
              <div className="empty-state" style={{ color: "var(--green)" }}>Nicio vulnerabilitate.</div>}
            {detail && detail.findings.map((f) => (
              <div key={`${f.rule_id}:${f.title}`} className={`finding-card ${f.severity.toLowerCase()}`}>
                <div className="finding-header">
                  <span className="finding-title">{f.title}</span>
                  <span className={`severity-badge severity-${f.severity.toLowerCase()}`}>{f.severity}</span>
                </div>
                <div className="finding-rec">{f.recommendation}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
