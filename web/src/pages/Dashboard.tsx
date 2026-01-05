import { useEffect, useMemo, useState } from "react";
import { getScan, listDeviceScans } from "../exposure.ts";
import type { DeviceScanListItem, ScanDetailResponse } from "../types";

function cls(...xs: Array<string | false | undefined>) {
  return xs.filter(Boolean).join(" ");
}

function SeverityPill({ severity }: { severity: string }) {
  const s = severity.toLowerCase();
  return (
    <span
      className={cls(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium border",
        s === "high" && "border-red-300",
        s === "medium" && "border-yellow-300",
        s === "low" && "border-green-300",
        !(s === "high" || s === "medium" || s === "low") && "border-gray-300"
      )}
    >
      {severity}
    </span>
  );
}

export default function Dashboard() {
  const [deviceId, setDeviceId] = useState("laptop-01");
  const [loading, setLoading] = useState(false);
  const [scans, setScans] = useState<DeviceScanListItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [scanDetail, setScanDetail] = useState<ScanDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canLoad = useMemo(() => deviceId.trim().length > 0, [deviceId]);

  async function loadScans() {
    setError(null);
    setLoading(true);
    setScanDetail(null);
    setSelectedScanId(null);
    try {
      const items = await listDeviceScans(deviceId.trim());
      setScans(items);
      if (items.length > 0) {
        setSelectedScanId(items[0].scan_id);
      }
    } catch (e) {
      setScans([]);
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!selectedScanId) return;
    let cancelled = false;
    (async () => {
      try {
        const detail = await getScan(selectedScanId);
        if (!cancelled) setScanDetail(detail);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Unknown error");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [selectedScanId]);

  return (
    <div style={{ fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif" }}>
      <div style={{ maxWidth: 1100, margin: "40px auto", padding: "0 16px" }}>
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between" }}>
          <h1 style={{ margin: 0, fontSize: 24, fontWeight: 700 }}>Exposure Dashboard</h1>
          <div style={{ fontSize: 12, opacity: 0.7 }}>API: /api/v1</div>
        </div>

        <div style={{ marginTop: 16, display: "flex", gap: 12, alignItems: "center" }}>
          <input
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
            placeholder="device_id (ex: laptop-01)"
            style={{
              flex: 1,
              height: 40,
              padding: "0 12px",
              borderRadius: 10,
              border: "1px solid #ddd",
              outline: "none",
            }}
          />
          <button
            disabled={!canLoad || loading}
            onClick={loadScans}
            style={{
              height: 40,
              padding: "0 14px",
              borderRadius: 10,
              border: "1px solid #ddd",
              background: "white",
              cursor: loading ? "not-allowed" : "pointer",
              fontWeight: 600,
            }}
          >
            {loading ? "Loading..." : "Load scans"}
          </button>
        </div>

        {error && (
          <div
            style={{
              marginTop: 12,
              padding: 12,
              borderRadius: 10,
              border: "1px solid #f1c2c2",
            }}
          >
            <div style={{ fontWeight: 700, marginBottom: 6 }}>Error</div>
            <div style={{ whiteSpace: "pre-wrap", fontSize: 13 }}>{error}</div>
          </div>
        )}

        <div style={{ marginTop: 16, display: "grid", gridTemplateColumns: "360px 1fr", gap: 16 }}>
          <div
            style={{
              border: "1px solid #eee",
              borderRadius: 14,
              padding: 12,
              minHeight: 420,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
              <div style={{ fontWeight: 700 }}>Scans</div>
              <div style={{ fontSize: 12, opacity: 0.7 }}>{scans.length}</div>
            </div>

            <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 8 }}>
              {scans.map((s) => (
                <button
                  key={s.scan_id}
                  onClick={() => setSelectedScanId(s.scan_id)}
                  style={{
                    textAlign: "left",
                    padding: 10,
                    borderRadius: 12,
                    border: selectedScanId === s.scan_id ? "1px solid #bbb" : "1px solid #eee",
                    background: "white",
                    cursor: "pointer",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <div style={{ fontWeight: 700 }}>#{s.scan_id}</div>
                    <div style={{ fontSize: 12, opacity: 0.7 }}>score: {s.exposure_score}</div>
                  </div>
                  <div style={{ fontSize: 12, opacity: 0.7, marginTop: 4 }}>{s.created_at}</div>
                </button>
              ))}
              {scans.length === 0 && (
                <div style={{ fontSize: 13, opacity: 0.7, padding: 10 }}>
                  No scans loaded. Create one via Swagger (/docs) then reload.
                </div>
              )}
            </div>
          </div>

          <div
            style={{
              border: "1px solid #eee",
              borderRadius: 14,
              padding: 12,
              minHeight: 420,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
              <div style={{ fontWeight: 700 }}>Scan detail</div>
              {scanDetail && (
                <div style={{ fontSize: 12, opacity: 0.7 }}>
                  score: {scanDetail.exposure_score} · findings: {scanDetail.findings.length}
                </div>
              )}
            </div>

            {!scanDetail && (
              <div style={{ marginTop: 10, fontSize: 13, opacity: 0.7 }}>
                Select a scan from the left.
              </div>
            )}

            {scanDetail && (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 13, opacity: 0.85 }}>
                  <div><b>device_id:</b> {scanDetail.device_id}</div>
                  <div><b>created_at:</b> {scanDetail.created_at}</div>
                </div>

                <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 10 }}>
                  {scanDetail.findings.map((f) => (
                    <div
                      key={`${scanDetail.scan_id}:${f.rule_id}:${f.title}`}
                      style={{
                        border: "1px solid #eee",
                        borderRadius: 14,
                        padding: 12,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                        <div style={{ fontWeight: 800 }}>{f.title}</div>
                        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                          <SeverityPill severity={f.severity} />
                          <span style={{ fontSize: 12, opacity: 0.7 }}>{f.rule_id}</span>
                        </div>
                      </div>
                      <div style={{ marginTop: 8, fontSize: 13, opacity: 0.85 }}>
                        {f.recommendation}
                      </div>
                    </div>
                  ))}
                  {scanDetail.findings.length === 0 && (
                    <div style={{ fontSize: 13, opacity: 0.7 }}>No findings.</div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
