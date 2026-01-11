import { useEffect, useMemo, useState } from "react";
import { getScan, listDeviceScans } from "../api/exposure";
import type { DeviceScanListItem, ScanDetailResponse } from "../api/types";
import Navbar from "../components/Navbar";

function pillBorder(sev: string) {
  const s = sev.toLowerCase();
  if (s === "high") return "#f2b8b8";
  if (s === "medium") return "#f2e2b8";
  if (s === "low") return "#bfe8c5";
  return "#ddd";
}

export default function Dashboard() {
  const [deviceId, setDeviceId] = useState("Utilizator 1");
  const [loading, setLoading] = useState(false);
  const [scans, setScans] = useState<DeviceScanListItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [detail, setDetail] = useState<ScanDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canLoad = useMemo(() => deviceId.trim().length > 0, [deviceId]);

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
      setError(e instanceof Error ? e.message : "Unknown error");
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
        if (!cancel) setError(e instanceof Error ? e.message : "Unknown error");
      }
    })();
    return () => {
      cancel = true;
    };
  }, [selectedScanId]);

  return (
    <div style={{ fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif", minHeight: "100vh", background: "#fafafa" }}>
      <Navbar />
      <div style={{ maxWidth: 1100, margin: "40px auto", padding: "0 16px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
          <h1 style={{ margin: 0, fontSize: 24, fontWeight: 800 }}>Expuneri Virtuale de Securitate</h1>
          <div style={{ fontSize: 12, opacity: 0.7 }}>Frontend → HTTP → API</div>
        </div>

        <div style={{ marginTop: 16, display: "flex", gap: 12 }}>
          <input
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
            placeholder="device_id (ex: Utilizator 1)"
            style={{
              flex: 1,
              height: 40,
              padding: "0 12px",
              borderRadius: 10,
              border: "1px solid #000000ff",
              outline: "none",
            }}
          />
          <button
            disabled={!canLoad || loading}
            onClick={load}
            style={{
              height: 40,
              padding: "0 14px",
              borderRadius: 10,
              border: "1px solid #000000ff",
              background: "white",
              fontWeight: 700,
              cursor: loading ? "not-allowed" : "pointer",
            }}
          >
            {loading ? "Loading..." : "Load scans"}
          </button>
        </div>

        {error && (
          <div style={{ marginTop: 12, padding: 12, borderRadius: 12, border: "1px solid #f2b8b8" }}>
            <div style={{ fontWeight: 800, marginBottom: 6 }}>Error</div>
            <div style={{ fontSize: 13, whiteSpace: "pre-wrap" }}>{error}</div>
          </div>
        )}

        <div style={{ marginTop: 16, display: "grid", gridTemplateColumns: "360px 1fr", gap: 16 }}>
          <div style={{ border: "1px solid #eee", borderRadius: 14, padding: 12, minHeight: 420 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
              <div style={{ fontWeight: 800 }}>Scans</div>
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
                    <div style={{ fontWeight: 800 }}>#{s.scan_id}</div>
                    <div style={{ fontSize: 12, opacity: 0.7 }}>score: {s.exposure_score}</div>
                  </div>
                  <div style={{ fontSize: 12, opacity: 0.7, marginTop: 4 }}>{s.created_at}</div>
                </button>
              ))}

              {scans.length === 0 && (
                <div style={{ fontSize: 13, opacity: 0.7, padding: 10 }}>
                  No scans. Create one via agent or /docs, then Load scans.
                </div>
              )}
            </div>
          </div>

          <div style={{ border: "1px solid #eee", borderRadius: 14, padding: 12, minHeight: 420 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
              <div style={{ fontWeight: 800 }}>Scan detail</div>
              {detail && (
                <div style={{ fontSize: 12, opacity: 0.7 }}>
                  score: {detail.exposure_score} · findings: {detail.findings.length}
                </div>
              )}
            </div>

            {!detail && (
              <div style={{ marginTop: 10, fontSize: 13, opacity: 0.7 }}>
                Select a scan.
              </div>
            )}

            {detail && (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 13, opacity: 0.85 }}>
                  <div><b>device_id:</b> {detail.device_id}</div>
                  <div><b>created_at:</b> {detail.created_at}</div>
                </div>

                <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 10 }}>
                  {detail.findings.map((f) => (
                    <div key={`${detail.scan_id}:${f.rule_id}:${f.title}`}
                      style={{ border: "1px solid #eee", borderRadius: 14, padding: 12 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                        <div style={{ fontWeight: 900 }}>{f.title}</div>
                        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                          <span
                            style={{
                              border: `1px solid ${pillBorder(f.severity)}`,
                              borderRadius: 999,
                              padding: "2px 8px",
                              fontSize: 12,
                              fontWeight: 700,
                            }}
                          >
                            {f.severity}
                          </span>
                          <span style={{ fontSize: 12, opacity: 0.7 }}>{f.rule_id}</span>
                        </div>
                      </div>
                      <div style={{ marginTop: 8, fontSize: 13, opacity: 0.85 }}>
                        {f.recommendation}
                      </div>
                    </div>
                  ))}
                  {detail.findings.length === 0 && (
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
