import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { getScan } from "../api/exposure";
import type { ScanDetailResponse, Finding } from "../api/types";

function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "high":
      return "#ef4444";
    case "medium":
      return "#f59e0b";
    case "low":
      return "#22c55e";
    default:
      return "#9ca3af";
  }
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div
      style={{
        border: "1px solid #2a2a2a",
        borderRadius: 12,
        padding: 14,
        background: "#0f0f0f",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 12,
        }}
      >
        <div style={{ fontWeight: 700 }}>{finding.title}</div>
        <div
          style={{
            border: `1px solid ${severityColor(finding.severity)}`,
            color: severityColor(finding.severity),
            borderRadius: 999,
            padding: "2px 10px",
            fontSize: 12,
            fontWeight: 700,
          }}
        >
          {finding.severity}
        </div>
      </div>

      <div style={{ marginTop: 8, fontSize: 13, color: "#cfcfcf" }}>
        {finding.recommendation}
      </div>

      <div style={{ marginTop: 6, fontSize: 11, opacity: 0.6 }}>
        Rule: {finding.rule_id}
      </div>
    </div>
  );
}

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

  const [data, setData] = useState<ScanDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const id = Number(scanId);
    if (!Number.isInteger(id)) {
      setError("Invalid scan id");
      setLoading(false);
      return;
    }

    let cancelled = false;

    async function load() {
      try {
        const res = await getScan(id);
        if (!cancelled) setData(res);
      } catch (e) {
        if (!cancelled)
          setError(e instanceof Error ? e.message : "Failed to load scan");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#0b0b0b",
        color: "#e5e5e5",
        fontFamily:
          "system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell",
      }}
    >
      <div style={{ maxWidth: 900, margin: "0 auto", padding: "40px 16px" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "baseline",
            marginBottom: 20,
          }}
        >
          <h1 style={{ margin: 0, fontSize: 24, fontWeight: 800 }}>
            Scan #{scanId}
          </h1>
          <button
            onClick={() => navigate("/dashboard")}
            style={{
              background: "transparent",
              color: "#e5e5e5",
              border: "1px solid #2a2a2a",
              borderRadius: 10,
              padding: "6px 12px",
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            Back
          </button>
        </div>

        {loading && <div style={{ opacity: 0.7 }}>Loading scan…</div>}

        {error && (
          <div
            style={{
              border: "1px solid #7f1d1d",
              borderRadius: 12,
              padding: 14,
              background: "#160b0b",
            }}
          >
            {error}
          </div>
        )}

        {data && (
          <>
            <div
              style={{
                border: "1px solid #2a2a2a",
                borderRadius: 14,
                padding: 14,
                marginBottom: 20,
                background: "#0f0f0f",
                fontSize: 13,
              }}
            >
              <div>
                <strong>Device:</strong> {data.device_id}
              </div>
              <div>
                <strong>Created:</strong> {data.created_at}
              </div>
              <div>
                <strong>Exposure score:</strong> {data.exposure_score}
              </div>
            </div>

            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: 12,
              }}
            >
              {data.findings.length === 0 && (
                <div style={{ opacity: 0.7 }}>No findings detected.</div>
              )}

              {data.findings.map((f) => (
                <FindingCard
                  key={`${data.scan_id}-${f.rule_id}-${f.title}`}
                  finding={f}
                />
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
