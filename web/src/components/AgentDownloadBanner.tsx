import { useEffect, useState } from "react";
import { getAgentDownloadInfo } from "../api/exposure";
import { API_BASE_URL } from "../api/http";
import { detectOS } from "../api/os";

type OsBuild = { available: boolean; size_bytes: number | null };
type OsKey = "windows" | "linux";

/** Banner OS-aware pentru descarcarea agentului: detecteaza OS-ul clientului si
 *  ofera artefactul potrivit (.exe Windows / binar Linux) + link spre celalalt. */
export function AgentDownloadBanner() {
  const [info, setInfo] = useState<{ windows: OsBuild; linux: OsBuild } | null>(null);
  const clientOS = detectOS();

  useEffect(() => {
    const empty: OsBuild = { available: false, size_bytes: null };
    getAgentDownloadInfo()
      .then((i) => setInfo({ windows: i.windows, linux: i.linux }))
      .catch(() => setInfo({ windows: empty, linux: empty }));
  }, []);

  const mb = (b: number | null) => (b ? `(${(b / (1024 * 1024)).toFixed(1)} MB)` : "");
  const primaryOS: OsKey = clientOS === "linux" ? "linux" : "windows";
  const otherOS: OsKey = primaryOS === "windows" ? "linux" : "windows";
  const build = (os: OsKey) => (os === "windows" ? info?.windows : info?.linux);
  const label = (os: OsKey) =>
    os === "windows"
      ? `↓ Descarca .exe (Windows) ${mb(info?.windows.size_bytes ?? null)}`
      : `↓ Descarca installer (Linux .sh)`;

  const primary = build(primaryOS);
  const other = build(otherOS);

  return (
    <div className="agent-download-banner">
      <div style={{ flex: 1, minWidth: 240 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 2 }}>
          Instaleaza VulnWatch Agent
        </div>
        <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
          Descarca, ruleaza, completeaza email-ul si parola in fereastra. Zero terminal.
        </div>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6, alignItems: "flex-end" }}>
        {primary?.available ? (
          <a href={`${API_BASE_URL}/agent/download/${primaryOS}`}
             className="btn btn-accent" style={{ textDecoration: "none" }}>
            {label(primaryOS)}
          </a>
        ) : (
          <span style={{ fontSize: 12, color: "var(--text-muted)", fontStyle: "italic" }}>
            Build {primaryOS} indisponibil pe server.
          </span>
        )}
        {other?.available && (
          <a href={`${API_BASE_URL}/agent/download/${otherOS}`}
             style={{ fontSize: 11, color: "var(--text-secondary)" }}>
            Alt sistem de operare: {label(otherOS)}
          </a>
        )}
      </div>
    </div>
  );
}
