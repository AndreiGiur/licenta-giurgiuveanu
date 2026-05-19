import type { NmapData } from "../api/types";
import NmapHostCard from "./NmapHostCard";

interface Props { nmap: NmapData; }

export default function NmapSection({ nmap }: Props) {
  if (nmap.error) {
    return (
      <section className="nmap-section">
        <h2>Network scan (nmap)</h2>
        <div className="nmap-error">⚠ Faza nmap eşuată: {nmap.error}</div>
      </section>
    );
  }
  return (
    <section className="nmap-section">
      <h2>Network scan {nmap.version ? `(nmap ${nmap.version})` : "(nmap)"}</h2>
      <div className="nmap-meta">
        Scanat: {nmap.targets?.join(", ") || "?"} ·
        {" "}Durată: {nmap.scan_time_sec ?? "?"}s ·
        {" "}{nmap.hosts?.length ?? 0} host-uri descoperite
      </div>
      <div className="nmap-hosts">
        {(nmap.hosts || []).map(h => <NmapHostCard key={h.ip} host={h} />)}
      </div>
      {nmap.lua_errors && nmap.lua_errors.length > 0 && (
        <details className="nmap-lua-errors">
          <summary>Lua warnings ({nmap.lua_errors.length})</summary>
          <pre>{nmap.lua_errors.join("\n")}</pre>
        </details>
      )}
    </section>
  );
}
