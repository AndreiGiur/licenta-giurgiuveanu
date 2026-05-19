import type { NmapHost } from "../api/types";

interface Props { host: NmapHost; }

export default function NmapHostCard({ host }: Props) {
  const role = host.topology?.role ?? "unknown";
  const risk = host.topology?.risk_score ?? 0;
  const openPorts = (host.ports || []).filter(p => p.state === "open");
  return (
    <div className="nmap-host-card">
      <header className="nmap-host-header">
        <span className="nmap-host-ip">{host.ip}</span>
        {host.hostname && <span className="nmap-host-name">({host.hostname})</span>}
        <span className={`nmap-role nmap-role-${role}`}>{role}</span>
        <span className="nmap-risk">risc {risk}/100</span>
      </header>
      {host.os_guess && <div className="nmap-os">OS: {host.os_guess}</div>}
      {openPorts.length > 0 && (
        <div className="nmap-ports">
          {openPorts.map(p => (
            <div key={`${p.proto}-${p.port}`} className="nmap-port">
              <code>{p.port}/{p.proto}</code> {p.service}
              {p.version && <span className="nmap-version"> {p.version}</span>}
            </div>
          ))}
        </div>
      )}
      {host.vulnwatch_findings && host.vulnwatch_findings.length > 0 && (
        <div className="nmap-findings">
          <h4>Findings ({host.vulnwatch_findings.length})</h4>
          {host.vulnwatch_findings.map((f, i) => (
            <div key={i} className={`nmap-finding sev-${f.severity}`}>
              <span className="finding-rule">{f.rule_id}</span>{" "}
              <span className="finding-title">{f.title}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
