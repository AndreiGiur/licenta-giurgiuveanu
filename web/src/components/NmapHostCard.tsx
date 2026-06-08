import type { NmapHost } from "../api/types";
import { InfoTip } from "./InfoTip";

interface Props { host: NmapHost; }

export default function NmapHostCard({ host }: Props) {
  const role = host.topology?.role ?? "unknown";
  const risk = host.topology?.risk_score ?? 0;
  const openPorts = (host.ports || []).filter(p => p.state === "open");
  return (
    <div className="nmap-host-card">
      <header className="nmap-host-header">
        <span className="nmap-host-ip">{host.ip}</span>
        <InfoTip topic="nmap-host" size={14} />
        {host.hostname && <span className="nmap-host-name">({host.hostname})</span>}
        <span className={`nmap-role nmap-role-${role}`}>{role}</span>
        <InfoTip topic="nmap-role" size={14} />
        <span className="nmap-risk">risc {risk}/100</span>
        <InfoTip topic="nmap-risk" size={14} />
      </header>
      {host.os_guess && <div className="nmap-os">OS: {host.os_guess}<InfoTip topic="nmap-os" size={14} /></div>}
      {openPorts.length > 0 && (
        <div className="nmap-ports">
          <div className="nmap-ports-label">Porturi deschise<InfoTip topic="nmap-ports" size={14} /></div>
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
          <h4>Findings ({host.vulnwatch_findings.length})<InfoTip topic="nmap-findings" size={14} /></h4>
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
