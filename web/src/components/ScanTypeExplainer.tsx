import type { ScanType } from "../api/types";

type Info = {
  label: string;
  duration: string;
  rules: number;
  collects: string[];
  nmap?: string;
};

export const SCAN_TYPE_INFO: Record<ScanType, Info> = {
  standard: {
    label: "Standard",
    duration: "~45-90s",
    rules: 9,
    collects: [
      "Porturi in ascultare (LISTEN)",
      "Sistem de operare + versiune",
      "Stare firewall",
      "Utilizatori locali",
      "Top 30 procese",
      "Software instalat",
    ],
  },
  advanced: {
    label: "Advanced",
    duration: "~3-8 min",
    rules: 15,
    collects: [
      "Toate procesele + linia de comanda",
      "Legatura port -> proces",
      "Conexiuni active (ESTABLISHED)",
      "Servicii, chei de startup, scheduled tasks",
      "Share-uri de retea + politica PowerShell",
      "Adaptoare de retea",
    ],
    nmap: "nmap moderat: versiuni de servicii, top 5000 porturi",
  },
  deep: {
    label: "Deep",
    duration: "~10-20 min",
    rules: 23,
    collects: [
      "Subscriptii WMI (persistenta)",
      "AppInit_DLLs / IFEO / Winlogon",
      "Security event log (login esuat / privilegii / cont nou)",
      "hosts, DNS + ARP",
      "Certificate root, BitLocker, Defender",
      "Fisiere recent modificate in System32 / Program Files",
    ],
    nmap: "nmap agresiv: detectie CVE (NSE vuln), topologie retea, OS fingerprint",
  },
};

/** Panou care explica ce face tipul de scanare selectat (educativ). */
export function ScanTypeExplainer({ type }: { type: ScanType }) {
  const info = SCAN_TYPE_INFO[type];
  return (
    <div className="scan-explainer">
      <div className="scan-explainer-head">
        <span className="scan-explainer-title">Scanare {info.label}</span>
        <span className="scan-explainer-meta">{info.duration} · {info.rules} reguli</span>
      </div>
      <div className="scan-explainer-sub">Ce se intampla in aceasta scanare:</div>
      <ul className="scan-explainer-list">
        {info.collects.map((c) => <li key={c}>{c}</li>)}
      </ul>
      {info.nmap && <div className="scan-explainer-nmap">+ {info.nmap}</div>}
    </div>
  );
}
