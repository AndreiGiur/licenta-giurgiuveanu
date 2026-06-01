export type SidebarDevice = {
  id: number;
  device_uid: string;
  name: string;
  is_online?: boolean;
  lastScore: number | null;
  scanCount: number;
};

type Props = {
  devices: SidebarDevice[];
  selectedUid: string | null;
  onSelect: (uid: string) => void;
};

export function DeviceSidebar({ devices, selectedUid, onSelect }: Props) {
  return (
    <div className="card device-sidebar">
      <div className="card-header">
        <span className="card-title">Dispozitive</span>
        <span className="card-badge">{devices.length}</span>
      </div>
      <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {devices.length === 0 && (
          <div className="empty-state">Niciun dispozitiv conectat.</div>
        )}
        {devices.map((d) => (
          <div key={d.device_uid}
            className={`scan-item ${selectedUid === d.device_uid ? "active" : ""}`}
            style={{ cursor: "pointer" }}
            onClick={() => onSelect(d.device_uid)}>
            <div className="scan-item-row">
              <span className="device-sidebar-name" title={d.name}>
                <span className={`topo-dot ${d.is_online ? "topo-dot-ok" : "topo-dot-off"}`}
                      style={{ marginBottom: 0, marginRight: 8, display: "inline-block" }} />
                {d.name}
              </span>
              {d.lastScore !== null && <span className="score-badge">{d.lastScore}</span>}
            </div>
            <div className="scan-date">
              {d.is_online ? "online" : "offline"} · {d.scanCount} scanari
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
