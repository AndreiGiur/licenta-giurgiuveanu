import { useEffect, useState, useCallback } from "react";
import { apiGet } from "../api/http";
import Navbar from "../components/Navbar";
import { DeviceSidebar, type SidebarDevice } from "../components/DeviceSidebar";
import { DeviceWorkspace } from "../components/DeviceWorkspace";
import type { Device } from "../api/types";

export default function UnifiedDashboard() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedUid, setSelectedUid] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadDevices = useCallback(async () => {
    try {
      const items = await apiGet<Device[]>("/devices");
      setDevices(items);
      setSelectedUid((cur) => {
        if (cur && items.some((d) => d.device_uid === cur)) return cur;
        const online = items.find((d) => d.is_online);
        return (online ?? items[0])?.device_uid ?? null;
      });
    } catch {
      setDevices([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadDevices(); }, [loadDevices]);

  const sidebarDevices: SidebarDevice[] = devices.map((d) => ({
    id: d.id, device_uid: d.device_uid, name: d.name, is_online: d.is_online,
    lastScore: null, scanCount: 0,
  }));
  const selected = devices.find((d) => d.device_uid === selectedUid) ?? null;

  return (
    <div className="page">
      <Navbar />
      <div className="container" style={{ paddingTop: 24, paddingBottom: 48 }}>
        <div className="page-header">
          <h1 className="page-title" style={{ fontSize: "clamp(1.4rem, 3vw, 2rem)" }}>Dashboard</h1>
          <p className="page-subtitle">Dispozitivele tale, monitorizare si scanari intr-un singur loc</p>
        </div>
        {loading ? (
          <div className="empty-state">Se incarca...</div>
        ) : (
          <div className="unified-grid">
            <DeviceSidebar devices={sidebarDevices} selectedUid={selectedUid} onSelect={setSelectedUid} />
            {selected ? (
              <DeviceWorkspace key={selected.device_uid} device={selected} onDeleted={loadDevices} />
            ) : (
              <div className="card"><div className="card-body">
                <div className="empty-state">
                  Niciun dispozitiv selectat. Descarca agentul si inroleaza primul dispozitiv.
                </div>
              </div></div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
