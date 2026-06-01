# Unified Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Unifica Dashboard + Dispozitive intr-o singura pagina master-detail (sidebar device-uri + workspace), cu explainer pentru tipul de scanare si typography responsiva.

**Architecture:** Pagina `UnifiedDashboard` = orchestrator subtire peste `DeviceSidebar` + `DeviceWorkspace` + `ScanTypeExplainer`, refolosind hooks-urile si componentele existente. Zero endpoint-uri noi. `/devices` redirectioneaza la `/dashboard`.

**Tech Stack:** React + TypeScript, Vite, Recharts, Framer Motion, vitest + @testing-library/react.

---

## Comenzi de test
- `cd web; npm test -- <pattern>` (un fisier) · `npm test` (tot) · `npx tsc -b` (type check)

---

# FAZA 1 — ScanTypeExplainer + SCAN_TYPE_INFO

### Task 1: Constanta SCAN_TYPE_INFO + componenta ScanTypeExplainer

**Files:**
- Create: `web/src/components/ScanTypeExplainer.tsx`
- Test: `web/src/components/ScanTypeExplainer.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
// web/src/components/ScanTypeExplainer.test.tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScanTypeExplainer } from "./ScanTypeExplainer";

describe("ScanTypeExplainer", () => {
  it("standard: arata durata + ce colecteaza", () => {
    render(<ScanTypeExplainer type="standard" />);
    expect(screen.getByText(/45-90s/i)).toBeInTheDocument();
    expect(screen.getByText(/porturi/i)).toBeInTheDocument();
  });
  it("deep: mentioneaza nmap agresiv / CVE", () => {
    render(<ScanTypeExplainer type="deep" />);
    expect(screen.getByText(/CVE|nmap agresiv/i)).toBeInTheDocument();
  });
  it("advanced: mentioneaza nmap moderat", () => {
    render(<ScanTypeExplainer type="advanced" />);
    expect(screen.getByText(/nmap moderat/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web; npm test -- ScanTypeExplainer`
Expected: FAIL — module not found

- [ ] **Step 3: Implement component + data**

```tsx
// web/src/components/ScanTypeExplainer.tsx
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
```

- [ ] **Step 4: Add CSS** in `web/src/index.css`:

```css
.scan-explainer {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 12px 14px;
  margin: 10px 0 16px;
  font-size: clamp(0.78rem, 1.6vw, 0.9rem);
}
.scan-explainer-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.scan-explainer-title { font-weight: 700; color: var(--text-primary); }
.scan-explainer-meta { font-size: 0.78em; color: var(--text-muted); font-family: "JetBrains Mono", monospace; }
.scan-explainer-sub { margin-top: 6px; color: var(--text-secondary); }
.scan-explainer-list { margin: 4px 0 0; padding-left: 18px; color: var(--text-secondary); }
.scan-explainer-list li { margin: 2px 0; }
.scan-explainer-nmap { margin-top: 8px; color: var(--accent); font-weight: 600; }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd web; npm test -- ScanTypeExplainer`
Expected: PASS (3)

- [ ] **Step 6: Commit**

```bash
git add web/src/components/ScanTypeExplainer.tsx web/src/components/ScanTypeExplainer.test.tsx web/src/index.css
git commit -m "feat(fe): ScanTypeExplainer + SCAN_TYPE_INFO (ce face fiecare tip de scan)"
```

---

# FAZA 2 — DeviceSidebar + DeviceWorkspace

### Task 2: DeviceSidebar

**Files:**
- Create: `web/src/components/DeviceSidebar.tsx`
- Test: `web/src/components/DeviceSidebar.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
// web/src/components/DeviceSidebar.test.tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { DeviceSidebar } from "./DeviceSidebar";

const devices = [
  { id: 1, device_uid: "pc1", name: "PC One", created_at: "x", is_online: true, lastScore: 42, scanCount: 3 },
  { id: 2, device_uid: "pc2", name: "PC Two", created_at: "x", is_online: false, lastScore: null, scanCount: 0 },
];

describe("DeviceSidebar", () => {
  it("listeaza device-urile", () => {
    render(<DeviceSidebar devices={devices} selectedUid="pc1" onSelect={() => {}} />);
    expect(screen.getByText("PC One")).toBeInTheDocument();
    expect(screen.getByText("PC Two")).toBeInTheDocument();
  });
  it("apeleaza onSelect la click", () => {
    const onSelect = vi.fn();
    render(<DeviceSidebar devices={devices} selectedUid="pc1" onSelect={onSelect} />);
    fireEvent.click(screen.getByText("PC Two"));
    expect(onSelect).toHaveBeenCalledWith("pc2");
  });
  it("empty state cand nu sunt device-uri", () => {
    render(<DeviceSidebar devices={[]} selectedUid={null} onSelect={() => {}} />);
    expect(screen.getByText(/niciun dispozitiv/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web; npm test -- DeviceSidebar`
Expected: FAIL — module not found

- [ ] **Step 3: Implement**

```tsx
// web/src/components/DeviceSidebar.tsx
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
      <div className="card-header"><span className="card-title">Dispozitive</span>
        <span className="card-badge">{devices.length}</span></div>
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
```

- [ ] **Step 4: Add CSS** in `web/src/index.css`:

```css
.device-sidebar-name {
  display: inline-flex; align-items: center;
  max-width: 170px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-weight: 600;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd web; npm test -- DeviceSidebar`
Expected: PASS (3)

- [ ] **Step 6: Commit**

```bash
git add web/src/components/DeviceSidebar.tsx web/src/components/DeviceSidebar.test.tsx web/src/index.css
git commit -m "feat(fe): DeviceSidebar (lista device-uri selectabila cu status + scor)"
```

---

### Task 3: DeviceWorkspace

**Files:**
- Create: `web/src/components/DeviceWorkspace.tsx`
- Test: `web/src/components/DeviceWorkspace.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
// web/src/components/DeviceWorkspace.test.tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

vi.mock("../api/exposure", () => ({
  listDeviceScans: vi.fn().mockResolvedValue([]),
  listScanJobs: vi.fn().mockResolvedValue([]),
  getScan: vi.fn().mockResolvedValue({ scan_id: 0, findings: [] }),
  getNetTraffic: vi.fn().mockResolvedValue([]),
  requestScan: vi.fn().mockResolvedValue({ job_id: 1 }),
}));
class RO { constructor(_: ResizeObserverCallback) {} observe() {} unobserve() {} disconnect() {} }
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).ResizeObserver = RO;

import { DeviceWorkspace } from "./DeviceWorkspace";

const device = { id: 1, device_uid: "pc1", name: "PC One", created_at: "x", is_online: true };

describe("DeviceWorkspace", () => {
  beforeEach(() => vi.clearAllMocks());

  it("afiseaza numele device-ului", () => {
    render(<DeviceWorkspace device={device} onDeleted={() => {}} />);
    expect(screen.getByText("PC One")).toBeInTheDocument();
  });

  it("afiseaza explainer-ul tipului de scanare implicit (standard)", () => {
    render(<DeviceWorkspace device={device} onDeleted={() => {}} />);
    expect(screen.getByText(/Scanare Standard/i)).toBeInTheDocument();
  });

  it("schimba explainer-ul cand selectezi deep", () => {
    render(<DeviceWorkspace device={device} onDeleted={() => {}} />);
    fireEvent.change(screen.getByLabelText(/tip scanare/i), { target: { value: "deep" } });
    expect(screen.getByText(/Scanare Deep/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web; npm test -- DeviceWorkspace`
Expected: FAIL — module not found

- [ ] **Step 3: Implement**

```tsx
// web/src/components/DeviceWorkspace.tsx
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import type { ScanType } from "../api/types";
import { requestScan } from "../api/exposure";
import { apiDelete } from "../api/http";
import { ScoreGauge } from "./ScoreGauge";
import { ConnectionTopology } from "./ConnectionTopology";
import { NetworkTrafficChart } from "./NetworkTrafficChart";
import { ScanTypeExplainer } from "./ScanTypeExplainer";
import { useScanJobPolling } from "../hooks/useScanJobPolling";
import { useScanDetail } from "../hooks/useScanDetail";
import { listDeviceScans } from "../api/exposure";
import { useEffect } from "react";
import type { DeviceScanListItem } from "../api/types";

type WorkspaceDevice = {
  id: number; device_uid: string; name: string;
  is_online?: boolean; last_heartbeat?: string | null;
};

export function DeviceWorkspace({ device, onDeleted }:
  { device: WorkspaceDevice; onDeleted: () => void }) {
  const navigate = useNavigate();
  const [scanType, setScanType] = useState<ScanType>("standard");
  const [scans, setScans] = useState<DeviceScanListItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);

  const uid = device.device_uid;

  async function loadScans() {
    try {
      const items = await listDeviceScans(uid);
      setScans(items);
      setSelectedScanId(items.length ? items[0].scan_id : null);
    } catch { setScans([]); }
  }
  useEffect(() => { loadScans(); /* eslint-disable-next-line */ }, [uid]);

  const activeJob = useScanJobPolling(uid, loadScans);
  const { detail } = useScanDetail(selectedScanId);

  async function onScanNow() {
    setBusy(true);
    try { await requestScan(uid, scanType); } finally { setBusy(false); }
  }

  async function onDelete() {
    if (!confirm(`Stergi dispozitivul ${device.name}?`)) return;
    await apiDelete(`/devices/${encodeURIComponent(uid)}`);
    onDeleted();
  }

  return (
    <div className="workspace">
      <div className="workspace-header">
        <h2 className="workspace-title" title={device.name}>
          {device.name}
          <span className="score-badge" style={{ marginLeft: 10, fontSize: 12 }}>
            {device.is_online ? "online" : "offline"}
          </span>
        </h2>
        <div className="workspace-actions">
          <label className="sr-only" htmlFor="scan-type">Tip scanare</label>
          <select id="scan-type" aria-label="Tip scanare" className="form-input"
            value={scanType} onChange={(e) => setScanType(e.target.value as ScanType)}
            style={{ width: 140 }}>
            <option value="standard">standard</option>
            <option value="advanced">advanced</option>
            <option value="deep">deep</option>
          </select>
          <button className="btn btn-accent" disabled={busy} onClick={onScanNow}>
            {busy ? "..." : "Scaneaza acum"}
          </button>
          <button className="btn btn-ghost btn-sm" onClick={onDelete}>Sterge</button>
        </div>
      </div>

      <ScanTypeExplainer type={scanType} />

      {activeJob && (activeJob.status === "running" || activeJob.status === "pending") && (
        <div className="job-progress">
          <div className="job-progress-bar">
            <div className="job-progress-fill" style={{ width: `${activeJob.progress ?? 0}%` }} />
          </div>
          <span className="job-progress-label">{activeJob.phase ?? "Pornire"} · {activeJob.progress ?? 0}%</span>
        </div>
      )}

      <div className="monitor-row">
        <div className="monitor-gauge">
          {detail ? <ScoreGauge value={detail.exposure_score} size={150} />
                  : <div className="empty-state">Nicio scanare inca.</div>}
        </div>
        <div className="card">
          <div className="card-header"><span className="card-title">Conexiune</span></div>
          <div className="card-body">
            <ConnectionTopology online={!!device.is_online}
              lastHeartbeat={device.last_heartbeat ?? null}
              scanActive={!!activeJob && activeJob.status === "running"} />
          </div>
        </div>
        <div className="card">
          <div className="card-header"><span className="card-title">Trafic de retea (live)</span></div>
          <div className="card-body"><NetworkTrafficChart deviceUid={uid} /></div>
        </div>
      </div>

      <div className="workspace-scans">
        <div className="card">
          <div className="card-header"><span className="card-title">Scanari</span>
            <span className="card-badge">{scans.length}</span></div>
          <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {scans.length === 0 && <div className="empty-state">Nicio scanare.</div>}
            {scans.map((s) => (
              <div key={s.scan_id} onClick={() => setSelectedScanId(s.scan_id)}
                className={`scan-item ${selectedScanId === s.scan_id ? "active" : ""}`}
                style={{ cursor: "pointer" }}>
                <div className="scan-item-row">
                  <span className="scan-id">#{s.scan_id}</span>
                  <span className="score-badge">{s.exposure_score}</span>
                </div>
                <div className="scan-date">{new Date(s.created_at).toLocaleString("ro-RO")}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="card">
          <div className="card-header"><span className="card-title">Findings</span>
            {detail && <button className="btn btn-ghost btn-sm"
              onClick={() => navigate(`/scans/${detail.scan_id}`)}>Detalii complete →</button>}</div>
          <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {!detail && <div className="empty-state">Selecteaza o scanare.</div>}
            {detail && detail.findings.length === 0 &&
              <div className="empty-state" style={{ color: "var(--green)" }}>Nicio vulnerabilitate.</div>}
            {detail && detail.findings.map((f) => (
              <div key={`${f.rule_id}:${f.title}`} className={`finding-card ${f.severity.toLowerCase()}`}>
                <div className="finding-header">
                  <span className="finding-title">{f.title}</span>
                  <span className={`severity-badge severity-${f.severity.toLowerCase()}`}>{f.severity}</span>
                </div>
                <div className="finding-rec">{f.recommendation}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Add CSS** in `web/src/index.css`:

```css
.workspace-header { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 4px; }
.workspace-title { margin: 0; font-size: clamp(1.1rem, 2.6vw, 1.6rem); display: flex; align-items: center; max-width: 100%; overflow: hidden; text-overflow: ellipsis; }
.workspace-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.monitor-row { display: grid; grid-template-columns: auto 1fr 1fr; gap: 16px; align-items: stretch; margin-bottom: 16px; }
.monitor-gauge { display: flex; align-items: center; justify-content: center; min-width: 160px; }
.workspace-scans { display: grid; grid-template-columns: 260px 1fr; gap: 16px; }
.job-progress { margin: 8px 0 16px; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); border: 0; }
@media (max-width: 900px) {
  .monitor-row { grid-template-columns: 1fr; }
  .workspace-scans { grid-template-columns: 1fr; }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd web; npm test -- DeviceWorkspace`
Expected: PASS (3)

- [ ] **Step 6: Commit**

```bash
git add web/src/components/DeviceWorkspace.tsx web/src/components/DeviceWorkspace.test.tsx web/src/index.css
git commit -m "feat(fe): DeviceWorkspace (monitor + scan + findings + explainer)"
```

---

# FAZA 3 — UnifiedDashboard + rutare + nav + cleanup

### Task 4: Pagina UnifiedDashboard

**Files:**
- Create: `web/src/pages/UnifiedDashboard.tsx`
- Test: `web/src/pages/UnifiedDashboard.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
// web/src/pages/UnifiedDashboard.test.tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

vi.mock("../api/http", () => ({ apiGet: vi.fn(), apiDelete: vi.fn(), API_BASE_URL: "/api/v1" }));
vi.mock("../api/exposure", () => ({
  listDeviceScans: vi.fn().mockResolvedValue([]),
  listScanJobs: vi.fn().mockResolvedValue([]),
  getScan: vi.fn().mockResolvedValue({ scan_id: 0, findings: [] }),
  getNetTraffic: vi.fn().mockResolvedValue([]),
  requestScan: vi.fn(),
  getAgentDownloadInfo: vi.fn().mockResolvedValue({ windows: { available: false }, linux: { available: false } }),
}));
vi.mock("../components/Navbar", () => ({ default: () => <nav /> }));
class RO { constructor(_: ResizeObserverCallback) {} observe() {} unobserve() {} disconnect() {} }
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).ResizeObserver = RO;

import UnifiedDashboard from "./UnifiedDashboard";
import { apiGet } from "../api/http";
const mGet = apiGet as ReturnType<typeof vi.fn>;

function renderPage() {
  return render(<MemoryRouter><UnifiedDashboard /></MemoryRouter>);
}

describe("UnifiedDashboard", () => {
  beforeEach(() => vi.clearAllMocks());

  it("preselecteaza primul device si arata workspace-ul", async () => {
    mGet.mockResolvedValue([{ id: 1, device_uid: "pc1", name: "PC One", created_at: "x", is_online: true }]);
    renderPage();
    await waitFor(() => expect(screen.getByText("PC One")).toBeInTheDocument());
    // explainer-ul din workspace
    await waitFor(() => expect(screen.getByText(/Scanare Standard/i)).toBeInTheDocument());
  });

  it("empty state cand nu sunt device-uri", async () => {
    mGet.mockResolvedValue([]);
    renderPage();
    await waitFor(() => expect(screen.getByText(/Niciun dispozitiv/i)).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web; npm test -- UnifiedDashboard`
Expected: FAIL — module not found

- [ ] **Step 3: Implement**

```tsx
// web/src/pages/UnifiedDashboard.tsx
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
```

- [ ] **Step 4: Add CSS** in `web/src/index.css`:

```css
.unified-grid { display: grid; grid-template-columns: 260px 1fr; gap: 16px; align-items: start; }
@media (max-width: 900px) { .unified-grid { grid-template-columns: 1fr; } }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd web; npm test -- UnifiedDashboard`
Expected: PASS (2)

- [ ] **Step 6: Commit**

```bash
git add web/src/pages/UnifiedDashboard.tsx web/src/pages/UnifiedDashboard.test.tsx web/src/index.css
git commit -m "feat(fe): pagina UnifiedDashboard (master-detail orchestrator)"
```

---

### Task 5: Rutare + Navbar + cleanup pagini vechi + mockup

**Files:**
- Modify: `web/src/App.tsx`
- Modify: `web/src/components/Navbar.tsx`
- Delete: `web/src/pages/Dashboard.tsx`, `web/src/pages/Dashboard.test.tsx`,
  `web/src/pages/Devices.tsx`, `web/src/pages/UnifyMockup.tsx`

- [ ] **Step 1: Update App.tsx**

Inlocuieste importurile + rutele:
```tsx
import UnifiedDashboard from "./pages/UnifiedDashboard";
// sterge: import Dashboard, import Devices, import UnifyMockup
```
Ruta `/dashboard` → `<UnifiedDashboard />`. Ruta `/devices` →
`<Navigate to="/dashboard" replace />`. Sterge ruta `/mockup`.

- [ ] **Step 2: Update Navbar.tsx**

Scoate link-ul "Dispozitive" (`to="/devices"`). Pastreaza link-ul "Dashboard"
(`to="/dashboard"`). Daca exista un test Navbar care asteapta "Dispozitive",
actualizeaza-l in Task 6.

- [ ] **Step 3: Delete old files**

```bash
git rm web/src/pages/Dashboard.tsx web/src/pages/Dashboard.test.tsx web/src/pages/Devices.tsx web/src/pages/UnifyMockup.tsx
```

- [ ] **Step 4: Type check**

Run: `cd web; npx tsc -b`
Expected: PASS (daca raman importuri moarte catre fisierele sterse, rezolva-le).

- [ ] **Step 5: Commit**

```bash
git add web/src/App.tsx web/src/components/Navbar.tsx
git commit -m "refactor(fe): /dashboard unificat, redirect /devices, sterge pagini vechi + mockup"
```

---

# FAZA 4 — Teste + memory.md + verificare

### Task 6: Fix teste afectate + suita verde + memory.md

**Files:**
- Modify: `web/src/components/Navbar.test.tsx` (daca verifica "Dispozitive")
- Modify: memory.md: `web/src/pages/memory.md`, `web/src/components/memory.md`

- [ ] **Step 1: Update Navbar.test.tsx**

Daca testul `afiseaza link-urile Dashboard, Dispozitive, Profil` exista, scoate
asertiunea pe "Dispozitive" (nu mai exista link). Pastreaza Dashboard + Profil.

- [ ] **Step 2: Ruleaza intreaga suita + tsc**

Run: `cd web; npx tsc -b; npm test`
Expected: toate verzi.

- [ ] **Step 3: Update memory.md**

`web/src/pages/memory.md`: inlocuieste intrarile `Dashboard.tsx` + `Devices.tsx`
cu `UnifiedDashboard.tsx` (master-detail: DeviceSidebar + DeviceWorkspace +
ScanTypeExplainer; `/devices` redirect). Actualizeaza tabelul de rute.
`web/src/components/memory.md`: adauga `DeviceSidebar.tsx`, `DeviceWorkspace.tsx`,
`ScanTypeExplainer.tsx`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "test+docs: actualizare teste Navbar + memory.md pentru dashboard unificat"
```

---

## Self-Review

**Spec coverage:** A (rutare/nav)→Task 5 | B (layout)→Task 4 | C (componente: Sidebar→T2,
Workspace→T3, Explainer→T1)→Task 1-3 | D (typography responsiva: clamp + media queries)→
Task 1,3,4 CSS | E (migrare logica)→Task 3,4 | F (testare)→Task 1-4,6. Toate acoperite. ✓
**Placeholders:** cod real in fiecare step; fara TBD. ✓
**Type consistency:** `SidebarDevice` (Sidebar), `WorkspaceDevice` (Workspace),
`SCAN_TYPE_INFO`/`ScanTypeExplainer`, `Device` (types.ts) folosite consistent;
`requestScan(uid, scanType)`, `apiDelete`, `listDeviceScans`, hooks refolosite cu
semnaturile existente. ✓
**Cleanup:** mockup `/mockup` + `UnifyMockup.tsx` sterse in Task 5; pagini vechi sterse. ✓
**Risc:** Navbar.test poate verifica "Dispozitive" → Task 6 il repara. Dashboard.test
vechi sters in Task 5 (inlocuit de UnifiedDashboard.test).
