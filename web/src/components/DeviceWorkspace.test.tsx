import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

vi.mock("../api/exposure", () => ({
  listDeviceScans: vi.fn().mockResolvedValue([]),
  listScanJobs: vi.fn().mockResolvedValue([]),
  getScan: vi.fn().mockResolvedValue({ scan_id: 0, findings: [] }),
  getNetTraffic: vi.fn().mockResolvedValue([]),
  requestScan: vi.fn().mockResolvedValue({ job_id: 1 }),
}));
vi.mock("../api/http", () => ({ apiDelete: vi.fn(), API_BASE_URL: "/api/v1" }));
class RO { constructor(_: ResizeObserverCallback) {} observe() {} unobserve() {} disconnect() {} }
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).ResizeObserver = RO;

import { DeviceWorkspace } from "./DeviceWorkspace";

const device = { id: 1, device_uid: "pc1", name: "PC One", is_online: true };

function renderWs() {
  return render(
    <MemoryRouter><DeviceWorkspace device={device} onDeleted={() => {}} /></MemoryRouter>,
  );
}

describe("DeviceWorkspace", () => {
  beforeEach(() => vi.clearAllMocks());

  it("afiseaza numele device-ului", () => {
    renderWs();
    expect(screen.getByText("PC One")).toBeInTheDocument();
  });

  it("afiseaza explainer-ul tipului de scanare implicit (standard)", () => {
    renderWs();
    expect(screen.getByText(/Scanare Standard/i)).toBeInTheDocument();
  });

  it("schimba explainer-ul cand selectezi deep", () => {
    renderWs();
    fireEvent.change(screen.getByLabelText(/tip scanare/i), { target: { value: "deep" } });
    expect(screen.getByText(/Scanare Deep/i)).toBeInTheDocument();
  });
});
