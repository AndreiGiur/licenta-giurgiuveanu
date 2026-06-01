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
  getAgentDownloadInfo: vi.fn().mockResolvedValue({
    windows: { available: false, size_bytes: null },
    linux: { available: false, size_bytes: null },
  }),
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

  it("preselecteaza primul device si arata workspace-ul cu explainer", async () => {
    mGet.mockResolvedValue([{ id: 1, device_uid: "pc1", name: "PC One", created_at: "x", is_online: true }]);
    renderPage();
    // "PC One" apare in sidebar + in header-ul workspace-ului (corect)
    await waitFor(() => expect(screen.getAllByText("PC One").length).toBeGreaterThanOrEqual(1));
    await waitFor(() => expect(screen.getByText(/Scanare Standard/i)).toBeInTheDocument());
  });

  it("empty state cand nu sunt device-uri", async () => {
    mGet.mockResolvedValue([]);
    renderPage();
    await waitFor(() =>
      expect(screen.getAllByText(/Niciun dispozitiv/i).length).toBeGreaterThanOrEqual(1));
  });
});
