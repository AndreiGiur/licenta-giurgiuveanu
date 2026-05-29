import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

// ── Mock-uri ─────────────────────────────────────────────────────────────────
vi.mock("../api/http", () => ({ apiGet: vi.fn() }));
vi.mock("../api/exposure", () => ({
  listDeviceScans: vi.fn(),
  listScanJobs: vi.fn(),
  getScan: vi.fn(),
}));
vi.mock("../components/Navbar", () => ({ default: () => <nav data-testid="navbar" /> }));

import Dashboard from "./Dashboard";
import { apiGet } from "../api/http";
import { listDeviceScans, listScanJobs, getScan } from "../api/exposure";

const mockApiGet = apiGet as ReturnType<typeof vi.fn>;
const mockListScans = listDeviceScans as ReturnType<typeof vi.fn>;
const mockListJobs = listScanJobs as ReturnType<typeof vi.fn>;
const mockGetScan = getScan as ReturnType<typeof vi.fn>;

function renderDashboard() {
  return render(
    <MemoryRouter initialEntries={["/dashboard"]}>
      <Dashboard />
    </MemoryRouter>,
  );
}

describe("Dashboard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListJobs.mockResolvedValue([]);     // fara job activ
    mockListScans.mockResolvedValue([]);    // fara scanari by default
    mockGetScan.mockResolvedValue({ scan_id: 0, findings: [] });
  });

  it("afiseaza titlul paginii", async () => {
    mockApiGet.mockResolvedValue([]);
    renderDashboard();
    expect(screen.getByText("Security Dashboard")).toBeInTheDocument();
  });

  it("afiseaza dispozitivele din /devices in picker", async () => {
    mockApiGet.mockResolvedValue([
      { id: 1, device_uid: "pc1", name: "PC One", created_at: "2026-01-01" },
      { id: 2, device_uid: "pc2", name: "PC Two", created_at: "2026-01-02" },
    ]);
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText(/PC One \(pc1\)/)).toBeInTheDocument();
      expect(screen.getByText(/PC Two \(pc2\)/)).toBeInTheDocument();
    });
  });

  it("preselecteaza singurul device si incarca scanarile (empty state)", async () => {
    mockApiGet.mockResolvedValue([
      { id: 1, device_uid: "solo", name: "Solo PC", created_at: "2026-01-01" },
    ]);
    renderDashboard();
    await waitFor(() => {
      expect(mockListScans).toHaveBeenCalledWith("solo");
    });
    await waitFor(() => {
      expect(screen.getByText(/Nicio scanare/i)).toBeInTheDocument();
    });
  });

  it("afiseaza scanarile in lista cand exista", async () => {
    mockApiGet.mockResolvedValue([
      { id: 1, device_uid: "solo", name: "Solo PC", created_at: "2026-01-01" },
    ]);
    mockListScans.mockResolvedValue([
      { scan_id: 10, created_at: "2026-05-01T10:00:00Z", exposure_score: 42 },
    ]);
    mockGetScan.mockResolvedValue({
      scan_id: 10, device_uid: "solo", device_name: "Solo PC",
      created_at: "2026-05-01T10:00:00Z", exposure_score: 42,
      score_breakdown: null, findings: [], payload: {}, scan_type: "standard",
    });
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText("#10")).toBeInTheDocument();
    });
  });

  it("afiseaza alerta de eroare cand incarcarea scanarilor esueaza", async () => {
    mockApiGet.mockResolvedValue([
      { id: 1, device_uid: "solo", name: "Solo PC", created_at: "2026-01-01" },
    ]);
    mockListScans.mockRejectedValue(new Error("backend down"));
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText("backend down")).toBeInTheDocument();
    });
  });

  it("afiseaza optiunea 'niciun dispozitiv' cand userul nu are device-uri", async () => {
    mockApiGet.mockResolvedValue([]);
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText(/Niciun dispozitiv inrolat/i)).toBeInTheDocument();
    });
  });
});
