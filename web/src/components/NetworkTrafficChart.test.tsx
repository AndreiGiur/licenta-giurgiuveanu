import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

vi.mock("../api/exposure", () => ({ getNetTraffic: vi.fn() }));

// Recharts foloseste ResizeObserver care nu exista in jsdom.
class ResizeObserverMock {
  constructor(_cb: ResizeObserverCallback) { /* mock */ }
  observe() {}
  unobserve() {}
  disconnect() {}
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).ResizeObserver = ResizeObserverMock;

import { getNetTraffic } from "../api/exposure";
import { NetworkTrafficChart } from "./NetworkTrafficChart";
const m = getNetTraffic as ReturnType<typeof vi.fn>;

describe("NetworkTrafficChart", () => {
  beforeEach(() => vi.clearAllMocks());

  it("afiseaza empty state cand nu sunt date", async () => {
    m.mockResolvedValue([]);
    render(<NetworkTrafficChart deviceUid="dev1" />);
    await waitFor(() =>
      expect(screen.getByText(/Niciun trafic/i)).toBeInTheDocument());
  });

  it("afiseaza ratele curente cand exista date", async () => {
    m.mockResolvedValue([
      { ts: 1, sent_rate_kbps: 12.5, recv_rate_kbps: 3.2, conn_count: 7 },
    ]);
    render(<NetworkTrafficChart deviceUid="dev1" />);
    await waitFor(() => {
      expect(screen.getByText(/12.5 KB\/s iesit/i)).toBeInTheDocument();
      expect(screen.getByText(/7 conexiuni active/i)).toBeInTheDocument();
    });
  });
});
