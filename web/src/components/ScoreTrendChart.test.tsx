import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { ScoreTrendChart } from "./ScoreTrendChart";

// Mock pentru API call
vi.mock("../api/http", () => ({
  apiGet: vi.fn(),
}));

// Recharts foloseste ResizeObserver care nu exista in jsdom; mock-uim global
class ResizeObserverMock {
  constructor(_cb: ResizeObserverCallback) { /* mock */ }
  observe() {}
  unobserve() {}
  disconnect() {}
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).ResizeObserver = ResizeObserverMock;

import { apiGet } from "../api/http";


describe("ScoreTrendChart", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("afiseaza loading state initial", () => {
    (apiGet as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));
    render(<ScoreTrendChart deviceUid="dev1" />);
    expect(screen.getByText(/incarca/i)).toBeInTheDocument();
  });

  it("afiseaza mesaj empty cand nu sunt scanari", async () => {
    (apiGet as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    render(<ScoreTrendChart deviceUid="dev1" />);
    await waitFor(() => {
      expect(screen.getByText(/Nu exista scanari/i)).toBeInTheDocument();
    });
  });

  it("apeleaza endpoint-ul score-trend cu device uid si days", async () => {
    (apiGet as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    render(<ScoreTrendChart deviceUid="my-device" days={60} />);
    await waitFor(() => {
      expect(apiGet).toHaveBeenCalledWith(
        expect.stringContaining("/devices/my-device/score-trend"),
      );
    });
    const callArg = (apiGet as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(callArg).toContain("days=60");
  });

  it("foloseste days=30 ca default", async () => {
    (apiGet as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    render(<ScoreTrendChart deviceUid="dev1" />);
    await waitFor(() => {
      const callArg = (apiGet as ReturnType<typeof vi.fn>).mock.calls[0][0];
      expect(callArg).toContain("days=30");
    });
  });

  it("afiseaza eroare cand API esueaza", async () => {
    (apiGet as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("Server down"));
    render(<ScoreTrendChart deviceUid="dev1" />);
    await waitFor(() => {
      expect(screen.getByText(/Eroare/i)).toBeInTheDocument();
    });
  });

  it("face cleanup la unmount fara erori (no setState pe componenta unmount-ata)", () => {
    (apiGet as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));
    const { unmount } = render(<ScoreTrendChart deviceUid="dev1" />);
    expect(() => unmount()).not.toThrow();
  });
});
