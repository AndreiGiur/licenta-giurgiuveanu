import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { useNetworkTraffic } from "./useNetworkTraffic";

vi.mock("../api/exposure", () => ({ getNetTraffic: vi.fn() }));
import { getNetTraffic } from "../api/exposure";
const m = getNetTraffic as ReturnType<typeof vi.fn>;

describe("useNetworkTraffic", () => {
  beforeEach(() => vi.clearAllMocks());

  it("nu fetch-uieste cand uid e gol", () => {
    const { result } = renderHook(() => useNetworkTraffic(""));
    expect(m).not.toHaveBeenCalled();
    expect(result.current).toEqual([]);
  });

  it("intoarce seria primita de la API", async () => {
    m.mockResolvedValue([{ ts: 1, sent_rate_kbps: 5, recv_rate_kbps: 2, conn_count: 3 }]);
    const { result } = renderHook(() => useNetworkTraffic("dev1"));
    await waitFor(() => expect(result.current.length).toBe(1));
    expect(result.current[0].conn_count).toBe(3);
  });

  it("apeleaza endpoint-ul cu device uid", async () => {
    m.mockResolvedValue([]);
    renderHook(() => useNetworkTraffic("my-dev"));
    await waitFor(() => expect(m).toHaveBeenCalledWith("my-dev"));
  });

  it("nu arunca la eroare de retea", async () => {
    m.mockRejectedValue(new Error("offline"));
    const { result } = renderHook(() => useNetworkTraffic("dev1"));
    await waitFor(() => expect(m).toHaveBeenCalled());
    expect(result.current).toEqual([]);
  });
});
