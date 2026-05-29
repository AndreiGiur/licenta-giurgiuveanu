import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { useScanDetail } from "./useScanDetail";

vi.mock("../api/exposure", () => ({
  getScan: vi.fn(),
}));

import { getScan } from "../api/exposure";

const mockGetScan = getScan as ReturnType<typeof vi.fn>;

describe("useScanDetail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("nu apeleaza getScan cand scanId e null", () => {
    const { result } = renderHook(() => useScanDetail(null));
    expect(mockGetScan).not.toHaveBeenCalled();
    expect(result.current.detail).toBeNull();
  });

  it("incarca detaliul cand scanId e setat", async () => {
    mockGetScan.mockResolvedValue({ scan_id: 7, findings: [] });
    const { result } = renderHook(() => useScanDetail(7));
    await waitFor(() => {
      expect(result.current.detail).toEqual({ scan_id: 7, findings: [] });
    });
    expect(mockGetScan).toHaveBeenCalledWith(7);
  });

  it("seteaza error cand getScan esueaza", async () => {
    mockGetScan.mockRejectedValue(new Error("boom"));
    const { result } = renderHook(() => useScanDetail(9));
    await waitFor(() => {
      expect(result.current.error).toBe("boom");
    });
  });

  it("reincarca cand scanId se schimba", async () => {
    mockGetScan.mockResolvedValue({ scan_id: 1, findings: [] });
    const { rerender } = renderHook(({ id }) => useScanDetail(id), {
      initialProps: { id: 1 as number | null },
    });
    await waitFor(() => expect(mockGetScan).toHaveBeenCalledWith(1));
    mockGetScan.mockResolvedValue({ scan_id: 2, findings: [] });
    rerender({ id: 2 });
    await waitFor(() => expect(mockGetScan).toHaveBeenCalledWith(2));
  });

  it("nu arunca daca se demonteaza inainte de raspuns", () => {
    mockGetScan.mockReturnValue(new Promise(() => {})); // never resolves
    const { unmount } = renderHook(() => useScanDetail(5));
    expect(() => unmount()).not.toThrow();
  });
});
