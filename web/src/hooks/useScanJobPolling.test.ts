import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { useScanJobPolling } from "./useScanJobPolling";

vi.mock("../api/exposure", () => ({
  listScanJobs: vi.fn(),
}));

import { listScanJobs } from "../api/exposure";

const mockListJobs = listScanJobs as ReturnType<typeof vi.fn>;

function job(overrides: Record<string, unknown>) {
  return {
    job_id: 1, device_uid: "dev1", device_name: "Dev", status: "pending",
    created_at: "2026-01-01T00:00:00Z", started_at: null, finished_at: null,
    scan_id: null, exposure_score: null, error_message: null,
    scan_type: "standard", progress: 0, phase: null,
    ...overrides,
  };
}

describe("useScanJobPolling", () => {
  beforeEach(() => vi.clearAllMocks());
  afterEach(() => vi.restoreAllMocks());

  it("nu polleaza cand deviceUid e gol", () => {
    const { result } = renderHook(() => useScanJobPolling("", () => {}));
    expect(mockListJobs).not.toHaveBeenCalled();
    expect(result.current).toBeNull();
  });

  it("intoarce job-ul activ (running)", async () => {
    mockListJobs.mockResolvedValue([job({ status: "running", job_id: 5, progress: 40 })]);
    const { result } = renderHook(() => useScanJobPolling("dev1", () => {}));
    await waitFor(() => {
      expect(result.current?.job_id).toBe(5);
      expect(result.current?.status).toBe("running");
    });
  });

  it("intoarce null cand nu exista job activ", async () => {
    mockListJobs.mockResolvedValue([job({ status: "done", job_id: 3, scan_id: 99 })]);
    const { result } = renderHook(() => useScanJobPolling("dev1", () => {}));
    await waitFor(() => expect(mockListJobs).toHaveBeenCalled());
    expect(result.current).toBeNull();
  });

  it("apeleaza onJobDone cand un job tocmai s-a finalizat", async () => {
    mockListJobs.mockResolvedValue([job({ status: "done", job_id: 3, scan_id: 99 })]);
    const onJobDone = vi.fn();
    renderHook(() => useScanJobPolling("dev1", onJobDone));
    await waitFor(() => expect(onJobDone).toHaveBeenCalledTimes(1));
  });

  it("intoarce null si nu arunca daca listScanJobs esueaza", async () => {
    mockListJobs.mockRejectedValue(new Error("network"));
    const { result } = renderHook(() => useScanJobPolling("dev1", () => {}));
    await waitFor(() => expect(mockListJobs).toHaveBeenCalled());
    expect(result.current).toBeNull();
  });

  it("face cleanup la unmount fara erori", () => {
    mockListJobs.mockResolvedValue([]);
    const { unmount } = renderHook(() => useScanJobPolling("dev1", () => {}));
    expect(() => unmount()).not.toThrow();
  });
});
