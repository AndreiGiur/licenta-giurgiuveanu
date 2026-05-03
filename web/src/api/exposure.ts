import { apiGet, apiPost } from "./client";
import type {
  DeviceScanListItem,
  ScanDetailResponse,
  ScanJobResponse,
} from "./types";

export function listDeviceScans(deviceId: string) {
  return apiGet<DeviceScanListItem[]>(
    `/devices/${encodeURIComponent(deviceId)}/scans`,
  );
}

export function getScan(scanId: number) {
  return apiGet<ScanDetailResponse>(`/scans/${scanId}`);
}

// ── Scan-on-demand ──────────────────────────────────────────────────────────

/** UI cere o scanare on-demand pentru un device. Returneaza jobul (initial pending). */
export function requestScan(deviceUid: string) {
  return apiPost<Record<string, never>, ScanJobResponse>(
    `/devices/${encodeURIComponent(deviceUid)}/scan-jobs`,
    {},
  );
}

/** UI polleaza statusul unui job. */
export function getScanJob(jobId: number) {
  return apiGet<ScanJobResponse>(`/scan-jobs/${jobId}`);
}

/** Istoricul ultimelor scanari cerute pentru un device. */
export function listScanJobs(deviceUid: string) {
  return apiGet<ScanJobResponse[]>(
    `/devices/${encodeURIComponent(deviceUid)}/scan-jobs`,
  );
}
