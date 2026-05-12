import { apiGet, apiPost } from "./client";
import type {
  DeviceScanListItem,
  ScanDetailResponse,
  ScanJobResponse,
  ScanType,
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

/** UI cere o scanare on-demand pentru un device. `scanType` controleaza
 * ce nivel de scanare ruleaza agentul (standard/advanced/deep). */
export function requestScan(deviceUid: string, scanType: ScanType = "standard") {
  return apiPost<{ scan_type: ScanType }, ScanJobResponse>(
    `/devices/${encodeURIComponent(deviceUid)}/scan-jobs`,
    { scan_type: scanType },
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

/** Verifica daca un build de agent este disponibil pe server. */
export function getAgentDownloadInfo() {
  return apiGet<{
    available: boolean;
    platform: string;
    size_bytes: number | null;
  }>("/agent/download/info");
}
