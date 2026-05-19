import { apiGet, apiPost } from "./client";
import type {
  DeviceScanListItem,
  ScanDetailResponse,
  ScanJobPreview,
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
export function requestScan(
  deviceUid: string,
  scanType: ScanType = "standard",
  nmapTarget?: string | null,
) {
  const body: { scan_type: ScanType; nmap_target?: string | null } = { scan_type: scanType };
  if (nmapTarget) body.nmap_target = nmapTarget;
  return apiPost<typeof body, ScanJobResponse>(
    `/devices/${encodeURIComponent(deviceUid)}/scan-jobs`,
    body,
  );
}

/** Preview pentru scan deep — afla detected_subnet, nmap_installed, etc. */
export function getScanJobPreview(deviceUid: string) {
  return apiGet<ScanJobPreview>(
    `/devices/${encodeURIComponent(deviceUid)}/scan-jobs/preview`,
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
