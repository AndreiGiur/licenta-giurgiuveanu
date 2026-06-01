import { apiGet, apiPost, apiDelete, API_BASE_URL } from "./client";
import type {
  DeviceScanListItem,
  NetTrafficPoint,
  Schedule,
  ScheduleFrequency,
  ScanDetailResponse,
  ScanJobPreview,
  ScanJobResponse,
  ScanType,
  ScoreTrendPoint,
  ScanDiff,
} from "./types";

export function getNetTraffic(deviceUid: string) {
  return apiGet<NetTrafficPoint[]>(
    `/devices/${encodeURIComponent(deviceUid)}/net-traffic`,
  );
}

export function getDeviceScoreTrend(deviceUid: string, days = 30) {
  return apiGet<ScoreTrendPoint[]>(
    `/devices/${encodeURIComponent(deviceUid)}/score-trend?days=${days}`,
  );
}

export function getScanDiff(scanId: number, previousId?: number) {
  const qs = previousId !== undefined ? `?previous=${previousId}` : "";
  return apiGet<ScanDiff>(`/scans/${scanId}/diff${qs}`);
}

export function listDeviceScans(deviceId: string) {
  return apiGet<DeviceScanListItem[]>(
    `/devices/${encodeURIComponent(deviceId)}/scans`,
  );
}

export function getScan(scanId: number) {
  return apiGet<ScanDetailResponse>(`/scans/${scanId}`);
}

/** URL absolut catre PDF report — folosit ca href pentru link download. */
export function getScanPdfUrl(scanId: number): string {
  return `${API_BASE_URL}/scans/${scanId}/report.pdf`;
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

/** ── Schedule CRUD ──────────────────────────────────────────────────────── */

export function listSchedules(deviceUid: string) {
  return apiGet<Schedule[]>(
    `/devices/${encodeURIComponent(deviceUid)}/schedules`,
  );
}

export function createSchedule(deviceUid: string, body: {
  scan_type: ScanType;
  frequency: ScheduleFrequency;
  hour: number;
  day_of_week?: number;
  day_of_month?: number;
  nmap_target?: string | null;
}) {
  return apiPost<typeof body, Schedule>(
    `/devices/${encodeURIComponent(deviceUid)}/schedules`,
    body,
  );
}

export function deleteSchedule(scheduleId: number) {
  return apiDelete(`/schedules/${scheduleId}`);
}


/** Verifica disponibilitatea build-urilor de agent pe server, per OS. */
export function getAgentDownloadInfo() {
  return apiGet<{
    available: boolean;            // backward-compat (Windows)
    platform: string;
    size_bytes: number | null;
    windows: { available: boolean; size_bytes: number | null };
    linux: { available: boolean; size_bytes: number | null };
  }>("/agent/download/info");
}
