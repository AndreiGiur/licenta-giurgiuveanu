import { apiGet } from "./client";
import type { DeviceScanListItem, ScanDetailResponse } from "./types";

export function listDeviceScans(deviceId: string) {
  return apiGet<DeviceScanListItem[]>(
    `/devices/${encodeURIComponent(deviceId)}/scans`
  );
}

export function getScan(scanId: number) {
  return apiGet<ScanDetailResponse>(`/scans/${scanId}`);
}
