import { apiGet, apiPost } from "./client";
import type {
  ScanCreateRequest,
  ScanCreateResponse,
  DeviceScanListItem,
  ScanDetailResponse,
} from "./types";

export function createScan(payload: ScanCreateRequest) {
  return apiPost<ScanCreateRequest, ScanCreateResponse>("/scans", payload);
}

export function listDeviceScans(deviceId: string) {
  return apiGet<DeviceScanListItem[]>(`/devices/${encodeURIComponent(deviceId)}/scans`);
}

export function getScan(scanId: number) {
  return apiGet<ScanDetailResponse>(`/scans/${scanId}`);
}
