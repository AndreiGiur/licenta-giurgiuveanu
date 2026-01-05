export type Finding = {
  rule_id: string;
  title: string;
  severity: "low" | "medium" | "high" | string;
  evidence?: unknown;
  recommendation: string;
};

export type ScanCreateRequest = {
  device_id: string;
  os: Record<string, unknown>;
  network?: Record<string, unknown>;
  processes?: Array<Record<string, unknown>>;
};

export type ScanCreateResponse = {
  scan_id: number;
  device_id: string;
  exposure_score: number;
  findings: Finding[];
};

export type DeviceScanListItem = {
  scan_id: number;
  created_at: string;
  exposure_score: number;
};

export type ScanDetailResponse = {
  scan_id: number;
  device_id: string;
  created_at: string;
  exposure_score: number;
  findings: Finding[];
};
