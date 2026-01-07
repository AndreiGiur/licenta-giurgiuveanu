export type Finding = {
  rule_id: string;
  title: string;
  severity: "low" | "medium" | "high" | string;
  evidence?: unknown;
  recommendation: string;
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
