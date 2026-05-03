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

export type ScanPayload = {
  os?: {
    system?: string;
    release?: string;
    version?: string;
    machine?: string;
    hostname?: string;
    is_admin?: boolean;
  };
  network?: {
    open_ports?: number[];
  };
  processes?: { pid: number; name: string; memory_mb: number; username?: string }[];
  software?: { name: string; version?: string }[];
};

export type ScanDetailResponse = {
  scan_id: number;
  device_uid: string;
  created_at: string;
  exposure_score: number;
  findings: Finding[];
  payload?: ScanPayload;
};
