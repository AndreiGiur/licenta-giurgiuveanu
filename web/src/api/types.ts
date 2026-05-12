export type ScanType = "standard" | "advanced" | "deep";

export type Finding = {
  rule_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info" | string;
  evidence?: unknown;
  recommendation: string;
};

export type DeviceScanListItem = {
  scan_id: number;
  created_at: string;
  exposure_score: number;
};

export type Device = {
  id: number;
  device_uid: string;
  name: string;
  created_at: string;
  is_online?: boolean;
  last_heartbeat?: string | null;
  agent_version?: string | null;
  capabilities?: string[];
};

export type ScanPayload = {
  scan_type?: ScanType;
  os?: {
    system?: string;
    release?: string;
    version?: string;
    machine?: string;
    hostname?: string;
    is_admin?: boolean;
    uptime_seconds?: number;
    username?: string;
  };
  system_info?: Record<string, unknown>;
  network?: {
    open_ports?: number[];
    connections?: unknown[];
    shares?: unknown[];
    adapters?: unknown[];
  };
  processes?: { pid: number; name: string; memory_percent?: number; memory_mb?: number; cmdline?: string }[];
  software?: { name: string; version?: string }[];
  persistence?: Record<string, unknown> | null;
  forensics?: Record<string, unknown> | null;
};

export type ScanDetailResponse = {
  scan_id: number;
  device_uid: string;
  device_name: string;
  created_at: string;
  exposure_score: number;
  findings: Finding[];
  payload?: ScanPayload;
  scan_type?: ScanType;
};

// ── Scan-on-demand ──────────────────────────────────────────────────────────

export type ScanJobStatus =
  | "pending"
  | "running"
  | "done"
  | "failed"
  | "cancelled";

export type ScanJobResponse = {
  job_id: number;
  device_uid: string;
  device_name: string;
  status: ScanJobStatus;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  scan_id?: number | null;
  exposure_score?: number | null;
  error_message?: string | null;
  scan_type?: ScanType;
  progress?: number;
  phase?: string | null;
};
