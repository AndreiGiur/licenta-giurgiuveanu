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
  nmap?: NmapData | null;
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

export type ScheduleFrequency = "daily" | "weekly" | "monthly";

export type Schedule = {
  id: number;
  device_id: number;
  scan_type: ScanType;
  frequency: ScheduleFrequency;
  hour: number;
  day_of_week: number | null;
  day_of_month: number | null;
  nmap_target: string | null;
  enabled: boolean;
  next_run_at: string;
  last_run_at: string | null;
  created_at: string;
};

export type ScanJobPreview = {
  detected_subnet: string | null;
  nmap_installed: boolean;
  estimated_hosts: number;
  estimated_duration_sec: number;
};

export type NmapFinding = {
  rule_id: string;
  severity: string;
  title: string;
  evidence: Record<string, unknown>;
};

export type NmapHost = {
  ip: string;
  hostname: string;
  state: string;
  os_guess: string;
  ports: Array<{
    port: number;
    proto: string;
    state: string;
    service: string;
    version: string;
    cpe: string;
  }>;
  vulnwatch_findings: NmapFinding[];
  topology: { role: string; risk_score: number; reasons: string[] };
};

export type NmapData = {
  version: string;
  scan_time_sec: number | null;
  targets: string[];
  lan_opt_in: boolean;
  lua_errors: string[];
  hosts: NmapHost[];
  error?: string;
};

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
