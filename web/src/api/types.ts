export type ScanType = "standard" | "advanced" | "deep";

export type ScoreBreakdown = {
  critical_risk: number;
  network_exposure: number;
  hygiene: number;
  activity: number;
};

export const SCORE_CATEGORIES: { key: keyof ScoreBreakdown; label: string; weight: number }[] = [
  { key: "critical_risk",    label: "Risc critic",       weight: 0.40 },
  { key: "network_exposure", label: "Expunere retea",    weight: 0.30 },
  { key: "hygiene",          label: "Igiena sistem",     weight: 0.20 },
  { key: "activity",         label: "Activitate suspecta", weight: 0.10 },
];

export type Finding = {
  rule_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info" | string;
  evidence?: unknown;
  recommendation: string;
  category?: string;
  rule_weight?: number;
  rule_confidence?: number;
  compliance?: string[];
};

export type ScoreTrendPoint = {
  scan_id: number;
  created_at: string;
  exposure_score: number;
  scan_type: string;
};

export type ScanDiffFinding = {
  rule_id: string;
  title: string;
  severity: string;
};

export type ScanDiff = {
  from_scan_id: number;
  to_scan_id: number;
  from_score: number;
  to_score: number;
  delta: number;
  added: ScanDiffFinding[];
  fixed: ScanDiffFinding[];
  unchanged: ScanDiffFinding[];
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
  scan_count?: number;
  last_score?: number | null;
};

export type NetTrafficPoint = {
  ts: number;
  sent_rate_kbps: number;
  recv_rate_kbps: number;
  conn_count: number;
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
  score_breakdown?: ScoreBreakdown | null;
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

// ── Profile + Admin ──────────────────────────────────────────────────────────

export type UserStats = {
  device_count: number;
  scan_count: number;
  avg_exposure_score: number | null;
  last_scan_at: string | null;
  last_scan_score: number | null;
};

export type SessionInfo = {
  id: number;
  user_agent: string | null;
  ip: string | null;
  created_at: string;
  expires_at: string | null;
  is_current: boolean;
};

export type PlatformStats = {
  total_users: number;
  total_devices: number;
  devices_online: number;
  scans_last_24h: number;
  scans_total: number;
  avg_exposure_score: number | null;
};

export type AdminUserRow = {
  id: number;
  email: string;
  role: "user" | "admin";
  auth_provider: string;
  created_at: string;
  device_count: number;
};

export type AdminDeviceRow = {
  id: number;
  device_uid: string;
  name: string;
  owner_id: number;
  owner_email: string;
  created_at: string;
  is_online: boolean;
};

export type AdminScanRow = {
  scan_id: number;
  device_uid: string;
  device_name: string;
  owner_email: string;
  created_at: string;
  exposure_score: number;
  scan_type: string | null;
};

export type AdminScansPage = {
  items: AdminScanRow[];
  total: number;
  limit: number;
  offset: number;
};

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
