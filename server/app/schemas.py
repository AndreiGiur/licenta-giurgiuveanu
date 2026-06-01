from datetime import datetime
from pydantic import BaseModel, EmailStr, Field
from typing import Any, Dict, List, Literal


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class TokenOut(BaseModel):
    session_token: str


class MeOut(BaseModel):
    id: int
    email: str
    google_picture_url: str | None = None
    auth_provider: str = "password"
    role: str = "user"
    first_name: str | None = None
    last_name: str | None = None
    default_scan_type: str = "standard"


class UpdateProfileIn(BaseModel):
    """PATCH /me — toate campurile sunt optionale, doar cele trimise se updateaza."""
    first_name: str | None = Field(default=None, max_length=64)
    last_name: str | None = Field(default=None, max_length=64)
    default_scan_type: str | None = Field(default=None, pattern=r"^(standard|advanced|deep)$")


class DeviceCreateIn(BaseModel):
    device_uid: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    token_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class DeviceOut(BaseModel):
    id: int
    device_uid: str
    name: str
    created_at: str
    is_online: bool = False
    last_heartbeat: str | None = None
    agent_version: str | None = None
    capabilities: List[str] = []
    scan_count: int = 0
    last_score: int | None = None


# DeviceCreateOut: identic cu DeviceOut — backend nu mai returneaza tokenul plain.
# Pastram alias-ul pentru compatibilitate signature in routes.py.
DeviceCreateOut = DeviceOut


class DeviceRelinkIn(BaseModel):
    """Body pentru POST /devices/{uid}/relink — token_hash generat de client."""
    token_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class ScanIn(BaseModel):
    """
    Payload trimis de agent. `device_uid` identifica dispozitivul,
    iar autentificarea se face prin header-ul X-Device-Token.
    """
    device_uid: str = Field(min_length=1, max_length=128)
    scan_type: Literal["standard", "advanced", "deep"] = "standard"
    os: Dict[str, Any]
    network: Dict[str, Any] = {}
    processes: List[Dict[str, Any]] = []
    software: List[Dict[str, Any]] = []
    system_info: Dict[str, Any] = {}
    persistence: Dict[str, Any] | None = None
    forensics: Dict[str, Any] | None = None
    nmap: Dict[str, Any] | None = None


class ScoreBreakdown(BaseModel):
    """Sub-scoruri 0-100 per categorie."""
    critical_risk: int = 0
    network_exposure: int = 0
    hygiene: int = 0
    activity: int = 0


class ScanCreateOut(BaseModel):
    scan_id: int
    device_uid: str
    device_name: str
    exposure_score: int
    score_breakdown: ScoreBreakdown | None = None
    findings: List[Dict[str, Any]]


class DeviceScanListItem(BaseModel):
    scan_id: int
    created_at: str
    exposure_score: int


class ScoreTrendPoint(BaseModel):
    """Punct pe graficul de trend pentru un device."""
    scan_id: int
    created_at: str
    exposure_score: int
    scan_type: str = "standard"


class ScanDiffFinding(BaseModel):
    """Reprezentare finding pentru diff intre scan-uri."""
    rule_id: str
    title: str
    severity: str


class ScanDiffOut(BaseModel):
    """Diff intre doua scan-uri ale aceluiasi device."""
    from_scan_id: int
    to_scan_id: int
    from_score: int
    to_score: int
    delta: int  # to_score - from_score (pozitiv = mai rau)
    added: List[ScanDiffFinding]      # in to dar nu in from = vulnerabilitati noi
    fixed: List[ScanDiffFinding]      # in from dar nu in to = rezolvate
    unchanged: List[ScanDiffFinding]  # in ambele


class ScanDetailOut(BaseModel):
    scan_id: int
    device_uid: str
    device_name: str
    created_at: str
    exposure_score: int
    score_breakdown: ScoreBreakdown | None = None
    findings: List[Dict[str, Any]]
    payload: Dict[str, Any] = {}
    scan_type: str = "standard"


# ── Scan-on-demand: schemas pentru job queue ─────────────────────────────────

class ScanJobOut(BaseModel):
    """Snapshot al unui ScanJob — folosit la creare si la polling status."""
    job_id: int
    device_uid: str
    device_name: str
    status: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    scan_id: int | None = None
    exposure_score: int | None = None
    error_message: str | None = None
    scan_type: str = "standard"
    progress: int = 0
    phase: str | None = None


class AgentJobOut(BaseModel):
    """Job livrat agentului. `scan_type` ii spune ce nivel sa colecteze."""
    job_id: int
    device_uid: str
    scan_type: str = "standard"


class JobResultIn(BaseModel):
    """Rezultatul trimis de agent dupa executia jobului."""
    os: Dict[str, Any]
    network: Dict[str, Any] = {}
    processes: List[Dict[str, Any]] = []
    software: List[Dict[str, Any]] = []
    system_info: Dict[str, Any] = {}
    persistence: Dict[str, Any] | None = None
    forensics: Dict[str, Any] | None = None
    nmap: Dict[str, Any] | None = None


class JobFailureIn(BaseModel):
    """Agentul raporteaza esec (eroare in colectare, etc.)."""
    error_message: str = Field(max_length=512)


# ── Heartbeat + scan-types ───────────────────────────────────────────────────


class HeartbeatIn(BaseModel):
    """Agent → backend la fiecare 10s. Backend marcheaza device-ul ca online."""
    agent_version: str = Field(max_length=32)
    capabilities: List[str] = Field(default_factory=list)
    os_version: str = Field(max_length=128)
    local_subnet: str | None = None
    # Contoare trafic de retea (cumulativ de la boot) pentru graficul live.
    net_bytes_sent: int | None = None
    net_bytes_recv: int | None = None
    net_conn_count: int | None = None


class ScanJobCreateIn(BaseModel):
    """UI cere o scanare on-demand de un anumit tip."""
    scan_type: Literal["standard", "advanced", "deep"] = "standard"
    nmap_target: str | None = None


class JobProgressIn(BaseModel):
    """Agent raporteaza progres in timpul executiei (intre colectori)."""
    progress: int = Field(ge=0, le=100)
    phase: str = Field(max_length=128)


# ── Google OAuth ─────────────────────────────────────────────────────────────


class GoogleAuthUrlOut(BaseModel):
    """Returnat de GET /auth/google/url — frontend redirect-uieste user-ul."""
    auth_url: str
    state: str


class GoogleAgentEnrollIn(BaseModel):
    """Agent trimite id_token + device info + token_hash la /agent/google-enroll.

    Tokenul plain este generat local de agent si pastrat in config.ini.
    Backend nu vede niciodata tokenul plain."""
    id_token: str = Field(min_length=1, max_length=4096)
    device_uid: str = Field(min_length=1, max_length=128)
    device_name: str = Field(min_length=1, max_length=128)
    token_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class GoogleAgentEnrollOut(BaseModel):
    """Raspuns la /agent/google-enroll — fara device_token (clientul il are deja)."""
    device_uid: str
    device_name: str
    user_email: str


# ── Admin endpoints ──────────────────────────────────────────────────────────

class AdminUserOut(BaseModel):
    id: int
    email: EmailStr
    role: str
    auth_provider: str
    created_at: datetime
    device_count: int


class AdminDeviceOut(BaseModel):
    id: int
    device_uid: str
    name: str
    owner_id: int
    owner_email: EmailStr
    created_at: datetime
    is_online: bool


class AdminScanListItem(BaseModel):
    scan_id: int
    device_uid: str
    device_name: str
    owner_email: EmailStr
    created_at: datetime
    exposure_score: int
    scan_type: str | None = None


class AdminScansPage(BaseModel):
    items: List[AdminScanListItem]
    total: int
    limit: int
    offset: int


class AdminRoleChangeIn(BaseModel):
    role: Literal["admin", "user"]


class AdminResetPasswordIn(BaseModel):
    new_password: str = Field(min_length=8, max_length=128)


# ── Scheduler ────────────────────────────────────────────────────────────────

class ScheduleIn(BaseModel):
    scan_type: Literal["standard", "advanced", "deep"] = "standard"
    frequency: Literal["daily", "weekly", "monthly"]
    hour: int = Field(ge=0, le=23)
    day_of_week: int | None = Field(default=None, ge=0, le=6)
    day_of_month: int | None = Field(default=None, ge=1, le=28)
    nmap_target: str | None = Field(default=None, max_length=64)
    enabled: bool = True


class ScheduleUpdateIn(BaseModel):
    scan_type: Literal["standard", "advanced", "deep"] | None = None
    frequency: Literal["daily", "weekly", "monthly"] | None = None
    hour: int | None = Field(default=None, ge=0, le=23)
    day_of_week: int | None = Field(default=None, ge=0, le=6)
    day_of_month: int | None = Field(default=None, ge=1, le=28)
    nmap_target: str | None = Field(default=None, max_length=64)
    enabled: bool | None = None


class ScheduleOut(BaseModel):
    id: int
    device_id: int
    scan_type: str
    frequency: str
    hour: int
    day_of_week: int | None
    day_of_month: int | None
    nmap_target: str | None
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Profile + user stats + sessions ──────────────────────────────────────────

class UserStatsOut(BaseModel):
    device_count: int
    scan_count: int
    avg_exposure_score: float | None  # None daca nu exista scan-uri
    last_scan_at: datetime | None
    last_scan_score: int | None


class SessionOut(BaseModel):
    id: int
    user_agent: str | None
    ip: str | None
    created_at: datetime
    expires_at: datetime | None
    is_current: bool


class ChangePasswordIn(BaseModel):
    old_password: str = Field(min_length=8, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


# ── Admin platform stats ─────────────────────────────────────────────────────

class AdminPlatformStatsOut(BaseModel):
    total_users: int
    total_devices: int
    devices_online: int
    scans_last_24h: int
    scans_total: int
    avg_exposure_score: float | None
