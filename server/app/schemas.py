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
    os: Dict[str, Any]
    network: Dict[str, Any] = {}
    processes: List[Dict[str, Any]] = []
    software: List[Dict[str, Any]] = []
    system_info: Dict[str, Any] = {}
    persistence: Dict[str, Any] | None = None
    forensics: Dict[str, Any] | None = None
    nmap: Dict[str, Any] | None = None


class ScanCreateOut(BaseModel):
    scan_id: int
    device_uid: str
    device_name: str
    exposure_score: int
    findings: List[Dict[str, Any]]


class DeviceScanListItem(BaseModel):
    scan_id: int
    created_at: str
    exposure_score: int


class ScanDetailOut(BaseModel):
    scan_id: int
    device_uid: str
    device_name: str
    created_at: str
    exposure_score: int
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
