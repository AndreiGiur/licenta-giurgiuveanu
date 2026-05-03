from pydantic import BaseModel, EmailStr, Field
from typing import Any, Dict, List


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


class DeviceCreateIn(BaseModel):
    device_uid: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)


class DeviceOut(BaseModel):
    id: int
    device_uid: str
    name: str
    created_at: str


class DeviceCreateOut(DeviceOut):
    device_token: str


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


class ScanCreateOut(BaseModel):
    scan_id: int
    device_uid: str
    exposure_score: int
    findings: List[Dict[str, Any]]


class DeviceScanListItem(BaseModel):
    scan_id: int
    created_at: str
    exposure_score: int


class ScanDetailOut(BaseModel):
    scan_id: int
    device_uid: str
    created_at: str
    exposure_score: int
    findings: List[Dict[str, Any]]
    payload: Dict[str, Any] = {}


# ── Scan-on-demand: schemas pentru job queue ─────────────────────────────────

class ScanJobOut(BaseModel):
    """Snapshot al unui ScanJob — folosit la creare si la polling status."""
    job_id: int
    device_uid: str
    status: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    scan_id: int | None = None
    exposure_score: int | None = None
    error_message: str | None = None


class AgentJobOut(BaseModel):
    """Job livrat agentului (cu device_uid pentru ca agentul sa stie ce sa colecteze)."""
    job_id: int
    device_uid: str


class JobResultIn(BaseModel):
    """Rezultatul trimis de agent dupa executia jobului."""
    os: Dict[str, Any]
    network: Dict[str, Any] = {}
    processes: List[Dict[str, Any]] = []
    software: List[Dict[str, Any]] = []


class JobFailureIn(BaseModel):
    """Agentul raporteaza esec (eroare in colectare, etc.)."""
    error_message: str = Field(max_length=512)
