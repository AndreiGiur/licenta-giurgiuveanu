from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional


# ---------- AUTH ----------

class RegisterIn(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MeOut(BaseModel):
    id: int
    email: str


# ---------- DEVICES ----------

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


# ---------- SCANS ----------

class ScanIn(BaseModel):
    # trebuie sa corespunda cu Device.device_uid
    device_id: str = Field(min_length=1, max_length=128)

    os: Dict[str, Any]
    network: Dict[str, Any] = {}
    processes: List[Dict[str, Any]] = []


class ScanCreateOut(BaseModel):
    scan_id: int
    device_id: str
    exposure_score: int
    findings: List[Dict[str, Any]]


class DeviceScanListItem(BaseModel):
    scan_id: int
    created_at: str
    exposure_score: int


class ScanDetailOut(BaseModel):
    scan_id: int
    device_id: str
    created_at: str
    exposure_score: int
    findings: List[Dict[str, Any]]
