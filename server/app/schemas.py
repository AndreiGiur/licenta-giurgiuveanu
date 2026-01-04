from pydantic import BaseModel, Field
from typing import Any, Dict, List


class ScanIn(BaseModel):
    device_id: str = Field(min_length=1, max_length=128)
    os: Dict[str, Any]
    network: Dict[str, Any] = {}
    processes: List[Dict[str, Any]] = []


class ScanOut(BaseModel):
    scan_id: int
    device_id: str
    findings: List[Dict[str, Any]]
    exposure_score: int
