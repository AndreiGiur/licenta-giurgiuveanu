"""Endpoint-uri scan-on-demand (job queue), latura UI.

UI ──► POST /devices/{uid}/scan-jobs           ──► job pending
UI ──► GET  /scan-jobs/{id}                    ──► polling status
(latura agent — pickup/result/fail — e in routes/agent.py)
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import MAX_NMAP_TARGET_HOSTS
from ..auth import get_db, require_user
from ..models import Device, ScanJob, ScanJobStatus, User
from ..schemas import ScanJobCreateIn, ScanJobOut
from ._helpers import _scan_job_to_out

router = APIRouter()


@router.get("/devices/{device_uid}/scan-jobs/preview", tags=["scan-jobs"])
def scan_jobs_preview(
    device_uid: str,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    """Returneaza detected_subnet + estimari pentru UI inainte de scan deep."""
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")
    import ipaddress
    estimated_hosts = 0
    if device.local_subnet:
        try:
            net = ipaddress.ip_network(device.local_subnet, strict=False)
            estimated_hosts = min(net.num_addresses, 256)
        except ValueError:
            pass
    return {
        "detected_subnet": device.local_subnet,
        "nmap_installed": bool(device.nmap_installed),
        "estimated_hosts": estimated_hosts,
        "estimated_duration_sec": 600 + estimated_hosts * 30,
    }


@router.post("/devices/{device_uid}/scan-jobs", response_model=ScanJobOut, tags=["scan-jobs"])
def create_scan_job(
    device_uid: str,
    payload: ScanJobCreateIn = Body(default_factory=ScanJobCreateIn),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """User cere o scanare on-demand pentru un device al sau.
    `scan_type` controleaza ce nivel de scanare ruleaza agentul."""
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")

    # Daca user-ul are deja un job PENDING (necules de agent) pentru acest
    # device, il reutilizam in loc sa cream duplicat (evita double-click).
    # Daca jobul anterior e deja RUNNING, lasam user-ul sa cocea unul nou —
    # poate vrea sa reia scanarea cu date proaspete.
    existing = db.execute(
        select(ScanJob).where(
            ScanJob.device_id == device.id,
            ScanJob.status == ScanJobStatus.PENDING,
        ).order_by(ScanJob.id.desc())
    ).scalars().first()
    if existing:
        return _scan_job_to_out(existing, device)

    if payload.nmap_target:
        import ipaddress
        try:
            net = ipaddress.ip_network(payload.nmap_target, strict=False)
            if net.is_global:
                raise HTTPException(400, "nmap_target nu poate fi IP public")
            if net.num_addresses > MAX_NMAP_TARGET_HOSTS:
                raise HTTPException(400, f"nmap_target prea mare (max {MAX_NMAP_TARGET_HOSTS} hosts)")
        except ValueError as e:
            raise HTTPException(400, f"nmap_target invalid: {e}")

    job = ScanJob(
        device_id=device.id,
        requested_by_user_id=user.id,
        status=ScanJobStatus.PENDING,
        scan_type=payload.scan_type,
        nmap_target=payload.nmap_target,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return _scan_job_to_out(job, device)


@router.get("/scan-jobs/{job_id}", response_model=ScanJobOut, tags=["scan-jobs"])
def get_scan_job(
    job_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """UI polleaza statusul unui job. Verifica izolarea pe owner."""
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="scan job not found")
    device = db.get(Device, job.device_id)
    if not device or device.owner_id != user.id:
        raise HTTPException(status_code=404, detail="scan job not found")
    return _scan_job_to_out(job, device)


@router.get("/devices/{device_uid}/scan-jobs", response_model=list[ScanJobOut], tags=["scan-jobs"])
def list_scan_jobs(
    device_uid: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """Istoricul ultimelor 20 de joburi pentru un device. Util in UI."""
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")

    jobs = db.execute(
        select(ScanJob).where(ScanJob.device_id == device.id)
        .order_by(ScanJob.id.desc()).limit(20)
    ).scalars().all()
    return [_scan_job_to_out(j, device) for j in jobs]
