"""Endpoint-uri pentru planificarea scanarilor recurente (scan schedules)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..config import MAX_SCHEDULES_PER_USER
from ..auth import get_db, require_user
from ..models import Device, ScanSchedule, User
from ..schemas import ScheduleIn, ScheduleOut, ScheduleUpdateIn

router = APIRouter()


@router.post("/devices/{device_uid}/schedules", response_model=ScheduleOut, tags=["scheduler"])
def create_schedule(
    device_uid: str,
    body: ScheduleIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    from ..scheduler import compute_next_run
    dev = db.query(Device).filter(
        Device.device_uid == device_uid,
        Device.owner_id == user.id,
    ).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    # Validare day_of_week / day_of_month per frequency
    if body.frequency == "weekly" and body.day_of_week is None:
        raise HTTPException(400, "day_of_week required for weekly frequency")
    if body.frequency == "monthly" and body.day_of_month is None:
        raise HTTPException(400, "day_of_month required for monthly frequency")
    # Max per user (count peste toate device-urile owner-ului)
    total = db.query(ScanSchedule).join(
        Device, Device.id == ScanSchedule.device_id
    ).filter(Device.owner_id == user.id).count()
    if total >= MAX_SCHEDULES_PER_USER:
        raise HTTPException(
            400,
            f"Maximum {MAX_SCHEDULES_PER_USER} schedules per user reached"
        )
    next_run = compute_next_run(
        body.frequency, body.hour, body.day_of_week, body.day_of_month
    )
    sched = ScanSchedule(
        device_id=dev.id,
        scan_type=body.scan_type,
        frequency=body.frequency,
        hour=body.hour,
        day_of_week=body.day_of_week,
        day_of_month=body.day_of_month,
        nmap_target=body.nmap_target,
        enabled=body.enabled,
        next_run_at=next_run.replace(tzinfo=None),
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return sched


@router.get("/devices/{device_uid}/schedules", tags=["scheduler"],
            response_model=list[ScheduleOut])
def list_schedules(
    device_uid: str,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    dev = db.query(Device).filter(
        Device.device_uid == device_uid,
        Device.owner_id == user.id,
    ).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    return db.query(ScanSchedule).filter(
        ScanSchedule.device_id == dev.id
    ).order_by(ScanSchedule.created_at.desc()).all()


@router.patch("/schedules/{schedule_id}", response_model=ScheduleOut, tags=["scheduler"])
def update_schedule(
    schedule_id: int,
    body: ScheduleUpdateIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    from ..scheduler import compute_next_run
    sched = db.query(ScanSchedule).join(
        Device, Device.id == ScanSchedule.device_id
    ).filter(
        ScanSchedule.id == schedule_id,
        Device.owner_id == user.id,
    ).first()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    data = body.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(sched, k, v)
    if any(k in data for k in ("frequency", "hour", "day_of_week", "day_of_month")):
        sched.next_run_at = compute_next_run(
            sched.frequency, sched.hour,
            sched.day_of_week, sched.day_of_month,
        ).replace(tzinfo=None)
    db.commit()
    db.refresh(sched)
    return sched


@router.delete("/schedules/{schedule_id}", status_code=204, tags=["scheduler"])
def delete_schedule(
    schedule_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    sched = db.query(ScanSchedule).join(
        Device, Device.id == ScanSchedule.device_id
    ).filter(
        ScanSchedule.id == schedule_id,
        Device.owner_id == user.id,
    ).first()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    db.delete(sched)
    db.commit()
