"""Endpoint-uri admin (auth: require_admin): useri, device-uri, scanari, statistici platforma."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import create_password, get_db, require_admin
from ..models import Device, Scan, Session as DbSession, User
from ..schemas import (
    AdminDeviceOut,
    AdminPlatformStatsOut,
    AdminResetPasswordIn,
    AdminRoleChangeIn,
    AdminScanListItem,
    AdminScansPage,
    AdminUserOut,
)

router = APIRouter()


@router.get("/admin/users", response_model=list[AdminUserOut], tags=["admin"])
def admin_list_users(
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    # Count-uri de device grupate intr-un singur query (nu unul per user).
    device_counts: dict[int, int] = dict(db.execute(
        select(Device.owner_id, func.count(Device.id)).group_by(Device.owner_id)
    ).all())
    return [
        AdminUserOut(
            id=u.id, email=u.email, role=u.role,
            auth_provider=u.auth_provider, created_at=u.created_at,
            device_count=device_counts.get(u.id, 0),
        )
        for u in users
    ]


@router.delete("/admin/users/{user_id}", status_code=204, tags=["admin"])
def admin_delete_user(
    user_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if user_id == admin.id:
        raise HTTPException(400, "Cannot delete your own admin account")
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    db.delete(u)
    db.commit()


@router.post("/admin/users/{user_id}/role", response_model=AdminUserOut, tags=["admin"])
def admin_change_role(
    user_id: int,
    body: AdminRoleChangeIn,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if user_id == admin.id and body.role == "user":
        raise HTTPException(400, "Cannot demote your own admin account")
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    u.role = body.role
    db.commit()
    db.refresh(u)
    dc = db.query(Device).filter(Device.owner_id == u.id).count()
    return AdminUserOut(
        id=u.id, email=u.email, role=u.role,
        auth_provider=u.auth_provider, created_at=u.created_at,
        device_count=dc,
    )


@router.post("/admin/users/{user_id}/reset-password", tags=["admin"])
def admin_reset_password(
    user_id: int,
    body: AdminResetPasswordIn,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    salt, hashed = create_password(body.new_password)
    u.password_salt = salt
    u.password_hash = hashed
    # Invalideaza toate sesiunile user-ului tinta
    db.query(DbSession).filter(DbSession.user_id == user_id).delete()
    db.commit()
    return {"ok": True}


@router.get("/admin/devices", response_model=list[AdminDeviceOut], tags=["admin"])
def admin_list_devices(
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    devices = db.query(Device).order_by(Device.created_at.desc()).all()
    # Emailurile owner-ilor intr-un singur query (nu unul per device).
    owner_ids = {d.owner_id for d in devices}
    emails: dict[int, str] = dict(db.execute(
        select(User.id, User.email).where(User.id.in_(owner_ids))
    ).all()) if owner_ids else {}
    return [
        AdminDeviceOut(
            id=d.id,
            device_uid=d.device_uid,
            name=d.name,
            owner_id=d.owner_id,
            owner_email=emails.get(d.owner_id, "unknown@x.com"),
            created_at=d.created_at,
            is_online=d.is_online,
        )
        for d in devices
    ]


@router.get("/admin/scans", response_model=AdminScansPage, tags=["admin"])
def admin_list_scans(
    limit: int = 50,
    offset: int = 0,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    limit = min(max(limit, 1), 200)
    offset = max(offset, 0)
    q = db.query(Scan).order_by(Scan.created_at.desc())
    total = q.count()
    scans = q.offset(offset).limit(limit).all()

    # Batch device + owner pentru pagina curenta (nu 2 query-uri per scan).
    device_ids = {s.device_id for s in scans}
    devices: dict[int, Device] = {
        d.id: d for d in db.execute(
            select(Device).where(Device.id.in_(device_ids))
        ).scalars().all()
    } if device_ids else {}
    owner_ids = {d.owner_id for d in devices.values()}
    emails: dict[int, str] = dict(db.execute(
        select(User.id, User.email).where(User.id.in_(owner_ids))
    ).all()) if owner_ids else {}

    items: list[AdminScanListItem] = []
    for s in scans:
        device = devices.get(s.device_id)
        scan_type = (s.payload or {}).get("scan_type") if s.payload else None
        items.append(AdminScanListItem(
            scan_id=s.id,
            device_uid=device.device_uid if device else "?",
            device_name=device.name if device else "?",
            owner_email=emails.get(device.owner_id, "unknown@x.com") if device else "unknown@x.com",
            created_at=s.created_at,
            exposure_score=s.exposure_score,
            scan_type=scan_type,
        ))
    return AdminScansPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/admin/stats", response_model=AdminPlatformStatsOut, tags=["admin"])
def admin_platform_stats(
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Metrici platforma — pentru sectiunea Platforma din profilul admin."""
    total_users = db.query(User).count()
    total_devices = db.query(Device).count()
    now = datetime.now(timezone.utc)
    # devices_online = last_heartbeat in ultimele 30s (echivalentul property-ului
    # is_online, dar calculat in SQL ca sa nu incarcam toate device-urile).
    online_cutoff = (now - timedelta(seconds=30)).replace(tzinfo=None)
    devices_online = db.query(Device).filter(
        Device.last_heartbeat.is_not(None),
        Device.last_heartbeat >= online_cutoff,
    ).count()
    cutoff_naive = (now - timedelta(hours=24)).replace(tzinfo=None)
    scans_24h = db.query(Scan).filter(Scan.created_at >= cutoff_naive).count()
    scans_total = db.query(Scan).count()
    avg_score: float | None = None
    if scans_total > 0:
        # Media in SQL (func.avg) in loc sa incarcam toate scanarile in memorie.
        avg_raw = db.query(func.avg(Scan.exposure_score)).scalar()
        avg_score = round(float(avg_raw), 1) if avg_raw is not None else None
    return AdminPlatformStatsOut(
        total_users=total_users,
        total_devices=total_devices,
        devices_online=devices_online,
        scans_last_24h=scans_24h,
        scans_total=scans_total,
        avg_exposure_score=avg_score,
    )
