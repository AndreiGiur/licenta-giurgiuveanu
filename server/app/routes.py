from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Header, status, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import get_db, get_user_by_email, create_password, verify_password, create_session, require_user
from .models import User, Device, Scan, Finding, Session as DbSession
from .schemas import (
    RegisterIn,
    LoginIn,
    TokenOut,
    MeOut,
    DeviceCreateIn,
    DeviceOut,
    DeviceCreateOut,
    ScanIn,
    ScanCreateOut,
    DeviceScanListItem,
    ScanDetailOut,
)
from .rules import evaluate

router = APIRouter()


@router.post("/auth/register", response_model=MeOut)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    if get_user_by_email(db, email):
        raise HTTPException(status_code=400, detail="email already registered")

    salt, pwd_hash = create_password(payload.password)
    user = User(email=email, password_salt=salt, password_hash=pwd_hash)

    db.add(user)
    db.commit()
    db.refresh(user)

    return MeOut(id=user.id, email=user.email)


@router.post("/auth/login", response_model=TokenOut)
def login(request: Request, payload: LoginIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = get_user_by_email(db, email)
    if not user or not verify_password(payload.password, user.password_salt, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    token = create_session(
        db,
        user.id,
        user_agent=request.headers.get("user-agent"),
        ip=request.client.host if request.client else None,
    )
    return TokenOut(session_token=token)


@router.get("/auth/me", response_model=MeOut)
def me(user: User = Depends(require_user)):
    return MeOut(id=user.id, email=user.email)


@router.delete("/auth/logout")
def logout(db: Session = Depends(get_db), x_session_token: str | None = Header(default=None)):
    if not x_session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing session token")

    sess = db.execute(select(DbSession).where(DbSession.token == x_session_token)).scalar_one_or_none()
    if not sess:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid session token")

    db.delete(sess)
    db.commit()
    return {"ok": True}


@router.post("/devices", response_model=DeviceCreateOut)
def create_device(payload: DeviceCreateIn, db: Session = Depends(get_db), user: User = Depends(require_user)):
    device_uid = payload.device_uid.strip()
    name = payload.name.strip()

    existing = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="device_uid already exists for this user")

    device = Device(
        owner_id=user.id,
        device_uid=device_uid,
        name=name,
        device_token=Device.generate_token(),
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    return DeviceCreateOut(
        id=device.id,
        device_uid=device.device_uid,
        name=device.name,
        created_at=device.created_at.isoformat(),
        device_token=device.device_token,
    )


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db), user: User = Depends(require_user)):
    rows = db.execute(select(Device).where(Device.owner_id == user.id).order_by(Device.id.desc())).scalars().all()
    return [
        DeviceOut(
            id=d.id,
            device_uid=d.device_uid,
            name=d.name,
            created_at=d.created_at.isoformat(),
        )
        for d in rows
    ]


@router.post("/scans", response_model=ScanCreateOut)
def create_scan(
    payload: ScanIn,
    x_device_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    if not x_device_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing X-Device-Token")

    device_uid = payload.device_id.strip()
    device = db.execute(select(Device).where(Device.device_uid == device_uid)).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not enrolled")

    if device.device_token != x_device_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid device token")

    scan_dict = payload.model_dump()
    score, findings = evaluate(scan_dict)

    scan = Scan(device_id=device.id, payload=scan_dict, exposure_score=score)
    db.add(scan)
    db.flush()

    for f in findings:
        db.add(
            Finding(
                scan_id=scan.id,
                rule_id=f["rule_id"],
                title=f["title"],
                severity=f["severity"],
                evidence=f.get("evidence", {}),
                recommendation=f["recommendation"],
            )
        )

    db.commit()
    db.refresh(scan)

    return ScanCreateOut(
        scan_id=scan.id,
        device_id=device.device_uid,
        exposure_score=score,
        findings=findings,
    )


@router.delete("/devices/{device_uid}", status_code=204)
def delete_device(device_uid: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")

    db.delete(device)
    db.commit()


@router.get("/devices/{device_uid}/scans", response_model=list[DeviceScanListItem])
def list_scans_for_device(device_uid: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")

    rows = db.execute(
        select(Scan.id, Scan.created_at, Scan.exposure_score)
        .where(Scan.device_id == device.id)
        .order_by(Scan.id.desc())
        .limit(50)
    ).all()

    return [
        DeviceScanListItem(
            scan_id=r.id,
            created_at=r.created_at.isoformat(),
            exposure_score=r.exposure_score,
        )
        for r in rows
    ]


@router.get("/scans/{scan_id}", response_model=ScanDetailOut)
def get_scan_detail(scan_id: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")

    device = db.get(Device, scan.device_id)
    if not device or device.owner_id != user.id:
        raise HTTPException(status_code=404, detail="scan not found")

    return ScanDetailOut(
        scan_id=scan.id,
        device_id=device.device_uid,
        created_at=scan.created_at.isoformat(),
        exposure_score=scan.exposure_score,
        findings=[
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in scan.findings
        ],
        payload=scan.payload or {},
    )
