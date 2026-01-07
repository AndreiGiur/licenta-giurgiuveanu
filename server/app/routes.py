from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Header, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import (
    get_db,
    get_user_by_email,
    hash_password,
    verify_password,
    create_access_token,
    require_user,
)
from .models import User, Device, Scan, Finding
from .schemas import (
    RegisterIn,
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


# ---------- AUTH ----------

@router.post("/auth/register", response_model=MeOut)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    existing = get_user_by_email(db, payload.email.lower().strip())
    if existing:
        raise HTTPException(status_code=400, detail="email already registered")

    user = User(
        email=payload.email.lower().strip(),
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return MeOut(id=user.id, email=user.email)


@router.post("/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email = form.username.lower().strip()
    user = get_user_by_email(db, email)
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    token = create_access_token(user.id)
    return TokenOut(access_token=token)


@router.get("/auth/me", response_model=MeOut)
def me(user: User = Depends(require_user)):
    return MeOut(id=user.id, email=user.email)


# ---------- DEVICES ----------

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


# ---------- SCANS (agent -> platform) ----------

@router.post("/scans", response_model=ScanCreateOut)
def create_scan(
    payload: ScanIn,
    x_device_token: str | None = Header(default=None, convert_underscores=False),
    db: Session = Depends(get_db),
):
    # endpoint-ul asta este pentru AGENT. Autorizare prin device token.
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
    db.flush()  # scan.id disponibil

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


# ---------- READ (frontend) ----------

@router.get("/devices/{device_uid}/scans", response_model=list[DeviceScanListItem])
def list_scans_for_device(
    device_uid: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
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
def get_scan_detail(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
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
    )
