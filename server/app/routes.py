from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Header, Response, status, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import (
    clear_session_cookie,
    create_password,
    create_session,
    get_db,
    get_session_token_for_logout,
    get_user_by_email,
    require_user,
    set_session_cookie,
    verify_password,
)
from .models import User, Device, Scan, Finding, Session as DbSession, hash_token
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
def login(request: Request, response: Response, payload: LoginIn, db: Session = Depends(get_db)):
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

    # Browser-ele primesc cookie HttpOnly. Clientii non-browser (agent, curl,
    # teste) folosesc tokenul din raspuns prin headerul X-Session-Token.
    set_session_cookie(response, token)
    return TokenOut(session_token=token)


@router.get("/auth/me", response_model=MeOut)
def me(user: User = Depends(require_user)):
    return MeOut(id=user.id, email=user.email)


@router.delete("/auth/logout")
def logout(
    response: Response,
    db: Session = Depends(get_db),
    token: str | None = Depends(get_session_token_for_logout),
):
    """Logout idempotent: sterge sesiunea din DB daca exista si curata cookie-ul.
    Nu intoarce 401 daca tokenul lipseste — clientul a vrut deja sa se delogeze."""
    if token:
        sess = db.execute(select(DbSession).where(DbSession.token == token)).scalar_one_or_none()
        if sess:
            db.delete(sess)
            db.commit()
    clear_session_cookie(response)
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

    # Generam tokenul, dar stocam doar hash-ul. Plain-ul este returnat o singura data.
    plain_token = Device.generate_token()
    device = Device(
        owner_id=user.id,
        device_uid=device_uid,
        name=name,
        device_token_hash=hash_token(plain_token),
        device_token_prefix=plain_token[:8],
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    return DeviceCreateOut(
        id=device.id,
        device_uid=device.device_uid,
        name=device.name,
        created_at=device.created_at.isoformat(),
        device_token=plain_token,
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

    device_uid = payload.device_uid.strip()

    # Cautam device-ul prin hash-ul tokenului. device_uid trebuie sa corespunda
    # cu device-ul indicat de token (defense in depth: nu lasam un token valid
    # sa scrie scan-uri pe alt device).
    token_h = hash_token(x_device_token)
    device = db.execute(
        select(Device).where(
            Device.device_token_hash == token_h,
            Device.device_uid == device_uid,
        )
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid device token or device_uid mismatch",
        )

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
        device_uid=device.device_uid,
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
        device_uid=device.device_uid,
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
