"""Endpoint-uri de profil pentru userul curent: PATCH /me + /me/stats, /me/sessions, /me/password."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import (
    create_password,
    get_db,
    get_session_token_for_logout,
    require_user,
    verify_password,
)
from ..models import Device, Scan, Session as DbSession, User, hash_token
from ..schemas import (
    ChangePasswordIn,
    MeOut,
    SessionOut,
    UpdateProfileIn,
    UserStatsOut,
)

from sqlalchemy.orm import Session

router = APIRouter()


@router.patch("/me", response_model=MeOut, tags=["profile"])
def update_my_profile(
    payload: UpdateProfileIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """Editare profil curent: nume, prenume, scan type default. Toate sunt
    optionale - doar campurile prezente in body sunt actualizate."""
    if payload.first_name is not None:
        user.first_name = payload.first_name.strip() or None
    if payload.last_name is not None:
        user.last_name = payload.last_name.strip() or None
    if payload.default_scan_type is not None:
        user.default_scan_type = payload.default_scan_type
    db.commit()
    db.refresh(user)
    return MeOut(
        id=user.id,
        email=user.email,
        google_picture_url=user.google_picture_url,
        auth_provider=user.auth_provider,
        role=user.role,
        first_name=user.first_name,
        last_name=user.last_name,
        default_scan_type=user.default_scan_type or "standard",
    )


@router.get("/me/stats", response_model=UserStatsOut, tags=["profile"])
def me_stats(
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    """Statistici personale: numar device-uri, numar scanari, avg score, ultima scanare."""
    device_count = db.query(Device).filter(Device.owner_id == user.id).count()
    device_ids = [d.id for d in db.query(Device.id).filter(
        Device.owner_id == user.id).all()]
    if not device_ids:
        return UserStatsOut(
            device_count=device_count,
            scan_count=0,
            avg_exposure_score=None,
            last_scan_at=None,
            last_scan_score=None,
        )
    scans = db.query(Scan).filter(Scan.device_id.in_(device_ids)).all()
    if not scans:
        return UserStatsOut(
            device_count=device_count,
            scan_count=0,
            avg_exposure_score=None,
            last_scan_at=None,
            last_scan_score=None,
        )
    avg = sum(s.exposure_score for s in scans) / len(scans)
    last = max(scans, key=lambda s: s.created_at)
    return UserStatsOut(
        device_count=device_count,
        scan_count=len(scans),
        avg_exposure_score=round(avg, 1),
        last_scan_at=last.created_at,
        last_scan_score=last.exposure_score,
    )


@router.get("/me/sessions", response_model=list[SessionOut], tags=["profile"])
def me_sessions(
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
    current_token: str | None = Depends(get_session_token_for_logout),
):
    """Lista sesiunilor active ale userului curent. `is_current` marcheaza
    sesiunea care a facut request-ul curent (deductibil din token)."""
    out: list[SessionOut] = []
    for s in db.query(DbSession).filter(
        DbSession.user_id == user.id
    ).order_by(DbSession.created_at.desc()).all():
        out.append(SessionOut(
            id=s.id,
            user_agent=s.user_agent,
            ip=s.ip,
            created_at=s.created_at,
            expires_at=s.expires_at,
            is_current=(current_token is not None and s.token == hash_token(current_token)),
        ))
    return out


@router.delete("/me/sessions/{session_id}", status_code=204, tags=["profile"])
def me_revoke_session(
    session_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    """Revoca o sesiune (alta decat cea curenta). Folosit din UI pentru logout
    remote (ex: ai uitat sa te delogezi pe alt device)."""
    sess = db.query(DbSession).filter(
        DbSession.id == session_id,
        DbSession.user_id == user.id,
    ).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    db.delete(sess)
    db.commit()


@router.post("/me/password", tags=["profile"])
def me_change_password(
    body: ChangePasswordIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    """Schimba parola pentru cont (necesita parola veche). Pentru conturi
    Google-only (fara password_hash) -> 400."""
    if not user.password_hash or not user.password_salt:
        raise HTTPException(
            status_code=400,
            detail="Account has no password set (Google-only). Set one via password reset.",
        )
    if not verify_password(body.old_password, user.password_salt, user.password_hash):
        raise HTTPException(status_code=401, detail="Old password incorrect")
    salt, pwd_hash = create_password(body.new_password)
    user.password_salt = salt
    user.password_hash = pwd_hash
    db.commit()
    return {"ok": True}
