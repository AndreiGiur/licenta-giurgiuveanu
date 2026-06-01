"""Helperi partajati intre sub-routerele din pachetul `routes`.

Aici stau functiile folosite de mai multe domenii: serializatori (`_device_to_out`,
`_scan_job_to_out`), autentificarea agentului (`_device_for_token_or_401`), store-ul
de state CSRF pentru Google OAuth, upsert-ul de user Google si localizarea
artefactului de agent.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import get_user_by_email
from ..models import Device, ScanJob, User, hash_token
from ..schemas import DeviceOut, ScanJobOut


# ── Time ────────────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Serializatori ─────────────────────────────────────────────────────────────

def _device_to_out(device: Device, scan_count: int = 0,
                   last_score: int | None = None) -> DeviceOut:
    """Serializeaza un Device cu campurile de online + agent meta. `scan_count`
    + `last_score` sunt populate de `list_devices` (default 0/None in rest)."""
    caps = device.capabilities if isinstance(device.capabilities, list) else []
    return DeviceOut(
        id=device.id,
        device_uid=device.device_uid,
        name=device.name,
        created_at=device.created_at.isoformat(),
        is_online=device.is_online,
        last_heartbeat=device.last_heartbeat.isoformat() if device.last_heartbeat else None,
        agent_version=device.agent_version,
        capabilities=caps,
        scan_count=scan_count,
        last_score=last_score,
    )


def _scan_job_to_out(job: ScanJob, device: Device) -> ScanJobOut:
    """Serializeaza un ScanJob pentru raspunsuri UI. Adauga exposure_score
    daca jobul a produs un Scan finalizat."""
    exposure_score = job.scan.exposure_score if (job.scan_id and getattr(job, "scan", None)) else None
    return ScanJobOut(
        job_id=job.id,
        device_uid=device.device_uid,
        device_name=device.name,
        status=job.status,
        created_at=job.created_at.isoformat(),
        started_at=job.started_at.isoformat() if job.started_at else None,
        finished_at=job.finished_at.isoformat() if job.finished_at else None,
        scan_id=job.scan_id,
        exposure_score=exposure_score,
        error_message=job.error_message,
        scan_type=job.scan_type,
        progress=job.progress,
        phase=job.phase,
    )


# ── Auth agent (X-Device-Token) ────────────────────────────────────────────────

def _device_for_token_or_401(db: Session, x_device_token: str | None) -> Device:
    """Autentifica agentul prin X-Device-Token. Folosit de endpoint-urile /agent/*."""
    if not x_device_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing X-Device-Token")
    device = db.execute(
        select(Device).where(Device.device_token_hash == hash_token(x_device_token))
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid device token")
    return device


# ── Google OAuth: state store CSRF in-memory cu TTL 5 minute ─────────────────
#
# Nu persistam in DB — flow-ul e scurt si nu vrem sa aglomeram tabelele.
# State expira automat dupa 5 minute. La fiecare salvare facem si un cleanup
# oportunist al starilor expirate (evitam memory leak).
_OAUTH_STATE_STORE: dict[str, float] = {}
_OAUTH_STATE_TTL = 300  # 5 minute


def _store_state(state: str) -> None:
    """Salveaza state CSRF + curata stari expirate."""
    now = time.time()
    expired = [s for s, t in _OAUTH_STATE_STORE.items() if now - t > _OAUTH_STATE_TTL]
    for s in expired:
        del _OAUTH_STATE_STORE[s]
    _OAUTH_STATE_STORE[state] = now


def _consume_state(state: str) -> bool:
    """Verifica state si il sterge. True daca e valid si neexpirat."""
    if state not in _OAUTH_STATE_STORE:
        return False
    ts = _OAUTH_STATE_STORE.pop(state)
    return (time.time() - ts) <= _OAUTH_STATE_TTL


def _upsert_google_user(db: Session, email: str, google_sub: str, picture: str | None) -> User:
    """User upsert pe baza email-ului. Daca exista, lipeste google_sub.

    Reguli auth_provider:
    - User nou: 'google'
    - User existent cu parola: 'both'
    - User existent fara parola dar cu google_sub: ramane 'google'"""
    user = get_user_by_email(db, email)
    if user is None:
        # Primul user inregistrat in platforma devine admin automat (acelasi
        # tratament ca la POST /auth/register).
        role = "admin" if db.query(User).count() == 0 else "user"
        user = User(
            email=email,
            google_sub=google_sub,
            google_picture_url=picture,
            auth_provider="google",
            role=role,
        )
        db.add(user)
    else:
        if user.google_sub is None:
            user.google_sub = google_sub
        user.google_picture_url = picture
        if user.password_hash is None:
            user.auth_provider = "google"
        else:
            user.auth_provider = "both"
    db.commit()
    db.refresh(user)
    return user


# ── Agent installer artifact ───────────────────────────────────────────────────
#
# Tinem build-ul fie in server/app/static/agent/ (langa cod) fie in
# server/static/agent/. Cautam in ambele locuri.
_AGENT_BUILD_LOCATIONS = (
    Path(__file__).resolve().parent.parent / "static" / "agent",
    Path(__file__).resolve().parent.parent.parent / "static" / "agent",
)


def _find_agent_artifact(filename: str) -> Path | None:
    for base in _AGENT_BUILD_LOCATIONS:
        candidate = base / filename
        if candidate.is_file():
            return candidate
    return None
