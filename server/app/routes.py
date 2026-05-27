from __future__ import annotations

import os
from .config import MAX_NMAP_TARGET_HOSTS, MAX_SCHEDULES_PER_USER
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Header, Response, status, Request
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config, google_auth
from .auth import (
    clear_session_cookie,
    create_password,
    create_session,
    get_db,
    get_session_token_for_logout,
    get_user_by_email,
    require_admin,
    require_user,
    set_session_cookie,
    verify_password,
)
from .models import (
    Device,
    Finding,
    Scan,
    ScanJob,
    ScanJobStatus,
    ScanSchedule,
    Session as DbSession,
    User,
    hash_token,
)
from .schemas import (
    AdminDeviceOut,
    AdminPlatformStatsOut,
    AdminResetPasswordIn,
    AdminRoleChangeIn,
    AdminScanListItem,
    AdminScansPage,
    AdminUserOut,
    AgentJobOut,
    ChangePasswordIn,
    SessionOut,
    UserStatsOut,
    ScheduleIn,
    ScheduleOut,
    ScheduleUpdateIn,
    DeviceCreateIn,
    DeviceCreateOut,
    DeviceOut,
    DeviceRelinkIn,
    DeviceScanListItem,
    ScoreTrendPoint,
    ScanDiffOut,
    ScanDiffFinding,
    GoogleAgentEnrollIn,
    GoogleAgentEnrollOut,
    GoogleAuthUrlOut,
    HeartbeatIn,
    JobFailureIn,
    JobProgressIn,
    JobResultIn,
    LoginIn,
    MeOut,
    UpdateProfileIn,
    RegisterIn,
    ScanCreateOut,
    ScanDetailOut,
    ScanIn,
    ScanJobCreateIn,
    ScanJobOut,
    TokenOut,
)
from .rules import evaluate

router = APIRouter()


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


# ── Helperi scan-job ──────────────────────────────────────────────────────────

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


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _device_to_out(device: Device) -> DeviceOut:
    """Serializeaza un Device cu campurile de online + agent meta."""
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
    )


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


@router.post("/auth/register", response_model=MeOut)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    if get_user_by_email(db, email):
        raise HTTPException(status_code=400, detail="email already registered")

    salt, pwd_hash = create_password(payload.password)
    # Primul user inregistrat in platforma devine admin automat.
    role = "admin" if db.query(User).count() == 0 else "user"
    user = User(email=email, password_salt=salt, password_hash=pwd_hash, role=role)

    db.add(user)
    db.commit()
    db.refresh(user)

    return MeOut(id=user.id, email=user.email, role=user.role)


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


@router.patch("/me", response_model=MeOut)
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

    # Client (agent) genereaza tokenul local si trimite doar hash-ul.
    # Backend stocheaza hash-ul ca atare. Tokenul plain nu apare niciodata aici.
    # Prefix-ul (12 chars) este derivat din primele caractere ale hash-ului pentru UI.
    device = Device(
        owner_id=user.id,
        device_uid=device_uid,
        name=name,
        device_token_hash=payload.token_hash,
        device_token_prefix=payload.token_hash[:8],
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    return _device_to_out(device)


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db), user: User = Depends(require_user)):
    rows = db.execute(select(Device).where(Device.owner_id == user.id).order_by(Device.id.desc())).scalars().all()
    return [_device_to_out(d) for d in rows]


# ── Smart re-link ────────────────────────────────────────────────────────────
#
# Cand agent-ul ruleaza pentru prima data pe o masina noua, sau dupa
# reinstalarea OS-ului, vrem ca user-ul sa nu duplice device-ul.
# Flow-ul este:
#   1. Agent (dupa login) cere GET /devices/by-uid/{uid}
#      → 200 daca device-ul exista deja (display info, oferi re-link)
#      → 404 daca nu exista (agent face POST /devices ca de obicei)
#   2. Daca user-ul confirma re-link, agent face POST /devices/{uid}/relink
#      care invalideaza tokenul vechi si emite unul nou. Scan-urile istorice
#      raman atasate de device.

@router.get("/devices/by-uid/{device_uid}", response_model=DeviceOut)
def get_device_by_uid(
    device_uid: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """Verifica daca un device cu acest UID exista pe contul user-ului.
    Folosit de agent in flow-ul de smart re-link."""
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")
    return _device_to_out(device)


@router.post("/devices/{device_uid}/relink", response_model=DeviceOut)
def relink_device(
    device_uid: str,
    payload: DeviceRelinkIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """Re-emite tokenul pentru un device existent. Clientul trimite noul
    token_hash; backend doar inlocuieste. Scan-urile istorice raman atasate."""
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")

    device.device_token_hash = payload.token_hash
    device.device_token_prefix = payload.token_hash[:8]
    db.commit()
    db.refresh(device)

    return _device_to_out(device)


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
    score, breakdown, findings = evaluate(scan_dict)

    scan = Scan(
        device_id=device.id,
        payload=scan_dict,
        exposure_score=score,
        score_breakdown=breakdown,
    )
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
        device_name=device.name,
        exposure_score=score,
        score_breakdown=breakdown,
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


@router.get("/devices/{device_uid}/score-trend", response_model=list[ScoreTrendPoint])
def device_score_trend(
    device_uid: str,
    days: int = 30,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """Punctele de scor pentru graficul de trend (Recharts) per device.
    Returneaza scan-urile din ultimele `days` zile (max 90), in ordine cronologica."""
    days = max(1, min(days, 90))
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")

    from datetime import timedelta
    cutoff = _utcnow() - timedelta(days=days)
    rows = db.execute(
        select(Scan.id, Scan.created_at, Scan.exposure_score, Scan.payload)
        .where(Scan.device_id == device.id, Scan.created_at >= cutoff)
        .order_by(Scan.created_at.asc())
    ).all()

    return [
        ScoreTrendPoint(
            scan_id=r.id,
            created_at=r.created_at.isoformat(),
            exposure_score=r.exposure_score,
            scan_type=(r.payload or {}).get("scan_type", "standard"),
        )
        for r in rows
    ]


@router.get("/scans/{scan_id}/diff", response_model=ScanDiffOut)
def scan_diff(
    scan_id: int,
    previous: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """Diff intre `previous` (scan vechi) si `scan_id` (scan nou).
    Daca `previous` nu e specificat, foloseste scan-ul anterior pentru acelasi device."""
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    device = db.get(Device, scan.device_id)
    if not device or device.owner_id != user.id:
        raise HTTPException(status_code=404, detail="scan not found")

    if previous is not None:
        prev = db.get(Scan, previous)
        if not prev or prev.device_id != scan.device_id:
            raise HTTPException(status_code=404, detail="previous scan not found on same device")
    else:
        # Cauta automat scan-ul anterior pe acelasi device.
        prev = db.execute(
            select(Scan)
            .where(Scan.device_id == scan.device_id, Scan.id < scan.id)
            .order_by(Scan.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        if not prev:
            raise HTTPException(status_code=404, detail="no previous scan exists for this device")

    def _key(f):
        return f.rule_id

    prev_findings = {_key(f): f for f in prev.findings}
    cur_findings = {_key(f): f for f in scan.findings}

    added_ids = set(cur_findings) - set(prev_findings)
    fixed_ids = set(prev_findings) - set(cur_findings)
    unchanged_ids = set(prev_findings) & set(cur_findings)

    def _to_diff(f):
        return ScanDiffFinding(rule_id=f.rule_id, title=f.title, severity=f.severity)

    return ScanDiffOut(
        from_scan_id=prev.id,
        to_scan_id=scan.id,
        from_score=prev.exposure_score,
        to_score=scan.exposure_score,
        delta=scan.exposure_score - prev.exposure_score,
        added=sorted([_to_diff(cur_findings[k]) for k in added_ids], key=lambda x: x.rule_id),
        fixed=sorted([_to_diff(prev_findings[k]) for k in fixed_ids], key=lambda x: x.rule_id),
        unchanged=sorted([_to_diff(cur_findings[k]) for k in unchanged_ids], key=lambda x: x.rule_id),
    )


@router.get("/scans/{scan_id}", response_model=ScanDetailOut)
def get_scan_detail(scan_id: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")

    device = db.get(Device, scan.device_id)
    if not device or device.owner_id != user.id:
        raise HTTPException(status_code=404, detail="scan not found")

    payload = scan.payload or {}
    return ScanDetailOut(
        scan_id=scan.id,
        device_uid=device.device_uid,
        device_name=device.name,
        created_at=scan.created_at.isoformat(),
        exposure_score=scan.exposure_score,
        score_breakdown=scan.score_breakdown,
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
        payload=payload,
        scan_type=payload.get("scan_type", "standard"),
    )


@router.get("/scans/{scan_id}/report.pdf")
def download_scan_report(scan_id: int, db: Session = Depends(get_db),
                        user: User = Depends(require_user)):
    """Genereaza si returneaza un PDF report pentru un scan. Owner-ul scan-ului
    sau orice admin poate descarca. Pentru alti useri: 404 (nu leak existenta)."""
    from .reports import generate_scan_pdf
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    device = db.get(Device, scan.device_id)
    if not device:
        raise HTTPException(status_code=404, detail="scan not found")
    # Admin bypass: poate descarca PDF pentru oricine
    if user.role != "admin" and device.owner_id != user.id:
        raise HTTPException(status_code=404, detail="scan not found")
    owner = db.get(User, device.owner_id)
    pdf_bytes = generate_scan_pdf(
        scan, device, scan.findings,
        owner_email=owner.email if owner else "unknown@x.com",
    )
    filename = f"vulnwatch-scan-{scan_id}-{scan.created_at.strftime('%Y%m%d')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ──────────────────────────────────────────────────────────────────────────────
# Scan-on-demand: job queue
# ──────────────────────────────────────────────────────────────────────────────
#
# UI ──► POST /devices/{uid}/scan-jobs           ──► job pending
# UI ──► GET  /scan-jobs/{id}                    ──► polling status
# Agent ──► GET  /agent/jobs/next                ──► picks pending → running
# Agent ──► POST /agent/jobs/{id}/result         ──► running → done + Scan
# Agent ──► POST /agent/jobs/{id}/fail           ──► running → failed
# ──────────────────────────────────────────────────────────────────────────────


@router.get("/devices/{device_uid}/scan-jobs/preview")
def scan_jobs_preview(
    device_uid: str,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    """Returnează detected_subnet + estimări pentru UI înainte de scan deep."""
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


@router.post("/devices/{device_uid}/scan-jobs", response_model=ScanJobOut)
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


@router.get("/scan-jobs/{job_id}", response_model=ScanJobOut)
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


@router.get("/devices/{device_uid}/scan-jobs", response_model=list[ScanJobOut])
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


# ── Endpoint-uri pentru agent (auth: X-Device-Token) ─────────────────────────

@router.get("/agent/jobs/next", response_model=AgentJobOut | None)
def agent_get_next_job(
    response: Response,
    db: Session = Depends(get_db),
    x_device_token: str | None = Header(default=None),
):
    """
    Agent polleaza endpoint-ul. Daca exista un job pending pentru device-ul
    asociat tokenului, este atomic mutat in 'running' si returnat. Altfel 204.
    """
    device = _device_for_token_or_401(db, x_device_token)

    # Atomic: SELECT cel mai vechi job pending al device-ului si UPDATE la running
    job = db.execute(
        select(ScanJob)
        .where(ScanJob.device_id == device.id, ScanJob.status == ScanJobStatus.PENDING)
        .order_by(ScanJob.id.asc())
        .with_for_update(skip_locked=True)
    ).scalars().first()

    if not job:
        response.status_code = status.HTTP_204_NO_CONTENT
        return None

    job.status = ScanJobStatus.RUNNING
    job.started_at = _utcnow()
    db.commit()

    return AgentJobOut(job_id=job.id, device_uid=device.device_uid, scan_type=job.scan_type)


@router.post("/agent/jobs/{job_id}/result", response_model=ScanJobOut)
def agent_submit_result(
    job_id: int,
    payload: JobResultIn,
    db: Session = Depends(get_db),
    x_device_token: str | None = Header(default=None),
):
    """Agent trimite rezultatul. Reuseste fluxul de scoring si creeaza Scan."""
    device = _device_for_token_or_401(db, x_device_token)

    job = db.get(ScanJob, job_id)
    if not job or job.device_id != device.id:
        raise HTTPException(status_code=404, detail="scan job not found")
    if job.status != ScanJobStatus.RUNNING:
        raise HTTPException(
            status_code=409,
            detail=f"job is in state '{job.status}', cannot accept results",
        )

    # Construim payload-ul scan-ului in format ScanIn (pentru evaluare).
    # `scan_type` din job determina ce reguli ruleaza (via min_level filtering).
    scan_dict = {
        "device_uid": device.device_uid,
        "scan_type": job.scan_type,
        "os": payload.os,
        "system_info": payload.system_info,
        "network": payload.network,
        "processes": payload.processes,
        "software": payload.software,
        "persistence": payload.persistence,
        "forensics": payload.forensics,
        "nmap": payload.nmap,
    }
    score, breakdown, findings = evaluate(scan_dict)

    scan = Scan(
        device_id=device.id,
        payload=scan_dict,
        exposure_score=score,
        score_breakdown=breakdown,
    )
    db.add(scan)
    db.flush()  # ca sa avem scan.id

    for f in findings:
        db.add(Finding(
            scan_id=scan.id,
            rule_id=f["rule_id"],
            title=f["title"],
            severity=f["severity"],
            evidence=f.get("evidence", {}),
            recommendation=f["recommendation"],
        ))

    job.status = ScanJobStatus.DONE
    job.finished_at = _utcnow()
    job.scan_id = scan.id
    db.commit()
    db.refresh(job)
    return _scan_job_to_out(job, device)


@router.post("/agent/heartbeat", status_code=204)
def agent_heartbeat(
    payload: HeartbeatIn,
    db: Session = Depends(get_db),
    x_device_token: str | None = Header(default=None),
):
    """Agent semnaleaza ca este online. Actualizeaza last_heartbeat + meta."""
    device = _device_for_token_or_401(db, x_device_token)
    device.last_heartbeat = _utcnow()
    device.agent_version = payload.agent_version[:32]
    device.capabilities = payload.capabilities
    if payload.local_subnet:
        device.local_subnet = payload.local_subnet
    if payload.capabilities and "deep" in payload.capabilities:
        device.nmap_installed = True
    else:
        device.nmap_installed = False
    db.commit()


@router.post("/agent/jobs/{job_id}/progress", status_code=204)
def agent_update_progress(
    job_id: int,
    payload: JobProgressIn,
    db: Session = Depends(get_db),
    x_device_token: str | None = Header(default=None),
):
    """Agent raporteaza progresul intre colectori. UI polleaza /scan-jobs/{id}."""
    device = _device_for_token_or_401(db, x_device_token)
    job = db.get(ScanJob, job_id)
    if not job or job.device_id != device.id:
        raise HTTPException(status_code=404, detail="scan job not found")
    if job.status != ScanJobStatus.RUNNING:
        raise HTTPException(
            status_code=409,
            detail=f"job is in state '{job.status}', cannot update progress",
        )
    job.progress = max(0, min(100, payload.progress))
    job.phase = payload.phase[:128]
    db.commit()


@router.post("/agent/jobs/{job_id}/fail", response_model=ScanJobOut)
def agent_submit_failure(
    job_id: int,
    payload: JobFailureIn,
    db: Session = Depends(get_db),
    x_device_token: str | None = Header(default=None),
):
    """Agent raporteaza esec (eroare la colectare, etc.)."""
    device = _device_for_token_or_401(db, x_device_token)

    job = db.get(ScanJob, job_id)
    if not job or job.device_id != device.id:
        raise HTTPException(status_code=404, detail="scan job not found")
    if job.status != ScanJobStatus.RUNNING:
        raise HTTPException(
            status_code=409,
            detail=f"job is in state '{job.status}', cannot mark as failed",
        )

    job.status = ScanJobStatus.FAILED
    job.finished_at = _utcnow()
    job.error_message = payload.error_message[:512]
    db.commit()
    db.refresh(job)
    return _scan_job_to_out(job, device)


# ──────────────────────────────────────────────────────────────────────────────
# Agent installer download
# ──────────────────────────────────────────────────────────────────────────────
#
# Cand exista un build PyInstaller (`agent/build.ps1` produce .exe-ul si il
# copiaza in server/app/static/agent/), acest endpoint il serveste catre
# user-ii autentificati. Daca .exe-ul nu a fost build-uit inca, intoarce
# 404 cu mesaj clar.
#
# Tinem build-ul fie in server/app/static/agent/ (langa cod) fie in
# server/static/agent/. Cautam in ambele locuri.

_AGENT_BUILD_LOCATIONS = (
    Path(__file__).resolve().parent / "static" / "agent",
    Path(__file__).resolve().parent.parent / "static" / "agent",
)


def _find_agent_artifact(filename: str) -> Path | None:
    for base in _AGENT_BUILD_LOCATIONS:
        candidate = base / filename
        if candidate.is_file():
            return candidate
    return None


@router.get("/agent/download/windows")
def download_agent_windows(_user: User = Depends(require_user)):
    """Serveste VulnWatchAgent.exe pentru user-ii autentificati. 404 daca
    nu a fost build-uit (vezi `agent/build.ps1`)."""
    artifact = _find_agent_artifact("VulnWatchAgent.exe")
    if not artifact:
        raise HTTPException(
            status_code=404,
            detail=(
                "Agent installer indisponibil. Build-eaza-l mai intai:\n"
                "    powershell -ExecutionPolicy Bypass -File agent/build.ps1"
            ),
        )
    return FileResponse(
        path=str(artifact),
        media_type="application/vnd.microsoft.portable-executable",
        filename="VulnWatchAgent.exe",
    )


@router.get("/agent/download/info")
def download_agent_info(_user: User = Depends(require_user)):
    """Indica daca un build de agent este disponibil. UI-ul afiseaza/ascunde
    butonul de descarcare in functie de raspuns."""
    artifact = _find_agent_artifact("VulnWatchAgent.exe")
    return {
        "available": artifact is not None,
        "platform": "windows",
        "size_bytes": artifact.stat().st_size if artifact else None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Google OAuth — web flow
# ──────────────────────────────────────────────────────────────────────────────
#
# Frontend: GET /auth/google/url → redirect user catre `auth_url`.
# Google: redirect inapoi la GET /auth/google/callback?code=...&state=...
# Backend: schimba code → id_token, creeaza User (sau il lipeste de email
# existent), seteaza cookie sesiune, redirect catre frontend /dashboard.


@router.get("/auth/google/url", response_model=GoogleAuthUrlOut)
def google_auth_url():
    """Frontend ia URL-ul si redirect-uieste user-ul catre Google."""
    if not config.GOOGLE_CLIENT_ID_WEB:
        raise HTTPException(status_code=503, detail="Google OAuth nu este configurat")
    state = secrets.token_urlsafe(32)
    _store_state(state)
    url = google_auth.build_authorization_url(
        client_id=config.GOOGLE_CLIENT_ID_WEB,
        redirect_uri=config.GOOGLE_REDIRECT_URI_WEB,
        state=state,
    )
    return GoogleAuthUrlOut(auth_url=url, state=state)


@router.get("/auth/google/callback")
async def google_auth_callback(
    code: str,
    state: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """Google a redirectionat user-ul aici. Schimbam code -> id_token,
    creem User (sau il gasim), setam cookie, redirect spre frontend."""
    if not _consume_state(state):
        raise HTTPException(status_code=400, detail="State invalid sau expirat")

    try:
        tokens = await google_auth.exchange_code_for_token(
            code=code,
            client_id=config.GOOGLE_CLIENT_ID_WEB,
            client_secret=config.GOOGLE_CLIENT_SECRET_WEB,
            redirect_uri=config.GOOGLE_REDIRECT_URI_WEB,
        )
        payload = google_auth.verify_id_token(
            tokens["id_token"], config.GOOGLE_CLIENT_ID_WEB
        )
    except google_auth.GoogleAuthError as e:
        raise HTTPException(status_code=400, detail=str(e))

    email = payload["email"].lower().strip()
    google_sub = payload["sub"]
    picture = payload.get("picture")

    user = _upsert_google_user(db, email=email, google_sub=google_sub, picture=picture)

    token = create_session(
        db, user.id,
        user_agent=request.headers.get("user-agent"),
        ip=request.client.host if request.client else None,
    )
    redirect_url = f"{config.FRONTEND_BASE_URL}/dashboard"
    resp = RedirectResponse(url=redirect_url, status_code=302)
    set_session_cookie(resp, token)
    return resp


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


@router.post("/agent/google-enroll", response_model=GoogleAgentEnrollOut)
def agent_google_enroll(payload: GoogleAgentEnrollIn, db: Session = Depends(get_db)):
    """Agent trimite id_token (deja obtinut prin loopback OAuth) + device info.
    Backend verifica tokenul, creeaza/gaseste User + Device, returneaza device_token."""
    if not config.GOOGLE_CLIENT_ID_DESKTOP:
        raise HTTPException(status_code=503, detail="Google OAuth nu este configurat")
    try:
        google_payload = google_auth.verify_id_token(
            payload.id_token, config.GOOGLE_CLIENT_ID_DESKTOP
        )
    except google_auth.GoogleAuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

    email = google_payload["email"].lower().strip()
    google_sub = google_payload["sub"]
    picture = google_payload.get("picture")

    user = _upsert_google_user(db, email=email, google_sub=google_sub, picture=picture)

    # Device upsert by (owner, uid). Clientul trimite token_hash; backend stocheaza
    # hash-ul ca atare (nu mai genereaza tokenul). Tokenul plain ramane pe client.
    device_uid = payload.device_uid.strip()
    device_name = payload.device_name.strip()

    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if device is None:
        device = Device(
            owner_id=user.id,
            device_uid=device_uid,
            name=device_name,
            device_token_hash=payload.token_hash,
            device_token_prefix=payload.token_hash[:8],
        )
        db.add(device)
    else:
        device.device_token_hash = payload.token_hash
        device.device_token_prefix = payload.token_hash[:8]
        device.name = device_name  # update name daca s-a schimbat

    db.commit()
    db.refresh(device)

    return GoogleAgentEnrollOut(
        device_uid=device.device_uid,
        device_name=device.name,
        user_email=user.email,
    )


# ── Admin endpoints ──────────────────────────────────────────────────────────


@router.get("/admin/users", response_model=list[AdminUserOut])
def admin_list_users(
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    out: list[AdminUserOut] = []
    for u in db.query(User).order_by(User.created_at.desc()).all():
        dc = db.query(Device).filter(Device.owner_id == u.id).count()
        out.append(AdminUserOut(
            id=u.id, email=u.email, role=u.role,
            auth_provider=u.auth_provider, created_at=u.created_at,
            device_count=dc,
        ))
    return out


@router.delete("/admin/users/{user_id}", status_code=204)
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


@router.post("/admin/users/{user_id}/role", response_model=AdminUserOut)
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


@router.post("/admin/users/{user_id}/reset-password")
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


@router.get("/admin/devices", response_model=list[AdminDeviceOut])
def admin_list_devices(
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    out: list[AdminDeviceOut] = []
    for d in db.query(Device).order_by(Device.created_at.desc()).all():
        owner = db.query(User).filter(User.id == d.owner_id).first()
        out.append(AdminDeviceOut(
            id=d.id,
            device_uid=d.device_uid,
            name=d.name,
            owner_id=d.owner_id,
            owner_email=owner.email if owner else "unknown@x.com",
            created_at=d.created_at,
            is_online=d.is_online,
        ))
    return out


@router.get("/admin/scans", response_model=AdminScansPage)
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
    items: list[AdminScanListItem] = []
    for s in q.offset(offset).limit(limit).all():
        device = db.query(Device).filter(Device.id == s.device_id).first()
        owner = db.query(User).filter(User.id == device.owner_id).first() if device else None
        scan_type = (s.payload or {}).get("scan_type") if s.payload else None
        items.append(AdminScanListItem(
            scan_id=s.id,
            device_uid=device.device_uid if device else "?",
            device_name=device.name if device else "?",
            owner_email=owner.email if owner else "unknown@x.com",
            created_at=s.created_at,
            exposure_score=s.exposure_score,
            scan_type=scan_type,
        ))
    return AdminScansPage(items=items, total=total, limit=limit, offset=offset)


# ── Scheduler endpoints ──────────────────────────────────────────────────────


@router.post("/devices/{device_uid}/schedules", response_model=ScheduleOut)
def create_schedule(
    device_uid: str,
    body: ScheduleIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    from .scheduler import compute_next_run
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


@router.get("/devices/{device_uid}/schedules",
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


@router.patch("/schedules/{schedule_id}", response_model=ScheduleOut)
def update_schedule(
    schedule_id: int,
    body: ScheduleUpdateIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    from .scheduler import compute_next_run
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


@router.delete("/schedules/{schedule_id}", status_code=204)
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


# ── Profile endpoints (/me/*) ────────────────────────────────────────────────


@router.get("/me/stats", response_model=UserStatsOut)
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


@router.get("/me/sessions", response_model=list[SessionOut])
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
            is_current=(s.token == current_token),
        ))
    return out


@router.delete("/me/sessions/{session_id}", status_code=204)
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


@router.post("/me/password")
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


# ── Admin platform stats ─────────────────────────────────────────────────────

@router.get("/admin/stats", response_model=AdminPlatformStatsOut)
def admin_platform_stats(
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Metrici platforma — pentru sectiunea Platforma din profilul admin."""
    from datetime import timedelta
    total_users = db.query(User).count()
    total_devices = db.query(Device).count()
    # devices_online = is_online property (last_heartbeat < 30s)
    devices_online = sum(1 for d in db.query(Device).all() if d.is_online)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    cutoff_naive = cutoff.replace(tzinfo=None)
    scans_24h = db.query(Scan).filter(Scan.created_at >= cutoff_naive).count()
    scans_total = db.query(Scan).count()
    avg_score: float | None = None
    if scans_total > 0:
        total = sum(s.exposure_score for s in db.query(Scan).all())
        avg_score = round(total / scans_total, 1)
    return AdminPlatformStatsOut(
        total_users=total_users,
        total_devices=total_devices,
        devices_online=devices_online,
        scans_last_24h=scans_24h,
        scans_total=scans_total,
        avg_exposure_score=avg_score,
    )
