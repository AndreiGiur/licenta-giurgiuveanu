from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Header, Response, status, Request
from fastapi.responses import FileResponse
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
from .models import (
    Device,
    Finding,
    Scan,
    ScanJob,
    ScanJobStatus,
    Session as DbSession,
    User,
    hash_token,
)
from .schemas import (
    AgentJobOut,
    DeviceCreateIn,
    DeviceCreateOut,
    DeviceOut,
    DeviceScanListItem,
    HeartbeatIn,
    JobFailureIn,
    JobProgressIn,
    JobResultIn,
    LoginIn,
    MeOut,
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

    out = _device_to_out(device)
    return DeviceCreateOut(**out.model_dump(), device_token=plain_token)


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


@router.post("/devices/{device_uid}/relink", response_model=DeviceCreateOut)
def relink_device(
    device_uid: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """Re-emite tokenul pentru un device existent (acelasi UID, acelasi owner).
    Tokenul vechi este invalidat. Scan-urile istorice raman atasate.
    Util pentru: reinstalare OS, mutare agent, recuperare token pierdut."""
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")

    plain_token = Device.generate_token()
    device.device_token_hash = hash_token(plain_token)
    device.device_token_prefix = plain_token[:8]
    db.commit()
    db.refresh(device)

    out = _device_to_out(device)
    return DeviceCreateOut(**out.model_dump(), device_token=plain_token)


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
        device_name=device.name,
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

    payload = scan.payload or {}
    return ScanDetailOut(
        scan_id=scan.id,
        device_uid=device.device_uid,
        device_name=device.name,
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
        payload=payload,
        scan_type=payload.get("scan_type", "standard"),
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

    job = ScanJob(
        device_id=device.id,
        requested_by_user_id=user.id,
        status=ScanJobStatus.PENDING,
        scan_type=payload.scan_type,
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
    }
    score, findings = evaluate(scan_dict)

    scan = Scan(device_id=device.id, payload=scan_dict, exposure_score=score)
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
