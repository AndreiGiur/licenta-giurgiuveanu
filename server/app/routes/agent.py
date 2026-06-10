"""Endpoint-uri pentru agent (auth: X-Device-Token) + download installer + Google enroll desktop."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, google_auth
from ..auth import get_db, require_user
from ..ratelimit import limiter
from ..models import Device, Finding, Scan, ScanJob, ScanJobStatus, User
from ..rules import evaluate
from ..schemas import (
    AgentJobOut,
    GoogleAgentEnrollIn,
    GoogleAgentEnrollOut,
    HeartbeatIn,
    JobFailureIn,
    JobProgressIn,
    JobResultIn,
    ScanJobOut,
)
from ._helpers import (
    _device_for_token_or_401,
    _find_agent_artifact,
    _scan_job_to_out,
    _upsert_google_user,
    _utcnow,
)

router = APIRouter()


@router.get("/agent/jobs/next", response_model=AgentJobOut | None, tags=["agent"])
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


@router.post("/agent/jobs/{job_id}/result", response_model=ScanJobOut, tags=["agent"])
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
        "linux": payload.linux,
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
    device.last_heartbeat = _utcnow()  # liveness: scanul tocmai s-a terminat
    db.commit()
    db.refresh(job)
    return _scan_job_to_out(job, device)


@router.post("/agent/heartbeat", status_code=204, tags=["agent"])
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

    # Alimenteaza ring-buffer-ul de trafic live (in-memory) daca agentul a
    # trimis contoarele de retea.
    if payload.net_bytes_sent is not None and payload.net_bytes_recv is not None:
        from ..livestate import record_sample
        record_sample(
            device_id=device.id,
            ts=_utcnow().timestamp(),
            sent=payload.net_bytes_sent,
            recv=payload.net_bytes_recv,
            conn_count=payload.net_conn_count or 0,
        )


@router.post("/agent/jobs/{job_id}/progress", status_code=204, tags=["agent"])
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
    # Progresul e dovada ca agentul e viu — il tinem ONLINE chiar daca heartbeat-ul
    # e blocat de scanarea in curs (deep dureaza minute). Fix 'fara conexiune'.
    device.last_heartbeat = _utcnow()
    db.commit()


@router.post("/agent/jobs/{job_id}/fail", response_model=ScanJobOut, tags=["agent"])
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
    device.last_heartbeat = _utcnow()  # liveness: agentul a raportat esecul
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


@router.get("/agent/download/windows", tags=["agent"])
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


@router.get("/agent/download/linux", tags=["agent"])
def download_agent_linux(_user: User = Depends(require_user)):
    """Serveste installer-ul Linux `install.sh` pentru user-ii autentificati.
    Scriptul instaleaza dependintele (apt + venv + pip) si aduce sursa
    (checkout local sau git clone). 404 daca lipseste din static."""
    artifact = _find_agent_artifact("install.sh")
    if not artifact:
        raise HTTPException(
            status_code=404,
            detail="Installer Linux indisponibil pe server (agent/install.sh).",
        )
    return FileResponse(
        path=str(artifact),
        media_type="text/x-shellscript",
        filename="install.sh",
    )


@router.get("/agent/download/info", tags=["agent"])
def download_agent_info(_user: User = Depends(require_user)):
    """Indica disponibilitatea build-urilor de agent, per OS. UI-ul afiseaza/
    ascunde butoanele de descarcare in functie de raspuns. Campurile top-level
    (`available`/`platform`/`size_bytes`) sunt pastrate pentru compatibilitate."""
    win = _find_agent_artifact("VulnWatchAgent.exe")
    lin = _find_agent_artifact("install.sh")
    return {
        # backward-compat (Windows la nivel top)
        "available": win is not None,
        "platform": "windows",
        "size_bytes": win.stat().st_size if win else None,
        # per-OS
        "windows": {"available": win is not None,
                    "size_bytes": win.stat().st_size if win else None},
        "linux": {"available": lin is not None,
                  "size_bytes": lin.stat().st_size if lin else None},
    }


@router.post("/agent/google-enroll", response_model=GoogleAgentEnrollOut, tags=["agent"])
@limiter.limit("10/minute")
def agent_google_enroll(request: Request, payload: GoogleAgentEnrollIn, db: Session = Depends(get_db)):
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
