"""Endpoint-uri pentru scanari: push direct, listare, score-trend, diff, detail, PDF report."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import get_db, require_user
from ..models import Device, Finding, Scan, User, hash_token
from ..rules import evaluate
from ..schemas import (
    DeviceScanListItem,
    ScanCreateOut,
    ScanDetailOut,
    ScanDiffFinding,
    ScanDiffOut,
    ScanIn,
    ScoreTrendPoint,
)
from ._helpers import _utcnow

router = APIRouter()


@router.post("/scans", response_model=ScanCreateOut, tags=["scans"])
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


@router.get("/devices/{device_uid}/scans", response_model=list[DeviceScanListItem], tags=["scans"])
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


@router.get("/devices/{device_uid}/score-trend", response_model=list[ScoreTrendPoint], tags=["scans"])
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


@router.get("/scans/{scan_id}/diff", response_model=ScanDiffOut, tags=["scans"])
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


@router.get("/scans/{scan_id}", response_model=ScanDetailOut, tags=["scans"])
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


@router.get("/scans/{scan_id}/report.pdf", tags=["scans"])
def download_scan_report(scan_id: int, db: Session = Depends(get_db),
                        user: User = Depends(require_user)):
    """Genereaza si returneaza un PDF report pentru un scan. Owner-ul scan-ului
    sau orice admin poate descarca. Pentru alti useri: 404 (nu leak existenta)."""
    from ..reports import generate_scan_pdf
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
