from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select

from .db import SessionLocal
from .models import Scan, Finding
from .schemas import ScanIn, ScanOut
from .rules import evaluate

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/scans", response_model=ScanOut)
def create_scan(payload: ScanIn, db: Session = Depends(get_db)):
    scan_dict = payload.model_dump()
    score, findings = evaluate(scan_dict)

    row = Scan(device_id=payload.device_id, payload=scan_dict, exposure_score=score)
    db.add(row)
    db.flush()  # obtine row.id fara commit

    for f in findings:
        db.add(
            Finding(
                scan_id=row.id,
                rule_id=f["rule_id"],
                title=f["title"],
                severity=f["severity"],
                evidence=f.get("evidence", {}),
                recommendation=f["recommendation"],
            )
        )

    db.commit()
    db.refresh(row)

    return ScanOut(
        scan_id=row.id,
        device_id=row.device_id,
        findings=findings,
        exposure_score=score,
    )


@router.get("/devices/{device_id}/scans")
def list_scans(device_id: str, db: Session = Depends(get_db)):
    rows = db.execute(
        select(Scan.id, Scan.created_at, Scan.exposure_score)
        .where(Scan.device_id == device_id)
        .order_by(Scan.id.desc())
        .limit(50)
    ).all()

    return [
        {"scan_id": r.id, "created_at": r.created_at, "exposure_score": r.exposure_score}
        for r in rows
    ]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="not found")

    return {
        "scan_id": scan.id,
        "device_id": scan.device_id,
        "created_at": scan.created_at,
        "exposure_score": scan.exposure_score,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in scan.findings
        ],
    }
