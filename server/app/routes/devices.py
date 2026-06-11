"""Endpoint-uri pentru device-uri: creare, listare, smart re-link, stergere.

Crearea de device-uri se face NUMAI prin executabil (agent). Platform UI permite
doar listare + stergere.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import get_db, require_user
from ..models import Device, Scan, User
from ..schemas import (
    DeviceCreateIn,
    DeviceCreateOut,
    DeviceOut,
    DeviceRelinkIn,
)
from ._helpers import _device_to_out

router = APIRouter()


@router.post("/devices", response_model=DeviceCreateOut, tags=["devices"])
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


@router.get("/devices", response_model=list[DeviceOut], tags=["devices"])
def list_devices(db: Session = Depends(get_db), user: User = Depends(require_user)):
    rows = db.execute(select(Device).where(Device.owner_id == user.id).order_by(Device.id.desc())).scalars().all()

    # Agregari intr-un numar fix de query-uri (nu 2 per device): count-uri
    # grupate + scorul ultimului scan (max(Scan.id) per device).
    counts: dict[int, int] = dict(db.execute(
        select(Scan.device_id, func.count(Scan.id))
        .join(Device, Scan.device_id == Device.id)
        .where(Device.owner_id == user.id)
        .group_by(Scan.device_id)
    ).all())
    latest_ids = (
        select(func.max(Scan.id))
        .join(Device, Scan.device_id == Device.id)
        .where(Device.owner_id == user.id)
        .group_by(Scan.device_id)
        .scalar_subquery()
    )
    last_scores: dict[int, int] = dict(db.execute(
        select(Scan.device_id, Scan.exposure_score).where(Scan.id.in_(latest_ids))
    ).all())

    return [
        _device_to_out(d, scan_count=counts.get(d.id, 0), last_score=last_scores.get(d.id))
        for d in rows
    ]


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

@router.get("/devices/by-uid/{device_uid}", response_model=DeviceOut, tags=["devices"])
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


@router.post("/devices/{device_uid}/relink", response_model=DeviceOut, tags=["devices"])
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


@router.get("/devices/{device_uid}/net-traffic", tags=["devices"])
def device_net_traffic(device_uid: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Serie de trafic live (ultimele ~10 min) pentru graficul de retea.
    Date in-memory din ring-buffer (livestate), alimentate de heartbeat."""
    from ..livestate import get_series
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")
    return get_series(device.id)


@router.delete("/devices/{device_uid}", status_code=204, tags=["devices"])
def delete_device(device_uid: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    device = db.execute(
        select(Device).where(Device.owner_id == user.id, Device.device_uid == device_uid)
    ).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")

    db.delete(device)
    db.commit()
