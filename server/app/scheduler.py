"""Scheduler logic — compute_next_run pure function + background asyncio loop."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone


logger = logging.getLogger(__name__)


def compute_next_run(
    frequency: str,
    hour: int,
    day_of_week: int | None,
    day_of_month: int | None,
    now: datetime | None = None,
) -> datetime:
    """Calculeaza urmatoarea ora de rulare, UTC, fara secunde.

    `frequency`: "daily" | "weekly" | "monthly".
    `hour`: 0-23.
    `day_of_week`: 0=luni..6=duminica (necesar pentru weekly).
    `day_of_month`: 1-28 (cap la 28 ca sa evitam edge case Feb).
    """
    if now is None:
        now = datetime.now(timezone.utc)
    # Normalizare: drop secunde + microsecunde
    now = now.replace(second=0, microsecond=0)
    if frequency == "daily":
        candidate = now.replace(hour=hour, minute=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate
    if frequency == "weekly":
        if day_of_week is None:
            raise ValueError("day_of_week required for weekly")
        candidate = now.replace(hour=hour, minute=0)
        days_ahead = (day_of_week - now.weekday()) % 7
        if days_ahead == 0 and candidate <= now:
            days_ahead = 7
        return candidate + timedelta(days=days_ahead)
    if frequency == "monthly":
        if day_of_month is None:
            raise ValueError("day_of_month required for monthly")
        dom = min(day_of_month, 28)
        candidate = now.replace(day=dom, hour=hour, minute=0)
        if candidate <= now:
            # Urmatoarea luna
            m = now.month + 1 if now.month < 12 else 1
            y = now.year if now.month < 12 else now.year + 1
            candidate = candidate.replace(year=y, month=m)
        return candidate
    raise ValueError(f"Unknown frequency: {frequency}")


async def scheduler_loop(session_factory, poll_interval: int = 60):
    """Background loop care creeaza ScanJob-uri pentru schedule-uri due.

    Ruleaza ca asyncio.Task pornit la startup-ul aplicatiei via FastAPI lifespan.
    Skip pe SC_DISABLED_SCHEDULER=true (folosit in teste)."""
    from .models import Device, ScanJob, ScanSchedule
    logger.info("Scheduler loop started (poll=%ds)", poll_interval)
    while True:
        try:
            with session_factory() as db:
                now_aware = datetime.now(timezone.utc)
                # SQLite stocheaza naive datetimes; comparam ca naive UTC.
                now_naive = now_aware.replace(tzinfo=None)
                due = db.query(ScanSchedule).filter(
                    ScanSchedule.enabled == True,  # noqa: E712
                    ScanSchedule.next_run_at <= now_naive,
                ).all()
                for sched in due:
                    dev = db.query(Device).filter(Device.id == sched.device_id).first()
                    if not dev:
                        continue
                    # Skip daca exista deja un job pending/running pentru device.
                    existing = db.query(ScanJob).filter(
                        ScanJob.device_id == sched.device_id,
                        ScanJob.status.in_(["pending", "running"]),
                    ).first()
                    if not existing:
                        db.add(ScanJob(
                            device_id=sched.device_id,
                            scan_type=sched.scan_type,
                            nmap_target=sched.nmap_target,
                            status="pending",
                            source="scheduled",
                        ))
                        logger.info(
                            "Scheduled job created for device %s (%s)",
                            dev.device_uid, sched.scan_type,
                        )
                    sched.last_run_at = now_naive
                    sched.next_run_at = compute_next_run(
                        sched.frequency, sched.hour,
                        sched.day_of_week, sched.day_of_month,
                        now=now_aware,
                    ).replace(tzinfo=None)
                db.commit()
        except Exception as e:
            logger.error("scheduler_loop error: %s", e, exc_info=True)
        await asyncio.sleep(poll_interval)
