"""Teste pentru fix-urile de securitate/robustete:

1. Session token stocat hash-uit in DB (nu plain) — auth.py
2. OAuth state semnat HMAC, stateless — routes/_helpers.py
3. reap_stale_jobs marcheaza failed joburile running blocate — scheduler.py
"""
import time
import uuid
from datetime import datetime, timedelta, timezone

from server.app.db import SessionLocal
from server.app.models import (
    Device,
    ScanJob,
    ScanJobStatus,
    Session as DbSession,
    User,
    hash_token,
)
from server.app.routes._helpers import _consume_state, _make_state
from server.app.scheduler import reap_stale_jobs


# ── 1. Session token hash-uit in DB ───────────────────────────────────────────

def test_session_token_stored_hashed(client):
    email = f"hash-{uuid.uuid4().hex[:8]}@example.com"
    password = "password123"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    plain = r.json()["session_token"]

    with SessionLocal() as db:
        # Tokenul plain NU exista in DB...
        assert db.query(DbSession).filter(DbSession.token == plain).first() is None
        # ...dar hash-ul lui da.
        row = db.query(DbSession).filter(DbSession.token == hash_token(plain)).first()
        assert row is not None

    # Tokenul plain functioneaza in continuare la autentificare.
    r = client.get("/api/v1/auth/me", headers={"X-Session-Token": plain})
    assert r.status_code == 200
    assert r.json()["email"] == email


def test_logout_deletes_hashed_session(client):
    email = f"hash-{uuid.uuid4().hex[:8]}@example.com"
    password = "password123"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    plain = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    ).json()["session_token"]

    r = client.delete("/api/v1/auth/logout", headers={"X-Session-Token": plain})
    assert r.status_code == 200
    with SessionLocal() as db:
        assert db.query(DbSession).filter(DbSession.token == hash_token(plain)).first() is None


def test_me_sessions_is_current_with_hashed_tokens(client):
    email = f"hash-{uuid.uuid4().hex[:8]}@example.com"
    password = "password123"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    t1 = client.post("/api/v1/auth/login",
                     json={"email": email, "password": password}).json()["session_token"]
    t2 = client.post("/api/v1/auth/login",
                     json={"email": email, "password": password}).json()["session_token"]

    r = client.get("/api/v1/me/sessions", headers={"X-Session-Token": t2})
    assert r.status_code == 200, r.text
    sessions = r.json()
    assert len(sessions) == 2
    # Exact una e marcata is_current (cea care a facut request-ul, t2).
    assert sum(1 for s in sessions if s["is_current"]) == 1


# ── 2. OAuth state HMAC ───────────────────────────────────────────────────────

def test_oauth_state_roundtrip():
    state = _make_state()
    assert _consume_state(state) is True


def test_oauth_state_tampered_signature():
    state = _make_state()
    # Stricam ultimul caracter al semnaturii.
    bad = state[:-1] + ("0" if state[-1] != "0" else "1")
    assert _consume_state(bad) is False


def test_oauth_state_tampered_payload():
    state = _make_state()
    nonce, ts, sig = state.split(".")
    assert _consume_state(f"{nonce}x.{ts}.{sig}") is False


def test_oauth_state_malformed():
    assert _consume_state("") is False
    assert _consume_state("garbage") is False
    assert _consume_state("a.b") is False


def test_oauth_state_expired(monkeypatch):
    state = _make_state()
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 301)
    assert _consume_state(state) is False


# ── 3. reap_stale_jobs ────────────────────────────────────────────────────────

def _make_device(db) -> Device:
    user = User(email=f"reap-{uuid.uuid4().hex[:8]}@example.com",
                password_salt="00", password_hash="00")
    db.add(user)
    db.flush()
    device = Device(
        owner_id=user.id,
        device_uid=f"dev-{uuid.uuid4().hex[:8]}",
        name="reap-test",
        device_token_hash=hash_token(uuid.uuid4().hex),
        device_token_prefix="abcdef12",
    )
    db.add(device)
    db.flush()
    return device


def test_reap_marks_stale_running_job_failed():
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        device = _make_device(db)
        stale = ScanJob(
            device_id=device.id, status=ScanJobStatus.RUNNING,
            started_at=(now - timedelta(minutes=120)).replace(tzinfo=None),
        )
        db.add(stale)
        db.commit()
        stale_id = stale.id

        reaped = reap_stale_jobs(db, now=now, timeout_min=90)
        db.commit()
        assert reaped == 1

        job = db.get(ScanJob, stale_id)
        assert job.status == ScanJobStatus.FAILED
        assert job.finished_at is not None
        assert "timeout" in job.error_message


def test_reap_leaves_fresh_and_pending_jobs_alone():
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        device = _make_device(db)
        fresh_running = ScanJob(
            device_id=device.id, status=ScanJobStatus.RUNNING,
            started_at=(now - timedelta(minutes=5)).replace(tzinfo=None),
        )
        pending = ScanJob(device_id=device.id, status=ScanJobStatus.PENDING)
        db.add_all([fresh_running, pending])
        db.commit()
        fresh_id, pending_id = fresh_running.id, pending.id

        reaped = reap_stale_jobs(db, now=now, timeout_min=90)
        db.commit()
        assert reaped == 0
        assert db.get(ScanJob, fresh_id).status == ScanJobStatus.RUNNING
        assert db.get(ScanJob, pending_id).status == ScanJobStatus.PENDING


def test_reap_unblocks_scheduler_skip_logic():
    """Dupa reap, scheduler-ul poate crea din nou joburi pentru device
    (verifica direct conditia de skip: niciun job pending/running ramas)."""
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        device = _make_device(db)
        db.add(ScanJob(
            device_id=device.id, status=ScanJobStatus.RUNNING,
            started_at=(now - timedelta(hours=3)).replace(tzinfo=None),
        ))
        db.commit()

        reap_stale_jobs(db, now=now, timeout_min=90)
        db.commit()

        blocking = db.query(ScanJob).filter(
            ScanJob.device_id == device.id,
            ScanJob.status.in_(["pending", "running"]),
        ).first()
        assert blocking is None
