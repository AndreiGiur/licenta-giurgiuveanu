"""Tests pentru scheduler — compute_next_run + CRUD endpoints."""
from datetime import datetime, timezone

from server.app.scheduler import compute_next_run


# ── compute_next_run pure logic ──────────────────────────────────────────────

def test_compute_next_daily_before_hour():
    # Daily la 23:00, acum e 10:00 → next = azi 23:00
    now = datetime(2026, 5, 19, 10, 0, 0, tzinfo=timezone.utc)
    nxt = compute_next_run("daily", hour=23, day_of_week=None,
                          day_of_month=None, now=now)
    assert nxt.hour == 23
    assert nxt.day == 19


def test_compute_next_daily_after_hour():
    # Daily la 03:00, acum e 10:00 → next = mâine 03:00
    now = datetime(2026, 5, 19, 10, 0, 0, tzinfo=timezone.utc)
    nxt = compute_next_run("daily", hour=3, day_of_week=None,
                          day_of_month=None, now=now)
    assert nxt.hour == 3
    assert nxt.day == 20


def test_compute_next_weekly():
    # Weekly luni 09:00 (day_of_week=0). 2026-05-19 e marti → next luni 25.
    now = datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc)
    nxt = compute_next_run("weekly", hour=9, day_of_week=0,
                          day_of_month=None, now=now)
    assert nxt.weekday() == 0
    assert nxt > now
    assert nxt.day == 25


def test_compute_next_monthly():
    # Monthly în ziua 15 la 02:00. Acum e 19 mai → next = 15 iunie.
    now = datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc)
    nxt = compute_next_run("monthly", hour=2, day_of_week=None,
                          day_of_month=15, now=now)
    assert nxt.day == 15
    assert nxt.month == 6


def test_compute_next_monthly_caps_day_to_28():
    # day_of_month=31 → cap la 28
    now = datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc)
    nxt = compute_next_run("monthly", hour=2, day_of_week=None,
                          day_of_month=31, now=now)
    assert nxt.day == 28


# ── CRUD endpoints ───────────────────────────────────────────────────────────

def _enroll(c, headers, uid="sch-pc"):
    from conftest import make_token_pair
    _, h = make_token_pair()
    r = c.post("/api/v1/devices", headers=headers,
               json={"device_uid": uid, "name": uid, "token_hash": h})
    assert r.status_code == 200, r.text


def test_create_schedule_for_my_device(auth_client):
    c, headers = auth_client["client"], auth_client["headers"]
    _enroll(c, headers, uid="sch-create")

    r = c.post("/api/v1/devices/sch-create/schedules", headers=headers,
               json={"scan_type": "standard", "frequency": "daily", "hour": 3})
    assert r.status_code == 200, r.text
    sched = r.json()
    assert sched["enabled"] is True
    assert sched["next_run_at"]
    assert sched["frequency"] == "daily"


def test_list_schedules_for_device(auth_client):
    c, headers = auth_client["client"], auth_client["headers"]
    _enroll(c, headers, uid="sch-list")
    c.post("/api/v1/devices/sch-list/schedules", headers=headers,
           json={"scan_type": "standard", "frequency": "daily", "hour": 3})

    r = c.get("/api/v1/devices/sch-list/schedules", headers=headers)
    assert r.status_code == 200, r.text
    items = r.json()
    assert len(items) == 1


def test_create_weekly_requires_day_of_week(auth_client):
    c, headers = auth_client["client"], auth_client["headers"]
    _enroll(c, headers, uid="sch-w")

    r = c.post("/api/v1/devices/sch-w/schedules", headers=headers,
               json={"scan_type": "standard", "frequency": "weekly", "hour": 9})
    assert r.status_code == 400


def test_max_schedules_per_user(fresh_db_client):
    c = fresh_db_client
    c.post("/api/v1/auth/register",
           json={"email": "scheduler-max@x.com", "password": "passwd123456"})
    c.post("/api/v1/auth/login",
           json={"email": "scheduler-max@x.com", "password": "passwd123456"})
    from conftest import make_token_pair
    _, h = make_token_pair()
    c.post("/api/v1/devices",
           json={"device_uid": "sch-max", "name": "Sch Max", "token_hash": h})

    for i in range(5):
        r = c.post("/api/v1/devices/sch-max/schedules",
                   json={"scan_type": "standard", "frequency": "daily", "hour": i})
        assert r.status_code == 200, r.text

    # Al 6-lea trebuie sa fie respins
    r = c.post("/api/v1/devices/sch-max/schedules",
               json={"scan_type": "standard", "frequency": "daily", "hour": 6})
    assert r.status_code == 400


def test_delete_schedule(auth_client):
    c, headers = auth_client["client"], auth_client["headers"]
    _enroll(c, headers, uid="sch-del")
    r = c.post("/api/v1/devices/sch-del/schedules", headers=headers,
               json={"scan_type": "standard", "frequency": "daily", "hour": 3})
    sched_id = r.json()["id"]

    r = c.delete(f"/api/v1/schedules/{sched_id}", headers=headers)
    assert r.status_code == 204

    r = c.get("/api/v1/devices/sch-del/schedules", headers=headers)
    assert r.json() == []


def test_cannot_schedule_other_users_device(fresh_db_client):
    c = fresh_db_client
    # User A → admin (first)
    c.post("/api/v1/auth/register",
           json={"email": "a@x.com", "password": "passwd123456"})
    c.post("/api/v1/auth/login",
           json={"email": "a@x.com", "password": "passwd123456"})
    from conftest import make_token_pair
    _, h = make_token_pair()
    c.post("/api/v1/devices",
           json={"device_uid": "a-pc", "name": "A PC", "token_hash": h})
    c.delete("/api/v1/auth/logout")

    # User B
    c.post("/api/v1/auth/register",
           json={"email": "b@x.com", "password": "passwd123456"})
    c.post("/api/v1/auth/login",
           json={"email": "b@x.com", "password": "passwd123456"})

    r = c.post("/api/v1/devices/a-pc/schedules",
               json={"scan_type": "standard", "frequency": "daily", "hour": 3})
    assert r.status_code == 404
