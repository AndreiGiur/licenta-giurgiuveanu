"""Pachet `routes` — agrega sub-routerele pe domeniu intr-un singur `router`.

Inainte: un singur `routes.py` monolitic (~1300 LOC). Acum, fiecare domeniu are
propriul modul cu propriul `APIRouter`, iar aici le includem pe toate intr-un
router unic. `main.py` ramane neschimbat (`from .routes import router`).

Importul lui `config` (prin sub-module) incarca `.env` automat la import.

Domenii:
  auth       — register, login, me, logout, Google OAuth web
  profile    — PATCH /me, /me/stats, /me/sessions, /me/password
  devices    — CRUD device-uri + smart re-link
  scans      — push direct, listare, score-trend, diff, detail, PDF
  scan_jobs  — scan-on-demand (latura UI)
  agent      — endpoint-uri agent (X-Device-Token) + download + Google enroll
  admin      — useri/device-uri/scanari/statistici (require_admin)
  scheduler  — scan schedules recurente
"""
from fastapi import APIRouter

from . import (
    admin,
    agent,
    auth,
    devices,
    profile,
    scan_jobs,
    scans,
    scheduler,
)

router = APIRouter()

# Ordinea de includere nu conteaza pentru matching (nu exista rute ambigue
# care sa depinda de ordine — segmentele literale le diferentiaza).
for _module in (auth, profile, devices, scans, scan_jobs, agent, admin, scheduler):
    router.include_router(_module.router)

__all__ = ["router"]
