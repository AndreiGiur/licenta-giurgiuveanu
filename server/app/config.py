"""Configuratie aplicatie citita din env."""
import os
from pathlib import Path

from dotenv import load_dotenv

# Incarca .env din radacina server/ (un nivel mai sus de app/).
# Trebuie facut INAINTE de citirea os.environ — `fastapi dev` o face automat,
# `uvicorn` nu, deci forta explicita aici.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

GOOGLE_CLIENT_ID_WEB = os.environ.get("GOOGLE_CLIENT_ID_WEB", "")
GOOGLE_CLIENT_SECRET_WEB = os.environ.get("GOOGLE_CLIENT_SECRET_WEB", "")
GOOGLE_REDIRECT_URI_WEB = os.environ.get(
    "GOOGLE_REDIRECT_URI_WEB",
    "http://localhost:8000/api/v1/auth/google/callback",
)
GOOGLE_CLIENT_ID_DESKTOP = os.environ.get("GOOGLE_CLIENT_ID_DESKTOP", "")
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "http://localhost:5173")

# ── Constante de business / pragulele motorului de scoring ──────────────────
# (extrase din rules.py + routes.py + scheduler.py pentru a fi configurabile)

# Numar maxim de planificari recurente per utilizator (anti-spam).
MAX_SCHEDULES_PER_USER = int(os.environ.get("MAX_SCHEDULES_PER_USER", "5"))

# Limita maxima de hosturi acceptata pe `nmap_target` (anti-abuz pentru retele mari).
MAX_NMAP_TARGET_HOSTS = int(os.environ.get("MAX_NMAP_TARGET_HOSTS", "4096"))

# Numar de porturi scanate per host de nmap (top-N most-common).
NMAP_TOP_PORTS = int(os.environ.get("NMAP_TOP_PORTS", "1000"))

# Prag de zile peste care semnaturile Windows Defender se considera vechi
# (regula AV-DISABLED-1).
SIGNATURE_AGE_DAYS_THRESHOLD = int(os.environ.get("SIGNATURE_AGE_DAYS_THRESHOLD", "7"))

# Prag minim de eventuri 4625 (failed logon) pentru regula EVENTLOG-BRUTEFORCE-1.
BRUTEFORCE_FAIL_COUNT_THRESHOLD = int(os.environ.get("BRUTEFORCE_FAIL_COUNT_THRESHOLD", "10"))

# Prag minim de porturi LISTEN deschise pentru regula NET-MANY-PORTS-2.
MANY_PORTS_THRESHOLD = int(os.environ.get("MANY_PORTS_THRESHOLD", "20"))
