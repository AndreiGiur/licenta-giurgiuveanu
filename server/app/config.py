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
