"""Configuratie aplicatie citita din env."""
import os

GOOGLE_CLIENT_ID_WEB = os.environ.get("GOOGLE_CLIENT_ID_WEB", "")
GOOGLE_CLIENT_SECRET_WEB = os.environ.get("GOOGLE_CLIENT_SECRET_WEB", "")
GOOGLE_REDIRECT_URI_WEB = os.environ.get(
    "GOOGLE_REDIRECT_URI_WEB",
    "http://localhost:8000/api/v1/auth/google/callback",
)
GOOGLE_CLIENT_ID_DESKTOP = os.environ.get("GOOGLE_CLIENT_ID_DESKTOP", "")
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "http://localhost:5173")
