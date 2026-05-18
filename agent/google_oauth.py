"""Loopback OAuth flow pentru desktop.

`InstalledAppFlow.run_local_server(port=0)` face toata coregrafia:
- genereaza PKCE code_verifier + challenge
- porneste local server pe port random (0 = OS alege)
- deschide browserul cu URL Google
- prinde codul de pe redirect
- face exchange cu Google
- returneaza Credentials cu id_token deja obtinut"""
from __future__ import annotations

import os

try:
    from .google_config import GOOGLE_CLIENT_ID
except ImportError:
    GOOGLE_CLIENT_ID = os.environ.get("AGENT_GOOGLE_CLIENT_ID", "")

try:
    from .google_config import GOOGLE_CLIENT_SECRET
except ImportError:
    GOOGLE_CLIENT_SECRET = os.environ.get("AGENT_GOOGLE_CLIENT_SECRET", "")

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]


class GoogleOAuthError(Exception):
    """Esec in flow-ul OAuth desktop."""


def is_configured() -> bool:
    return bool(GOOGLE_CLIENT_ID)


def login_with_google(success_message: str = "Te poti intoarce la VulnWatch Agent.") -> str:
    """Deschide browserul, asteapta autentificare, returneaza id_token.

    Functia e BLOCANTA — apeleaz-o intr-un thread daca esti pe Tk main loop."""
    if not GOOGLE_CLIENT_ID:
        raise GoogleOAuthError(
            "GOOGLE_CLIENT_ID lipseste. Configureaza agent/google_config.py "
            "sau seteaza AGENT_GOOGLE_CLIENT_ID."
        )
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError as e:
        raise GoogleOAuthError(
            "google-auth-oauthlib nu este instalat. Ruleaza pip install -r requirements.txt."
        ) from e

    flow = InstalledAppFlow.from_client_config(
        {
            "installed": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://127.0.0.1"],
            }
        },
        scopes=SCOPES,
    )
    try:
        flow.run_local_server(
            port=0,
            open_browser=True,
            success_message=success_message,
        )
    except Exception as e:
        raise GoogleOAuthError(f"flow OAuth esuat: {e}") from e

    id_tok = getattr(flow.credentials, "id_token", None)
    if not id_tok:
        raise GoogleOAuthError("Google nu a returnat id_token. Verifica scope-urile.")
    return id_tok
