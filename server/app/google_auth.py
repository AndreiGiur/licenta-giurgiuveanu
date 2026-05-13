"""Verificare ID tokens Google + exchange code -> token.

Centralizam interactiunea cu Google ca sa fie usor de mock-uit in teste."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

import httpx
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token


class GoogleAuthError(Exception):
    """Eroare la verificare token sau exchange cu Google."""


GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"


def verify_id_token(token: str, client_id: str) -> dict[str, Any]:
    """Verifica un id_token Google. Returneaza payload-ul decodat.

    Arunca GoogleAuthError daca tokenul e invalid, expirat sau pentru alt aud."""
    try:
        payload = id_token.verify_oauth2_token(
            token, google_requests.Request(), client_id
        )
    except Exception as e:
        raise GoogleAuthError(f"id_token invalid: {e}") from e
    return payload


async def exchange_code_for_token(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code_verifier: str | None = None,
) -> dict[str, Any]:
    """POST la token endpoint Google. Returneaza dict cu id_token, access_token, etc.

    Daca dam code_verifier (PKCE), client_secret poate fi gol pentru desktop apps."""
    data = {
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    if client_secret:
        data["client_secret"] = client_secret
    if code_verifier:
        data["code_verifier"] = code_verifier

    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(GOOGLE_TOKEN_ENDPOINT, data=data, timeout=15)
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise GoogleAuthError(f"exchange code esuat: {e}") from e
        return r.json()


def build_authorization_url(
    client_id: str,
    redirect_uri: str,
    state: str,
    scopes: list[str] | None = None,
) -> str:
    """Construieste URL-ul de autorizare Google pentru flow-ul web."""
    if scopes is None:
        scopes = ["openid", "email", "profile"]
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    return f"{GOOGLE_AUTH_ENDPOINT}?{urlencode(params)}"
