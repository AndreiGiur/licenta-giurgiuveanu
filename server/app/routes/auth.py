"""Endpoint-uri de autentificare: register, login, me, logout + Google OAuth web flow."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, google_auth
from ..auth import (
    clear_session_cookie,
    create_password,
    create_session,
    get_db,
    get_session_token_for_logout,
    get_user_by_email,
    require_user,
    set_session_cookie,
    verify_password,
)
from ..models import Session as DbSession, User
from ..ratelimit import limiter
from ..schemas import GoogleAuthUrlOut, LoginIn, MeOut, RegisterIn, TokenOut
from ._helpers import _consume_state, _store_state, _upsert_google_user

router = APIRouter()


@router.post("/auth/register", response_model=MeOut, tags=["auth"])
@limiter.limit("5/minute")
def register(request: Request, payload: RegisterIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    if get_user_by_email(db, email):
        raise HTTPException(status_code=400, detail="email already registered")

    salt, pwd_hash = create_password(payload.password)
    # Primul user inregistrat in platforma devine admin automat.
    role = "admin" if db.query(User).count() == 0 else "user"
    user = User(email=email, password_salt=salt, password_hash=pwd_hash, role=role)

    db.add(user)
    db.commit()
    db.refresh(user)

    return MeOut(id=user.id, email=user.email, role=user.role)


@router.post("/auth/login", response_model=TokenOut, tags=["auth"])
@limiter.limit("5/minute")
def login(request: Request, response: Response, payload: LoginIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = get_user_by_email(db, email)
    if not user or not verify_password(payload.password, user.password_salt, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    token = create_session(
        db,
        user.id,
        user_agent=request.headers.get("user-agent"),
        ip=request.client.host if request.client else None,
    )

    # Browser-ele primesc cookie HttpOnly. Clientii non-browser (agent, curl,
    # teste) folosesc tokenul din raspuns prin headerul X-Session-Token.
    set_session_cookie(response, token)
    return TokenOut(session_token=token)


@router.get("/auth/me", response_model=MeOut, tags=["auth"])
def me(user: User = Depends(require_user)):
    return MeOut(
        id=user.id,
        email=user.email,
        google_picture_url=user.google_picture_url,
        auth_provider=user.auth_provider,
        role=user.role,
        first_name=user.first_name,
        last_name=user.last_name,
        default_scan_type=user.default_scan_type or "standard",
    )


@router.delete("/auth/logout", tags=["auth"])
def logout(
    response: Response,
    db: Session = Depends(get_db),
    token: str | None = Depends(get_session_token_for_logout),
):
    """Logout idempotent: sterge sesiunea din DB daca exista si curata cookie-ul.
    Nu intoarce 401 daca tokenul lipseste — clientul a vrut deja sa se delogeze."""
    if token:
        sess = db.execute(select(DbSession).where(DbSession.token == token)).scalar_one_or_none()
        if sess:
            db.delete(sess)
            db.commit()
    clear_session_cookie(response)
    return {"ok": True}


# ──────────────────────────────────────────────────────────────────────────────
# Google OAuth — web flow
# ──────────────────────────────────────────────────────────────────────────────
#
# Frontend: GET /auth/google/url → redirect user catre `auth_url`.
# Google: redirect inapoi la GET /auth/google/callback?code=...&state=...
# Backend: schimba code → id_token, creeaza User (sau il lipeste de email
# existent), seteaza cookie sesiune, redirect catre frontend /dashboard.


@router.get("/auth/google/url", response_model=GoogleAuthUrlOut, tags=["auth"])
def google_auth_url():
    """Frontend ia URL-ul si redirect-uieste user-ul catre Google."""
    if not config.GOOGLE_CLIENT_ID_WEB:
        raise HTTPException(status_code=503, detail="Google OAuth nu este configurat")
    state = secrets.token_urlsafe(32)
    _store_state(state)
    url = google_auth.build_authorization_url(
        client_id=config.GOOGLE_CLIENT_ID_WEB,
        redirect_uri=config.GOOGLE_REDIRECT_URI_WEB,
        state=state,
    )
    return GoogleAuthUrlOut(auth_url=url, state=state)


@router.get("/auth/google/callback", tags=["auth"])
async def google_auth_callback(
    code: str,
    state: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """Google a redirectionat user-ul aici. Schimbam code -> id_token,
    creem User (sau il gasim), setam cookie, redirect spre frontend."""
    if not _consume_state(state):
        raise HTTPException(status_code=400, detail="State invalid sau expirat")

    try:
        tokens = await google_auth.exchange_code_for_token(
            code=code,
            client_id=config.GOOGLE_CLIENT_ID_WEB,
            client_secret=config.GOOGLE_CLIENT_SECRET_WEB,
            redirect_uri=config.GOOGLE_REDIRECT_URI_WEB,
        )
        payload = google_auth.verify_id_token(
            tokens["id_token"], config.GOOGLE_CLIENT_ID_WEB
        )
    except google_auth.GoogleAuthError as e:
        raise HTTPException(status_code=400, detail=str(e))

    email = payload["email"].lower().strip()
    google_sub = payload["sub"]
    picture = payload.get("picture")

    user = _upsert_google_user(db, email=email, google_sub=google_sub, picture=picture)

    token = create_session(
        db, user.id,
        user_agent=request.headers.get("user-agent"),
        ip=request.client.host if request.client else None,
    )
    redirect_url = f"{config.FRONTEND_BASE_URL}/dashboard"
    resp = RedirectResponse(url=redirect_url, status_code=302)
    set_session_cookie(resp, token)
    return resp
