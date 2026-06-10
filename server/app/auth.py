from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import Cookie, Depends, HTTPException, Header, Response, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import User, Session as DbSession, hash_token


PBKDF2_ITERATIONS = 200_000
SESSION_EXPIRE_HOURS = int(os.getenv("SESSION_EXPIRE_HOURS", "24"))

# Numele cookie-ului de sesiune. Frontend-ul nu il citeste niciodata
# (HttpOnly), browser-ul il trimite automat la cereri pe acelasi origin.
SESSION_COOKIE_NAME = "vw_session"

# In productie: cookie peste HTTPS si SameSite=strict.
# In development (HTTP localhost) lasam Secure=False ca sa functioneze.
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")  # "lax" | "strict" | "none"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Parole ────────────────────────────────────────────────────────────────────

def _pbkdf2_hash(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)
    return dk.hex()


def create_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16).hex()
    pwd_hash = _pbkdf2_hash(password, salt)
    return salt, pwd_hash


def verify_password(password: str, salt_hex: str | None, pwd_hash_hex: str | None) -> bool:
    """Verifica parola. Returneaza False daca user-ul nu are parola setata
    (cont Google-only — `salt_hex` sau `pwd_hash_hex` lipsesc)."""
    if salt_hex is None or pwd_hash_hex is None:
        return False
    calc = _pbkdf2_hash(password, salt_hex)
    return hmac.compare_digest(calc, pwd_hash_hex)


# ── Sesiuni ───────────────────────────────────────────────────────────────────

def _purge_expired_sessions(db: Session, user_id: int | None = None) -> None:
    """Sterge sesiunile expirate (optional doar pentru un user) ca DB-ul sa nu se umfle."""
    now = datetime.now(timezone.utc)
    stmt = delete(DbSession).where(DbSession.expires_at.is_not(None), DbSession.expires_at < now)
    if user_id is not None:
        stmt = stmt.where(DbSession.user_id == user_id)
    db.execute(stmt)


def create_session(db: Session, user_id: int, user_agent: str | None, ip: str | None) -> str:
    # Cleanup oportunist la creare sesiune noua
    _purge_expired_sessions(db, user_id=user_id)

    # In DB stocam doar SHA-256 al tokenului (acelasi tratament ca device_token).
    # Tokenul plain pleaca o singura data catre client si nu poate fi recuperat
    # dintr-un dump al bazei de date.
    token = DbSession.new_token()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=SESSION_EXPIRE_HOURS)
    sess = DbSession(user_id=user_id, token=hash_token(token), user_agent=user_agent, ip=ip, expires_at=expires_at)
    db.add(sess)
    db.commit()
    return token


def set_session_cookie(response: Response, token: str) -> None:
    """Scrie cookie-ul HttpOnly pentru sesiune."""
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_EXPIRE_HOURS * 3600,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
    )


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.execute(select(User).where(User.email == email)).scalar_one_or_none()


def _resolve_session_token(
    x_session_token: str | None,
    cookie_token: str | None,
) -> str | None:
    """Token-ul poate veni fie din cookie (browser), fie din header (agent / curl).
    Cookie are prioritate pentru ca este mai sigur."""
    if cookie_token:
        return cookie_token
    if x_session_token:
        return x_session_token
    return None


def require_user(
    db: Session = Depends(get_db),
    x_session_token: str | None = Header(default=None),
    vw_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> User:
    token = _resolve_session_token(x_session_token, vw_session)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing session token")

    sess = db.execute(select(DbSession).where(DbSession.token == hash_token(token))).scalar_one_or_none()
    if not sess:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid session token")

    # Verifica expirarea (suport pentru DB-uri ce intorc datetime naive – ex SQLite in teste)
    now = datetime.now(timezone.utc)
    if sess.expires_at is not None:
        if sess.expires_at.tzinfo is None:
            sess.expires_at = sess.expires_at.replace(tzinfo=timezone.utc)
        if sess.expires_at < now:
            db.delete(sess)
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session expired")

    user = db.get(User, sess.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid session token")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    """Restricteaza accesul doar la userii cu role='admin'."""
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Admin role required")
    return user


def get_session_token_for_logout(
    x_session_token: str | None = Header(default=None),
    vw_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> str | None:
    """Helper pentru endpoint-ul de logout (nu cere user valid)."""
    return _resolve_session_token(x_session_token, vw_session)
