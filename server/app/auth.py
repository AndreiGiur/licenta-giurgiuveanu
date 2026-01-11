from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status, Header
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import User, Session as DbSession


PBKDF2_ITERATIONS = 200_000
SESSION_EXPIRE_HOURS = int(os.getenv("SESSION_EXPIRE_HOURS", "24"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _pbkdf2_hash(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)
    return dk.hex()


def create_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16).hex()
    pwd_hash = _pbkdf2_hash(password, salt)
    return salt, pwd_hash


def verify_password(password: str, salt_hex: str, pwd_hash_hex: str) -> bool:
    calc = _pbkdf2_hash(password, salt_hex)
    return hmac.compare_digest(calc, pwd_hash_hex)


def create_session(db: Session, user_id: int, user_agent: str | None, ip: str | None) -> str:
    token = DbSession.new_token()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=SESSION_EXPIRE_HOURS)
    sess = DbSession(user_id=user_id, token=token, user_agent=user_agent, ip=ip, expires_at=expires_at)
    db.add(sess)
    db.commit()
    return token


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.execute(select(User).where(User.email == email)).scalar_one_or_none()


def require_user(db: Session = Depends(get_db), x_session_token: str | None = Header(default=None)) -> User:
    if not x_session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing session token")

    sess = db.execute(select(DbSession).where(DbSession.token == x_session_token)).scalar_one_or_none()
    if not sess:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid session token")

    # check expiration (handle DB backends that return naive datetimes)
    now = datetime.now(timezone.utc)
    if sess.expires_at is not None:
        if sess.expires_at.tzinfo is None:
            sess.expires_at = sess.expires_at.replace(tzinfo=timezone.utc)
        if sess.expires_at < now:
            # expire session
            db.delete(sess)
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session expired")

    user = db.get(User, sess.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid session token")
    return user
