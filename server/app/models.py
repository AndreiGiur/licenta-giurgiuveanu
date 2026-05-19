from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, JSON, Integer, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_token(token: str) -> str:
    """SHA-256 al unui token. Folosit pentru stocarea device_token in DB."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    # PBKDF2 fields — NULLABLE pentru utilizatorii Google-only
    password_salt: Mapped[str | None] = mapped_column(String(64), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Google OAuth fields
    google_sub: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True, index=True)
    google_picture_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    auth_provider: Mapped[str] = mapped_column(String(16), default="password", nullable=False)

    # Rol platforma: "user" (default) sau "admin". Primul user inregistrat
    # devine admin automat (vezi register handler). Admin = vede tot + manage users.
    role: Mapped[str] = mapped_column(String(16), default="user", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    sessions: Mapped[list["Session"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    devices: Mapped[list["Device"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)

    token: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user: Mapped["User"] = relationship(back_populates="sessions")

    @staticmethod
    def new_token() -> str:
        return secrets.token_urlsafe(48)


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("owner_id", "device_uid", name="uq_owner_device_uid"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)

    device_uid: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(128))

    # Stocam doar hash-ul SHA-256 al token-ului (token-ul plain este afisat
    # o singura data la enrollment si nu poate fi recuperat). Un prefix scurt
    # este pastrat pentru identificare in UI ("token care incepe cu...").
    device_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    device_token_prefix: Mapped[str] = mapped_column(String(12))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Heartbeat: agent semnaleaza ca este online la fiecare ~10s.
    # is_online se calculeaza la cerere (last_heartbeat < 30s); nu e coloana.
    last_heartbeat: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    capabilities: Mapped[list | None] = mapped_column(JSON, nullable=True)
    local_subnet: Mapped[str | None] = mapped_column(String(64), nullable=True)
    nmap_installed: Mapped[bool] = mapped_column(Integer, default=0)

    owner: Mapped["User"] = relationship(back_populates="devices")
    scans: Mapped[list["Scan"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="device", cascade="all, delete-orphan")

    @property
    def is_online(self) -> bool:
        """Online = last_heartbeat in ultimele 30s. Se calculeaza la query;
        nu este coloana persistata. SQLite poate stoca datetime naive, asa ca
        normalizam la UTC inainte de calcul."""
        if self.last_heartbeat is None:
            return False
        hb = self.last_heartbeat
        if hb.tzinfo is None:
            hb = hb.replace(tzinfo=timezone.utc)
        delta = utcnow() - hb
        return delta.total_seconds() < 30

    @staticmethod
    def generate_token() -> str:
        """Genereaza un token nou (plain). Apelantul trebuie sa-l afiseze
        utilizatorului si sa stocheze doar hash-ul (`hash_token`)."""
        return secrets.token_urlsafe(32)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    exposure_score: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict] = mapped_column(JSON)
    nmap_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    device: Mapped["Device"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(16))
    evidence: Mapped[dict] = mapped_column(JSON, default={})
    recommendation: Mapped[str] = mapped_column(String(512))

    scan: Mapped["Scan"] = relationship(back_populates="findings")


# ── Scan-on-demand: job queue pentru orchestrarea agent-ului ─────────────────
#
# State machine:
#
#     pending  ── agent ridica jobul prin GET /agent/jobs/next ──► running
#     running  ── agent trimite rezultatul prin POST /...result ──► done
#     running  ── eroare la executie / timeout ─────────────────► failed
#     pending/running ── user anuleaza ──────────────────────────► cancelled
#
# Decoupling: UI creeaza jobul si nu asteapta executia in acelasi request.
# Agentul polleaza la cateva secunde si executa cand prinde un job pending.
# Fluxul functioneaza prin firewall/NAT pentru ca toate cererile sunt
# initiate de agent (outbound HTTPS).

class ScanJobStatus:
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"

    ALL = (PENDING, RUNNING, DONE, FAILED, CANCELLED)
    TERMINAL = (DONE, FAILED, CANCELLED)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)

    # User-ul care a cerut jobul. Poate fi null pentru auto-scan declansat de
    # daemon-ul agentului (fara request UI).
    requested_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[str] = mapped_column(String(16), default=ScanJobStatus.PENDING, index=True)

    created_at:  Mapped[datetime]            = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at:  Mapped[datetime | None]     = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None]     = mapped_column(DateTime(timezone=True), nullable=True)

    # Set la finalizare cu success — face legatura cu raportul produs.
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )

    # Mesaj de eroare in caz de failed (max 512c; truncat daca e mai lung).
    error_message: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Tipul scanarii ales de user (standard / advanced / deep). Agentul
    # foloseste valoarea ca sa stie ce SCAN_PROFILE sa aplice. Backend-ul
    # o foloseste pentru evaluate() (filtrare reguli dupa min_level).
    scan_type: Mapped[str] = mapped_column(String(16), default="standard")
    nmap_target: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Progres raportat de agent intre colectori (0-100) + faza curenta.
    # Util pentru UI in cazul scanarilor Advanced/Deep care dureaza minute.
    progress: Mapped[int] = mapped_column(Integer, default=0)
    phase: Mapped[str | None] = mapped_column(String(128), nullable=True)

    device: Mapped["Device"] = relationship(back_populates="scan_jobs")
    scan: Mapped["Scan | None"] = relationship(foreign_keys=[scan_id])
