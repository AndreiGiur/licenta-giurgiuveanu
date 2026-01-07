from __future__ import annotations

from datetime import datetime, timezone
import secrets

from sqlalchemy import (
    String,
    DateTime,
    JSON,
    ForeignKey,
    Integer,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    devices: Mapped[list["Device"]] = relationship(
        back_populates="owner",
        cascade="all, delete-orphan",
    )


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("owner_id", "device_uid", name="uq_owner_device_uid"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)

    # identificator stabil, trimis de agent in payload (ex: "laptop-01")
    device_uid: Mapped[str] = mapped_column(String(128), index=True)

    # nume prietenos in UI (ex: "Laptop personal")
    name: Mapped[str] = mapped_column(String(128))

    # token folosit de agent la POST /scans (nu JWT; e "device token")
    device_token: Mapped[str] = mapped_column(String(128), unique=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    owner: Mapped["User"] = relationship(back_populates="devices")
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="device",
        cascade="all, delete-orphan",
    )

    @staticmethod
    def generate_token() -> str:
        return secrets.token_urlsafe(32)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        index=True,
    )
    exposure_score: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict] = mapped_column(JSON)

    device: Mapped["Device"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )


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
