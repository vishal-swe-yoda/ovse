from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class VerificationStatus(StrEnum):
    CREATED = "CREATED"
    INTENT_GENERATED = "INTENT_GENERATED"
    CALLBACK_RECEIVED = "CALLBACK_RECEIVED"
    VERIFIED_MOCK = "VERIFIED_MOCK"
    FAILED = "FAILED"


class VerificationSession(Base):
    __tablename__ = "verification_sessions"

    session_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    txn_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    jti: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    status: Mapped[VerificationStatus] = mapped_column(
        Enum(VerificationStatus), default=VerificationStatus.CREATED
    )
    claims_bitmap: Mapped[str] = mapped_column(String(64))
    intent_jwt: Mapped[str] = mapped_column(Text)
    invocation_url: Mapped[str] = mapped_column(Text)
    callback_xml: Mapped[str | None] = mapped_column(Text, nullable=True)
    credential_sd_jwt: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified_claims_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_errors_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC)
    )
