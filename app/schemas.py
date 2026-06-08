from datetime import datetime

from pydantic import BaseModel, Field

from app.models import VerificationStatus


class CreateSessionRequest(BaseModel):
    claims: list[str] = Field(default_factory=lambda: ["name", "dob", "gender"])
    redirect_url: str | None = None
    language_code: str | None = None
    profile_hint: str | None = None


class CreateSessionResponse(BaseModel):
    session_id: str
    txn_id: str
    jti: str
    status: VerificationStatus
    intent_jwt: str
    invocation_url: str


class SessionResponse(BaseModel):
    session_id: str
    txn_id: str
    jti: str
    status: VerificationStatus
    claims_bitmap: str
    invocation_url: str
    verified_claims: dict | None = None
    verification_errors: list[str] | None = None
    created_at: datetime
    updated_at: datetime


class CallbackAck(BaseModel):
    txn_id: str
    status: str
