import json
import uuid
from contextlib import asynccontextmanager

from typing import Annotated

from fastapi import Body, Depends, FastAPI, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_db, init_db
from app.mock_uidai import build_ack_xml, build_mock_callback_xml, parse_callback_xml
from app.models import VerificationSession, VerificationStatus
from app.ovse import (
    build_claims_bitmap,
    build_intent_jwt,
    build_invocation_url,
    create_jti,
    create_txn_id,
)
from app.schemas import CreateSessionRequest, CreateSessionResponse, SessionResponse
from app.sd_jwt import verify_sd_jwt_disclosures, verify_sd_jwt_signature


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="OVSE Web-to-App MVP Shell", lifespan=lifespan)


def serialize_session(session: VerificationSession) -> SessionResponse:
    return SessionResponse(
        session_id=session.session_id,
        txn_id=session.txn_id,
        jti=session.jti,
        status=session.status,
        claims_bitmap=session.claims_bitmap,
        invocation_url=session.invocation_url,
        verified_claims=json.loads(session.verified_claims_json)
        if session.verified_claims_json
        else None,
        verification_errors=json.loads(session.verification_errors_json)
        if session.verification_errors_json
        else None,
        created_at=session.created_at,
        updated_at=session.updated_at,
    )


@app.post("/api/ovse/sessions", response_model=CreateSessionResponse)
def create_session(
    request: CreateSessionRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> CreateSessionResponse:
    session_id = str(uuid.uuid4())
    txn_id = create_txn_id()
    jti = create_jti()
    claims_bitmap = build_claims_bitmap(request.claims)
    intent_jwt = build_intent_jwt(
        settings=settings,
        txn_id=txn_id,
        jti=jti,
        claims_bitmap=claims_bitmap,
        redirect_url=request.redirect_url,
        language_code=request.language_code,
        profile_hint=request.profile_hint,
    )
    invocation_url = build_invocation_url(settings=settings, intent_jwt=intent_jwt)

    session = VerificationSession(
        session_id=session_id,
        txn_id=txn_id,
        jti=jti,
        status=VerificationStatus.INTENT_GENERATED,
        claims_bitmap=claims_bitmap,
        intent_jwt=intent_jwt,
        invocation_url=invocation_url,
    )
    db.add(session)
    db.commit()

    return CreateSessionResponse(
        session_id=session_id,
        txn_id=txn_id,
        jti=jti,
        status=session.status,
        intent_jwt=intent_jwt,
        invocation_url=invocation_url,
    )


@app.get("/api/ovse/sessions/{session_id}", response_model=SessionResponse)
def get_session(session_id: str, db: Session = Depends(get_db)) -> SessionResponse:
    session = db.get(VerificationSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Verification session not found")
    return serialize_session(session)


@app.post("/api/ovse/mock/callback/{session_id}")
def trigger_mock_callback(
    session_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    if not settings.mock_mode:
        raise HTTPException(status_code=403, detail="Mock callback is disabled")

    session = db.get(VerificationSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Verification session not found")

    xml_body = build_mock_callback_xml(settings=settings, txn_id=session.txn_id)
    return handle_callback_xml(xml_body=xml_body, db=db, settings=settings)


@app.get("/api/ovse/mock/callback-xml/{session_id}")
def get_mock_callback_xml(
    session_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    if not settings.mock_mode:
        raise HTTPException(status_code=403, detail="Mock callback is disabled")

    session = db.get(VerificationSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Verification session not found")

    xml_body = build_mock_callback_xml(settings=settings, txn_id=session.txn_id)
    return Response(content=xml_body, media_type="application/xml")


@app.post("/api/ovse/callback")
def receive_callback(
    xml_body: Annotated[
        str,
        Body(
            media_type="application/xml",
            examples=[
                """<Request>
  <TxnID>00000000-0000-0000-0000-000000000000</TxnID>
  <Credential>PASTE_SD_JWT_HERE</Credential>
</Request>"""
            ],
        ),
    ],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    return handle_callback_xml(xml_body=xml_body, db=db, settings=settings)


def handle_callback_xml(
    *, xml_body: str, db: Session, settings: Settings
) -> Response:
    try:
        txn_id, credential = parse_callback_xml(xml_body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    session = db.scalar(
        select(VerificationSession).where(VerificationSession.txn_id == txn_id)
    )
    if session is None:
        raise HTTPException(status_code=404, detail="TxnID not found")

    if session.status != VerificationStatus.INTENT_GENERATED:
        return Response(
            content=build_ack_xml(
                txn_id=txn_id,
                status="FAILURE",
                response_code="409",
                response_msg="Transaction already processed",
            ),
            media_type="application/xml",
            status_code=409,
        )

    session.status = VerificationStatus.CALLBACK_RECEIVED
    session.callback_xml = xml_body
    session.credential_sd_jwt = credential

    credential_public_key = (
        settings.verifier_public_key_pem
        if settings.mock_mode
        else settings.uidai_public_key_pem
    )
    if not settings.mock_mode and not settings.uidai_signature_verification_enabled:
        session.status = VerificationStatus.FAILED
        session.verification_errors_json = json.dumps(
            ["UIDAI credential signature verification must be enabled"]
        )
    elif not credential_public_key:
        session.status = VerificationStatus.FAILED
        session.verification_errors_json = json.dumps(
            ["UIDAI public key is required for credential signature verification"]
        )
    else:
        errors = []
        try:
            credential_payload = verify_sd_jwt_signature(
                credential,
                public_key_pem=credential_public_key,
                audience=settings.verifier_issuer,
                issuer=settings.uidai_issuer,
            )
            if credential_payload.get("txn") != session.txn_id:
                errors.append("Credential txn does not match session txn")
        except ValueError as exc:
            credential_payload = {}
            errors.append(str(exc))

        claims, disclosure_errors = verify_sd_jwt_disclosures(credential)
        errors.extend(disclosure_errors)
        if credential_payload and credential_payload.get("txn") != session.txn_id:
            errors.append("Credential txn does not match session txn")
        session.verified_claims_json = json.dumps(claims)
        session.verification_errors_json = json.dumps(errors)
        session.status = (
            VerificationStatus.FAILED if errors else VerificationStatus.VERIFIED_MOCK
        )

    db.add(session)
    db.commit()

    ack_status = "FAILURE" if session.status == VerificationStatus.FAILED else "SUCCESS"
    return Response(
        content=build_ack_xml(txn_id=txn_id, status=ack_status),
        media_type="application/xml",
    )
