import sqlite3
import uuid
from urllib.parse import unquote

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.database import Base, get_db, reset_database_state
from app.main import app
from app.models import VerificationStatus
from app.mock_uidai import build_mock_callback_xml
from app.ovse import build_claims_bitmap


def test_startup_creates_sqlite_database_without_migrations(tmp_path, monkeypatch):
    database_path = tmp_path / "startup.db"
    monkeypatch.setenv("OVSE_DATABASE_URL", f"sqlite:///{database_path}")
    monkeypatch.setenv(
        "OVSE_VERIFIER_CALLBACK_URL",
        "https://verifier.example.test/api/ovse/callback",
    )
    get_settings.cache_clear()
    reset_database_state()

    with TestClient(app):
        pass

    assert database_path.exists()
    with sqlite3.connect(database_path) as connection:
        table = connection.execute(
            "select name from sqlite_master "
            "where type = 'table' and name = 'verification_sessions'"
        ).fetchone()

    assert table == ("verification_sessions",)
    get_settings.cache_clear()
    reset_database_state()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    database_url = f"sqlite:///{tmp_path / 'test.db'}"
    monkeypatch.setenv("OVSE_DATABASE_URL", database_url)
    monkeypatch.setenv(
        "OVSE_VERIFIER_CALLBACK_URL",
        "https://verifier.example.test/api/ovse/callback",
    )
    monkeypatch.setenv("OVSE_VERIFIER_AUDIENCE", "https://verifier.example.test")
    monkeypatch.setenv("OVSE_UIDAI_SIGNATURE_VERIFICATION_ENABLED", "true")
    get_settings.cache_clear()
    reset_database_state()

    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    get_settings.cache_clear()
    reset_database_state()


def test_create_session_returns_rs256_intent_and_invocation_url(client):
    response = client.post("/api/ovse/sessions", json={"claims": ["name", "dob"]})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == VerificationStatus.INTENT_GENERATED
    assert body["invocation_url"].startswith(
        "intent:#Intent;action=in.gov.uidai.pehchaan.WEB_INTENT_REQUEST;"
    )

    header = jwt.get_unverified_header(body["intent_jwt"])
    payload = jwt.decode(
        body["intent_jwt"],
        get_settings().verifier_public_key_pem,
        algorithms=["RS256"],
        audience=get_settings().verifier_audience,
    )

    assert header["alg"] == "RS256"
    uuid.UUID(payload["txn"])
    uuid.UUID(payload["jti"])
    assert payload["txn"] == body["txn_id"]
    assert payload["i"] == "credential"
    assert payload["lang"] == "23"
    assert payload["pop"] == 1
    assert payload["ch"] == "app"
    assert payload["m"] == "1"
    assert payload["cb"].startswith("https://")
    assert payload["aud"] == get_settings().verifier_audience
    assert payload["iss"] == get_settings().uidai_issuer
    assert payload["exp"] - payload["iat"] == 300
    assert payload["ht"] is None
    assert payload["aid"] is None
    assert payload["asig"] is None
    assert len(payload["sc"]) == 42
    assert payload["sc"][5] == "1"
    assert payload["sc"][11] == "1"
    assert payload["sc"].count("1") == 2


def test_claims_bitmap_uses_uidai_42_bit_mapping():
    bitmap = build_claims_bitmap(
        ["credentialIssuingDate", "residentName", "dob", "gender", "maskedEmail"]
    )

    assert len(bitmap) == 42
    assert bitmap[0] == "1"
    assert bitmap[5] == "1"
    assert bitmap[11] == "1"
    assert bitmap[12] == "1"
    assert bitmap[39] == "1"
    assert bitmap[40:] == "00"
    assert bitmap.count("1") == 5


def test_mock_callback_verifies_sd_jwt_and_updates_session(client):
    created = client.post("/api/ovse/sessions", json={"claims": ["name"]}).json()

    callback = client.post(f"/api/ovse/mock/callback/{created['session_id']}")
    assert callback.status_code == 200
    assert callback.headers["content-type"].startswith("application/xml")
    assert "<ResponseCode>200</ResponseCode>" in callback.text
    assert "<ResponseMsg>Success</ResponseMsg>" in callback.text

    polled = client.get(f"/api/ovse/sessions/{created['session_id']}")
    assert polled.status_code == 200
    body = polled.json()
    assert body["status"] == VerificationStatus.VERIFIED_MOCK
    assert body["verified_claims"]["name"] == "MOCK AADHAAR USER"
    assert body["verification_errors"] == []


def test_mock_callback_xml_can_be_posted_to_callback(client):
    created = client.post("/api/ovse/sessions", json={"claims": ["name"]}).json()

    xml_response = client.get(
        f"/api/ovse/mock/callback-xml/{created['session_id']}"
    )
    assert xml_response.status_code == 200
    assert xml_response.headers["content-type"].startswith("application/xml")
    assert f"<TxnID>{created['txn_id']}</TxnID>" in xml_response.text
    assert "<Credential>" in xml_response.text

    callback = client.post(
        "/api/ovse/callback",
        content=xml_response.text,
        headers={"content-type": "application/xml"},
    )

    assert callback.status_code == 200
    assert "<ResponseCode>200</ResponseCode>" in callback.text
    assert "<ResponseMsg>Success</ResponseMsg>" in callback.text


def test_mock_callback_verifies_when_real_uidai_signature_check_disabled(client, monkeypatch):
    monkeypatch.setenv("OVSE_UIDAI_SIGNATURE_VERIFICATION_ENABLED", "false")
    get_settings.cache_clear()

    created = client.post("/api/ovse/sessions", json={"claims": ["name"]}).json()

    callback = client.post(f"/api/ovse/mock/callback/{created['session_id']}")

    assert callback.status_code == 200
    assert "<ResponseCode>200</ResponseCode>" in callback.text
    assert "<ResponseMsg>Success</ResponseMsg>" in callback.text


def test_app_integration_flow_from_session_to_callback_verification(client):
    settings = get_settings()

    created_response = client.post(
        "/api/ovse/sessions",
        json={
            "claims": ["name", "dob", "gender"],
            "redirect_url": "https://verifier.example.test/complete",
        },
    )

    assert created_response.status_code == 200
    created = created_response.json()
    assert created["status"] == VerificationStatus.INTENT_GENERATED

    invocation_url = created["invocation_url"]
    assert invocation_url.startswith(
        "intent:#Intent;action=in.gov.uidai.pehchaan.WEB_INTENT_REQUEST;"
    )
    encoded_intent_jwt = invocation_url.split("S.request=", 1)[1].split(";", 1)[0]
    assert unquote(encoded_intent_jwt) == created["intent_jwt"]

    intent_payload = jwt.decode(
        created["intent_jwt"],
        settings.verifier_public_key_pem,
        algorithms=["RS256"],
        audience=settings.verifier_audience,
    )
    assert intent_payload["txn"] == created["txn_id"]
    assert intent_payload["jti"] == created["jti"]
    assert intent_payload["i"] == "credential"
    assert intent_payload["lang"] == settings.intent_language_code
    assert intent_payload["sc"] == build_claims_bitmap(["name", "dob", "gender"])
    assert intent_payload["pop"] == 1
    assert intent_payload["ch"] == "app"
    assert intent_payload["m"] == "1"
    assert intent_payload["ac"] == settings.uidai_ovse_client_id
    assert intent_payload["sa"] == settings.uidai_ovse_registration_number
    assert intent_payload["cb"] == settings.verifier_callback_url
    assert intent_payload["aud"] == settings.verifier_audience
    assert intent_payload["iss"] == settings.uidai_issuer
    assert intent_payload["redirect_url"] == "https://verifier.example.test/complete"

    pending_response = client.get(f"/api/ovse/sessions/{created['session_id']}")
    assert pending_response.status_code == 200
    pending = pending_response.json()
    assert pending["status"] == VerificationStatus.INTENT_GENERATED
    assert pending["verified_claims"] is None
    assert pending["verification_errors"] is None

    callback_xml = build_mock_callback_xml(settings=settings, txn_id=created["txn_id"])
    callback_response = client.post(
        "/api/ovse/callback",
        content=callback_xml,
        headers={"content-type": "application/xml"},
    )

    assert callback_response.status_code == 200
    assert callback_response.headers["content-type"].startswith("application/xml")
    assert f"<TxnID>{created['txn_id']}</TxnID>" in callback_response.text
    assert "<ResponseCode>200</ResponseCode>" in callback_response.text
    assert "<ResponseMsg>Success</ResponseMsg>" in callback_response.text

    verified_response = client.get(f"/api/ovse/sessions/{created['session_id']}")
    assert verified_response.status_code == 200
    verified = verified_response.json()
    assert verified["status"] == VerificationStatus.VERIFIED_MOCK
    assert verified["verified_claims"] == {
        "name": "MOCK AADHAAR USER",
        "dob": "1990-01-01",
        "gender": "X",
    }
    assert verified["verification_errors"] == []


def test_callback_rejects_replayed_transactions(client):
    settings = get_settings()
    created = client.post("/api/ovse/sessions", json={"claims": ["name"]}).json()
    callback_xml = build_mock_callback_xml(settings=settings, txn_id=created["txn_id"])

    first_response = client.post(
        "/api/ovse/callback",
        content=callback_xml,
        headers={"content-type": "application/xml"},
    )
    replay_response = client.post(
        "/api/ovse/callback",
        content=callback_xml,
        headers={"content-type": "application/xml"},
    )

    assert first_response.status_code == 200
    assert replay_response.status_code == 409
    assert "<ResponseCode>409</ResponseCode>" in replay_response.text
    assert "<ResponseMsg>Transaction already processed</ResponseMsg>" in replay_response.text
