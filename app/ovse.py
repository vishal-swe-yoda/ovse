import time
import uuid
from urllib.parse import quote

import jwt

from app.config import Settings


CLAIM_BITS_42 = {
    "credentialIssuingDate": 1,
    "enrolmentDate": 2,
    "enrolmentNumber": 3,
    "isNRI": 4,
    "residentImage": 5,
    "residentName": 6,
    "localResidentName": 7,
    "ageAbove18": 8,
    "ageAbove50": 9,
    "ageAbove60": 10,
    "ageAbove75": 11,
    "dob": 12,
    "gender": 13,
    "careOf": 14,
    "localCareOf": 15,
    "building": 16,
    "localBuilding": 17,
    "locality": 18,
    "localLocality": 19,
    "street": 20,
    "localStreet": 21,
    "landmark": 22,
    "localLandmark": 23,
    "vtc": 24,
    "localVtc": 25,
    "subDistrict": 26,
    "localSubDistrict": 27,
    "district": 28,
    "localDistrict": 29,
    "state": 30,
    "localState": 31,
    "poName": 32,
    "localPoName": 33,
    "pincode": 34,
    "address": 35,
    "regionalAddress": 36,
    "mobile": 37,
    "maskedMobile": 38,
    "email": 39,
    "maskedEmail": 40,
}

CLAIM_ALIASES = {
    "name": "residentName",
    "photo": "residentImage",
    "mobile_hash": "maskedMobile",
    "email_hash": "maskedEmail",
}


def create_txn_id() -> str:
    return str(uuid.uuid4())


def create_jti() -> str:
    return str(uuid.uuid4())


def build_claims_bitmap(claims: list[str]) -> str:
    bits = ["0"] * 42
    for claim in claims:
        mapped_claim = CLAIM_ALIASES.get(claim, claim)
        if mapped_claim not in CLAIM_BITS_42:
            continue
        bit_position = CLAIM_BITS_42[mapped_claim]
        bits[bit_position - 1] = "1"
    return "".join(bits)


def build_intent_jwt(
    *,
    settings: Settings,
    txn_id: str,
    jti: str,
    claims_bitmap: str,
    redirect_url: str | None,
    language_code: str | None = None,
    profile_hint: str | None = None,
) -> str:
    now = int(time.time())
    payload = {
        "txn": txn_id,
        "i": "credential",
        "lang": language_code or settings.intent_language_code,
        "sc": claims_bitmap,
        "pop": 1,
        "ch": "app",
        "m": "1",
        "ac": settings.uidai_ovse_client_id,
        "sa": settings.uidai_ovse_registration_number,
        "cb": settings.verifier_callback_url,
        "aud": settings.verifier_audience,
        "iss": settings.uidai_issuer,
        "exp": now + settings.intent_expiry_seconds,
        "iat": now,
        "ht": profile_hint,
        "aid": settings.aadhaar_app_id,
        "asig": settings.aadhaar_app_signature,
        "jti": jti,
    }
    if redirect_url is not None:
        payload["redirect_url"] = redirect_url
    headers = {"alg": "RS256", "typ": "JWT"}
    return jwt.encode(
        payload,
        settings.verifier_private_key_pem,
        algorithm="RS256",
        headers=headers,
    )


def build_invocation_url(*, settings: Settings, intent_jwt: str) -> str:
    return (
        "intent:#Intent;"
        f"action={settings.uidai_web_intent_action};"
        f"S.request={quote(intent_jwt, safe='')};"
        "end"
    )
