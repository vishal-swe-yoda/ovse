import time
import uuid
import xml.etree.ElementTree as ET

import jwt

from app.config import Settings
from app.sd_jwt import disclosure_hash, encode_disclosure


def build_mock_sd_jwt(*, settings: Settings, txn_id: str) -> str:
    disclosures = [
        encode_disclosure(str(uuid.uuid4()), "name", "MOCK AADHAAR USER"),
        encode_disclosure(str(uuid.uuid4()), "dob", "1990-01-01"),
        encode_disclosure(str(uuid.uuid4()), "gender", "X"),
    ]
    now = int(time.time())
    payload = {
        "iss": settings.uidai_issuer,
        "aud": settings.verifier_issuer,
        "iat": now,
        "exp": now + 600,
        "txn": txn_id,
        "_sd_alg": "sha-256",
        "_sd": [disclosure_hash(disclosure) for disclosure in disclosures],
    }
    credential_jwt = jwt.encode(
        payload,
        settings.verifier_private_key_pem,
        algorithm="RS256",
        headers={"alg": "RS256", "typ": "vc+sd-jwt"},
    )
    return credential_jwt + "~" + "~".join(disclosures) + "~"


def build_mock_callback_xml(*, settings: Settings, txn_id: str) -> str:
    credential = build_mock_sd_jwt(settings=settings, txn_id=txn_id)
    root = ET.Element("Request")
    ET.SubElement(root, "TxnID").text = txn_id
    ET.SubElement(root, "Credential").text = credential
    return ET.tostring(root, encoding="unicode")


def parse_callback_xml(xml_body: str) -> tuple[str, str]:
    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError as exc:
        raise ValueError("Callback XML is malformed") from exc
    txn_id = root.findtext("TxnID")
    credential = root.findtext("Credential")
    if not txn_id:
        raise ValueError("Callback XML is missing TxnID")
    if not credential:
        raise ValueError("Callback XML is missing Credential")
    return txn_id, credential


def build_ack_xml(
    *,
    txn_id: str,
    status: str,
    response_code: str | None = None,
    response_msg: str | None = None,
) -> str:
    code = response_code or ("200" if status == "SUCCESS" else "400")
    message = response_msg or ("Success" if status == "SUCCESS" else "Failure")
    root = ET.Element("Response")
    ET.SubElement(root, "TxnID").text = txn_id
    ET.SubElement(root, "ResponseCode").text = code
    ET.SubElement(root, "ResponseMsg").text = message
    return ET.tostring(root, encoding="unicode")
