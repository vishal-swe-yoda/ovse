import base64
import hashlib
import json
from typing import Any

import jwt
from jwt import PyJWTError


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def disclosure_hash(disclosure: str) -> str:
    return b64url_encode(hashlib.sha256(disclosure.encode("ascii")).digest())


def encode_disclosure(salt: str, claim_name: str, claim_value: Any) -> str:
    payload = json.dumps([salt, claim_name, claim_value], separators=(",", ":")).encode()
    return b64url_encode(payload)


def parse_disclosure(disclosure: str) -> tuple[str, str, Any]:
    decoded = json.loads(b64url_decode(disclosure))
    if not isinstance(decoded, list) or len(decoded) != 3:
        raise ValueError("Disclosure must be a three-item SD-JWT array")
    salt, claim_name, claim_value = decoded
    return str(salt), str(claim_name), claim_value


def parse_unverified_jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Credential JWT must have three parts")
    return json.loads(b64url_decode(parts[1]))


def verify_sd_jwt_signature(
    sd_jwt: str,
    *,
    public_key_pem: str,
    audience: str | None = None,
    issuer: str | None = None,
) -> dict[str, Any]:
    credential_jwt = sd_jwt.split("~", 1)[0]
    options = {"verify_aud": audience is not None}
    try:
        return jwt.decode(
            credential_jwt,
            public_key_pem,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            options=options,
        )
    except PyJWTError as exc:
        raise ValueError(f"Credential signature verification failed: {exc}") from exc


def verify_sd_jwt_disclosures(sd_jwt: str) -> tuple[dict[str, Any], list[str]]:
    parts = sd_jwt.split("~")
    credential_jwt = parts[0]
    disclosures = [part for part in parts[1:] if part]
    payload = parse_unverified_jwt_payload(credential_jwt)
    expected_hashes = payload.get("_sd", [])

    if not isinstance(expected_hashes, list):
        return {}, ["Credential _sd claim must be a list"]

    claims: dict[str, Any] = {}
    errors: list[str] = []
    seen_hashes: set[str] = set()

    for disclosure in disclosures:
        digest = disclosure_hash(disclosure)
        seen_hashes.add(digest)
        if digest not in expected_hashes:
            errors.append(f"Disclosure hash not present in credential: {digest}")
            continue
        try:
            _, claim_name, claim_value = parse_disclosure(disclosure)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        claims[claim_name] = claim_value

    missing = sorted(set(expected_hashes) - seen_hashes)
    for digest in missing:
        errors.append(f"Missing disclosure for hash: {digest}")

    return claims, errors
