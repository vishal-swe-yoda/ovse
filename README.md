# OVSE Web-to-App MVP Shell

Mock-first FastAPI verifier backend for a UIDAI Aadhaar App Web-to-App credential exchange flow.

The service can:

- create Aadhaar verification sessions
- generate RS256-signed OVSE intent JWTs using the Aadhaar App intent fields
- return UIDAI Web-to-App intent invocation URLs
- accept mock UIDAI-style XML callbacks
- parse mock SD-JWT credentials
- verify SD-JWT signatures and disclosure hashes
- update and poll verification session status
- construct the UIDAI spec's 42-bit selective-claim bitmap
- reject replayed callback transactions

UIDAI public key verification, real Aadhaar App testing, and sandbox calls are intentionally disabled by configuration until UIDAI keys and environments are available.

## Run

```powershell
uv sync
uv run uvicorn app.main:app --reload
```

`uv sync` creates and updates the project `.venv` automatically. You do not need to activate it or change your shell interpreter. Run project commands through `uv run ...`; avoid `uv sync --active`, which targets the currently active environment instead of the project `.venv`.

On startup, the app creates the configured database tables with SQLAlchemy metadata.
There is no Alembic migration step for this MVP.

By default, local runs use SQLite at `ovse_mvp.db`. To use Neon/Postgres instead,
create a `.env` file with your database URL:

```txt
OVSE_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST/DBNAME?sslmode=require
OVSE_VERIFIER_PRIVATE_KEY_PATH=keys/verifier_private.pem
OVSE_VERIFIER_PUBLIC_KEY_PATH=keys/verifier_public.pem
OVSE_VERIFIER_CALLBACK_URL=https://verifier.example.test/api/ovse/callback
OVSE_VERIFIER_AUDIENCE=https://verifier.example.test
```

Neon URLs that start with `postgres://` or `postgresql://` are normalized to SQLAlchemy's `postgresql+psycopg://` driver form automatically.

The verifier signs OVSE intent JWTs with the RSA private key at `keys/verifier_private.pem`.
The matching public key is at `keys/verifier_public.pem` and is the key UIDAI would need for request verification in a real integration. These local PEM files are ignored by git.

The Aadhaar App intent specification requires an HTTPS callback URL, short-lived `exp`, transaction and `jti` uniqueness, RS256 JWT signing, SD-JWT signature verification, and replay rejection. Local HTTP callback URLs are rejected by configuration.

## API

```txt
POST /api/ovse/sessions
GET  /api/ovse/sessions/{session_id}
GET  /api/ovse/mock/callback-xml/{session_id}
POST /api/ovse/mock/callback/{session_id}
POST /api/ovse/callback
```

Swagger UI is available at:

```txt
http://127.0.0.1:8000/docs
```

## Workflow

The mock flow mirrors the real OVSE exchange:

1. The verifier creates an intent request JWT.
2. The Aadhaar app receives that intent through the invocation URL.
3. UIDAI/Aadhaar app sends callback XML containing an SD-JWT credential.
4. The verifier validates the SD-JWT signature, disclosures, and transaction ID.
5. The verifier stores verified claims or verification errors on the session.

For local testing, the app can generate mock callback XML with a mock SD-JWT.

### 1. Create a verification session

Swagger:

Run `POST /api/ovse/sessions` with:

```json
{
  "claims": ["name", "dob", "gender"]
}
```

PowerShell:

```powershell
curl -X POST http://127.0.0.1:8000/api/ovse/sessions `
  -H "Content-Type: application/json" `
  -d "{\"claims\":[\"name\",\"dob\",\"gender\"]}"
```

Sample response:

```json
{
  "session_id": "5d2d3a1e-0e47-47b7-9a5e-67f6d3ab0c4f",
  "txn_id": "a3614152-9288-4e16-8719-ee9d4d8e959e",
  "jti": "4c4b47c8-b78e-4f8f-b9cd-5998174a24f3",
  "status": "INTENT_GENERATED",
  "intent_jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "invocation_url": "intent:#Intent;action=in.gov.uidai.pehchaan.WEB_INTENT_REQUEST;S.request=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...;end"
}
```

The `intent_jwt` is the signed request JWT. It is not the SD-JWT credential.
The `sc` claim inside it is a 42-bit bitmap built from the requested claims.

### 2. Generate mock callback XML

Swagger:

Run `GET /api/ovse/mock/callback-xml/{session_id}`.

PowerShell:

```powershell
curl http://127.0.0.1:8000/api/ovse/mock/callback-xml/5d2d3a1e-0e47-47b7-9a5e-67f6d3ab0c4f
```

Sample response:

```xml
<Request>
  <TxnID>a3614152-9288-4e16-8719-ee9d4d8e959e</TxnID>
  <Credential>eyJhbGciOiJSUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9...~WyJzYWx0IiwibmFtZSIsIk1PQ0sgQUFESEFBUiBVU0VSIl0~</Credential>
</Request>
```

This endpoint only generates XML. It does not update the session, so the XML can be pasted into the real callback endpoint.

### 3. Submit the callback XML

Swagger:

Run `POST /api/ovse/callback` and paste the XML from step 2 as the request body.

PowerShell:

```powershell
$xml = @"
<Request>
  <TxnID>a3614152-9288-4e16-8719-ee9d4d8e959e</TxnID>
  <Credential>PASTE_SD_JWT_HERE</Credential>
</Request>
"@

curl -X POST http://127.0.0.1:8000/api/ovse/callback `
  -H "Content-Type: application/xml" `
  --data-binary $xml
```

Sample success response:

```xml
<Response>
  <TxnID>a3614152-9288-4e16-8719-ee9d4d8e959e</TxnID>
  <ResponseCode>200</ResponseCode>
  <ResponseMsg>Success</ResponseMsg>
</Response>
```

If the same XML is posted again, the app returns `409` because callback transactions are replay-protected.

### 4. Poll the session

Swagger:

Run `GET /api/ovse/sessions/{session_id}`.

PowerShell:

```powershell
curl http://127.0.0.1:8000/api/ovse/sessions/5d2d3a1e-0e47-47b7-9a5e-67f6d3ab0c4f
```

Sample verified response:

```json
{
  "session_id": "5d2d3a1e-0e47-47b7-9a5e-67f6d3ab0c4f",
  "txn_id": "a3614152-9288-4e16-8719-ee9d4d8e959e",
  "jti": "4c4b47c8-b78e-4f8f-b9cd-5998174a24f3",
  "status": "VERIFIED_MOCK",
  "claims_bitmap": "000001000001100000000000000000000000000000",
  "invocation_url": "intent:#Intent;action=in.gov.uidai.pehchaan.WEB_INTENT_REQUEST;S.request=...",
  "verified_claims": {
    "name": "MOCK AADHAAR USER",
    "dob": "1990-01-01",
    "gender": "X"
  },
  "verification_errors": [],
  "created_at": "2026-06-05T10:00:00",
  "updated_at": "2026-06-05T10:00:05"
}
```

### Shortcut mock callback

For quick testing, use:

```txt
POST /api/ovse/mock/callback/{session_id}
```

This generates the same mock XML internally and immediately passes it through `/api/ovse/callback` verification logic. Use `GET /api/ovse/mock/callback-xml/{session_id}` instead when you want to copy the XML into Swagger manually.

## Claims bitmap

The `claims` array is converted into the `sc` bitmap in the intent JWT.

Example:

```json
{
  "claims": ["name", "dob", "gender"]
}
```

sets:

- `name` alias `residentName`: bit 6
- `dob`: bit 12
- `gender`: bit 13

Bits 41-42 are reserved padding and remain `0`.

## Test

```powershell
uv run pytest
```
